//! How joins and credential issues meet the board's row lock.
//!
//! A refused join (unknown id, wrong secret) is decided by one unlocked read: it never waits
//! behind a lock on the board or the invite, so its timing cannot reveal what is happening on
//! the board. A join with the right secret, and a credential issue, take the board row lock and
//! re-check under it: one that queues behind an archive finds the board archived and is
//! refused, so no credential survives an archive.
//!
//! Each test holds a lock in a transaction of its own and acts only once the callers are seen
//! queued behind it (`queued_behind`): conditions, not sleeps.

use std::sync::Arc;
use std::time::Duration;

use stigmer_core::{BoardId, Principal, PrincipalKind, Role, TokenId};
use stigmer_store::{
    ConflictKind, CredentialScope, Entity, IdentityStore, NewCredential, NewInvite,
    NewJoinCredential, SecurityEvent, SecurityEventKind, Store, StoreError,
};
use stigmer_store_postgres::testing::{backend_pid, database_url, queued_behind, TestSchema};
use stigmer_store_postgres::PgStore;

const NOW: i64 = 1_700_000_000_000;

/// Upper bound for a refusal that must not wait, and for callers to show up queued. Only a
/// bound: nothing sleeps for it.
const LIMIT: Duration = Duration::from_secs(5);

const INVITE_HASH: [u8; 32] = [1; 32];

fn audit(kind: SecurityEventKind) -> SecurityEvent {
    SecurityEvent {
        at_ms: NOW,
        kind,
        board: None,
        principal: Some("root".to_owned()),
        detail: format!("{kind}"),
    }
}

fn id(n: u8) -> TokenId {
    TokenId::new(&format!("{n:016x}")).unwrap()
}

fn ops() -> BoardId {
    BoardId::new("ops").unwrap()
}

fn dave() -> Principal {
    Principal::new("dave").unwrap()
}

fn join() -> NewJoinCredential {
    NewJoinCredential {
        id: id(2),
        secret_hash: [2; 32],
        expires_at_ms: NOW + 1_000_000,
    }
}

fn refused() -> StoreError {
    StoreError::NotFound {
        entity: Entity::Invite,
        id: id(1).to_string(),
    }
}

/// A migrated store with board `ops` and invite 1 into it, a client holding nothing yet (the
/// blocker), its backend pid, and a second client to watch the lock queue.
struct Setup {
    store: Arc<PgStore>,
    blocker: tokio_postgres::Client,
    pid: i32,
    watcher: tokio_postgres::Client,
    _schema: TestSchema,
}

async fn setup(url: &str) -> Setup {
    let schema = TestSchema::create(url).await.unwrap();
    let store = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store
        .create_board(&ops(), None, audit(SecurityEventKind::BoardCreated))
        .await
        .unwrap();
    let invite = NewInvite {
        id: id(1),
        secret_hash: INVITE_HASH,
        board: ops(),
        role: Role::Member,
        kind: PrincipalKind::Agent,
        created_by: Principal::new("root").unwrap(),
        expires_at_ms: NOW + 1_000_000,
    };
    store
        .create_invite(invite, audit(SecurityEventKind::InviteCreated))
        .await
        .unwrap();
    let blocker = schema.client().await.unwrap();
    let pid = backend_pid(&blocker).await.unwrap();
    let watcher = schema.client().await.unwrap();
    Setup {
        store: Arc::new(store),
        blocker,
        pid,
        watcher,
        _schema: schema,
    }
}

impl Setup {
    /// Begins the blocker's transaction and locks board `ops`, and with `invite_too` invite 1.
    async fn hold(&self, invite_too: bool) {
        self.blocker
            .batch_execute("BEGIN; SELECT 1 FROM boards WHERE id = 'ops' FOR UPDATE")
            .await
            .unwrap();
        if invite_too {
            self.blocker
                .batch_execute("SELECT 1 FROM invites FOR UPDATE")
                .await
                .unwrap();
        }
    }

    /// Waits until `n` backends are queued behind the blocker, while `pending` stay unfinished.
    async fn until_queued(&self, n: i64, pending: &[&tokio::task::JoinHandle<impl Sized>]) {
        let queued = tokio::time::timeout(LIMIT, async {
            while queued_behind(&self.watcher, self.pid).await.unwrap() < n {
                assert!(
                    pending.iter().all(|task| !task.is_finished()),
                    "a caller finished while the board row was held"
                );
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(queued.is_ok(), "{n} callers queue behind the held lock");
    }

    async fn live_credentials_on_ops(&self) -> Vec<Principal> {
        let all = self.store.list_credentials(&ops()).await.unwrap();
        all.into_iter()
            .filter(|c| c.revoked_at_ms.is_none())
            .map(|c| c.principal)
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_join_does_not_wait_behind_the_board_or_invite_lock() {
    const TEST: &str = "a_refused_join_does_not_wait_behind_the_board_or_invite_lock";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let s = setup(&url).await;
    s.hold(true).await;
    let unknown = TokenId::new("00000000000000ff").unwrap();
    let attempts = [
        (id(1), [9; 32], refused()),
        (
            unknown.clone(),
            INVITE_HASH,
            StoreError::NotFound {
                entity: Entity::Invite,
                id: unknown.to_string(),
            },
        ),
    ];
    for (invite, hash, expected) in attempts {
        let name = dave();
        let attempt = s.store.consume_invite(&invite, &hash, &name, NOW, join());
        let result = tokio::time::timeout(LIMIT, attempt).await;
        assert_eq!(
            result,
            Ok(Err(expected)),
            "refused at once while the board and invite rows are locked ({invite})"
        );
    }
    assert_eq!(queued_behind(&s.watcher, s.pid).await.unwrap(), 0);
    s.blocker.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(s.store.list_members(&ops()).await, Ok(Vec::new()));
}

/// The right secret waits for the board lock, then re-checks under it: `change` is what the
/// blocker commits before letting go (nothing, an archive, or another join's used mark).
async fn held_join(url: &str, change: Option<&str>) -> (Result<(), StoreError>, Setup) {
    let s = setup(url).await;
    s.hold(false).await;
    let task = {
        let store = Arc::clone(&s.store);
        tokio::spawn(async move {
            store
                .consume_invite(&id(1), &INVITE_HASH, &dave(), NOW, join())
                .await
                .map(drop)
        })
    };
    s.until_queued(1, &[&task]).await;
    assert!(!task.is_finished(), "the join waits for the board row");
    match change {
        None => s.blocker.batch_execute("ROLLBACK").await.unwrap(),
        Some(sql) => s
            .blocker
            .batch_execute(&format!("{sql}; COMMIT"))
            .await
            .unwrap(),
    }
    (task.await.unwrap(), s)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_with_the_right_secret_waits_for_the_board_lock_and_rechecks_under_it() {
    const TEST: &str =
        "a_join_with_the_right_secret_waits_for_the_board_lock_and_rechecks_under_it";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    // Released unchanged: the join goes through.
    let (result, s) = held_join(&url, None).await;
    assert_eq!(result, Ok(()));
    assert_eq!(s.live_credentials_on_ops().await, vec![dave()]);

    // Archived while the join waited, or used by another join: refused, nothing written.
    for change in [
        "UPDATE boards SET archived_at_ms = 1 WHERE id = 'ops'",
        "UPDATE invites SET used_at_ms = 1",
    ] {
        let (result, s) = held_join(&url, Some(change)).await;
        assert_eq!(result, Err(refused()), "{change}");
        assert_eq!(
            s.store.list_members(&ops()).await,
            Ok(Vec::new()),
            "{change}"
        );
        assert_eq!(s.store.find_credential(&id(2)).await, Ok(None), "{change}");
    }
}

/// Queues an archive behind the held board row, then `issue` behind the archive, and lets go:
/// `issue` must find the board archived. Returns what `issue` returned and the live
/// credentials left on the board.
async fn issue_behind_an_archive<F, Fut>(
    url: &str,
    issue: F,
) -> (Result<(), StoreError>, Vec<Principal>)
where
    F: FnOnce(Arc<PgStore>) -> Fut,
    Fut: std::future::Future<Output = Result<(), StoreError>> + Send + 'static,
{
    let s = setup(url).await;
    s.hold(false).await;
    let archive = {
        let store = Arc::clone(&s.store);
        let row = audit(SecurityEventKind::BoardArchived);
        tokio::spawn(async move { store.archive_board_revoking(&ops(), row).await })
    };
    s.until_queued(1, &[&archive]).await;
    let issued = tokio::spawn(issue(Arc::clone(&s.store)));
    s.until_queued(2, &[&archive]).await;
    s.blocker.batch_execute("ROLLBACK").await.unwrap();
    let archived = archive.await.unwrap().unwrap();
    assert!(archived.archived_at_ms.is_some());
    let result = issued.await.unwrap();
    (result, s.live_credentials_on_ops().await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_credential_issued_behind_an_archive_cannot_survive_it() {
    const TEST: &str = "a_credential_issued_behind_an_archive_cannot_survive_it";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let (result, live) = issue_behind_an_archive(&url, |store| async move {
        let credential = NewCredential {
            id: id(3),
            secret_hash: [3; 32],
            scope: CredentialScope::Board(ops()),
            principal: dave(),
            expires_at_ms: NOW + 1_000_000,
        };
        let row = audit(SecurityEventKind::MemberTokenIssued);
        store.create_credential(credential, row).await
    })
    .await;
    assert_eq!(
        result,
        Err(StoreError::Conflict(ConflictKind::BoardArchived))
    );
    assert_eq!(
        live,
        Vec::<Principal>::new(),
        "no live credential after the archive"
    );

    let (result, live) = issue_behind_an_archive(&url, |store| async move {
        store
            .consume_invite(&id(1), &INVITE_HASH, &dave(), NOW, join())
            .await
            .map(drop)
    })
    .await;
    assert_eq!(result, Err(refused()));
    assert_eq!(
        live,
        Vec::<Principal>::new(),
        "no live credential after the archive"
    );
}
