//! The instance mode switch under two replicas: two callers at once, forced to overlap, give
//! exactly one switch.

use std::sync::Arc;
use std::time::Duration;

use stigmer_core::{generate_secret, Principal, SecretKind};
use stigmer_store::{
    ConflictKind, CredentialScope, EnableAudits, IdentityStore, Mode, NewCredential, SecurityEvent,
    SecurityEventKind, StoreError,
};
use stigmer_store_postgres::testing::{backend_pid, database_url, queued_behind, TestSchema};
use stigmer_store_postgres::PgStore;

const NOW: i64 = 1_700_000_000_000;

/// How long the blocked callers may take to queue behind the test's lock: an upper bound only.
const QUEUE_LIMIT: Duration = Duration::from_secs(10);

fn audit(kind: SecurityEventKind, at_ms: i64) -> SecurityEvent {
    SecurityEvent {
        at_ms,
        kind,
        board: None,
        principal: Some("root".to_owned()),
        detail: format!("{kind} at {at_ms}"),
    }
}

fn name(raw: &str) -> Principal {
    Principal::new(raw).unwrap()
}

fn instance_credential() -> NewCredential {
    let secret = generate_secret(SecretKind::Token).unwrap();
    NewCredential {
        id: secret.id,
        secret_hash: secret.hash,
        scope: CredentialScope::Instance,
        principal: name("instance-admin"),
        expires_at_ms: NOW + 1_000_000,
    }
}

async fn store_on(schema: &TestSchema) -> PgStore {
    let store = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store
}

/// Runs `switch` through two handles at once, forced to overlap: a transaction of the test's
/// holds the instance row until both callers are queued behind it, then lets them go. Returns
/// both results and the store.
async fn race<F, Fut>(url: &str, switch: F) -> (Vec<Result<(), StoreError>>, PgStore, TestSchema)
where
    F: Fn(Arc<PgStore>, u8) -> Fut,
    Fut: std::future::Future<Output = Result<(), StoreError>> + Send + 'static,
{
    let schema = TestSchema::create(url).await.unwrap();
    let a = store_on(&schema).await;
    let b = a.second_handle_for_tests().await.unwrap();
    let blocker = schema.client().await.unwrap();
    blocker
        .batch_execute("BEGIN; SELECT 1 FROM instance WHERE id = 1 FOR UPDATE")
        .await
        .unwrap();
    let pid = backend_pid(&blocker).await.unwrap();
    let watcher = schema.client().await.unwrap();

    let (a, b) = (Arc::new(a), Arc::new(b));
    let tasks = [
        tokio::spawn(switch(Arc::clone(&a), 1)),
        tokio::spawn(switch(Arc::clone(&b), 2)),
    ];
    // A condition wait, not a sleep: QUEUE_LIMIT is only an upper bound.
    let queued = tokio::time::timeout(QUEUE_LIMIT, async {
        while queued_behind(&watcher, pid).await.unwrap() < 2 {
            assert!(
                tasks.iter().all(|task| !task.is_finished()),
                "a caller finished while the instance row was held"
            );
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        queued.is_ok(),
        "both callers queue behind the held instance row"
    );
    blocker.batch_execute("ROLLBACK").await.unwrap();

    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }
    drop(b);
    let a = Arc::into_inner(a).unwrap();
    (results, a, schema)
}

/// Exactly one of `results` is Ok and the other is `AlreadyNetwork`; returns the winner's index.
fn one_winner(results: &[Result<(), StoreError>]) -> usize {
    let winners: Vec<usize> = (0..results.len()).filter(|&i| results[i].is_ok()).collect();
    let [winner] = winners.as_slice() else {
        panic!("exactly one caller switches the mode: {results:?}");
    };
    for (i, result) in results.iter().enumerate() {
        if i != *winner {
            assert_eq!(
                result,
                &Err(StoreError::Conflict(ConflictKind::AlreadyNetwork)),
                "the other caller"
            );
        }
    }
    *winner
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enable_network_mode_is_safe_against_two_concurrent_callers() {
    const TEST: &str = "enable_network_mode_is_safe_against_two_concurrent_callers";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };

    // The bare switch.
    let (results, store, _schema) = race(&url, |store, n| async move {
        let row = audit(SecurityEventKind::ModeEnabled, NOW + i64::from(n));
        store.enable_network_mode(row).await
    })
    .await;
    let winner = one_winner(&results);
    assert_eq!(store.mode().await, Ok(Mode::Network));
    let log = store.security_log(100).await.unwrap();
    let winning_at = NOW + 1 + i64::try_from(winner).unwrap();
    assert_eq!(
        log,
        vec![audit(SecurityEventKind::ModeEnabled, winning_at)],
        "one ModeEnabled row, the winner's"
    );

    // The whole enable: only the winner's credential and rows are stored.
    let credentials = [instance_credential(), instance_credential()];
    let ids = [credentials[0].id.clone(), credentials[1].id.clone()];
    let shared = Arc::new(credentials);
    let (results, store, _schema) = race(&url, move |store, n| {
        let credential = shared[usize::from(n - 1)].clone();
        async move {
            let at = NOW + i64::from(n);
            let audits = EnableAudits {
                mode: audit(SecurityEventKind::ModeEnabled, at),
                token: audit(SecurityEventKind::InstanceTokenIssued, at),
            };
            store.enable_network(credential, None, audits).await
        }
    })
    .await;
    let winner = one_winner(&results);
    assert_eq!(store.mode().await, Ok(Mode::Network));
    for (i, id) in ids.iter().enumerate() {
        let found = store.find_credential(id).await.unwrap();
        assert_eq!(
            found.is_some(),
            i == winner,
            "credential {i} stored by the winner only"
        );
    }
    let winning_at = NOW + 1 + i64::try_from(winner).unwrap();
    let log = store.security_log(100).await.unwrap();
    assert_eq!(
        log,
        vec![
            audit(SecurityEventKind::InstanceTokenIssued, winning_at),
            audit(SecurityEventKind::ModeEnabled, winning_at),
        ],
        "the winner's two rows, newest first, and nothing from the loser"
    );
}
