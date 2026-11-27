//! Multi-row writes on a board lock the board row first and only then its dependent rows
//! (members, credentials, invites, messages), and single-credential writes lock only their own
//! row, so mixed writers on one board never deadlock.
//!
//! The test runs rounds until about five seconds have passed in total (at least two rounds).
//! Each round uses a fresh board, because an archive is irreversible: after the first archive a
//! board refuses posts, joins and new credentials, so reusing one would leave nothing to contend
//! for. A round first prepares its board one step at a time (an admin with a credential, and the
//! invites, members and credentials its operations need), then starts 50 concurrent operations
//! on that board, alternating between two handles (two pools, as two replicas would have).
//! Every round mixes all six kinds: posts, joins, credential revocations, member removals,
//! credential issues and archives with revocation (about eight archives per round, the repeats
//! idempotent). Every operation must succeed or return its documented conflict; a deadlock
//! (SQLSTATE 40P01) surfaces as a backend error and fails the test. After each round the board
//! is archived, no credential but the admin's is live, every join that succeeded left a member,
//! and the chain is valid and counts exactly the posts that succeeded. The time bound only
//! decides how many rounds run: nothing waits on a timer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use stigmer_core::{
    BoardId, ChannelPath, NewMessage, Principal, PrincipalKind, Role, Target, TokenId,
};
use stigmer_store::{
    ChainReport, ConflictKind, CredentialScope, Entity, IdentityStore, NewCredential, NewInvite,
    NewJoinCredential, SecurityEvent, SecurityEventKind, Store, StoreError,
};
use stigmer_store_postgres::testing::{database_url, TestSchema};
use stigmer_store_postgres::PgStore;

const NOW: i64 = 1_700_000_000_000;
const RUN_FOR: Duration = Duration::from_secs(5);
const OPS: usize = 50;
/// Operation kinds; operation `i` of a round is kind `i % KINDS`.
const KINDS: usize = 6;

fn audit(kind: SecurityEventKind, on: &BoardId) -> SecurityEvent {
    SecurityEvent {
        at_ms: NOW,
        kind,
        board: Some(on.clone()),
        principal: Some("root".to_owned()),
        detail: format!("{kind}"),
    }
}

fn name(raw: &str) -> Principal {
    Principal::new(raw).unwrap()
}

/// A token id unique across rounds: round `round`, operation `i`, slot `slot`.
fn token(round: usize, i: usize, slot: usize) -> TokenId {
    TokenId::new(&format!("{:016x}", (round * 1000 + i) * 10 + slot)).unwrap()
}

fn credential(id: TokenId, on: &BoardId, who: &str) -> NewCredential {
    NewCredential {
        secret_hash: [7; 32],
        id,
        scope: CredentialScope::Board(on.clone()),
        principal: name(who),
        expires_at_ms: NOW + 1_000_000,
    }
}

/// What operation `i` of a round did, for the checks at the end of the round.
#[derive(Debug)]
enum Outcome {
    Posted,
    Joined(Principal),
    Done,
}

/// Prepares round `round` on `board`: an admin with a credential, and for each operation the
/// invite, member or credential it needs.
async fn prepare(store: &PgStore, round: usize, board: &BoardId) {
    store
        .create_board(board, None, audit(SecurityEventKind::BoardCreated, board))
        .await
        .unwrap();
    store
        .add_member(board, &name("ann"), PrincipalKind::Human, Role::Admin, NOW)
        .await
        .unwrap();
    let ann = credential(token(round, 0, 9), board, "ann");
    let issued = audit(SecurityEventKind::MemberTokenIssued, board);
    store.create_credential(ann, issued).await.unwrap();
    for i in 0..OPS {
        match i % KINDS {
            1 => {
                let invite = NewInvite {
                    id: token(round, i, 0),
                    secret_hash: [i as u8; 32],
                    board: board.clone(),
                    role: Role::Member,
                    kind: PrincipalKind::Agent,
                    created_by: name("root"),
                    expires_at_ms: NOW + 1_000_000,
                };
                let row = audit(SecurityEventKind::InviteCreated, board);
                store.create_invite(invite, row).await.unwrap();
            }
            2 | 3 => {
                let who = format!("m-{i}");
                store
                    .add_member(board, &name(&who), PrincipalKind::Agent, Role::Member, NOW)
                    .await
                    .unwrap();
                let row = audit(SecurityEventKind::MemberTokenIssued, board);
                let c = credential(token(round, i, 0), board, &who);
                store.create_credential(c, row).await.unwrap();
            }
            _ => {}
        }
    }
}

/// Runs operation `i` of round `round` on `board` and checks its result is a success or its
/// documented conflict.
async fn operate(store: Arc<PgStore>, round: usize, i: usize, board: BoardId) -> Outcome {
    let refused_as = |result: &StoreError, allowed: &StoreError, what: &str| {
        assert_eq!(result, allowed, "round {round} op {i} ({what})");
    };
    let archived = StoreError::Conflict(ConflictKind::BoardArchived);
    match i % KINDS {
        0 => {
            let post = NewMessage {
                board,
                target: Target::NewThread {
                    channel: ChannelPath::new("load").unwrap(),
                },
                author: name("ann"),
                text: format!("post {i}"),
                labels: Vec::new(),
                idempotency_key: None,
            };
            match store.post(post).await {
                Ok(_) => Outcome::Posted,
                Err(e) => {
                    refused_as(&e, &archived, "post");
                    Outcome::Done
                }
            }
        }
        1 => {
            let id = token(round, i, 0);
            let who = name(&format!("j-{i}"));
            let join = NewJoinCredential {
                id: token(round, i, 1),
                secret_hash: [8; 32],
                expires_at_ms: NOW + 1_000_000,
            };
            match store
                .consume_invite(&id, &[i as u8; 32], &who, NOW, join)
                .await
            {
                Ok(consumed) => Outcome::Joined(consumed.member.name),
                Err(e) => {
                    let refused = StoreError::NotFound {
                        entity: Entity::Invite,
                        id: id.to_string(),
                    };
                    refused_as(&e, &refused, "join");
                    Outcome::Done
                }
            }
        }
        2 => {
            let row = audit(SecurityEventKind::TokenRevoked, &board);
            let result = store.revoke_credential(&token(round, i, 0), row).await;
            assert_eq!(result, Ok(()), "round {round} op {i} (revoke)");
            Outcome::Done
        }
        3 => {
            let row = audit(SecurityEventKind::MemberRemoved, &board);
            let who = name(&format!("m-{i}"));
            let result = store.remove_member(&board, &who, row).await;
            assert_eq!(result, Ok(()), "round {round} op {i} (remove member)");
            Outcome::Done
        }
        4 => {
            let row = audit(SecurityEventKind::MemberTokenIssued, &board);
            let c = credential(token(round, i, 0), &board, &format!("late-{i}"));
            if let Err(e) = store.create_credential(c, row).await {
                refused_as(&e, &archived, "create credential");
            }
            Outcome::Done
        }
        _ => {
            let row = audit(SecurityEventKind::BoardArchived, &board);
            let result = store.archive_board_revoking(&board, row).await;
            assert!(result.is_ok(), "round {round} op {i} (archive): {result:?}");
            Outcome::Done
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn lock_order_is_board_then_rows_no_deadlock_under_mixed_load() {
    const TEST: &str = "lock_order_is_board_then_rows_no_deadlock_under_mixed_load";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let a = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    a.migrate().await.unwrap();
    let b = a.second_handle_for_tests().await.unwrap();
    let handles = [Arc::new(a), Arc::new(b)];

    let started = Instant::now();
    let mut round = 0;
    while round == 0 || started.elapsed() < RUN_FOR {
        round += 1;
        let board = BoardId::new(&format!("load-{round}")).unwrap();
        prepare(&handles[0], round, &board).await;
        let tasks: Vec<_> = (0..OPS)
            .map(|i| {
                let store = Arc::clone(&handles[i % handles.len()]);
                tokio::spawn(operate(store, round, i, board.clone()))
            })
            .collect();
        let mut posts = 0;
        let mut joined = Vec::new();
        for task in tasks {
            match task.await.unwrap() {
                Outcome::Posted => posts += 1,
                Outcome::Joined(who) => joined.push(who),
                Outcome::Done => {}
            }
        }

        // The archive ran, and nothing escaped its revocation: every credential on the board
        // but the admin's is revoked, however the joins and issues interleaved with it.
        let store = &handles[1];
        let info = store.get_board(&board).await.unwrap();
        assert!(info.archived_at_ms.is_some(), "round {round}: archived");
        for c in store.list_credentials(&board).await.unwrap() {
            let admin = c.principal == name("ann");
            assert_eq!(
                c.revoked_at_ms.is_none(),
                admin,
                "round {round}: credential of {} after the archive",
                c.principal
            );
        }
        let members = store.list_members(&board).await.unwrap();
        for who in &joined {
            assert!(
                members.iter().any(|m| &m.name == who),
                "round {round}: {who} joined"
            );
        }
        // Posts kept the chain gapless.
        assert_eq!(
            store.verify_chain(&board).await,
            Ok(ChainReport {
                valid: true,
                checked: posts,
                first_bad_seq: None,
            }),
            "round {round}: chain"
        );
    }
    assert!(round > 1, "more than one round ran in {RUN_FOR:?}");
}
