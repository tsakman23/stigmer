//! The security log itself: ordering, limits, and no secret material in any row.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{CredentialScope, IdentityStore, SecurityEvent, SecurityEventKind, Store};

use crate::identity::{credential, hash_of, hex, invite, join_credential, token_id, NOW};
use crate::support::{board, invite_created, ok, principal, token_issued};

fn event(
    at_ms: i64,
    kind: SecurityEventKind,
    on: Option<BoardId>,
    who: Option<&str>,
) -> SecurityEvent {
    SecurityEvent {
        at_ms,
        kind,
        board: on,
        principal: who.map(str::to_owned),
        detail: format!("{kind} at {at_ms}"),
    }
}

pub(crate) async fn security_log_newest_first_and_limited<S: IdentityStore>(store: S) {
    const SCENARIO: &str = "security_log_newest_first_and_limited";
    let events = vec![
        event(NOW, SecurityEventKind::ModeEnabled, None, None),
        event(
            NOW + 1,
            SecurityEventKind::BoardCreated,
            Some(board("research")),
            Some("root"),
        ),
        event(
            NOW + 2,
            SecurityEventKind::Join,
            Some(BoardId::main()),
            Some("alice"),
        ),
        event(
            NOW + 3,
            SecurityEventKind::InviteCreated,
            Some(BoardId::main()),
            Some("root"),
        ),
        event(NOW + 3, SecurityEventKind::AuthFailed, None, None),
        event(
            NOW + 4,
            SecurityEventKind::InstanceTokenIssued,
            None,
            Some("instance-admin"),
        ),
        event(
            NOW + 4,
            SecurityEventKind::MemberTokenIssued,
            Some(BoardId::main()),
            Some("instance-admin"),
        ),
        // Logged later but stamped earlier: the log keeps insertion order.
        event(
            NOW - 5,
            SecurityEventKind::RateLimited,
            None,
            Some("unknown"),
        ),
    ];
    for e in &events {
        ok(
            store.log_security(e.clone()).await,
            format_args!("{SCENARIO}: log {}", e.kind),
        );
    }
    let newest_first: Vec<_> = events.iter().rev().cloned().collect();
    assert_eq!(
        store.security_log(3).await,
        Ok(newest_first[..3].to_vec()),
        "{SCENARIO}: limit 3"
    );
    assert_eq!(
        store.security_log(50).await,
        Ok(newest_first),
        "{SCENARIO}: all"
    );
    assert_eq!(
        store.security_log(0).await,
        Ok(vec![]),
        "{SCENARIO}: limit 0"
    );
}

pub(crate) async fn no_secret_material_in_security_log_rows<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "no_secret_material_in_security_log_rows";
    let main = BoardId::main();
    let token = credential(1, CredentialScope::Board(main.clone()), "alice");
    let into = invite(2, &main, Role::Member, PrincipalKind::Agent);
    let (token_hash, invite_hash, wrong_hash, join_hash) = (
        token.secret_hash,
        into.secret_hash,
        hash_of("wrong"),
        join_credential(100).secret_hash,
    );
    ok(
        store.create_credential(token, NOW, token_issued(NOW)).await,
        SCENARIO,
    );
    ok(
        store.create_invite(into, NOW, invite_created(NOW)).await,
        SCENARIO,
    );

    let refused = store
        .consume_invite(
            &token_id(2),
            &wrong_hash,
            &principal("dave"),
            NOW,
            join_credential(100),
        )
        .await;
    let joined = ok(
        store
            .consume_invite(
                &token_id(2),
                &invite_hash,
                &principal("dave"),
                NOW,
                join_credential(100),
            )
            .await,
        format_args!("{SCENARIO}: join"),
    );
    // What an API would log for these: ids and names, never secrets.
    for e in [
        event(NOW, SecurityEventKind::AuthFailed, Some(main.clone()), None),
        SecurityEvent {
            detail: format!("joined with invite {}", token_id(2)),
            ..event(
                NOW,
                SecurityEventKind::Join,
                Some(main.clone()),
                Some("dave"),
            )
        },
    ] {
        ok(store.log_security(e).await, SCENARIO);
    }
    let found = ok(store.find_credential(&token_id(1)).await, SCENARIO);
    let log = ok(store.security_log(50).await, SCENARIO);

    let mut shown = vec![
        format!("{refused:?}"),
        format!("{joined:?}"),
        format!("{found:?}"),
    ];
    if let Err(e) = &refused {
        shown.push(e.to_string());
    }
    shown.extend(log.iter().map(|e| format!("{e:?}")));
    for text in &shown {
        for hash in [&token_hash, &invite_hash, &wrong_hash, &join_hash] {
            assert!(
                !text.contains(&hex(hash)) && !text.contains(&format!("{hash:?}")),
                "{SCENARIO}: a secret hash leaked into {text}"
            );
        }
    }
    // The credential's and the invite's audit rows, the two rows given above, plus the join's
    // own row from `consume_invite`.
    assert_eq!(
        log.len(),
        5,
        "{SCENARIO}: the store logs only what it is given and the join"
    );
}
