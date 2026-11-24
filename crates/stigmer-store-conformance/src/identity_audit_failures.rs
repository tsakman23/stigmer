//! A failed audited mutation writes no security log row and stores nothing.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{CredentialScope, IdentityStore, Store};

use crate::identity::{credential, invite, join_credential, token_id, NOW};
use crate::support::{
    board, board_archived, board_created, instance_token_issued, invite_created, log_of,
    member_removed, ok, principal, token_issued, token_revoked,
};

pub(crate) async fn failed_mutations_write_no_rows<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "failed_mutations_write_no_rows";
    let (nowhere, old, main) = (board("nowhere"), board("old"), BoardId::main());
    ok(
        store
            .create_board(&old, None, NOW, board_created(&old, NOW))
            .await,
        SCENARIO,
    );
    ok(
        store
            .archive_board(&old, NOW, board_archived(&old, NOW))
            .await,
        SCENARIO,
    );
    let existing = credential(9, CredentialScope::Board(main.clone()), "zed");
    ok(
        store
            .create_credential(existing, NOW, token_issued(NOW))
            .await,
        SCENARIO,
    );
    let into_main = invite(8, &main, Role::Member, PrincipalKind::Agent);
    let main_hash = into_main.secret_hash;
    ok(
        store
            .create_invite(into_main, NOW, invite_created(NOW))
            .await,
        SCENARIO,
    );
    let added = store
        .add_member(
            &main,
            &principal("taken"),
            PrincipalKind::Agent,
            Role::Member,
            NOW,
        )
        .await;
    ok(added, SCENARIO);
    let before = log_of(&store, SCENARIO).await;
    let at = NOW + 1;

    let mut failures: Vec<(&str, bool)> = Vec::new();
    // Unknown board.
    failures.push((
        "create_invite unknown board",
        store
            .create_invite(
                invite(1, &nowhere, Role::Member, PrincipalKind::Agent),
                at,
                invite_created(at),
            )
            .await
            .is_err(),
    ));
    failures.push((
        "create_credential unknown board",
        store
            .create_credential(
                credential(2, CredentialScope::Board(nowhere.clone()), "a"),
                at,
                token_issued(at),
            )
            .await
            .is_err(),
    ));
    failures.push((
        "remove_member unknown board",
        store
            .remove_member(&nowhere, &principal("a"), at, member_removed(&nowhere, at))
            .await
            .is_err(),
    ));
    failures.push((
        "archive_board unknown board",
        store
            .archive_board(&nowhere, at, board_archived(&nowhere, at))
            .await
            .is_err(),
    ));
    failures.push((
        "archive_board main",
        store
            .archive_board(&main, at, board_archived(&main, at))
            .await
            .is_err(),
    ));
    // Archived board.
    failures.push((
        "create_invite archived board",
        store
            .create_invite(
                invite(3, &old, Role::Member, PrincipalKind::Agent),
                at,
                invite_created(at),
            )
            .await
            .is_err(),
    ));
    failures.push((
        "create_credential archived board",
        store
            .create_credential(
                credential(4, CredentialScope::Board(old.clone()), "a"),
                at,
                token_issued(at),
            )
            .await
            .is_err(),
    ));
    // Taken names and ids.
    failures.push((
        "create_board taken id",
        store
            .create_board(&old, None, at, board_created(&old, at))
            .await
            .is_err(),
    ));
    failures.push((
        "create_credential taken id",
        store
            .create_credential(
                credential(9, CredentialScope::Board(main.clone()), "zed"),
                at,
                token_issued(at),
            )
            .await
            .is_err(),
    ));
    failures.push((
        "consume_invite taken name",
        store
            .consume_invite(
                &token_id(8),
                &main_hash,
                &principal("taken"),
                at,
                join_credential(100),
            )
            .await
            .is_err(),
    ));
    // Unknown member and credential.
    failures.push((
        "remove_member unknown member",
        store
            .remove_member(&main, &principal("nobody"), at, member_removed(&main, at))
            .await
            .is_err(),
    ));
    failures.push((
        "revoke_credential unknown id",
        store
            .revoke_credential(&token_id(77), at, token_revoked(at))
            .await
            .is_err(),
    ));
    failures.push((
        "replace_instance_credential board scope",
        store
            .replace_instance_credential(
                credential(5, CredentialScope::Board(main.clone()), "a"),
                at,
                instance_token_issued(at),
            )
            .await
            .is_err(),
    ));
    for (what, failed) in failures {
        assert!(failed, "{SCENARIO}: {what} should fail");
    }
    assert_eq!(
        log_of(&store, SCENARIO).await,
        before,
        "{SCENARIO}: no failed mutation wrote a row"
    );
    for n in [1, 2, 3, 4, 5] {
        assert_eq!(
            store
                .find_credential(&token_id(n))
                .await
                .map(|c| c.is_some()),
            Ok(false),
            "{SCENARIO}: credential {n} not stored"
        );
    }
}
