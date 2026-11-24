//! Two handles on one database, identity half: credentials and one-time invites.

use std::sync::Arc;

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{CredentialScope, Entity, IdentityStore};

use crate::identity::{credential, invite, join_credential, not_found, token_id};
use crate::identity_credentials::stored;
use crate::support::NOW;
use crate::support::{fail, invite_created, log_of, ok, principal, token_issued, token_revoked};

pub(crate) async fn credential_issued_on_one_handle_is_valid_on_the_other_and_revocable_from_either<
    S: IdentityStore,
>(
    a: S,
    b: S,
) {
    const SCENARIO: &str =
        "credential_issued_on_one_handle_is_valid_on_the_other_and_revocable_from_either";
    let main = BoardId::main();
    // Issued through a and revoked through b, then the other way round.
    for (n, (issuer, other)) in [(1, (&a, &b)), (2, (&b, &a))] {
        let issued_at = NOW + i64::from(n);
        let revoked_at = issued_at + 10;
        let c = credential(n, CredentialScope::Board(main.clone()), "alice");
        let issued = token_issued(issued_at);
        ok(
            issuer.create_credential(c.clone(), issued.clone()).await,
            format_args!("{SCENARIO}: issue {n}"),
        );
        assert_eq!(
            other.find_credential(&c.id).await,
            Ok(Some(stored(&c))),
            "{SCENARIO}: credential {n} is live through the other handle"
        );
        assert_eq!(
            log_of(other, SCENARIO).await.last(),
            Some(&issued),
            "{SCENARIO}: the other handle sees the audit row of credential {n}"
        );

        ok(
            other
                .revoke_credential(&c.id, token_revoked(revoked_at))
                .await,
            format_args!("{SCENARIO}: revoke {n}"),
        );
        let found = ok(issuer.find_credential(&c.id).await, SCENARIO);
        assert_eq!(
            found.and_then(|f| f.revoked_at_ms),
            Some(revoked_at),
            "{SCENARIO}: the issuing handle sees credential {n} revoked"
        );
    }
}

pub(crate) async fn invite_redeemed_once_across_handles<S: IdentityStore>(a: S, b: S) {
    const SCENARIO: &str = "invite_redeemed_once_across_handles";
    const TASKS: usize = 20;
    let main = BoardId::main();
    let new = invite(1, &main, Role::Member, PrincipalKind::Agent);
    let hash = new.secret_hash;
    ok(a.create_invite(new, invite_created(NOW)).await, SCENARIO);
    let handles = [Arc::new(a), Arc::new(b)];
    let tasks: Vec<_> = (0..TASKS)
        .zip(handles.iter().cycle())
        .map(|(i, store)| {
            let store = Arc::clone(store);
            tokio::spawn(async move {
                let name = principal(&format!("agent-{i}"));
                store
                    .consume_invite(
                        &token_id(1),
                        &hash,
                        &name,
                        NOW,
                        join_credential(100 + i as u8),
                    )
                    .await
            })
        })
        .collect();

    let mut joined = Vec::new();
    for task in tasks {
        match ok(task.await, format_args!("{SCENARIO}: task failed")) {
            Ok(consumed) => joined.push(consumed.member),
            Err(e) => assert_eq!(
                e,
                not_found(Entity::Invite, token_id(1)),
                "{SCENARIO}: a losing consume"
            ),
        }
    }
    let [winner] = joined.as_slice() else {
        fail(format_args!(
            "{SCENARIO}: exactly one winner, got {}",
            joined.len()
        ));
    };
    for (n, store) in handles.iter().enumerate() {
        assert_eq!(
            store.list_members(&main).await,
            Ok(vec![winner.clone()]),
            "{SCENARIO}: exactly one member through handle {n}"
        );
        let credentials = ok(store.list_credentials(&main).await, SCENARIO);
        let principals: Vec<_> = credentials.iter().map(|c| &c.principal).collect();
        assert_eq!(
            principals,
            vec![&winner.name],
            "{SCENARIO}: exactly one credential, the winner's, through handle {n}"
        );
    }
}
