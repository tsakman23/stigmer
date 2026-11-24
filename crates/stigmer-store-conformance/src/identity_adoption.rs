//! Adopting local (M0) authors as members of a board.

use stigmer_core::{BoardId, EventFilter, PrincipalKind, Role};
use stigmer_store::{
    Adoption, ConflictKind, IdentityStore, SecurityEvent, SecurityEventKind, Store, StoreError,
};

use crate::identity::{member, NOW};
use crate::support::board_created;
use crate::support::{board, new_thread_on, ok, post_ok, principal, reply_on, valid_chain};

fn adoption(name: &str, kind: PrincipalKind, role: Role) -> Adoption {
    Adoption {
        name: principal(name),
        kind,
        role,
    }
}

/// Posts on `on` by each author in turn: a thread from the first, replies from the rest.
async fn post_as<S: Store>(store: &S, on: &BoardId, authors: &[&str], scenario: &str) {
    let Some((first, rest)) = authors.split_first() else {
        return;
    };
    let root = post_ok(store, new_thread_on(on, "eng", first, "root"), scenario).await;
    for author in rest {
        post_ok(
            store,
            reply_on(on, &root.message.id, author, "reply"),
            scenario,
        )
        .await;
    }
}

pub(crate) async fn list_local_authors_returns_distinct_sorted_authors<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "list_local_authors_returns_distinct_sorted_authors";
    let (main, other, empty) = (BoardId::main(), board("other"), board("empty"));
    for b in [&other, &empty] {
        ok(
            store
                .create_board(b, None, NOW, board_created(b, NOW))
                .await,
            SCENARIO,
        );
    }
    post_as(&store, &main, &["carol", "alice", "bob", "alice"], SCENARIO).await;
    post_as(&store, &other, &["zed"], SCENARIO).await;
    let names = |list: &[&str]| list.iter().map(|n| principal(n)).collect::<Vec<_>>();
    assert_eq!(
        store.list_local_authors(&main).await,
        Ok(names(&["alice", "bob", "carol"])),
        "{SCENARIO}: main"
    );
    assert_eq!(
        store.list_local_authors(&other).await,
        Ok(names(&["zed"])),
        "{SCENARIO}: other"
    );
    assert_eq!(
        store.list_local_authors(&empty).await,
        Ok(vec![]),
        "{SCENARIO}: empty"
    );
}

/// A post by a member of the board is not a local author's; a non-member's still is, even if it
/// is a member of another board.
pub(crate) async fn members_posts_are_not_listed_as_local_authors<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "members_posts_are_not_listed_as_local_authors";
    let (main, other) = (BoardId::main(), board("other"));
    ok(
        store
            .create_board(&other, None, NOW, board_created(&other, NOW))
            .await,
        SCENARIO,
    );
    ok(
        store
            .add_member(
                &main,
                &principal("alice"),
                PrincipalKind::Agent,
                Role::Member,
                NOW,
            )
            .await,
        SCENARIO,
    );
    ok(
        store
            .add_member(
                &other,
                &principal("bob"),
                PrincipalKind::Agent,
                Role::Member,
                NOW,
            )
            .await,
        SCENARIO,
    );
    post_as(&store, &main, &["alice", "bob", "zed", "alice"], SCENARIO).await;
    assert_eq!(
        store.list_local_authors(&main).await,
        Ok(vec![principal("bob"), principal("zed")]),
        "{SCENARIO}: alice is a member of main; bob only of another board"
    );
}

pub(crate) async fn adopt_local_authors_creates_members_and_flips_author_kind_atomically<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "adopt_local_authors_creates_members_and_flips_author_kind_atomically";
    let (main, research) = (BoardId::main(), board("research"));
    ok(
        store
            .create_board(&research, None, NOW, board_created(&research, NOW))
            .await,
        SCENARIO,
    );
    post_as(&store, &main, &["alice", "bob", "alice", "carol"], SCENARIO).await;
    post_as(&store, &research, &["alice"], SCENARIO).await;
    let erin = ok(
        store
            .add_member(
                &main,
                &principal("erin"),
                PrincipalKind::Human,
                Role::Member,
                NOW,
            )
            .await,
        SCENARIO,
    );
    let (human, agent) = (PrincipalKind::Human, PrincipalKind::Agent);
    let names = |list: &[&str]| list.iter().map(|n| principal(n)).collect::<Vec<_>>();

    for failing in [
        vec![
            adoption("alice", human, Role::Admin),
            adoption("erin", human, Role::Admin),
        ],
        vec![
            adoption("carol", agent, Role::Member),
            adoption("carol", agent, Role::Member),
        ],
    ] {
        assert_eq!(
            store.adopt_local_authors(&main, &failing, NOW + 1).await,
            Err(StoreError::Conflict(ConflictKind::NameTaken)),
            "{SCENARIO}: a taken name"
        );
        assert_eq!(
            store.list_members(&main).await,
            Ok(vec![erin.clone()]),
            "{SCENARIO}: no member was created"
        );
        assert_eq!(
            store.list_local_authors(&main).await,
            Ok(names(&["alice", "bob", "carol"])),
            "{SCENARIO}: every author is still local"
        );
    }

    let adopted = store
        .adopt_local_authors(
            &main,
            &[
                adoption("alice", human, Role::Admin),
                adoption("bob", agent, Role::Member),
            ],
            NOW + 2,
        )
        .await;
    assert_eq!(
        adopted,
        Ok(3),
        "{SCENARIO}: alice's two messages and bob's one"
    );
    assert_eq!(
        store.list_members(&main).await,
        Ok(vec![
            member(&main, "alice", human, Role::Admin, NOW + 2),
            member(&main, "bob", agent, Role::Member, NOW + 2),
            erin,
        ]),
        "{SCENARIO}: members"
    );
    assert_eq!(
        store.list_local_authors(&main).await,
        Ok(names(&["carol"])),
        "{SCENARIO}: carol was not adopted"
    );
    assert_eq!(
        store.list_local_authors(&research).await,
        Ok(names(&["alice"])),
        "{SCENARIO}: other boards are untouched"
    );
    let silent = store
        .adopt_local_authors(&main, &[adoption("frank", human, Role::Member)], NOW + 3)
        .await;
    assert_eq!(silent, Ok(0), "{SCENARIO}: a name with no messages");
    assert!(
        matches!(
            store.get_member(&main, &principal("frank")).await,
            Ok(Some(_))
        ),
        "{SCENARIO}: frank is a member"
    );
}

pub(crate) async fn adopt_local_authors_writes_one_audit_row_and_a_failure_writes_none<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "adopt_local_authors_writes_one_audit_row_and_a_failure_writes_none";
    let main = BoardId::main();
    post_as(&store, &main, &["alice", "bob", "alice"], SCENARIO).await;
    let (human, agent) = (PrincipalKind::Human, PrincipalKind::Agent);

    let taken = [
        adoption("alice", human, Role::Admin),
        adoption("alice", human, Role::Admin),
    ];
    assert_eq!(
        store.adopt_local_authors(&main, &taken, NOW).await,
        Err(StoreError::Conflict(ConflictKind::NameTaken)),
        "{SCENARIO}: a failing adoption"
    );
    assert_eq!(
        store.security_log(10).await,
        Ok(vec![]),
        "{SCENARIO}: a failed adoption writes no row"
    );

    let adoptions = [
        adoption("alice", human, Role::Admin),
        adoption("bob", agent, Role::Member),
    ];
    assert_eq!(
        store.adopt_local_authors(&main, &adoptions, NOW + 1).await,
        Ok(3),
        "{SCENARIO}"
    );
    assert_eq!(
        store.security_log(10).await,
        Ok(vec![SecurityEvent {
            at_ms: NOW + 1,
            kind: SecurityEventKind::PrincipalsAdopted,
            board: Some(main.clone()),
            principal: Some("instance-admin".to_owned()),
            detail: "adopted 2 authors (3 messages) into board main".to_owned(),
        }]),
        "{SCENARIO}: exactly one row, in the adoption's transaction"
    );
}

pub(crate) async fn adopt_local_authors_leaves_the_hash_chain_valid<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "adopt_local_authors_leaves_the_hash_chain_valid";
    let main = BoardId::main();
    post_as(&store, &main, &["alice", "bob", "alice"], SCENARIO).await;
    let filter = EventFilter::default();
    let before = ok(store.events_after(&main, None, &filter, 50).await, SCENARIO);
    assert_eq!(
        store.verify_chain(&main).await,
        Ok(valid_chain(3)),
        "{SCENARIO}: before"
    );

    let adoptions = [
        adoption("alice", PrincipalKind::Human, Role::Admin),
        adoption("bob", PrincipalKind::Agent, Role::Member),
    ];
    let adopted = store.adopt_local_authors(&main, &adoptions, NOW).await;
    assert_eq!(adopted, Ok(3), "{SCENARIO}");

    assert_eq!(
        store.verify_chain(&main).await,
        Ok(valid_chain(3)),
        "{SCENARIO}: after"
    );
    assert_eq!(
        store.events_after(&main, None, &filter, 50).await,
        Ok(before),
        "{SCENARIO}: the events are unchanged"
    );
}
