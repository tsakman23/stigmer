//! The authorization seam: every board route asks `Authorize::check` before touching the store.

use std::future::{ready, Future};

use stigmer_core::{BoardId, ChannelPath, Principal, PrincipalKind, Role, TokenId};
use stigmer_store::CredentialScope;
use thiserror::Error;

/// Who is calling, as established by authentication.
///
/// In local mode the principal is the `X-Stigmer-As` name (reads default to `anonymous`),
/// with the instance scope, the admin role and no credential. In network mode every field comes
/// from the verified credential and the caller's membership of its board.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    pub principal: Principal,
    pub kind: PrincipalKind,
    /// What the credential covers: one board, or the whole instance.
    pub scope: CredentialScope,
    /// The caller's role on the credential's board; `None` for the instance credential.
    pub role: Option<Role>,
    /// The credential's id; `None` in local mode.
    pub credential: Option<TokenId>,
}

/// What a check is about: the instance, or one board (optionally one channel of it).
///
/// `channel` is `None` for the whole board. In M1 every caller passes `None`; per-channel
/// grants arrive in M4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope<'a> {
    Instance,
    Board {
        board: &'a BoardId,
        channel: Option<&'a ChannelPath>,
    },
}

/// What a principal wants to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read messages and events.
    Read,
    /// Post threads and replies.
    Post,
    /// List and remove members, mint invites, list and revoke tokens.
    ManageMembers,
    /// Create and archive boards.
    ManageBoards,
}

/// The principal may not do this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("forbidden")]
pub struct Denied;

/// Decides whether `who` may perform `action` on `scope`. Async so an implementation may
/// consult storage.
pub trait Authorize: Clone + Send + Sync + 'static {
    fn check(
        &self,
        who: &Authenticated,
        action: Action,
        scope: &Scope<'_>,
    ) -> impl Future<Output = Result<(), Denied>> + Send;
}

/// Allows everything. Local mode's implementation: the board is loopback only.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl Authorize for AllowAll {
    fn check(
        &self,
        _: &Authenticated,
        _: Action,
        _: &Scope<'_>,
    ) -> impl Future<Output = Result<(), Denied>> + Send {
        ready(Ok(()))
    }
}

/// Network mode's implementation: coarse roles per board.
///
/// A board admin may read, post and manage members on its own board; a member or bridge may
/// read and post there. The instance credential may manage boards and members anywhere but never
/// read or post content. A board credential is denied everything outside its board.
#[derive(Debug, Clone, Copy, Default)]
pub struct RoleAuthorize;

impl Authorize for RoleAuthorize {
    fn check(
        &self,
        who: &Authenticated,
        action: Action,
        scope: &Scope<'_>,
    ) -> impl Future<Output = Result<(), Denied>> + Send {
        ready(if role_allows(who, action, scope) {
            Ok(())
        } else {
            Err(Denied)
        })
    }
}

fn role_allows(who: &Authenticated, action: Action, scope: &Scope<'_>) -> bool {
    match (&who.scope, scope) {
        (CredentialScope::Instance, _) => {
            matches!(action, Action::ManageBoards | Action::ManageMembers)
        }
        (CredentialScope::Board(own), Scope::Board { board, .. }) if own == *board => {
            match who.role {
                Some(Role::Admin) => {
                    matches!(action, Action::Read | Action::Post | Action::ManageMembers)
                }
                Some(Role::Member | Role::Bridge) => matches!(action, Action::Read | Action::Post),
                None => false,
            }
        }
        (CredentialScope::Board(_), _) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Action; 4] = [
        Action::Read,
        Action::Post,
        Action::ManageMembers,
        Action::ManageBoards,
    ];

    fn who(scope: CredentialScope, role: Option<Role>) -> Authenticated {
        Authenticated {
            principal: Principal::new("alice").unwrap(),
            kind: PrincipalKind::Human,
            scope,
            role,
            credential: Some(TokenId::new("0123456789abcdef").unwrap()),
        }
    }

    async fn allowed(who: &Authenticated, scope: &Scope<'_>) -> Vec<Action> {
        let mut out = Vec::new();
        for action in ALL {
            if RoleAuthorize.check(who, action, scope).await.is_ok() {
                out.push(action);
            }
        }
        out
    }

    fn on(board: &BoardId) -> Scope<'_> {
        Scope::Board {
            board,
            channel: None,
        }
    }

    #[tokio::test]
    async fn board_roles_grant_their_actions_on_their_own_board_only() {
        let main = BoardId::main();
        let other = BoardId::new("other").unwrap();
        let mine = CredentialScope::Board(main.clone());
        let admin = who(mine.clone(), Some(Role::Admin));
        assert_eq!(
            allowed(&admin, &on(&main)).await,
            [Action::Read, Action::Post, Action::ManageMembers]
        );
        for role in [Role::Member, Role::Bridge] {
            let w = who(mine.clone(), Some(role));
            assert_eq!(allowed(&w, &on(&main)).await, [Action::Read, Action::Post]);
        }
        for role in [Role::Admin, Role::Member, Role::Bridge] {
            let w = who(mine.clone(), Some(role));
            assert!(allowed(&w, &on(&other)).await.is_empty(), "{role:?}");
            assert!(allowed(&w, &Scope::Instance).await.is_empty(), "{role:?}");
        }
        assert!(allowed(&who(mine, None), &on(&main)).await.is_empty());
    }

    #[tokio::test]
    async fn instance_credential_manages_but_never_reads_or_posts() {
        let main = BoardId::main();
        let instance = who(CredentialScope::Instance, None);
        for scope in [Scope::Instance, on(&main)] {
            assert_eq!(
                allowed(&instance, &scope).await,
                [Action::ManageMembers, Action::ManageBoards]
            );
        }
    }

    #[tokio::test]
    async fn allow_all_allows_everything() {
        let instance = who(CredentialScope::Instance, None);
        for action in ALL {
            assert_eq!(
                AllowAll.check(&instance, action, &Scope::Instance).await,
                Ok(())
            );
        }
    }
}
