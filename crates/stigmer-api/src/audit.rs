//! Typed security log rows: the mutating routes hand theirs to the store, which writes each in
//! its mutation's transaction; the join rate limit's is written best effort.
//!
//! Details carry public ids, names and the source address only. A secret, a secret hash or a
//! full token never reaches these constructors.

use stigmer_core::{BoardId, Principal, PrincipalKind, Role, TokenId};
use stigmer_store::{SecurityEvent, SecurityEventKind};

use crate::ratelimit::Source;

/// Who did something, when, and from where; each method builds one row about a board.
pub(crate) struct Audit<'a> {
    pub(crate) at_ms: i64,
    pub(crate) source: Source,
    pub(crate) by: &'a Principal,
}

impl Audit<'_> {
    fn event(&self, kind: SecurityEventKind, board: &BoardId, what: String) -> SecurityEvent {
        SecurityEvent {
            at_ms: self.at_ms,
            kind,
            board: Some(board.clone()),
            principal: Some(self.by.to_string()),
            detail: format!("source={} {what}", self.source),
        }
    }

    pub(crate) fn board_created(&self, board: &BoardId) -> SecurityEvent {
        self.event(SecurityEventKind::BoardCreated, board, String::new())
    }

    pub(crate) fn board_archived(&self, board: &BoardId) -> SecurityEvent {
        self.event(SecurityEventKind::BoardArchived, board, String::new())
    }

    pub(crate) fn invite_created(
        &self,
        board: &BoardId,
        invite: &TokenId,
        kind: PrincipalKind,
        role: Role,
    ) -> SecurityEvent {
        let what = format!(
            "invite created invite={invite} kind={} role={}",
            kind.as_str(),
            role.as_str()
        );
        self.event(SecurityEventKind::InviteCreated, board, what)
    }

    pub(crate) fn token_revoked(
        &self,
        board: &BoardId,
        token: &TokenId,
        owner: &Principal,
    ) -> SecurityEvent {
        self.event(
            SecurityEventKind::TokenRevoked,
            board,
            format!("token={token} principal={owner}"),
        )
    }

    pub(crate) fn member_removed(&self, board: &BoardId, member: &Principal) -> SecurityEvent {
        self.event(
            SecurityEventKind::MemberRemoved,
            board,
            format!("member={member}"),
        )
    }
}

/// A join attempt refused by the join limit.
pub(crate) fn join_rate_limited(at_ms: i64, source: Source) -> SecurityEvent {
    SecurityEvent {
        at_ms,
        kind: SecurityEventKind::RateLimited,
        board: None,
        principal: None,
        detail: format!("source={source} route=join"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_name_the_source_and_public_ids_only() {
        let by = Principal::new("ann").unwrap();
        let board = BoardId::main();
        let id = TokenId::new("0123456789abcdef").unwrap();
        let audit = Audit {
            at_ms: 7,
            source: Source::Unknown,
            by: &by,
        };
        let row = audit.invite_created(&board, &id, PrincipalKind::Agent, Role::Member);
        assert_eq!(row.kind, SecurityEventKind::InviteCreated);
        assert_eq!(row.board, Some(board.clone()));
        assert_eq!(row.principal.as_deref(), Some("ann"));
        assert_eq!(
            row.detail,
            "source=unknown invite created invite=0123456789abcdef kind=agent role=member"
        );
        assert_eq!(audit.board_created(&board).detail, "source=unknown ");
        assert_eq!(join_rate_limited(1, Source::Unknown).at_ms, 1);
    }
}
