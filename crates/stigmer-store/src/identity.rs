//! Identity storage: instance mode, board members, credentials, invites and the security log.
//!
//! Time always comes from the caller (`now_ms` parameters and `expires_at_ms` fields), so a
//! backend never reads a clock here. Secrets never reach the store: credentials and invites are
//! stored as `sha256(secret)`, and `Debug` output redacts even that hash.

use std::fmt;
use std::future::Future;

use stigmer_core::{BoardId, Principal, PrincipalKind, Role, TokenId};

use crate::StoreError;

/// Whether the instance requires authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Loopback only, no authentication (M0 behaviour). Every new data directory starts here.
    Local,
    /// Authentication on every route but health and join. One-way.
    Network,
}

/// What a credential authorizes: the whole instance (the instance admin) or one board.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialScope {
    Instance,
    Board(BoardId),
}

/// A principal's membership of one board. The role lives here, not on credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub board: BoardId,
    pub name: Principal,
    pub kind: PrincipalKind,
    pub role: Role,
    pub created_at_ms: i64,
}

/// A credential to store. Only the hash of its secret is kept.
#[derive(Clone, PartialEq, Eq)]
pub struct NewCredential {
    pub id: TokenId,
    pub secret_hash: [u8; 32],
    pub scope: CredentialScope,
    pub principal: Principal,
    pub expires_at_ms: i64,
}

impl fmt::Debug for NewCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewCredential")
            .field("id", &self.id)
            .field("secret_hash", &REDACTED)
            .field("scope", &self.scope)
            .field("principal", &self.principal)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// A stored credential. The caller compares `secret_hash` in constant time
/// (`stigmer_core::hashes_match`) and checks expiry and revocation.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    pub id: TokenId,
    pub secret_hash: [u8; 32],
    pub scope: CredentialScope,
    pub principal: Principal,
    pub expires_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub last_seen_ms: Option<i64>,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("id", &self.id)
            .field("secret_hash", &REDACTED)
            .field("scope", &self.scope)
            .field("principal", &self.principal)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("revoked_at_ms", &self.revoked_at_ms)
            .field("last_seen_ms", &self.last_seen_ms)
            .finish()
    }
}

/// A single-use invite into `board` with a fixed role and kind. Only the hash of its secret is
/// kept.
#[derive(Clone, PartialEq, Eq)]
pub struct NewInvite {
    pub id: TokenId,
    pub secret_hash: [u8; 32],
    pub board: BoardId,
    pub role: Role,
    pub kind: PrincipalKind,
    pub created_by: Principal,
    pub expires_at_ms: i64,
}

impl fmt::Debug for NewInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewInvite")
            .field("id", &self.id)
            .field("secret_hash", &REDACTED)
            .field("board", &self.board)
            .field("role", &self.role)
            .field("kind", &self.kind)
            .field("created_by", &self.created_by)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// The credential `consume_invite` creates for the new member, on the invite's board. Only the
/// hash of its secret is kept.
#[derive(Clone, PartialEq, Eq)]
pub struct NewJoinCredential {
    pub id: TokenId,
    pub secret_hash: [u8; 32],
    pub expires_at_ms: i64,
}

impl fmt::Debug for NewJoinCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewJoinCredential")
            .field("id", &self.id)
            .field("secret_hash", &REDACTED)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// What consuming an invite produced: the new member, with the invite's board, role and kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumed {
    pub board: BoardId,
    pub role: Role,
    pub kind: PrincipalKind,
    pub member: Member,
}

/// A local (M0) author to turn into a member of a board.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adoption {
    pub name: Principal,
    pub kind: PrincipalKind,
    pub role: Role,
}

/// What a security log entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventKind {
    Join,
    TokenRevoked,
    MemberRemoved,
    BoardCreated,
    BoardArchived,
    InviteCreated,
    AuthFailed,
    RateLimited,
    ModeEnabled,
    /// An instance-admin credential was issued from the command line.
    InstanceTokenIssued,
    /// A board credential for an existing member was issued from the command line.
    MemberTokenIssued,
}

impl SecurityEventKind {
    const ALL: [SecurityEventKind; 11] = [
        SecurityEventKind::Join,
        SecurityEventKind::TokenRevoked,
        SecurityEventKind::MemberRemoved,
        SecurityEventKind::BoardCreated,
        SecurityEventKind::BoardArchived,
        SecurityEventKind::InviteCreated,
        SecurityEventKind::AuthFailed,
        SecurityEventKind::RateLimited,
        SecurityEventKind::ModeEnabled,
        SecurityEventKind::InstanceTokenIssued,
        SecurityEventKind::MemberTokenIssued,
    ];

    /// The stored name, in snake case.
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityEventKind::Join => "join",
            SecurityEventKind::TokenRevoked => "token_revoked",
            SecurityEventKind::MemberRemoved => "member_removed",
            SecurityEventKind::BoardCreated => "board_created",
            SecurityEventKind::BoardArchived => "board_archived",
            SecurityEventKind::InviteCreated => "invite_created",
            SecurityEventKind::AuthFailed => "auth_failed",
            SecurityEventKind::RateLimited => "rate_limited",
            SecurityEventKind::ModeEnabled => "mode_enabled",
            SecurityEventKind::InstanceTokenIssued => "instance_token_issued",
            SecurityEventKind::MemberTokenIssued => "member_token_issued",
        }
    }

    /// The kind stored as `name`, or `None` for a name no kind has.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }
}

impl fmt::Display for SecurityEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One security log entry. `detail` is written by the caller and must never hold a secret,
/// a secret hash or a full token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    pub at_ms: i64,
    pub kind: SecurityEventKind,
    pub board: Option<BoardId>,
    pub principal: Option<String>,
    pub detail: String,
}

const REDACTED: &str = "<redacted>";

/// Storage for the instance mode, board members, credentials, invites and the security log.
///
/// Implemented by the same backend as `Store`; verified by `run_identity_all` in
/// `stigmer-store-conformance`. Every method that takes a board reports an unknown board as
/// `NotFound` with `Entity::Board`.
///
/// An archived board takes no new identities: `add_member`, `create_invite` and
/// `adopt_local_authors` refuse it with `Conflict(ConflictKind::BoardArchived)`, as does
/// `create_credential` for that board, and `consume_invite` refuses an invite into it like any
/// other unusable invite. Reads, `remove_member` and revocation keep working on archived boards,
/// as the archive flow needs them.
pub trait IdentityStore: Send + Sync + 'static {
    /// The instance mode. A fresh store is `Mode::Local`.
    fn mode(&self) -> impl Future<Output = Result<Mode, StoreError>> + Send;

    /// Switches the instance to `Mode::Network`, one-way. A second call is
    /// `Conflict(ConflictKind::AlreadyNetwork)` and changes nothing.
    fn enable_network_mode(&self) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Adds `name` to `board` at `now_ms`. A name already on the board is
    /// `Conflict(ConflictKind::NameTaken)`; the same name may exist on other boards. An archived
    /// board is `Conflict(ConflictKind::BoardArchived)`.
    fn add_member(
        &self,
        board: &BoardId,
        name: &Principal,
        kind: PrincipalKind,
        role: Role,
        now_ms: i64,
    ) -> impl Future<Output = Result<Member, StoreError>> + Send;

    /// The member `name` of `board`, or `None`.
    fn get_member(
        &self,
        board: &BoardId,
        name: &Principal,
    ) -> impl Future<Output = Result<Option<Member>, StoreError>> + Send;

    /// Every member of `board`, by name.
    fn list_members(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Member>, StoreError>> + Send;

    /// Removes `name` from `board` and revokes, at `now_ms`, every credential of theirs on
    /// that board, atomically. An unknown member is `NotFound` with `Entity::Member`.
    fn remove_member(
        &self,
        board: &BoardId,
        name: &Principal,
        now_ms: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The distinct authors, sorted, of the messages on `board` still written by a local (M0)
    /// principal.
    fn list_local_authors(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Principal>, StoreError>> + Send;

    /// In one transaction: makes each adoption a member of `board` at `now_ms` and marks that
    /// author's messages on the board as written by a real principal. Returns the number of
    /// messages marked. Authors not adopted stay local. The event log and its hashes are not
    /// touched. A name already on the board is `Conflict(ConflictKind::NameTaken)` and an
    /// archived board is `Conflict(ConflictKind::BoardArchived)`; either changes nothing.
    fn adopt_local_authors(
        &self,
        board: &BoardId,
        adoptions: &[Adoption],
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Stores a credential created at `now_ms`. A board-scoped credential for an archived board
    /// is `Conflict(ConflictKind::BoardArchived)`; the instance scope is not tied to a board.
    fn create_credential(
        &self,
        credential: NewCredential,
        now_ms: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The credential `id`, or `None`, whatever its expiry or revocation.
    fn find_credential(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<Option<Credential>, StoreError>> + Send;

    /// Records that credential `id` was used at `now_ms`. An unknown id is `NotFound` with
    /// `Entity::Credential`.
    fn touch_credential(
        &self,
        id: &TokenId,
        now_ms: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Every credential scoped to `board`, revoked ones included, oldest first.
    fn list_credentials(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Credential>, StoreError>> + Send;

    /// Revokes credential `id` at `now_ms`. Revoking a revoked credential keeps the first
    /// time. An unknown id is `NotFound` with `Entity::Credential`.
    fn revoke_credential(
        &self,
        id: &TokenId,
        now_ms: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Revokes at `now_ms` every live credential scoped to `board`, except, when
    /// `keep_admins` is true, those whose principal is an admin of the board. Never touches the
    /// instance credential. Returns the number revoked.
    fn revoke_board_credentials(
        &self,
        board: &BoardId,
        keep_admins: bool,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Revokes at `now_ms` every live instance-scope credential except `keep`. Never touches a
    /// board credential, and leaves `keep` as it is (it need not exist). Returns the number
    /// revoked.
    fn revoke_instance_credentials_except(
        &self,
        keep: &TokenId,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// In one transaction: stores `credential`, which must have the instance scope, and revokes
    /// at `now_ms` every other live instance credential. Returns the number revoked. Either all
    /// of it happens or none, so a failure leaves the old instance credentials valid. A board
    /// scope is refused with `StoreError::Backend` and stores nothing.
    fn replace_instance_credential(
        &self,
        credential: NewCredential,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Stores an invite created at `now_ms`. An archived board is
    /// `Conflict(ConflictKind::BoardArchived)`.
    fn create_invite(
        &self,
        invite: NewInvite,
        now_ms: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// In one transaction: checks the invite (its hash compared in constant time, valid while
    /// `now_ms < expires_at_ms`, unused, board not archived), adds `name` as a member with the
    /// invite's role and kind, stores `credential` for that member on the invite's board, marks
    /// the invite used and appends a `SecurityEventKind::Join` row (board, member name, kind and
    /// role words, no secrets). Either all of it happens or none. An unknown id, a wrong hash, an
    /// expired invite, a used one and one into an archived board are all the same `NotFound` with
    /// `Entity::Invite`. A name already on the board is `Conflict(ConflictKind::NameTaken)`.
    /// Every failure leaves the invite unused and no member, credential or log row behind.
    fn consume_invite(
        &self,
        id: &TokenId,
        secret_hash: &[u8; 32],
        name: &Principal,
        now_ms: i64,
        credential: NewJoinCredential,
    ) -> impl Future<Output = Result<Consumed, StoreError>> + Send;

    /// Appends an entry to the security log.
    fn log_security(
        &self,
        event: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Up to `limit` security log entries, newest first.
    fn security_log(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<SecurityEvent>, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use stigmer_core::{hash_secret, BoardId, Principal, PrincipalKind, Role, TokenId};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn security_event_kind_names_roundtrip() {
        let kinds = [
            (SecurityEventKind::Join, "join"),
            (SecurityEventKind::TokenRevoked, "token_revoked"),
            (SecurityEventKind::MemberRemoved, "member_removed"),
            (SecurityEventKind::BoardCreated, "board_created"),
            (SecurityEventKind::BoardArchived, "board_archived"),
            (SecurityEventKind::InviteCreated, "invite_created"),
            (SecurityEventKind::AuthFailed, "auth_failed"),
            (SecurityEventKind::RateLimited, "rate_limited"),
            (SecurityEventKind::ModeEnabled, "mode_enabled"),
            (
                SecurityEventKind::InstanceTokenIssued,
                "instance_token_issued",
            ),
            (SecurityEventKind::MemberTokenIssued, "member_token_issued"),
        ];
        for (kind, name) in kinds {
            assert_eq!(kind.as_str(), name);
            assert_eq!(kind.to_string(), name);
            assert_eq!(SecurityEventKind::parse(name), Some(kind));
        }
        assert_eq!(SecurityEventKind::parse("JOIN"), None);
        assert_eq!(SecurityEventKind::parse(""), None);
    }

    #[test]
    fn debug_output_redacts_secret_hashes() {
        let hash = hash_secret("not-a-real-secret");
        let id = TokenId::new("0123456789abcdef").unwrap();
        let board = BoardId::main();
        let alice = Principal::new("alice").unwrap();
        let new_credential = NewCredential {
            id: id.clone(),
            secret_hash: hash,
            scope: CredentialScope::Board(board.clone()),
            principal: alice.clone(),
            expires_at_ms: 10,
        };
        let credential = Credential {
            id: id.clone(),
            secret_hash: hash,
            scope: CredentialScope::Instance,
            principal: alice.clone(),
            expires_at_ms: 10,
            revoked_at_ms: None,
            last_seen_ms: Some(5),
        };
        let invite = NewInvite {
            id: id.clone(),
            secret_hash: hash,
            board,
            role: Role::Member,
            kind: PrincipalKind::Agent,
            created_by: alice,
            expires_at_ms: 10,
        };
        for shown in [
            format!("{new_credential:?}"),
            format!("{credential:?}"),
            format!("{invite:?}"),
        ] {
            assert!(shown.contains("0123456789abcdef"), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
            assert!(!shown.contains(&hex(&hash)), "{shown}");
            assert!(!shown.contains(&format!("{hash:?}")), "{shown}");
        }
    }
}
