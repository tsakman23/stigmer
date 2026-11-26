//! `IdentityStore` for `PgStore`: each method clones what it needs and runs as one future on
//! the pool, as the `Store` methods do.

use std::future::Future;

use stigmer_core::{BoardId, BoardInfo, Principal, PrincipalKind, Role, TokenId};
use stigmer_store::{
    Adoption, Consumed, Credential, EnableAudits, IdentityStore, Member, Mode, NewCredential,
    NewInvite, NewJoinCredential, SecurityEvent, StoreError,
};

use crate::{
    boards, identity_credentials as credentials, identity_invites as invites,
    identity_members as members, identity_security as security, PgStore,
};

impl IdentityStore for PgStore {
    fn mode(&self) -> impl Future<Output = Result<Mode, StoreError>> + Send {
        let pool = self.pool.clone();
        async move { security::mode(&pool).await }
    }

    fn enable_network_mode(
        &self,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let pool = self.pool.clone();
        async move { security::enable_network_mode(&pool, &audit).await }
    }

    fn enable_network(
        &self,
        credential: NewCredential,
        invite: Option<(NewInvite, SecurityEvent)>,
        audits: EnableAudits,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let pool = self.pool.clone();
        async move { security::enable_network(&pool, &credential, invite.as_ref(), &audits).await }
    }

    fn add_member(
        &self,
        board: &BoardId,
        name: &Principal,
        kind: PrincipalKind,
        role: Role,
        now_ms: i64,
    ) -> impl Future<Output = Result<Member, StoreError>> + Send {
        let (pool, board, name) = (self.pool.clone(), board.clone(), name.clone());
        async move { members::add(&pool, &board, &name, kind, role, now_ms).await }
    }

    fn get_member(
        &self,
        board: &BoardId,
        name: &Principal,
    ) -> impl Future<Output = Result<Option<Member>, StoreError>> + Send {
        let (pool, board, name) = (self.pool.clone(), board.clone(), name.clone());
        async move { members::get(&pool, &board, &name).await }
    }

    fn list_members(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Member>, StoreError>> + Send {
        let (pool, board) = (self.pool.clone(), board.clone());
        async move { members::list(&pool, &board).await }
    }

    fn remove_member(
        &self,
        board: &BoardId,
        name: &Principal,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let (pool, board, name) = (self.pool.clone(), board.clone(), name.clone());
        async move { members::remove(&pool, &board, &name, &audit).await }
    }

    fn list_local_authors(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Principal>, StoreError>> + Send {
        let (pool, board) = (self.pool.clone(), board.clone());
        async move { members::local_authors(&pool, &board).await }
    }

    fn adopt_local_authors(
        &self,
        board: &BoardId,
        adoptions: &[Adoption],
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let (pool, board, adoptions) = (self.pool.clone(), board.clone(), adoptions.to_vec());
        async move { members::adopt(&pool, &board, &adoptions, now_ms).await }
    }

    fn create_credential(
        &self,
        credential: NewCredential,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let pool = self.pool.clone();
        async move { credentials::create(&pool, &credential, &audit).await }
    }

    fn find_credential(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<Option<Credential>, StoreError>> + Send {
        let (pool, id) = (self.pool.clone(), id.clone());
        async move { credentials::find(&pool, &id).await }
    }

    fn touch_credential(
        &self,
        id: &TokenId,
        now_ms: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let (pool, id) = (self.pool.clone(), id.clone());
        async move { credentials::touch(&pool, &id, now_ms).await }
    }

    fn list_credentials(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Credential>, StoreError>> + Send {
        let (pool, board) = (self.pool.clone(), board.clone());
        async move { credentials::list(&pool, &board).await }
    }

    fn revoke_credential(
        &self,
        id: &TokenId,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let (pool, id) = (self.pool.clone(), id.clone());
        async move { credentials::revoke(&pool, &id, &audit).await }
    }

    fn revoke_board_credentials(
        &self,
        board: &BoardId,
        keep_admins: bool,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let (pool, board) = (self.pool.clone(), board.clone());
        async move { credentials::revoke_board(&pool, &board, keep_admins, now_ms).await }
    }

    fn archive_board_revoking(
        &self,
        id: &BoardId,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        let (pool, id) = (self.pool.clone(), id.clone());
        async move { boards::archive_revoking(&pool, &id, &audit).await }
    }

    fn revoke_instance_credentials_except(
        &self,
        keep: &TokenId,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let (pool, keep) = (self.pool.clone(), keep.clone());
        async move { credentials::revoke_instance_except(&pool, &keep, now_ms).await }
    }

    fn replace_instance_credential(
        &self,
        credential: NewCredential,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let pool = self.pool.clone();
        async move { credentials::replace_instance(&pool, &credential, &audit).await }
    }

    fn create_invite(
        &self,
        invite: NewInvite,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let pool = self.pool.clone();
        async move { invites::create_invite(&pool, &invite, &audit).await }
    }

    fn consume_invite(
        &self,
        id: &TokenId,
        secret_hash: &[u8; 32],
        name: &Principal,
        now_ms: i64,
        credential: NewJoinCredential,
    ) -> impl Future<Output = Result<Consumed, StoreError>> + Send {
        let (pool, id, secret_hash, name) =
            (self.pool.clone(), id.clone(), *secret_hash, name.clone());
        async move { invites::consume_invite(&pool, &id, &secret_hash, &name, now_ms, credential).await }
    }

    fn log_security(
        &self,
        event: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let pool = self.pool.clone();
        async move { security::log_security(&pool, &event).await }
    }

    fn security_log(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<SecurityEvent>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move { security::security_log(&pool, limit).await }
    }
}
