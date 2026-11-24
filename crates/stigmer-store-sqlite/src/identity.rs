//! `IdentityStore` for SQLite: each method runs one call of `members` or `credentials` on the
//! shared connection.

use std::future::Future;

use std::sync::Arc;

use stigmer_core::{BoardId, BoardInfo, Principal, PrincipalKind, Role, TokenId};
use stigmer_store::{
    Adoption, Consumed, Credential, EnableAudits, IdentityStore, Member, Mode, NewCredential,
    NewInvite, NewJoinCredential, SecurityEvent, StoreError,
};

use crate::{boards, credentials, members, SqliteStore};

impl IdentityStore for SqliteStore {
    fn mode(&self) -> impl Future<Output = Result<Mode, StoreError>> + Send {
        self.run(|conn| members::mode(conn))
    }

    fn enable_network_mode(
        &self,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.run(move |conn| members::enable_network_mode(conn, &audit))
    }

    fn enable_network(
        &self,
        credential: NewCredential,
        invite: Option<NewInvite>,
        audits: EnableAudits,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.run(move |conn| members::enable_network(conn, &credential, invite.as_ref(), &audits))
    }

    fn add_member(
        &self,
        board: &BoardId,
        name: &Principal,
        kind: PrincipalKind,
        role: Role,
        now_ms: i64,
    ) -> impl Future<Output = Result<Member, StoreError>> + Send {
        let (board, name) = (board.clone(), name.clone());
        self.run(move |conn| members::add(conn, &board, &name, kind, role, now_ms))
    }

    fn get_member(
        &self,
        board: &BoardId,
        name: &Principal,
    ) -> impl Future<Output = Result<Option<Member>, StoreError>> + Send {
        let (board, name) = (board.clone(), name.clone());
        self.run(move |conn| members::get(conn, &board, &name))
    }

    fn list_members(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Member>, StoreError>> + Send {
        let board = board.clone();
        self.run(move |conn| members::list(conn, &board))
    }

    fn remove_member(
        &self,
        board: &BoardId,
        name: &Principal,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let (board, name) = (board.clone(), name.clone());
        self.run(move |conn| members::remove(conn, &board, &name, &audit))
    }

    fn list_local_authors(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Principal>, StoreError>> + Send {
        let board = board.clone();
        self.run(move |conn| members::local_authors(conn, &board))
    }

    fn adopt_local_authors(
        &self,
        board: &BoardId,
        adoptions: &[Adoption],
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let (board, adoptions) = (board.clone(), adoptions.to_vec());
        self.run(move |conn| members::adopt(conn, &board, &adoptions, now_ms))
    }

    fn create_credential(
        &self,
        credential: NewCredential,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.run(move |conn| credentials::create(conn, credential, &audit))
    }

    fn find_credential(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<Option<Credential>, StoreError>> + Send {
        let id = id.clone();
        self.run(move |conn| credentials::find(conn, &id))
    }

    fn touch_credential(
        &self,
        id: &TokenId,
        now_ms: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let id = id.clone();
        self.run(move |conn| credentials::touch(conn, &id, now_ms))
    }

    fn list_credentials(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Credential>, StoreError>> + Send {
        let board = board.clone();
        self.run(move |conn| credentials::list(conn, &board))
    }

    fn revoke_credential(
        &self,
        id: &TokenId,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let id = id.clone();
        self.run(move |conn| credentials::revoke(conn, &id, &audit))
    }

    fn revoke_board_credentials(
        &self,
        board: &BoardId,
        keep_admins: bool,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let board = board.clone();
        self.run(move |conn| credentials::revoke_board(conn, &board, keep_admins, now_ms))
    }

    fn archive_board_revoking(
        &self,
        id: &BoardId,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        let id = id.clone();
        let notifier = Arc::clone(&self.notifier);
        self.run(move |conn| {
            let info = boards::archive_revoking(conn, &id, &audit)?;
            // Under the connection lock, as in `archive_board`.
            notifier.forget(&id);
            Ok(info)
        })
    }

    fn revoke_instance_credentials_except(
        &self,
        keep: &TokenId,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        let keep = keep.clone();
        self.run(move |conn| credentials::revoke_instance_except(conn, &keep, now_ms))
    }

    fn replace_instance_credential(
        &self,
        credential: NewCredential,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        self.run(move |conn| credentials::replace_instance(conn, credential, &audit))
    }

    fn create_invite(
        &self,
        invite: NewInvite,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.run(move |conn| credentials::create_invite(conn, invite, &audit))
    }

    fn consume_invite(
        &self,
        id: &TokenId,
        secret_hash: &[u8; 32],
        name: &Principal,
        now_ms: i64,
        credential: NewJoinCredential,
    ) -> impl Future<Output = Result<Consumed, StoreError>> + Send {
        let (id, secret_hash, name) = (id.clone(), *secret_hash, name.clone());
        self.run(move |conn| {
            credentials::consume_invite(conn, &id, &secret_hash, &name, now_ms, credential)
        })
    }

    fn log_security(
        &self,
        event: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.run(move |conn| credentials::log_in_tx(conn, &event))
    }

    fn security_log(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<SecurityEvent>, StoreError>> + Send {
        self.run(move |conn| credentials::security_log(conn, limit))
    }
}
