//! A store whose mutations or best-effort security log can be made to fail.
//!
//! An audited mutation writes its security log row inside the store's own transaction, so a
//! failing audit write cannot be injected from a wrapper: `fail_mutations` makes every audited
//! mutation fail as the store reports such a failure (a backend error, nothing changed). The
//! real rollback is proven against SQLite in `stigmer-store-sqlite/tests/audit_rollback.rs`.

#![allow(dead_code)]

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use stigmer_core::{
    BoardId, BoardInfo, ChannelPath, Cursor, Event, EventFilter, MessageId, NewMessage, Page,
    Posted, Principal, PrincipalKind, Role, Thread, ThreadSummary, TokenId,
};
use stigmer_store::{
    Adoption, ChainReport, Consumed, Credential, EnableAudits, IdentityStore, Member, Mode,
    NewCredential, NewInvite, NewJoinCredential, SecurityEvent, Store, StoreError,
};
use stigmer_store_sqlite::SqliteStore;

pub struct LogFailingStore {
    pub inner: SqliteStore,
    /// While true, `log_security` (the best-effort log) fails with a backend error.
    pub fail_log: AtomicBool,
    /// While true, every audited mutation fails with a backend error and changes nothing.
    pub fail_mutations: AtomicBool,
    /// Runs once right after the next `archive_board_revoking`: a join that races in there.
    pub join_after_archive: Mutex<Option<JoinAttempt>>,
    /// What that join got.
    pub join_result: Mutex<Option<Result<Consumed, StoreError>>>,
}

/// A `consume_invite` call to make at a chosen moment.
pub struct JoinAttempt {
    pub id: TokenId,
    pub secret_hash: [u8; 32],
    pub name: Principal,
    pub credential: NewJoinCredential,
}

impl LogFailingStore {
    pub fn new(inner: SqliteStore) -> Self {
        Self {
            inner,
            fail_log: AtomicBool::new(false),
            fail_mutations: AtomicBool::new(false),
            join_after_archive: Mutex::new(None),
            join_result: Mutex::new(None),
        }
    }

    /// `mutation`, or the failure `fail_mutations` asks for without running it.
    async fn mutate<T>(
        &self,
        mutation: impl Future<Output = Result<T, StoreError>>,
    ) -> Result<T, StoreError> {
        if self.fail_mutations.load(Ordering::SeqCst) {
            return Err(StoreError::Backend("audit write failed".into()));
        }
        mutation.await
    }
}

impl Store for LogFailingStore {
    async fn create_board(
        &self,
        id: &BoardId,
        created_by: Option<&Principal>,
        audit: SecurityEvent,
    ) -> Result<BoardInfo, StoreError> {
        self.mutate(self.inner.create_board(id, created_by, audit))
            .await
    }

    fn get_board(
        &self,
        id: &BoardId,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        self.inner.get_board(id)
    }

    fn list_boards(&self) -> impl Future<Output = Result<Vec<BoardInfo>, StoreError>> + Send {
        self.inner.list_boards()
    }

    async fn archive_board(
        &self,
        id: &BoardId,
        audit: SecurityEvent,
    ) -> Result<BoardInfo, StoreError> {
        self.mutate(self.inner.archive_board(id, audit)).await
    }

    fn post(&self, msg: NewMessage) -> impl Future<Output = Result<Posted, StoreError>> + Send {
        self.inner.post(msg)
    }

    fn verify_chain(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<ChainReport, StoreError>> + Send {
        self.inner.verify_chain(board)
    }

    fn read_channel(
        &self,
        board: &BoardId,
        prefix: &ChannelPath,
        page: Page,
    ) -> impl Future<Output = Result<Vec<ThreadSummary>, StoreError>> + Send {
        self.inner.read_channel(board, prefix, page)
    }

    fn read_thread(
        &self,
        board: &BoardId,
        thread: &MessageId,
    ) -> impl Future<Output = Result<Thread, StoreError>> + Send {
        self.inner.read_thread(board, thread)
    }

    fn events_after(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        filter: &EventFilter,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Event>, StoreError>> + Send {
        self.inner.events_after(board, after, filter, limit)
    }

    fn head(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Option<Cursor>, StoreError>> + Send {
        self.inner.head(board)
    }

    fn wait_past(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        timeout: Duration,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        self.inner.wait_past(board, after, timeout)
    }
}

impl IdentityStore for LogFailingStore {
    fn mode(&self) -> impl Future<Output = Result<Mode, StoreError>> + Send {
        self.inner.mode()
    }

    async fn enable_network_mode(&self, audit: SecurityEvent) -> Result<(), StoreError> {
        self.mutate(self.inner.enable_network_mode(audit)).await
    }

    async fn enable_network(
        &self,
        credential: NewCredential,
        invite: Option<(NewInvite, SecurityEvent)>,
        audits: EnableAudits,
    ) -> Result<(), StoreError> {
        self.mutate(self.inner.enable_network(credential, invite, audits))
            .await
    }

    fn add_member(
        &self,
        board: &BoardId,
        name: &Principal,
        kind: PrincipalKind,
        role: Role,
        now_ms: i64,
    ) -> impl Future<Output = Result<Member, StoreError>> + Send {
        self.inner.add_member(board, name, kind, role, now_ms)
    }

    fn get_member(
        &self,
        board: &BoardId,
        name: &Principal,
    ) -> impl Future<Output = Result<Option<Member>, StoreError>> + Send {
        self.inner.get_member(board, name)
    }

    fn list_members(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Member>, StoreError>> + Send {
        self.inner.list_members(board)
    }

    async fn remove_member(
        &self,
        board: &BoardId,
        name: &Principal,
        audit: SecurityEvent,
    ) -> Result<(), StoreError> {
        self.mutate(self.inner.remove_member(board, name, audit))
            .await
    }

    fn list_local_authors(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Principal>, StoreError>> + Send {
        self.inner.list_local_authors(board)
    }

    fn adopt_local_authors(
        &self,
        board: &BoardId,
        adoptions: &[Adoption],
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        self.inner.adopt_local_authors(board, adoptions, now_ms)
    }

    async fn create_credential(
        &self,
        credential: NewCredential,
        audit: SecurityEvent,
    ) -> Result<(), StoreError> {
        self.mutate(self.inner.create_credential(credential, audit))
            .await
    }

    fn find_credential(
        &self,
        id: &TokenId,
    ) -> impl Future<Output = Result<Option<Credential>, StoreError>> + Send {
        self.inner.find_credential(id)
    }

    fn touch_credential(
        &self,
        id: &TokenId,
        now_ms: i64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.touch_credential(id, now_ms)
    }

    fn list_credentials(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Vec<Credential>, StoreError>> + Send {
        self.inner.list_credentials(board)
    }

    async fn revoke_credential(
        &self,
        id: &TokenId,
        audit: SecurityEvent,
    ) -> Result<(), StoreError> {
        self.mutate(self.inner.revoke_credential(id, audit)).await
    }

    fn revoke_board_credentials(
        &self,
        board: &BoardId,
        keep_admins: bool,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        self.inner
            .revoke_board_credentials(board, keep_admins, now_ms)
    }

    async fn archive_board_revoking(
        &self,
        id: &BoardId,
        audit: SecurityEvent,
    ) -> Result<BoardInfo, StoreError> {
        let now_ms = audit.at_ms;
        let archived = self
            .mutate(self.inner.archive_board_revoking(id, audit))
            .await;
        let racer = self.join_after_archive.lock().unwrap().take();
        if let Some(j) = racer {
            let joined = self
                .inner
                .consume_invite(&j.id, &j.secret_hash, &j.name, now_ms, j.credential)
                .await;
            *self.join_result.lock().unwrap() = Some(joined);
        }
        archived
    }

    fn revoke_instance_credentials_except(
        &self,
        keep: &TokenId,
        now_ms: i64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send {
        self.inner.revoke_instance_credentials_except(keep, now_ms)
    }

    async fn replace_instance_credential(
        &self,
        credential: NewCredential,
        audit: SecurityEvent,
    ) -> Result<u64, StoreError> {
        self.mutate(self.inner.replace_instance_credential(credential, audit))
            .await
    }

    async fn create_invite(
        &self,
        invite: NewInvite,
        audit: SecurityEvent,
    ) -> Result<(), StoreError> {
        self.mutate(self.inner.create_invite(invite, audit)).await
    }

    fn consume_invite(
        &self,
        id: &TokenId,
        secret_hash: &[u8; 32],
        name: &Principal,
        now_ms: i64,
        credential: NewJoinCredential,
    ) -> impl Future<Output = Result<Consumed, StoreError>> + Send {
        self.inner
            .consume_invite(id, secret_hash, name, now_ms, credential)
    }

    fn log_security(
        &self,
        event: SecurityEvent,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let fail = self.fail_log.load(Ordering::SeqCst);
        let result = self.inner.log_security(event);
        async move {
            if fail {
                return Err(StoreError::Backend("log unavailable".into()));
            }
            result.await
        }
    }

    fn security_log(
        &self,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<SecurityEvent>, StoreError>> + Send {
        self.inner.security_log(limit)
    }
}
