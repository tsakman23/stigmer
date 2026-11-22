# M1 Networked Board Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a Stigmer server usable by a team over a network: dynamic boards, token authentication with single-use invites, role-based authorization, built-in TLS plus a trusted-proxy mode, CLI and TypeScript SDK support, and the hardening items carried from M0.

**Architecture:** The existing crates grow in place. `stigmer-core` gains identity and wire types; `stigmer-store` gains board management and a separate `IdentityStore` trait (same SQLite database, own conformance scenarios); `stigmer-api` gains an async `Authorize`, an authentication layer, rate limits and the new routes; `stigmerd` gains modes, admin commands, TLS and limits; `stigmer-cli` gains logins and management commands; `sdk/typescript` is new. Local mode keeps working exactly as in M0.

**Tech Stack:** Rust (pinned toolchain), axum, tokio, rustls and tokio-rustls, rusqlite, sha2, clap, ureq; TypeScript (Node 20+, node:test, tsc) for the SDK.

**Spec:** `docs/superpowers/specs/2026-11-22-m1-networked-board-design.md` (sections 6 and 11 govern; `docs/design.md` and `docs/adr/` for the base). Branch `milestone/m1-networked-board`; task branches `<type>/m1-tNN-<slug>`.

## Global Constraints

- Rust; `unsafe_code = "forbid"`; cargo-deny clean; Apache-2.0; conventional commits per CONTRIBUTING.md.
- The v0.1.0 hash-chain format is frozen: the event hash input stays `{prev}:{seq}:{kind}:{actor}:{message_id}:{thread_id}:{channel}:{at_ms}` and `HASH_VERSION` stays 1. `author_kind` is not a hash input.
- Local mode (default for a new data dir) is unchanged: loopback only, no authentication, author from `X-Stigmer-As`. The M0 e2e test must pass unchanged.
- Network mode: every route except `/healthz`, `/readyz` and `POST /v1/join` requires a valid token. A non-loopback bind is refused unless the data dir is in network mode AND (TLS files are supplied OR `--trusted-proxy` is set).
- Token format `stg1_<16 hex id>_<43 char base64url secret>` (32 random bytes); invite `stgi1_<16 hex id>_<43 char secret>`. Only sha256(secret) is stored; compare in constant time. Tokens expire after 90 days by default (max 365); invites after 60 minutes by default (max 7 days), single use.
- Tokens and invite secrets never appear in logs, error messages, the database, or process arguments (the only argument that carries a secret is the invite given to `stigmer join`; tokens come from the login file or `STIGMER_TOKEN`).
- 401 `unauthorized` with ONE generic body for missing, malformed, unknown, expired or revoked tokens and for bad invites; 403 `forbidden` for a weak role; 404 `not_found` for a board the credential does not belong to or that does not exist; 429 `rate_limited` with `Retry-After` (checked before credential verification).
- TLS 1.3 only; no self-signed generation; certificates reload on file change without ending open waits.
- Roles: admin, member, bridge per board; the instance-admin credential cannot read or post content (403) but manages boards, invites, tokens.
- Archived board: tokens of members, agents and bridges revoked; admin tokens stay valid read-only; posts refused with 409 `board_archived`.
- Unknown board is `NotFound{Board}` from every Store method that takes a board (read_thread keeps Thread, as documented).

## Review Focus

1. Token handling: hashing, constant-time comparison, no secret ever logged or echoed, identical 401 bodies and no timing/existence difference between unknown, expired and revoked. (Tasks 1, 4)
2. Invite redemption is atomic: two concurrent joins with one invite create exactly one member; a taken name does not consume the invite. (Task 3)
3. Board isolation: a token for board A gets 404 on every board-B route, including events, threads and members. (Tasks 4, 5, 10)
4. Rate limiter keys: forged `X-Forwarded-For` from an untrusted source cannot evade or poison limits. (Tasks 4, 7)
5. Migrating M0 data: `enable-auth` and `map-local-principals` keep `verify_chain` valid and old content readable. (Tasks 6, 10)

---

## File Structure

```
crates/stigmer-core/src/{credentials,identity}.rs (new); wire.rs, error.rs, event.rs, model.rs (extended)
crates/stigmer-store/src/{lib.rs,identity.rs}; store-conformance/src/{boards,identity}.rs (new)
crates/stigmer-store-sqlite/src/{boards,identity}.rs (new); schema.rs (migrations 5-7); notify.rs, lib.rs, posts.rs, reads.rs
crates/stigmer-api/src/{auth,limits,ratelimit,admin_routes}.rs (new); authz.rs, routes.rs, lib.rs, host_guard.rs
crates/stigmerd/src/{main,admin,tls,serve,lock}.rs
crates/stigmer-cli/src/{logins,manage}.rs (new); main.rs, client.rs, commands.rs, render.rs, wait.rs
sdk/typescript/{package.json,tsconfig.json,src/*.ts,test/*.test.ts,examples/two-agents.mjs}
.github/workflows/ci.yml (SDK job); docs/adr/0008-0011; README.md; docs/design.md (section 14)
```

---

### Task 1: Identity, credential and wire types (stigmer-core)

**Files:**
- Create: `crates/stigmer-core/src/credentials.rs`, `crates/stigmer-core/src/identity.rs`
- Modify: `wire.rs`, `error.rs`, `event.rs`, `lib.rs` (re-exports)
- Test: unit tests in each file.

**Interfaces:**
- Produces:
```rust
pub enum PrincipalKind { Human, Agent, Bridge }          // serde snake_case, as_str()
pub enum Role { Admin, Member, Bridge }                  // serde snake_case, as_str()
pub struct TokenId(String);                               // 16 lowercase hex, validated (also used for invite ids)
pub enum SecretKind { Token, Invite }
pub struct NewSecret { pub id: TokenId, pub full: String, pub hash: [u8; 32] }  // full is shown once
pub fn generate_secret(kind: SecretKind) -> Result<NewSecret, CoreError>        // stg1_/stgi1_ + id + base64url(32 bytes)
pub fn parse_secret(kind: SecretKind, raw: &str) -> Result<(TokenId, String), CoreError>   // CoreError::BadToken, never echoes raw
pub fn hash_secret(secret: &str) -> [u8; 32]             // sha256
pub fn secrets_match(secret: &str, stored: &[u8; 32]) -> bool   // constant time
// wire.rs additions (serde, validated types): BoardInfo, CreateBoardRequest{name}, BoardsResponse,
// MemberInfo{name,kind,role,last_seen_ms}, MembersResponse, TokenInfo{id,principal,role,expires_at_ms,revoked,last_seen_ms},
// TokensResponse, InviteRequest{kind,role,expires_in_minutes?}, InviteResponse{invite,expires_at_ms}, JoinRequest{invite,name},
// JoinResponse{token,board,role,kind,expires_at_ms}, WhoAmI{principal,kind,board,role,instance_admin}
// ErrorCode gains Unauthorized, RateLimited, BoardArchived and #[serde(other)] Unknown; EventKind gains #[serde(other)] Unknown
//   (Unknown is only ever produced by deserializing; event_hash and as_str never see it from a server)
```

- [ ] **Step 1: Write failing tests:** `generated_token_has_the_stg1_shape` (prefix, 16-hex id, 43-char secret, parse roundtrip); `invite_prefix_differs_from_token_prefix_and_cross_parse_fails`; `parse_secret_rejects_garbage_without_echoing_it` (error Display does not contain the input); `hash_is_sha256_of_the_secret_only` (pinned digest computed with a shell sha256 on a fixed secret); `secrets_match_is_true_for_equal_and_false_for_one_bit_difference`; `two_generated_secrets_differ`; `error_code_unknown_deserializes_from_a_future_value` (`"rate_limited_v2"` parses as Unknown); `event_kind_unknown_deserializes_from_a_future_value`; `role_and_kind_roundtrip_serde`; `join_response_never_serializes_without_a_token_field_name_clash` (wire shape pinned).
- [ ] **Step 2:** Run `cargo test -p stigmer-core`. Expected: FAIL.
- [ ] **Step 3:** Implement per the signatures; randomness via `getrandom`; constant-time comparison by folding XOR over all 32 bytes (no early exit).
- [ ] **Step 4:** Run `cargo test -p stigmer-core`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(core): identity roles, credential secrets and wire types`.

---

### Task 2: Dynamic boards in the store (stigmer-store, store-sqlite, conformance)

**Files:**
- Create: `crates/stigmer-store-sqlite/src/boards.rs`, `crates/stigmer-store-conformance/src/boards.rs`
- Modify: `crates/stigmer-store/src/lib.rs`, `schema.rs` (migration 5), `notify.rs`, `lib.rs`, `posts.rs`, `reads.rs`, `events.rs`, conformance `lib.rs` and `support.rs`.

**Interfaces:**
- Consumes: Task 1 types (`Principal` from core).
- Produces:
```rust
// stigmer-core model.rs
pub struct BoardInfo { pub id: BoardId, pub created_at_ms: i64, pub created_by: Option<Principal>, pub archived_at_ms: Option<i64> }
// stigmer-store: ConflictKind gains BoardExists and BoardArchived (Display texts: "board already exists", "board is archived")
fn create_board(&self, id: &BoardId, created_by: Option<&Principal>) -> impl Future<Output=Result<BoardInfo, StoreError>> + Send; // BoardExists on duplicate
fn get_board(&self, id: &BoardId)  -> ... Result<BoardInfo, StoreError>   // NotFound{Board}
fn list_boards(&self)              -> ... Result<Vec<BoardInfo>, StoreError> // oldest first
fn archive_board(&self, id: &BoardId) -> ... Result<BoardInfo, StoreError>  // idempotent; sets archived_at_ms once
```
Migration 5 (appended): `ALTER TABLE boards ADD COLUMN created_at_ms INTEGER NOT NULL DEFAULT 0; ADD COLUMN created_by TEXT; ADD COLUMN archived_at_ms INTEGER;` (one ALTER per statement). Contract changes, documented on the trait: every method that takes a board returns `NotFound{Board}` for an unknown board (`read_channel`, `verify_chain`, `wait_past`, `events_after`, `head`, `post`); `post` on an archived board returns `Conflict(BoardArchived)` before consuming a sequence number; reads on archived boards still work.

- [ ] **Step 1: Write failing conformance scenarios:** `create_board_then_get_and_list`; `create_duplicate_board_is_board_exists`; `main_exists_on_a_fresh_store`; `boards_are_isolated_sequences_start_at_1_per_board` (post to two boards, each chain verifies, seqs independent); `unknown_board_is_not_found_from_every_method` (read_channel, verify_chain, wait_past, events_after, head, post); `post_to_archived_board_is_board_archived_and_uses_no_sequence_number`; `archived_board_is_still_readable`; `archive_is_idempotent_and_keeps_first_timestamp`; `wait_past_on_unknown_board_leaves_no_notifier_entry` (sqlite-only test, via a test accessor on the notifier). Update the contract docs and the existing scenario that expected an empty `read_channel` on an unknown board.
- [ ] **Step 2:** Run `cargo test -p stigmer-store-sqlite`. Expected: FAIL.
- [ ] **Step 3:** Implement. Board existence checks run first in each method (inside the same transaction as the work); the notifier creates an entry only for boards that exist and drops a board's entry on archive.
- [ ] **Step 4:** Run `cargo test --workspace --locked`. Expected: PASS (the API still hard-codes `main` until Task 4).
- [ ] **Step 5:** Commit `feat(store): dynamic boards with archive and unknown-board contract`.

---

### Task 3: IdentityStore (stigmer-store trait, SQLite, conformance)

**Files:**
- Create: `crates/stigmer-store/src/identity.rs`, `crates/stigmer-store-sqlite/src/identity.rs`, `crates/stigmer-store-conformance/src/identity.rs`
- Modify: `schema.rs` (migrations 6 and 7), `lib.rs` files, conformance `run_all` (identity scenarios run through a second entry point `run_identity_all`).

**Interfaces:**
- Consumes: Tasks 1, 2.
- Produces:
```rust
pub enum Mode { Local, Network }
pub enum CredentialScope { Instance, Board(BoardId) }
pub struct Member { pub board: BoardId, pub name: Principal, pub kind: PrincipalKind, pub role: Role, pub created_at_ms: i64 }
pub struct NewCredential { pub id: TokenId, pub secret_hash: [u8; 32], pub scope: CredentialScope, pub principal: Principal, pub expires_at_ms: i64 }
pub struct Credential { pub id: TokenId, pub secret_hash: [u8; 32], pub scope: CredentialScope, pub principal: Principal, pub expires_at_ms: i64, pub revoked_at_ms: Option<i64>, pub last_seen_ms: Option<i64> }
pub struct NewInvite { pub id: TokenId, pub secret_hash: [u8; 32], pub board: BoardId, pub role: Role, pub kind: PrincipalKind, pub created_by: Principal, pub expires_at_ms: i64 }
pub struct Consumed { pub board: BoardId, pub role: Role, pub kind: PrincipalKind, pub member: Member }
pub enum SecurityEventKind { Join, TokenRevoked, MemberRemoved, BoardCreated, BoardArchived, AuthFailed, RateLimited, ModeEnabled }
pub struct SecurityEvent { pub at_ms: i64, pub kind: SecurityEventKind, pub board: Option<BoardId>, pub principal: Option<String>, pub detail: String } // detail never holds secrets
pub trait IdentityStore: Send + Sync + 'static {
  fn mode(&self) -> impl Future<Output=Result<Mode, StoreError>> + Send;
  fn enable_network_mode(&self) -> ...Result<(), StoreError>;                       // one-way; second call is Conflict(ConflictKind::AlreadyNetwork)
  fn add_member(&self, board: &BoardId, name: &Principal, kind: PrincipalKind, role: Role) -> ...Result<Member, StoreError>;  // Conflict(NameTaken)
  fn list_members(&self, board: &BoardId) -> ...Result<Vec<Member>, StoreError>;
  fn remove_member(&self, board: &BoardId, name: &Principal) -> ...Result<(), StoreError>;   // also revokes that member's credentials; NotFound{Member}
  fn create_credential(&self, c: NewCredential) -> ...Result<(), StoreError>;
  fn find_credential(&self, id: &TokenId) -> ...Result<Option<Credential>, StoreError>;
  fn touch_credential(&self, id: &TokenId, now_ms: i64) -> ...Result<(), StoreError>;
  fn list_credentials(&self, board: &BoardId) -> ...Result<Vec<Credential>, StoreError>;
  fn revoke_credential(&self, id: &TokenId, now_ms: i64) -> ...Result<(), StoreError>;       // NotFound{Credential}; idempotent
  fn revoke_board_credentials(&self, board: &BoardId, keep_admins: bool, now_ms: i64) -> ...Result<u64, StoreError>;
  fn create_invite(&self, i: NewInvite) -> ...Result<(), StoreError>;
  fn consume_invite(&self, id: &TokenId, secret_hash: &[u8; 32], name: &Principal, now_ms: i64) -> ...Result<Consumed, StoreError>;
  fn log_security(&self, e: SecurityEvent) -> ...Result<(), StoreError>;
  fn security_log(&self, limit: u32) -> ...Result<Vec<SecurityEvent>, StoreError>;           // newest first
}
```
Entity gains `Member`, `Credential`, `Invite`; ConflictKind gains `NameTaken`, `AlreadyNetwork`. `consume_invite` returns a single generic `NotFound{Invite}` for unknown, wrong-hash, expired and used invites (callers map all to the identical 401). Migration 6: tables `instance` (single row: mode), `principals` (board_id, name, kind, role, created_at_ms; PK board_id+name), `credentials`, `invites` (`used_at_ms`), `security_log`. Migration 7: index `credentials(board_id)`.

- [ ] **Step 1: Write failing conformance scenarios (`run_identity_all`):** `fresh_store_is_local_mode`; `enable_network_mode_is_one_way`; `add_member_then_list_and_name_taken_conflict`; `member_names_are_unique_per_board_not_globally`; `credential_roundtrip_and_find_unknown_is_none`; `revoke_credential_is_idempotent`; `remove_member_revokes_their_credentials`; `archive_style_revoke_keeps_admins_when_asked` (3 members, admin kept); `invite_consumes_once`; `invite_expired_is_not_found`; `invite_wrong_hash_is_not_found_and_not_consumed`; `invite_with_taken_name_conflicts_and_stays_unconsumed`; `concurrent_consumes_of_one_invite_create_exactly_one_member` (20 tasks); `security_log_newest_first_and_limited`; `no_secret_material_in_security_log_rows` (insert, then scan the table text for the hash bytes hex). SQLite-only: `secret_hashes_not_stored_in_plain_text` (the table holds 32-byte blobs and no token text) and a v5-to-v7 upgrade test modelled on the existing upgrade tests.
- [ ] **Step 2:** Run `cargo test -p stigmer-store-sqlite`. Expected: FAIL.
- [ ] **Step 3:** Implement on the existing single connection; `consume_invite` does lookup, hash comparison (constant time), expiry check, name check, member insert and used-mark in ONE `BEGIN IMMEDIATE` transaction.
- [ ] **Step 4:** Run `cargo test --workspace --locked`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(store): identity store with invites, credentials and security log`.

---

### Task 4: Authentication, async authorization and limits (stigmer-api)

**Files:**
- Create: `crates/stigmer-api/src/auth.rs`, `ratelimit.rs`, `limits.rs`
- Modify: `authz.rs`, `routes.rs`, `wait.rs`, `error.rs`, `lib.rs`, `host_guard.rs` (configurable hosts); tests `crates/stigmer-api/tests/api.rs` and a new `tests/auth.rs`.

**Interfaces:**
- Consumes: Tasks 1 to 3.
- Produces:
```rust
pub struct Authenticated { pub principal: Principal, pub kind: PrincipalKind, pub scope: CredentialScope, pub role: Option<Role>, pub credential: Option<TokenId> }
pub enum Scope<'a> { Instance, Board { board: &'a BoardId, channel: Option<&'a ChannelPath> } }   // M1 callers always pass channel None
pub enum Action { Read, Post, ManageMembers, ManageBoards }
pub trait Authorize: Clone + Send + Sync + 'static {
    fn check(&self, who: &Authenticated, action: Action, scope: &Scope<'_>) -> impl Future<Output = Result<(), Denied>> + Send;
}
pub struct AllowAll;        // local mode: every check passes
pub struct RoleAuthorize;   // network mode: admin = Read, Post, ManageMembers; member and bridge = Read, Post; instance credential = ManageBoards, ManageMembers only
pub struct Limits { pub max_waits: usize, pub auth_failures_per_minute: u32, pub join_per_minute: u32 }   // defaults 256, 10, 10
pub struct ApiConfig { pub mode: Mode, pub allowed_hosts: Vec<String>, pub trusted_proxies: Vec<IpNet>, pub limits: Limits }
pub fn router<S: Store + IdentityStore, A: Authorize>(store: Arc<S>, authz: A, shutdown: watch::Receiver<bool>, config: ApiConfig) -> Router
```
Behaviour: in local mode the principal comes from `X-Stigmer-As` (reads default to `anonymous`) and the board-membership rule is skipped; in network mode `Authorization: Bearer <token>` is verified (parse, lookup, expiry, revoked, constant-time hash compare, `touch_credential`) and the author of writes is the credential's principal (`X-Stigmer-As` ignored). A credential used against another board, or any unknown board, yields 404; the instance credential on content routes yields 403; every other failure to authenticate yields the identical 401 body (`ErrorCode::Unauthorized`, message "invalid or expired credentials"). `require_main_board` is removed: existence comes from the store. Rate limiting (token bucket, keyed by source address, plus token id once parsed) runs before credential verification; the limited response is 429 with `Retry-After`. The source address is the peer address unless the peer is in `trusted_proxies`, in which case the first untrusted `X-Forwarded-For` hop is used. Waits beyond `max_waits` get 429 `rate_limited`. `allowed_hosts` extends the loopback Host/Origin allow-list.

- [ ] **Step 1: Write failing tests (tests/auth.rs unless noted):** `local_mode_behaves_as_m0` (existing api tests still pass unchanged, via a local-mode `ApiConfig`); `network_mode_requires_a_token_on_every_route_except_health_and_join` (loop over routes); `missing_malformed_unknown_expired_revoked_tokens_return_identical_401_bodies` (byte-equal bodies and equal headers); `valid_token_for_another_board_gets_404_on_every_board_route`; `unknown_board_is_404_not_a_405_or_empty_list`; `member_cannot_manage_and_gets_403`; `admin_can_read_and_post_but_instance_credential_gets_403_on_content`; `author_comes_from_the_credential_not_the_header`; `authz_check_is_async_and_denied_maps_to_403` (test-only deny authorizer, thread route and reply path included); `failed_auth_is_rate_limited_per_source_with_429_and_retry_after`; `forged_x_forwarded_for_from_untrusted_peer_is_ignored`; `x_forwarded_for_honoured_only_from_trusted_proxy`; `waits_beyond_the_cap_get_429`; `allowed_host_extends_the_host_guard_and_rebinding_still_blocked`; `touch_updates_last_seen`; `no_secret_in_any_error_body` (send a real token with a corrupted tail, grep the response).
- [ ] **Step 2:** Run `cargo test -p stigmer-api`. Expected: FAIL.
- [ ] **Step 3:** Implement the extractor as an axum middleware that produces `Authenticated` into request extensions; routes call `authz.check(...).await`; map failures per the policy; update `ADR 0004` text only in Task 10.
- [ ] **Step 4:** Run `cargo test --workspace --locked`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(api): token authentication, async authorization and request limits`.

---

### Task 5: Board, member, invite, token and join routes (stigmer-api)

**Files:**
- Create: `crates/stigmer-api/src/admin_routes.rs`
- Modify: `routes.rs` (mount), `lib.rs`; tests `crates/stigmer-api/tests/admin.rs`.

**Interfaces:**
- Consumes: Tasks 1 to 4.
- Produces routes (all JSON, wire types from Task 1): `POST /v1/boards` (instance admin; body CreateBoardRequest; 201 BoardInfo; duplicate 409), `GET /v1/boards` (instance: all; member or board admin: only own board), `GET /v1/boards/{b}`, `POST /v1/boards/{b}/archive` (instance admin or that board's admin; revokes member, agent and bridge tokens, keeps admin tokens read-only), `GET /v1/boards/{b}/members`, `DELETE /v1/boards/{b}/members/{name}`, `POST /v1/boards/{b}/invites` (InviteRequest: kind, role, expires_in_minutes default 60 max 10080), `GET /v1/boards/{b}/tokens` (metadata only, never secrets or hashes), `DELETE /v1/boards/{b}/tokens/{id}`, `POST /v1/join` (unauthenticated; JoinRequest; returns JoinResponse once), `GET /v1/whoami`. Every mutation writes a security-log event. Archived boards: posts 409 `board_archived`, admin tokens read-only.

- [ ] **Step 1: Write failing tests:** `instance_admin_creates_and_lists_boards`; `board_admin_gets_403_creating_boards_and_sees_only_own_board_in_list`; `create_duplicate_board_is_409`; `invalid_board_name_is_400`; `invite_join_roundtrip_returns_token_once_and_whoami_matches`; `join_with_taken_name_is_409_and_invite_still_usable`; `join_with_bad_expired_or_used_invite_returns_the_identical_401`; `concurrent_joins_with_one_invite_succeed_exactly_once`; `member_lists_are_visible_to_board_admin_and_instance_admin_only`; `tokens_list_never_contains_secrets_or_hashes`; `revoked_token_is_refused_on_the_next_request` (and `remove_member_revokes_tokens`); `archive_revokes_non_admin_tokens_keeps_admin_read_only_and_posts_409`; `archive_allowed_for_instance_admin_and_board_admin_only`; `invite_expiry_default_60_minutes_max_7_days` (over the max is 400); `every_mutation_writes_a_security_log_row_without_secrets`; `join_is_rate_limited`.
- [ ] **Step 2:** Run `cargo test -p stigmer-api --test admin`. Expected: FAIL.
- [ ] **Step 3:** Implement handlers as thin wrappers over the stores; generate secrets with Task 1 functions; return the invite or token string exactly once.
- [ ] **Step 4:** Run `cargo test --workspace --locked`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(api): board, member, invite, token and join routes`.

---

### Task 6: Server modes, admin commands, lock file and permissions (stigmerd)

**Files:**
- Create: `crates/stigmerd/src/admin.rs`, `crates/stigmerd/src/lock.rs`
- Modify: `crates/stigmerd/src/main.rs`; tests `crates/stigmerd/tests/admin.rs` and `serve.rs`.

**Interfaces:**
- Consumes: Tasks 2 to 5.
- Produces CLI: `stigmerd admin enable-auth [--no-main-invite]` (creates the instance-admin token, prints it ONCE to stdout together with, unless skipped, a single-use 24 hour admin invite into `main`; switches the data dir to network mode); `stigmerd admin map-local-principals [--human NAME ...] --admin NAME [--admin NAME ...] [--apply]` (dry-run by default: lists distinct M0 authors that would become principals of `main` (kind agent unless listed as human; role admin for `--admin` names, member otherwise); `--apply` writes principals and sets `messages.author_kind` to `principal`; requires at least one `--admin`; refuses unless network mode is enabled); `stigmerd admin security-log [--limit N]`. `serve` gains `--tls-cert`, `--tls-key`, `--trusted-proxy`, `--allowed-host` (wired in Task 7) and the non-loopback rule from the Global Constraints. `stigmer.lock`: exclusive lock held for the process lifetime; a second `serve` on the same data dir exits 1 with a clear message. The database file and its WAL/SHM are created mode 0600 and the data dir 0700 (unix).

- [ ] **Step 1: Write failing tests:** `enable_auth_prints_instance_token_once_and_a_main_admin_invite`; `enable_auth_twice_refuses_and_prints_no_token`; `enable_auth_no_main_invite_omits_the_invite`; `serve_refuses_non_loopback_bind_in_local_mode` (exit 2, message names the address); `serve_refuses_non_loopback_in_network_mode_without_tls_or_trusted_proxy`; `second_serve_on_same_data_dir_fails_with_lock_message`; `database_files_are_0600_and_dir_0700` (unix); `map_local_principals_dry_run_changes_nothing`; `map_local_principals_requires_an_admin`; `map_local_principals_apply_keeps_verify_chain_valid_and_content_readable` (post M0-style data first, then map, then verify through the store); `map_local_principals_refused_in_local_mode`; `security_log_lists_mode_enabled_event`; `instance_token_is_not_logged_to_stderr_or_the_security_log`.
- [ ] **Step 2:** Run `cargo test -p stigmerd`. Expected: FAIL.
- [ ] **Step 3:** Implement with `fs2`-style advisory locking via std (`File::lock`) or an equivalent small dependency approved by cargo-deny; subcommands call the stores directly (no HTTP).
- [ ] **Step 4:** Run `cargo test --workspace --locked`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(server): enable-auth, principal mapping, lock file and private data dir`.

---

### Task 7: TLS, trusted proxy and connection limits (stigmerd)

**Files:**
- Create: `crates/stigmerd/src/tls.rs`, `crates/stigmerd/src/serve.rs`
- Modify: `main.rs`; tests `crates/stigmerd/tests/tls.rs` (test CA generated at test time with `rcgen` as a dev-dependency).

**Interfaces:**
- Consumes: Tasks 4 and 6.
- Produces: `serve` accepts connections itself (hyper-util accept loop) so it can enforce: max concurrent connections (`--max-connections`, default 1024; excess connections are closed immediately), header read timeout (10 s), TLS 1.3 via rustls when `--tls-cert` and `--tls-key` are given, `Strict-Transport-Security: max-age=31536000` on TLS responses, certificate reload when either file's modification time changes (checked every 5 s; a pair that fails to parse keeps the old one and logs a warning), `--trusted-proxy <cidr,...>` (plain HTTP accepted only from those ranges when TLS is off; peers outside are dropped), `--allowed-host` passed into `ApiConfig`. Graceful shutdown semantics from M0 are preserved (waits end with timed_out, drain cap 5 s).

- [ ] **Step 1: Write failing tests:** `tls_serves_https_and_rejects_tls12_clients`; `plain_http_to_a_tls_port_is_refused`; `cert_reload_serves_the_new_certificate_without_dropping_a_pending_wait` (swap files, new connections see the new cert fingerprint, the open wait still completes); `unparseable_replacement_pair_keeps_serving_the_old_certificate`; `partial_write_of_cert_then_key_never_serves_a_mismatched_pair`; `hsts_header_present_on_tls_only`; `max_connections_closes_the_excess_connection`; `slow_header_connection_is_closed_after_the_timeout` (use a short test override); `trusted_proxy_accepts_plain_http_only_from_listed_ranges`; `allowed_host_flag_permits_that_host_and_rebinding_still_blocked`; `m0_serve_tests_still_pass_in_local_mode`.
- [ ] **Step 2:** Run `cargo test -p stigmerd --test tls`. Expected: FAIL.
- [ ] **Step 3:** Implement with `rustls` (ring or aws-lc as cargo-deny allows) and `tokio-rustls`; build the server config behind an `ArcSwap`-style cell so reloads do not touch live connections.
- [ ] **Step 4:** Run `cargo test --workspace --locked` and `cargo deny --locked check`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(server): built-in tls, trusted proxy mode and connection limits`.

---

### Task 8: CLI identity, boards and management (stigmer-cli)

**Files:**
- Create: `crates/stigmer-cli/src/logins.rs`, `crates/stigmer-cli/src/manage.rs`
- Modify: `main.rs`, `client.rs`, `commands.rs`, `render.rs`, `wait.rs`, `exit.rs`; tests `crates/stigmer-cli/tests/identity.rs` and `cli.rs`.

**Interfaces:**
- Consumes: Tasks 1, 5, 7.
- Produces CLI: global `--board` / `STIGMER_BOARD` (default `main`), `--ca-cert <file>` / `STIGMER_CA_CERT`; `stigmer join <invite> --url <url> --as <name>` (POST /v1/join; stores the token in `~/.config/stigmer/logins.json` honouring `XDG_CONFIG_HOME`, file mode 0600, keyed by server URL and board; never prints the token); token resolution order `STIGMER_TOKEN` then the login file entry for url+board; `whoami`; `boards list|create <name>|archive <name>`; `members list|remove <name>`; `invite create --kind --role [--expires 60m]` (prints the invite once); `token list|revoke <id>`. Token-bearing requests send `Authorization: Bearer` (never in the URL), and the CLI refuses to send a token over plain http to a non-loopback host unless `--insecure` is given. The v0.1.0 local workflow (no token, `--as`) is unchanged. Carried M0 minors: `tail` retries transient network errors with exponential backoff (1 s to 30 s) and says so on stderr; `wait --json` timeout output includes a top-level `cursor` field; `read` previews are framed or marked untrusted (JSON `untrusted: true` already; text output frames the preview); `render_message` escapes Unicode bidi override and isolate characters (U+202A to U+202E, U+2066 to U+2069) and zero-width format characters other than the neutralising ZWSP it adds, as visible `\u{..}`.

- [ ] **Step 1: Write failing tests:** `join_stores_a_0600_login_and_never_prints_the_token`; `logins_are_keyed_by_server_and_board`; `token_env_overrides_the_login_file`; `whoami_prints_principal_board_and_role`; `boards_create_list_archive_roundtrip_as_instance_admin`; `invite_create_prints_once_and_join_consumes_it`; `member_remove_and_token_revoke_take_effect`; `token_over_plain_http_to_a_remote_host_is_refused_without_insecure`; `unauthorized_maps_to_exit_1_with_next_hint_login`; `forbidden_and_not_found_have_distinct_exit_codes_and_hints` (documented in --help); `rate_limited_prints_retry_after_hint`; `ca_cert_flag_trusts_a_private_ca` (tests/identity.rs with an in-process TLS server); `tail_retries_after_a_server_restart`; `wait_json_timeout_has_a_cursor_field`; `read_text_output_frames_previews`; `render_escapes_bidi_and_format_characters` (U+202E, U+2066, U+200E, U+FEFF); `m0_cli_tests_pass_unchanged`.
- [ ] **Step 2:** Run `cargo test -p stigmer-cli`. Expected: FAIL.
- [ ] **Step 3:** Implement; keep each file under about 400 lines (split management commands into `manage.rs`); build login-file writes with create-new then rename and mode 0600 before any secret is written.
- [ ] **Step 4:** Run `cargo test --workspace --locked`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(cli): join, board and member management, tls trust and logins`.

---

### Task 9: TypeScript SDK alpha (sdk/typescript)

**Files:**
- Create: `sdk/typescript/package.json` (name `stigmer`, `"private": true`, type module, engines node >=20), `tsconfig.json` (strict), `src/{index,client,errors,types,wait}.ts`, `test/{client,wait}.test.ts`, `examples/two-agents.mjs`, `README.md`
- Modify: `.github/workflows/ci.yml` (job `sdk`: setup Node 20, build `stigmerd`, run `npm ci`, `npm run typecheck`, `npm test`; actions pinned by SHA).

**Interfaces:**
- Consumes: Task 5 routes and Task 1 wire shapes.
- Produces: zero runtime dependencies.
```ts
export interface StigmerOptions { url: string; token?: string | (() => string | Promise<string>); board?: string; as?: string; fetch?: typeof fetch }
export class Stigmer {
  constructor(options: StigmerOptions);
  post(channel: string, text: string, opts?: { labels?: Record<string,string>; key?: string }): Promise<Posted>;
  reply(thread: string, text: string, opts?: { labels?: Record<string,string>; key?: string }): Promise<Posted>;
  readChannel(prefix: string, opts?: { limit?: number; before?: string }): Promise<ThreadSummary[]>;
  readThread(id: string): Promise<Thread>;
  events(opts?: { after?: string; fromNow?: boolean; channel?: string; thread?: string; label?: string; timeoutS?: number; limit?: number }): Promise<EventsResponse>;
  wait(opts?: { after?: string; fromNow?: boolean; channel?: string; thread?: string; label?: string; timeoutMs?: number; signal?: AbortSignal }): Promise<{ events: Event[]; cursor: string | null; timedOut: boolean }>;
  whoami(): Promise<WhoAmI>;
}
export class StigmerError extends Error { code: string; status: number }   // code is the server's error code string, unknown codes preserved
```
`wait` chunks at 300 s exactly like the CLI: only the first chunk may send `from_now`; later chunks send `after` with the previous cursor; if the first cursor is null later chunks send neither. Messages are returned as data (never executed); the README states the untrusted-data rule.

- [ ] **Step 1: Write failing tests (node:test against a real stigmerd started on an ephemeral port in local mode, and a second suite in network mode with a join flow):** `post_then_read_thread_roundtrip`; `reply_in_thread`; `idempotency_key_replays`; `events_filters_by_channel_thread_label`; `wait_returns_when_another_client_posts`; `wait_from_now_skips_history`; `wait_chunk_loop_carries_cursor_and_never_resends_from_now` (unit test with an injected fetch that simulates chunks); `wait_timeout_returns_timedOut_true`; `abort_signal_cancels_a_wait`; `errors_carry_server_codes_and_unknown_codes_are_preserved`; `bearer_token_sent_in_header_never_in_url` (injected fetch inspects); `token_provider_function_is_called_per_request`; `network_mode_join_and_two_agents_exchange` (the exit-test flow through the SDK); `no_runtime_dependencies` (package.json assertion).
- [ ] **Step 2:** Run `cd sdk/typescript && npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement with `fetch` only (injectable) and no libraries; types hand-written.
- [ ] **Step 4:** Run `npm run typecheck && npm test`. Expected: PASS; CI job green.
- [ ] **Step 5:** Commit `feat(sdk): typescript alpha with post, read and wait`.

---

### Task 10: End-to-end exit tests, ADRs and docs

**Files:**
- Create: `crates/stigmer-cli/tests/e2e_m1.rs`, `docs/adr/0008-board-isolation-and-credentials.md`, `0009-token-and-invite-format.md`, `0010-tls-and-trusted-proxy.md`, `0011-authentication-policy-401-403-404.md`
- Modify: `README.md` (network quickstart), `docs/design.md` (section 14: M1 as built and known gaps), `docs/adr/README.md` (index), `docs/adr/0004-authorization-seam.md` and `0007-local-principals.md` (status and consequences updated), `CONTRIBUTING.md` only if scopes change.

**Interfaces:**
- Consumes: everything. Test helper builds the binaries once (as in e2e_m0), generates a test CA and leaf cert with `rcgen`, starts `stigmerd serve --bind 127.0.0.1:0 --tls-cert ... --tls-key ...` in network mode (via `admin enable-auth`).

- [ ] **Step 1: Write the failing e2e tests:** `two_processes_exchange_over_tls_and_a_revoked_token_is_refused` (instance admin creates board and invite; two CLI processes with separate `XDG_CONFIG_HOME` join as agent-a and agent-c; A posts, C waits and replies, A reads both; revoke C's token; C's next request exits 1 with the unauthorized hint); `a_token_for_one_board_gets_404_for_every_other_boards_routes`; `m0_exit_test_still_passes_in_local_mode` (the existing e2e_m0 file, unchanged, still part of the suite); `enable_auth_and_map_local_principals_on_m0_data_keeps_the_chain_valid` (stigmerd stopped, M0-style data created through local mode, then admin commands, restart in network mode, verify via the API/CLI that content reads and the chain verifies); `no_token_or_invite_secret_appears_in_server_stdout_stderr_or_the_login_file_permissions_are_0600` (grep captured output and inspect file mode); `sdk_example_reproduces_the_exit_exchange` (runs `node sdk/typescript/examples/two-agents.mjs` against the TLS server using the test CA via NODE_EXTRA_CA_CERTS; skipped with a clear message when node is absent locally but required in CI).
- [ ] **Step 2:** Run `cargo test -p stigmer-cli --test e2e_m1`. Expected: FAIL until tasks 1 to 9 are in.
- [ ] **Step 3:** Write the four ADRs (each 30 to 60 lines: context, decision, consequences, what a later milestone must change; verify every claim against the code), update the index and the two touched ADRs, add the network quickstart to the README (measured commands, honest about prerequisites), and add design section 14 listing M1 as built, deviations from the plan, and known gaps carried into M2 and later.
- [ ] **Step 4:** Run `cargo fmt --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked && cargo deny --locked check` and the SDK checks. Expected: all pass.
- [ ] **Step 5:** Commit `test(e2e): m1 exit tests`; `docs(adr): record m1 decisions`; `docs: m1 as built and network quickstart`. Tag `v0.2.0` only after the user approves.

---

## Self-review notes

- Spec coverage: modes and bootstrap (6.1, 11.3: Tasks 4, 6); principals, tokens, invites (6.2, 6.3: Tasks 1, 3, 5); authorization and the 401/403/404 policy (6.4, 11.2: Task 4); boards and unknown-board contract (6.5, 11.1: Task 2); identity store (6.5: Task 3); routes (6.6: Task 5); limits (6.6: Tasks 4, 7); TLS and proxy (6.7: Task 7); CLI and admin commands (6.8: Tasks 6, 8); hardening (6.9: Tasks 2, 6, 8); SDK (6.10: Task 9); exit tests (section 7: Task 10); wire-enum fallbacks (Task 1); rate-limit response (11.6: Tasks 4, 5).
- Names are consistent across tasks: `Authenticated`, `Scope`, `Action`, `CredentialScope`, `NewCredential`, `NewInvite`, `Consumed`, `Mode`, `TokenId`, `SecretKind`.
- Deliberate ordering: boards (2) before identity (3) because members and credentials reference boards; the API tasks (4, 5) before server wiring (6, 7); CLI (8) and SDK (9) after the server can authenticate.
- Known soft spots a reviewer should press: the exact file-lock mechanism (std versus a small crate), the TLS reload cell, and test-time CA generation.
