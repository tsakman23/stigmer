# M2 Postgres Backend and Multi-Replica Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let several Stigmer servers share one Postgres database (SQLite stays the default), with audit rows written in their mutation's transaction, cross-replica wake-ups, and the two scaling fixes M1's reviews found.

**Architecture:** Audited mutations gain an audit-event parameter so every backend writes the row in the mutation's transaction. A maintained `threads` table replaces the correlated subqueries behind `read_channel`. The conformance suites become generic over a fixture that can hand out two handles on one database. A new `stigmer-store-postgres` crate (tokio-postgres plus deadpool-postgres) implements both store traits and passes those suites unchanged; LISTEN/NOTIFY connects replicas' waiters; `stigmerd` selects the backend at startup.

**Tech Stack:** Rust (pinned toolchain), rusqlite, tokio-postgres, deadpool-postgres, rustls (ring provider only), axum, existing stigmer crates.

**Spec:** `docs/superpowers/specs/2026-11-23-m2-postgres-backend-design.md` (sections 6 and 11 govern; `docs/design.md` and `docs/adr/` for the base). One PR per task, each merged before the next starts. The design and this plan ride in Task 1's PR.

## Global Constraints

- Rust; `unsafe_code = "forbid"`; cargo-deny clean; Apache-2.0; conventional commits per CONTRIBUTING.md; every commit ends with the trailer line given in the session's attribution instruction.
- The v0.1.0 hash-chain format is frozen: the event hash input string and the pinned digest test stay unchanged; `HASH_VERSION` 1.
- ADRs frozen at v0.2.0 are NOT edited: only an ADR's status line may gain "Partly superseded by NNNN"; every change of decision is a NEW ADR (0012 backend selection and Postgres, 0013 cross-replica wake-ups, 0014 audit rows in the mutation transaction, 0015 thread summaries and sequence ordering).
- SQLite stays the default and keeps working with zero configuration, its lock file and automatic migration at open.
- Postgres connection strings with passwords never appear on command lines, in logs, in errors or in Debug output; TLS to Postgres uses rustls (ring provider only; no aws-lc, no OpenSSL).
- Conformance suites are the definition of correct: no scenario is weakened or skipped for any backend; Postgres tests read `STIGMER_TEST_DATABASE_URL` and skip loudly when it and `CI` are unset, and FAIL when `CI` is set and the URL is missing; each Postgres test uses its own schema.
- Every store method that stamps a time takes it from the caller (`now_ms`, or the audit event for an audited mutation); event order is the per-board sequence, never a wall clock.
- Audited mutations take their instant from the audit event (`audit.at_ms`), not from a separate `now_ms`.
- A wait never holds a database connection or transaction while it sleeps.
- No change to the HTTP API, wire types, CLI or SDK behaviour except where a task says so.

## Review Focus

1. A failed audit write rolls the mutation back and the client sees 500; retrying the request is safe (nothing happened). (Task 1)
2. Thread summaries never drift from messages: after any random sequence of posts, replies, concurrent writers and a backfill, the table equals what the messages say. (Task 2)
3. A rolled-back post consumes no sequence number and two writers on one board never produce a gap or a duplicate, on both backends and across two handles. (Tasks 3, 4)
4. A wake-up is never lost between "subscribe", "read head" and "sleep", including across a listener reconnect. (Task 6)
5. A database password never leaks through argv, logs, errors, Debug output or the process environment printed by tooling. (Task 7)

---

## File Structure

```
crates/stigmer-store/src/{lib.rs,identity.rs}                  (audit parameters, combined archive method)
crates/stigmer-store-sqlite/src/{boards,members,credentials,identity,reads,posts,schema,notify,lib}.rs
crates/stigmer-store-conformance/src/{lib,fixture,cross_instance,support,...}.rs
crates/stigmer-store-postgres/                                 (new crate)
  src/{lib,pool,schema,migrate,boards,posts,reads,events,wait,identity_*,notify,error}.rs
  migrations/0001_init.sql ... 0008_threads.sql
crates/stigmer-api/src/{admin_routes,routes,audit,wait}.rs
crates/stigmerd/src/{main,serve,backend,admin/*}.rs
crates/stigmer-cli/tests/e2e_m2.rs
.github/workflows/ci.yml (postgres job), docs/adr/0012-0015, README.md, docs/design.md (section 15)
```

---

### Task 1: Audit rows in the mutation transaction

**Files:**
- Modify: `crates/stigmer-store/src/{lib.rs,identity.rs}`, `crates/stigmer-store-sqlite/src/{boards,members,credentials,identity,lib}.rs`, conformance modules touching these methods, `crates/stigmer-api/src/{admin_routes,routes,audit,join_routes}.rs`, `crates/stigmerd/src/admin/{mod,tokens,principals}.rs`
- Create: `docs/adr/0014-audit-rows-in-the-mutation-transaction.md` (and the status-line note on ADR 0008 and the index row)
- Test: conformance scenarios, `crates/stigmer-store-sqlite/tests/audit_rollback.rs`, `crates/stigmer-api/tests/admin_audit.rs` (rewritten), stigmerd admin tests.

**Interfaces:**
- Produces (every audited mutation takes the event and the store writes the row in the same transaction; an audited method has no separate `now_ms`: its instant is `audit.at_ms`, for the row and for every time it stamps):
```rust
// Store
fn create_board(&self, id: &BoardId, created_by: Option<&Principal>, audit: SecurityEvent) -> ...Result<BoardInfo, StoreError>;
fn archive_board(&self, id: &BoardId, audit: SecurityEvent) -> ...Result<BoardInfo, StoreError>;   // idempotent: an already-archived board writes NO row
// IdentityStore
fn enable_network_mode(&self, audit: SecurityEvent) -> ...Result<(), StoreError>;
/// NEW: ONE transaction: instance credential, optional main invite (bundled with its own row), switch to network mode, rows mode, token, invite. AlreadyNetwork writes nothing.
fn enable_network(&self, credential: NewCredential, invite: Option<(NewInvite, SecurityEvent)>, audits: EnableAudits) -> ...Result<(), StoreError>;
pub struct EnableAudits { pub mode: SecurityEvent, pub token: SecurityEvent }   // EnableAudits::rows(invite_audit) lists the rows in order
fn remove_member(&self, board: &BoardId, name: &Principal, audit: SecurityEvent) -> ...;
fn create_credential(&self, credential: NewCredential, audit: SecurityEvent) -> ...;
fn revoke_credential(&self, id: &TokenId, audit: SecurityEvent) -> ...;   // an already-revoked credential writes NO row
fn replace_instance_credential(&self, credential: NewCredential, audit: SecurityEvent) -> ...Result<u64, StoreError>;   // revoking N > 0 others also writes a TokenRevoked count row
fn create_invite(&self, invite: NewInvite, audit: SecurityEvent) -> ...;
/// NEW: ONE transaction: archive the board, revoke every live credential of the board except admins', write the audit row. Replaces the API's archive-then-revoke two steps. Returns the board as archived.
fn archive_board_revoking(&self, id: &BoardId, audit: SecurityEvent) -> ...Result<BoardInfo, StoreError>;
// unchanged: adopt_local_authors and consume_invite (already audit inside), log_security (only for non-mutation events: auth failure, rate limits)
```
Rules: an audited method that changes nothing (idempotent no-op) writes no audit row; a method that fails writes no row and changes nothing; a failing audit INSERT aborts the whole transaction. `SecurityEvent` details keep coming only from the typed constructors in stigmer-api and stigmerd.

- [ ] **Step 1: Write failing tests:** conformance (both traits, via the existing suites): `create_board_writes_exactly_one_board_created_row`; `duplicate_create_board_writes_no_row`; `archive_board_writes_one_row_and_a_second_archive_writes_none`; `archive_board_revoking_archives_revokes_non_admin_credentials_and_keeps_admins_in_one_transaction` (plus: main is protected: refused with BoardProtected, nothing revoked, no row); `revoke_credential_writes_one_row_and_a_repeat_writes_none`; `remove_member_revokes_credentials_and_writes_one_row`; `create_invite_and_create_credential_and_replace_instance_credential_each_write_one_row`; `enable_network_mode_writes_one_row_and_a_second_call_none`; `failed_mutations_write_no_rows` (unknown board, archived board, taken name). SQLite-only `audit_rollback.rs`: install a trigger on `security_log` that RAISEs ABORT, then each audited mutation returns a backend error AND leaves its state unchanged (board not created, board not archived and credentials not revoked, credential not created/revoked, member not removed, invite not created, mode still local). API tests (`admin_audit.rs` rewritten): `audit_failure_fails_the_request_with_500_and_changes_nothing` for create board, archive, invite, token revoke, member remove (wrapper store that fails the mutation, asserting no state change and the generic 500 body), `retry_after_an_audit_failure_succeeds`, `rate_limited_and_auth_failed_events_stay_best_effort` (log_security failure still gives the identical 401/429 and one warning). stigmerd: each admin command's audit row exists after success (security-log) and none after a refused command.
- [ ] **Step 2:** Run `cargo test --workspace --locked`. Expected: FAIL (signatures missing).
- [ ] **Step 3:** Implement the signature changes in both traits, SQLite (each method writes through one shared internal `log_in_tx`), update every call site (API handlers build the event with the existing `Audit` constructors and pass it in; delete `audit_best_effort` for the admin routes only; stigmerd admin commands pass their events). The API archive handler calls `archive_board_revoking` once.
- [ ] **Step 4:** Run fmt, clippy (`-D warnings`), `cargo test --workspace --locked`, `cargo deny --locked check`, SDK tests. Expected: all pass; the M0/M1 e2e tests unchanged and green.
- [ ] **Step 5:** Write ADR 0014 (context, decision, consequences incl. 500-on-audit-failure and why non-mutation events stay best-effort), add "Partly superseded by 0014" to ADR 0008's status line and the index, update design `14 where it describes best-effort audit. Commit in logical units (`refactor(store): audit events travel with the mutation`, `feat(store): archive and revoke in one transaction`, `refactor(api): audit through the store`, `refactor(server): admin commands pass their audit events`, `docs(adr): record audit rows in the mutation transaction`).

---

### Task 2: Thread summaries, read_channel and wait scan advance

**Files:**
- Modify: `crates/stigmer-store-sqlite/src/{schema,posts,reads}.rs`, `crates/stigmer-store/src/lib.rs` (docs), `crates/stigmer-api/src/wait.rs`, conformance `reads.rs`/`posts.rs`
- Create: `docs/adr/0015-thread-summaries-and-sequence-ordering.md`
- Test: conformance reads scenarios, SQLite migration/backfill tests, `crates/stigmer-api/tests/wait_scan.rs`.

**Interfaces:**
- Produces: SQLite migration 8: `threads(board_id TEXT NOT NULL REFERENCES boards(id), thread_id TEXT NOT NULL, channel TEXT NOT NULL, preview TEXT NOT NULL, reply_count INTEGER NOT NULL, first_seq INTEGER NOT NULL, last_seq INTEGER NOT NULL, last_at_ms INTEGER NOT NULL, PRIMARY KEY (board_id, thread_id))` plus an index on `(board_id, last_seq DESC, thread_id DESC)`; the migration backfills every existing thread from `messages` and `events`. The post transaction inserts (new thread) or updates (reply: `reply_count + 1`, `last_seq`, `last_at_ms`) in the same transaction as the event. `read_channel` orders by `last_seq DESC, thread_id DESC` with keyset pagination on that pair and whole-segment prefix matching as today (still no LIKE); `ThreadSummary` and the wire shape are unchanged (`last_at_ms` is the time of the last message).
- Wait loop (`stigmer-api/src/wait.rs`): after a pass that found nothing, the next scan starts at the head read in that pass (keeping "read head BEFORE the scan"); the returned cursor rules are unchanged. `WaitRequest` is unchanged.

- [ ] **Step 1: Write failing tests:** conformance `read_channel_orders_by_last_event_sequence_not_wall_clock` (posts with identical and decreasing at_ms still order by activity); `reply_moves_its_thread_to_the_top_and_updates_count_and_preview_stays_the_root`; `pagination_returns_every_thread_exactly_once_across_pages_with_tied_times` (200 threads, page 7); `concurrent_posts_keep_summaries_equal_to_messages` (20 tasks, then compare each summary with a count over read_thread); `summaries_are_consistent_after_random_operations` (seeded random mix of posts/replies/idempotent replays across 3 channels; compare with a reference model built from read_thread). SQLite: `v7_database_backfills_threads_and_matches_the_new_write_path` (build v7 data with the v7 schema SQL from MIGRATIONS, upgrade, compare every row with what posting the same messages through the new path produces) and `migration_8_is_appended_not_edited`. API: `a_wait_does_not_rescan_from_its_original_cursor` (counting store wrapper: after a non-matching wake the next events_after call's `after` equals the previous pass's head), `matching_event_after_non_matching_wakes_is_returned`, `resume_cursor_after_timeout_still_loses_nothing` (reuse the RacingStore invariant test).
- [ ] **Step 2:** Run the new tests. Expected: FAIL.
- [ ] **Step 3:** Implement migration 8 with backfill, the post-path writes, the `read_channel` rewrite (delete the correlated subqueries), the wait scan advance, trait docs (ordering is by last event sequence).
- [ ] **Step 4:** Run the full checks (as Task 1). Expected: PASS; conformance unchanged except the new scenarios.
- [ ] **Step 5:** Write ADR 0015 (supersedes the activity-ordering sentence of ADR 0001's contract by being the newer decision; status line note only on 0001). Commit `feat(store-sqlite): thread summary table with backfill`, `feat(store-sqlite): list channels from thread summaries`, `fix(api): advance the wait scan position`, `docs(adr): record thread summaries`.

---

### Task 3: Conformance hardening and the two-handle fixture

**Files:**
- Create: `crates/stigmer-store-conformance/src/{fixture,cross_instance}.rs`
- Modify: `crates/stigmer-store-conformance/src/{lib,support,posts,reads,boards,...}.rs`, `crates/stigmer-store-sqlite/src/lib.rs` (test-support constructor), `crates/stigmer-store-sqlite/tests/conformance.rs`

**Interfaces:**
- Produces:
```rust
pub trait Fixture {
    type Store: Store + IdentityStore;
    /// Informational: true when separate handles are separate PROCESS-level notifiers (Postgres).
    const CROSS_PROCESS_WAKE: bool;
    fn fresh(&self) -> impl Future<Output = Self::Store> + Send;
    /// Another handle on the SAME database as store.
    fn second_handle(&self, store: &Self::Store) -> impl Future<Output = Self::Store> + Send;
    /// wait_past callers currently subscribed to board's wake-up channel on store's handle.
    fn waiters(&self, store: &Self::Store, board: &BoardId) -> usize;
}
pub async fn run_all<X: Fixture>(fixture: &X);            // replaces run_all(factory) and run_identity_all(factory); runs store, identity and cross_instance suites
// SQLite: a #[doc(hidden)] pub fn SqliteStore::second_handle_for_tests(&self) -> impl Future<Output=Result<SqliteStore, StoreError>>: a new connection to the same file SHARING the in-process notifier; and a #[doc(hidden)] pub fn SqliteStore::waiters_for_tests(&self, board: &BoardId) -> usize (the notifier's receiver count, 0 without an entry)
```
- `cross_instance` scenarios (each takes the two handles): `wake_across_handles`, `wake_reaches_a_blocked_waiter_on_the_other_handle` (also takes the fixture: posts only once `fixture.waiters` shows the waiter subscribed and it is still pending), `credential_issued_on_one_handle_is_valid_on_the_other_and_revocable_from_either`, `concurrent_create_board_across_handles_has_one_winner_and_one_board_exists`, `invite_redeemed_once_across_handles`, `sequence_is_gapless_with_concurrent_posts_from_both_handles`. The runner prints one summary line including `CROSS_PROCESS_WAKE`.

- [ ] **Step 1: Write failing tests:** the five scenarios above plus (single handle) `concurrent_create_board_has_one_winner`; sleep removal: every scenario that called `tick()` or slept to get distinct timestamps must pass with a fixed clock (`ordering_never_depends_on_wall_clock_time` posts all messages at the same at_ms); `fixture_summary_line_reports_cross_process_wake` (captured output).
- [ ] **Step 2:** Run `cargo test -p stigmer-store-sqlite`. Expected: FAIL.
- [ ] **Step 3:** Implement the fixture trait and runner, the SQLite fixture (file-backed in a tempdir, second handle shares the notifier), the cross_instance module; delete `tick()` and remaining wall-clock sleeps (none may remain as synchronisation); migrate the SQLite conformance test file to `run_all(&SqliteFixture)`.
- [ ] **Step 4:** Full checks; run the conformance tests 30 times in a shell loop. Expected: all pass, 30/30.
- [ ] **Step 5:** Commit `refactor(store-conformance): fixture trait with a second handle`, `test(store-conformance): cross-instance scenarios`, `test(store-conformance): remove wall-clock sleeps`.

---

### Task 4: Postgres store, part 1 (Store trait)

**Files:**
- Create: the `crates/stigmer-store-postgres` crate (see File Structure) with `migrations/0001_init.sql` to `0008_threads.sql` mirroring SQLite migrations 1 to 8 in Postgres types (`bigint`, `bytea` with length CHECKs, `text` ids, partial unique index for idempotency keys)
- Modify: workspace `Cargo.toml`, `deny.toml` (licenses only if reported), `crates/stigmer-store-conformance` (a Postgres fixture lives in the postgres crate's tests)
- Test: `crates/stigmer-store-postgres/tests/conformance.rs` (the shared suites for the Store half), unit tests for error mapping and migrations.

**Interfaces:**
- Consumes: Tasks 1 to 3 (audit parameters, threads schema, `Fixture`).
- Produces:
```rust
pub struct PgOptions { pub max_connections: usize, pub tls: PgTls }          // PgTls::{Disable, Require, VerifyFull}
impl PgStore {
    pub async fn connect(url: &str, options: PgOptions) -> Result<PgStore, StoreError>;   // never logs or returns the URL's password; errors name host/db only
    pub async fn migrate(&self) -> Result<MigrationReport, StoreError>;                    // one transaction, advisory lock, schema_version table
    pub async fn schema_state(&self) -> Result<SchemaState, StoreError>;                   // Current | Behind { have, need } | Ahead { have, need }
}
impl Store for PgStore { ... }   // all methods, same contracts and error mapping as SQLite
```
Behaviour (design 6.3): post takes `SELECT ... FROM boards WHERE id = $1 FOR UPDATE`, assigns `head_seq + 1`, writes message, labels, thread summary, event, head and audit in one transaction; SQLSTATE 23505 maps to the same `ConflictKind` as SQLite (board exists, idempotency key replay or reuse); `wait_past` for now POLLS the head every 100 ms (bounded by the timeout, never holding a connection while sleeping): Task 6 replaces the polling with LISTEN/NOTIFY; the only blocking calls hold no transaction.

- [ ] **Step 1: Write failing tests:** the shared Store conformance suites through a `PgFixture` (fresh store = new schema from `STIGMER_TEST_DATABASE_URL`, second handle = a second pool on the same schema), unit tests: `sqlstate_23505_maps_to_conflict_kinds`, `connect_errors_never_contain_the_password` (URL with password to a closed port: error text, Debug and Display contain no password), `migrate_is_idempotent_and_records_schema_version`, `schema_state_reports_behind_and_ahead`, `pg_hash_chain_matches_sqlite_for_the_same_messages` (same inputs produce identical event hashes on both backends), `rolled_back_post_consumes_no_sequence_number` (force failure after the head update inside the transaction), `skips_loudly_without_a_database_url_and_fails_in_ci_without_one`.
- [ ] **Step 2:** Run with a local Postgres (Docker or Homebrew) and `STIGMER_TEST_DATABASE_URL` set. Expected: FAIL.
- [ ] **Step 3:** Implement the crate: pool, TLS (rustls ring), migrations runner, boards, posts (with threads), reads (from threads), events, wait (polling), error mapping; no unwrap/expect in product code; each module under about 400 lines.
- [ ] **Step 4:** Full checks plus the Postgres suites; the IdentityStore half of `run_all` is excluded here ONLY because the type does not implement it yet: the fixture's `Store` bound is split in this task (Store suites generic over `Store`, identity suites over `IdentityStore`) so the PR is green; Task 5 re-joins them.
- [ ] **Step 5:** Commit `feat(store-postgres): crate, connection and migrations`, `feat(store-postgres): boards and posts`, `feat(store-postgres): reads, events and polling wait`, `test(store-postgres): conformance through a schema per test`.

---

### Task 5: Postgres store, part 2 (IdentityStore)

**Files:**
- Create: `crates/stigmer-store-postgres/src/{identity_members,identity_credentials,identity_invites,identity_security}.rs`
- Modify: the Postgres fixture and conformance runner wiring (Store + IdentityStore joined again).

**Interfaces:**
- Consumes: Task 4. Produces: `impl IdentityStore for PgStore` with the same contracts as SQLite (generic NotFound for any unusable invite incl. the dummy-hash compare path, archived-board refusals, reserved name `instance-admin`, adoption in one transaction with its audit row, `consume_invite` doing member + credential + used mark + Join row in one transaction with the invite row locked `FOR UPDATE`, `archive_board_revoking` taking the board row lock then revoking, mode switch in one transaction safe against two replicas).

- [ ] **Step 1: Write failing tests:** the full shared IdentityStore suites plus cross-instance (`invite_redeemed_once_across_handles`, `concurrent_create_board_across_handles_has_one_winner_and_one_board_exists`, `credential_issued_on_one_handle_is_valid_on_the_other_and_revocable_from_either`); Postgres-only: `enable_network_mode_is_safe_against_two_concurrent_callers` (exactly one succeeds, one gets AlreadyNetwork), `lock_order_is_board_then_rows_no_deadlock_under_mixed_load` (50 concurrent posts, joins, archives and revocations on one board for 5 seconds: no deadlock error, every operation either succeeds or returns its documented conflict), `secret_hashes_stored_as_32_byte_bytea_only`.
- [ ] **Step 2:** Run. Expected: FAIL. **Step 3:** Implement (SQL parameterised; a single function that maps SQLSTATE to ConflictKind shared with Task 4). **Step 4:** Full checks plus both suites green. **Step 5:** Commit `feat(store-postgres): members and credentials`, `feat(store-postgres): invites, audit and archive`, `test(store-postgres): identity conformance and lock ordering`.

---

### Task 6: Cross-replica wake-ups

**Files:**
- Create: `crates/stigmer-store-postgres/src/notify.rs` (listener), docs `docs/adr/0013-cross-replica-wake-ups.md`
- Modify: `wait.rs` and `posts.rs` in the Postgres crate.

**Interfaces:**
- Consumes: Tasks 4, 5. Produces: the post transaction runs `SELECT pg_notify('stigmer_events', $board || ':' || $seq)` before commit; one dedicated listener connection per process with reconnect and exponential backoff (100 ms to 10 s) feeds a per-board `watch` notifier with the same subscribe-then-read-then-wait contract as SQLite's; on every (re)connect it re-reads the heads of boards that have waiters; a safety poll of those boards' heads runs every `--db-poll-interval-ms` (default 2000, bounds 100..=60000, hidden flag wired in Task 7; a constructor option here); notifications for unknown or archived boards are ignored (no entry created); archive drops a board's entry.

- [ ] **Step 1: Write failing tests:** `wake_across_handles` with NO polling (set the safety poll to an hour: the wake must arrive through NOTIFY within one second); `wake_is_not_lost_when_the_post_commits_between_subscribe_and_head_read` (hook between subscribe and read); `notification_for_an_uncommitted_post_is_never_delivered` (post in a transaction that rolls back after notify: waiters do not wake); `listener_reconnect_does_not_lose_a_wake` (terminate the listener backend with `pg_terminate_backend` then post: the waiter wakes, via reconnect re-read or the safety poll, within the poll interval plus backoff); `no_entry_for_unknown_board`; `wait_holds_no_connection_while_sleeping` (pool of 2 connections, 20 concurrent waits all pending, other queries still run).
  - The Postgres fixture implements `Fixture::waiters` with its listener-fed notifier (the receiver count of the board's `watch` entry), so `wake_reaches_a_blocked_waiter_on_the_other_handle` proves a NOTIFY wakes a blocked waiter on the other handle.
- [ ] **Step 2:** Run. Expected: FAIL (polling only). **Step 3:** Implement the listener and notifier, replace the polling wait. **Step 4:** Full checks; the cross-instance wake scenario now passes without the 100 ms poll; repeat the wake tests 30 times. **Step 5:** Write ADR 0013. Commit `feat(store-postgres): listen and notify wake-ups`, `test(store-postgres): lost-wake and reconnect scenarios`, `docs(adr): record cross-replica wake-ups`.

---

### Task 7: stigmerd backend selection and operations

**Files:**
- Create: `crates/stigmerd/src/backend.rs`, `docs/adr/0012-postgres-backend-and-selection.md`
- Modify: `crates/stigmerd/src/{main,serve}.rs`, `crates/stigmerd/src/admin/*.rs`, README operations section.

**Interfaces:**
- Consumes: Tasks 4 to 6. Produces: `serve` and every `admin` subcommand take `--database-url <url>` (env `STIGMER_DATABASE_URL`), `--database-url-file <path>`, `--db-max-connections` (default 16, 1..=500), `--db-poll-interval-ms` (hidden, 100..=60000), and `--db-tls <disable|require|verify-full>` (default `require` for non-loopback hosts, `disable` allowed only for loopback or when given explicitly). A URL with a password given as a command-line argument exits 2 ("put it in STIGMER_DATABASE_URL or --database-url-file"). `--database-url` and `--data-dir` together: data-dir ignored with one warning. New `stigmerd admin migrate` (Postgres: applies pending migrations in one transaction; SQLite: a no-op that says migrations are automatic) and `serve` against a behind or ahead schema exits 1 with the `SchemaState` message. In Postgres mode there is no lock file and admin commands run while servers run (each is one transaction); `enable-auth` is one transaction. A `Backend` enum dispatches to generic server and admin code (no API changes).

- [ ] **Step 1: Write failing tests:** `password_in_the_url_argument_is_refused_with_exit_2`; `url_from_env_and_from_file_work_and_never_print_the_password` (grep captured stdout/stderr and the process listing of the child for the password); `data_dir_with_database_url_warns_once`; `serve_refuses_a_behind_schema_and_names_migrate`; `serve_refuses_an_ahead_schema`; `admin_migrate_applies_and_is_idempotent`; `admin_enable_auth_on_postgres_is_safe_with_two_concurrent_runs`; `admin_commands_run_while_a_server_is_running_on_postgres`; `sqlite_default_is_unchanged` (the existing M0/M1 tests pass untouched); out-of-range flags exit 2.
- [ ] **Step 2:** Run. Expected: FAIL. **Step 3:** Implement `backend.rs` and wire it through serve and admin. **Step 4:** Full checks with Postgres tests enabled. **Step 5:** Write ADR 0012 (Postgres backend, selection rules, additive-migration rule, the stop-migrate-start upgrade for v0.2 to v0.3). Commit `feat(server): choose the storage backend at startup`, `feat(server): migrate command and schema checks`, `docs(adr): record the postgres backend`.

---

### Task 8: CI, two-replica end-to-end and docs

**Files:**
- Create: `crates/stigmer-cli/tests/e2e_m2.rs`
- Modify: `.github/workflows/ci.yml` (job `postgres`), `README.md`, `docs/design.md` (section 15 "M2 as built"), `docs/adr/README.md` index, `CONTRIBUTING.md` (scopes: `store-postgres`).

**Interfaces:**
- Consumes: everything. CI job `postgres`: service container (the newest Postgres major released at least six months ago: verify against the official support table and say which in a workflow comment), actions pinned by full SHA, read-only permissions, `STIGMER_TEST_DATABASE_URL` set, runs the Postgres conformance suites and the two-replica e2e; added to the required checks only after two consecutive green runs on main (the controller does that after merge).

- [ ] **Step 1: Write the failing e2e tests (`e2e_m2.rs`, skipped loudly without the URL unless `CI`):** `wait_on_replica_a_wakes_on_a_post_through_replica_b` (two real stigmerd on one database, shared TLS test CA); `member_token_issued_through_a_is_accepted_and_revocable_through_b` (revoke via B, A answers the identical 401 on its next request); `killing_replica_b_mid_wait_leaves_a_serving_and_data_intact` (SIGKILL B; A serves; verify_chain valid; all posts present); `m1_e2e_tests_still_pass_on_sqlite` (do not touch e2e_m1.rs); `password_never_appears_in_replica_output_or_argv`.
- [ ] **Step 2:** Run. Expected: FAIL until Tasks 1 to 7 are in. **Step 3:** Write the CI job, README (running with Postgres: URL via env, migrate, two replicas behind a proxy, per-replica limits caveat, the v0.2 to v0.3 upgrade procedure), design section 15 (what shipped, deviations, known gaps), index and scopes. **Step 4:** Full checks and every doc link; CI green including the new job. **Step 5:** Commit `test(e2e): two replicas on one postgres`, `ci: add the postgres job`, `docs: run with postgres and describe m2 as built`.

---

## Self-review notes

- Coverage of the spec: G1 (Tasks 4, 5), G2 (Task 1), G3 (Task 6), G4 (Task 2), G5 (Task 2), G6 (Tasks 4, 7), G7 (Task 3), G8 (Task 8); backend selection and password handling (Task 7); archive+revoke atomic and audited mutations taking their instant from the audit event (Task 1); conformance sleeps and concurrent board creation (Task 3); ADRs 0012 to 0015 (Tasks 7, 6, 1, 2).
- Deliberate ordering: audit parameters first because every later store method (both backends) is written against the final signatures; Task 2 before Task 3 because ordering by sequence lets the sleeps go; the Postgres store before LISTEN/NOTIFY (polling wait keeps its PR green); wiring and CI last.
- Soft spots a reviewer should press: the combined archive method (it crosses both traits), the polling wait that Task 4 ships and Task 6 replaces, and the fixture split in Task 4 that Task 5 undoes.
