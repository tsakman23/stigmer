# M2: Postgres backend and multi-replica — design

Status: DRAFT for approval. Date: 2026-11-23. Parent documents: docs/design.md (sections 8, 12, 13, 14), docs/adr/ (0001, 0002, 0005, 0008 to 0011), docs/superpowers/specs/2026-11-22-m1-networked-board-design.md. Builds on release v0.2.0 (M1).

## 1. Intent

Let several Stigmer servers share one database so a team deployment can run more than one replica and survive a restart or rollout with no downtime, while SQLite stays the default for solo use. M2 adds a Postgres storage backend behind the existing `Store` and `IdentityStore` traits, makes wake-ups work across replicas, moves audit rows into the transaction of the action they record, and removes the two scaling problems M1's reviews found (`read_channel` and the wait rescan).

Why, from the user: a company-wide deployment (Terraform and Kubernetes in M6) needs a shared database and more than one server process; SQLite is fine as the default for individuals and small setups.

M2 exit test: two `stigmerd` processes on one Postgres database: a wait on replica A wakes on a post to replica B; a token issued through A is accepted and revocable through B; the same conformance suite that SQLite passes passes on Postgres unchanged; killing a replica loses no committed data.

## 2. Goals

G1. A Postgres backend (`stigmer-store-postgres`) implementing `Store` and `IdentityStore`, selected at startup, passing the shared conformance suites with no backend-specific exceptions.
G2. Audit rows are written in the same transaction as the mutation they record: both happen or neither does.
G3. Cross-replica wake-ups: a post committed through any replica wakes waits on every replica without polling in the normal case.
G4. `read_channel` scales with the number of threads listed, not the size of the board (a maintained thread-summary table), on both backends.
G5. A wait does not rescan the whole log from its original cursor on every wake (scan position advances within the wait).
G6. Explicit schema migration for Postgres (`stigmerd admin migrate`); a server refuses to start against a schema it does not understand and says what to run.
G7. Hardened conformance: concurrent board creation, no wall-clock sleeps, tied-ordering pagination, and a two-instance harness that can run any scenario against two store handles on the same database.
G8. CI runs the Postgres suite and a two-replica end-to-end test.

## 3. Non-goals

SQLite to Postgres data migration tooling, Postgres high availability or connection-pooler tuning, read replicas, row-level security, sharing rate-limiter state between replicas (limits stay per process and are documented as such), invite listing and revocation, Helm and Terraform (M6), changing the HTTP API or wire types, changing the hash-chain format.

## 4. Anti-goals

- A Postgres backend that needs backend-specific behaviour in the API, CLI or SDK.
- Any change that alters existing event hashes or the hash input string (HASH_VERSION stays 1).
- Postgres connection strings with passwords on command lines or in logs.
- Weakening a conformance scenario to let Postgres pass.
- Breaking SQLite solo use: zero-config `stigmerd serve` must keep working exactly as in v0.2.0.

## 5. Approaches considered

Postgres client: (a) sqlx, (b) tokio-postgres with deadpool-postgres. Chosen (b): explicit SQL that mirrors the existing rusqlite code, no compile-time query macros or database needed at build time, and LISTEN/NOTIFY is a first-class feature of the connection object. sqlx is rejected for build-time friction (offline query data or a live database for macros) not for quality.
Wake-ups across replicas: (a) every replica polls the head on a short interval, (b) LISTEN/NOTIFY with a polling safety net. Chosen (b): NOTIFY inside the posting transaction is delivered only on commit, so a listener never sees an uncommitted event; a slow poll (default 2 s) covers a dropped listener connection until it reconnects.
Audit atomicity: (a) keep best-effort writes, (b) pass the audit event into each mutating store method. Chosen (b): the store writes the row in the same transaction, which also deletes the best-effort warning path for admin mutations.
Thread listing: (a) keep the correlated subqueries and add indexes, (b) a maintained `threads` table written in the post transaction. Chosen (b): O(page) reads on both backends, and ordering by last event sequence instead of wall-clock time fixes tied-timestamp pagination and replica clock skew.
Wait rescans: (a) leave, (b) advance the scan position inside the wait loop. Chosen (b): safe because the loop already reads the head before each scan (the ADR 0005 invariant), so scanning from the previous head loses nothing.

## 6. Design (calls are mine unless marked as the user's)

### 6.1 Backend selection
- Default (no flag): SQLite in the data directory exactly as today, including the lock file and automatic migrations (user's call: SQLite stays the default).
- `stigmerd serve --database-url <url>` (and `STIGMER_DATABASE_URL`) selects Postgres. A URL containing a password is accepted from the environment variable or from a file named by `--database-url-file`; passing a URL with a password as a command-line argument is refused with exit 2 and a hint (the password would show in process listings). Connection options: `--db-max-connections` (default 16), TLS to Postgres through rustls (`sslmode=require` or `verify-full` in the URL; plain connections allowed only to loopback or when `sslmode=disable` is explicit).
- In Postgres mode there is no data directory, no `stigmer.lock` and no 0600 database file; the data-dir flags are ignored with a warning if both are given. `stigmerd admin` commands run against whichever backend is selected the same way, and in Postgres mode they do not need the servers stopped (each is one transaction). `enable-auth` uses a single transaction so two replicas cannot both switch the mode.
- A `Backend` enum in stigmerd (Sqlite or Postgres) hides the choice; the API and server code stay generic over the traits, as today.

### 6.2 Schema and migrations (Postgres)
- Same logical schema as SQLite migrations 1 to 8 (this milestone adds `threads` as migration 8 on both), expressed in Postgres types: `bigint` times and sequence numbers, `bytea` hashes with a length CHECK, `text` ids, partial unique index for idempotency keys. Migrations are versioned SQL files embedded in the crate and applied by `stigmerd admin migrate` inside one transaction with an advisory lock; a `schema_version` table records the state. `serve` against an older schema exits 1 with "run stigmerd admin migrate"; against a newer schema exits 1 with "this server is older than the database".
- SQLite keeps automatic migration at open (solo mode).

### 6.3 Ordering, sequence and concurrency
- Per-board gapless sequence: the post transaction takes a row lock on the board's `boards` row (`SELECT ... FOR UPDATE`), reads the head, assigns `seq = head_seq + 1`, writes message, labels, thread summary, event and head, and commits. Writes to one board serialise on that row; different boards run in parallel (the design's "scale by adding boards").
- Uniqueness violations (board exists, name taken, idempotency key) are mapped from SQLSTATE 23505 to the same typed `ConflictKind` values as SQLite; no find-then-insert races.
- `consume_invite` locks the invite row (`FOR UPDATE`) and does member, credential and invite-used in one transaction, as in SQLite.
- Archive: a board row lock in the same transaction as the credential revocation, so archive plus revoke become ONE transaction in M2 (closing the two-step window M1 documented).
- Time: every store method that stamps a time takes it from the caller (the API's injected clock). `create_board` and `archive_board` gain a `now_ms` parameter (they read their own clock today). Event ordering never depends on wall clocks: it is the per-board sequence.

### 6.4 Audit rows in the transaction (both backends)
- Mutating methods that M1 audits through `log_security` take the event to write: `create_board`, `archive_board` (including its revocation), `create_invite`, `revoke_credential`, `remove_member`, `replace_instance_credential`, `enable_network_mode`, and the admin-command paths. The store writes the row in the same transaction. `adopt_local_authors` and `consume_invite` already do.
- `log_security` stays for events that are not part of a mutation (auth failures, rate limits, join-rate-limited), which remain best-effort. SecurityEvent keeps its typed constructors in stigmer-api; the free-text fields stay but are only built by those constructors.
- The API deletes the admin-mutation best-effort path and its warning sink for those routes; a failed audit write now fails the request and rolls back the mutation (the client may retry safely: the mutation did not happen).

### 6.5 Thread summaries and read_channel
- New `threads` table (migration 8, both backends): board, thread id, channel, root preview, reply count, first and last event sequence. Written in the post transaction (insert on a new thread, update on a reply). `read_channel` reads it with a channel-prefix filter and keyset pagination on last event sequence (descending), then thread id; no scan of messages.
- The ordering key changes from last-message wall-clock time to last event sequence. The `before` pagination token is still a thread id, so the wire shape is unchanged. Existing SQLite databases are backfilled by migration 8 (one pass, derived from messages and events; the backfill is tested against v7 data and the result must equal what the new write path would have produced).
- Conformance gains: tied timestamps do not affect order, deep pagination returns every thread exactly once, a reply moves its thread to the top, summary counts match message counts after concurrent posts.

### 6.6 Wait and wake-ups
- Scan advance: the wait loop in stigmer-api keeps a scan position and passes the previous head as the next scan's start when no event matched, preserving the head-before-scan invariant (comment and tests updated). The returned cursor rules do not change.
- SQLite: unchanged in-process notifier.
- Postgres: the posting transaction runs `SELECT pg_notify('stigmer_events', '<board>:<seq>')` before commit. Each process runs one dedicated listener connection (reconnecting with backoff) that feeds the same per-board `watch` notifier abstraction used today. The subscribe-then-read ordering is preserved: a waiter subscribes to the in-process channel, then reads the head from the database, then waits. A slow poll (default 2 s, bounded 100 ms to 60 s, hidden flag `--db-poll-interval-ms`) of the heads of boards that have waiters is the safety net while the listener is reconnecting; on reconnect the listener re-reads the heads of boards with waiters.
- Archive removes a board's notifier entry as today; a notification for an unknown or archived board is ignored (no entry is created).

### 6.7 Conformance and tests
- The suites become generic over a factory that can produce TWO handles on the same database (`Fixture<S>` with `fresh()` and `second_handle()`). SQLite implements the second handle as another connection to the same file. A new `cross_instance` module runs: wake across handles, token valid across handles, concurrent create_board across handles, invite redeemed once across handles, sequence gapless with concurrent posts from both handles.
- Remove the wall-clock sleeps (the 3 ms `tick()` and others): ordering scenarios no longer depend on distinct timestamps now that ordering is by sequence.
- Postgres tests need a database: they read `STIGMER_TEST_DATABASE_URL` and skip with a loud message when it is unset and `CI` is unset; with `CI` set a missing URL fails the run. Each test gets its own schema (`CREATE SCHEMA` + search_path) so tests run in parallel and leave nothing behind.
- CI: a `postgres` job with a service container (version pinned) runs the conformance suites against it plus the two-replica end-to-end test; added to the required checks after it has run green once.

### 6.8 Two-replica end-to-end
`crates/stigmer-cli/tests/e2e_m2.rs`: one Postgres (from the test URL), two real `stigmerd` processes with different ports and the same URL, shared TLS test CA; instance token created via one replica's admin command; a CLI wait started against replica A wakes on a post through replica B; a member token issued through A is revoked through B and A answers 401 on the next request; killing replica B mid-wait leaves A serving and all committed data intact; the M1 e2e tests still pass unchanged on SQLite.

## 7. Decisions recorded as ADRs
0012 Postgres backend and selection; 0013 cross-replica wake-ups; 0014 audit rows in the mutation transaction (amends ADR 0011's best-effort rule); ADRs 0001 and 0005 get Amendments sections only if their text changes (ADRs frozen at v0.2.0 are NOT edited: record changes as new ADRs that supersede, per the ADR rule).

## 8. Risks and review focus
Postgres lock ordering (board row vs invite/credential rows) and deadlocks under concurrent admin and post traffic; NOTIFY delivery and listener reconnect gaps (lost wake-ups); the subscribe-before-read ordering on a networked database; sequence gaplessness under rollback (a rolled-back post must consume no sequence number: the row lock guarantees it, tested); SQLSTATE mapping completeness; connection-pool exhaustion by long waits (a wait must not hold a connection while sleeping: waits use the notifier, not a held transaction); migration backfill correctness for `threads`; credentials in connection strings (logs, errors, process listings); the thread-summary table drifting from messages (consistency test after random operation sequences).

## 9. Left to the builder
Crate names inside the workspace beyond `stigmer-store-postgres`, pool sizing internals, exact SQL, listener task structure, migration file layout, CI service container version (pin one currently supported Postgres major), test schema naming.

## 10. Task breakdown (one PR each, merged before the next starts)
1. Audit rows in the mutation transaction (trait changes, SQLite, API, conformance) and clock parameters for board create/archive.
2. Thread summaries (`threads` migration with backfill, `read_channel` rewrite, conformance) and wait scan advance.
3. Conformance hardening: two-handle fixture, cross_instance module, sleep removal, concurrent board creation.
4. Postgres store, part 1: crate, schema and migrations, boards, posts, reads, events (Store trait), conformance green.
5. Postgres store, part 2: IdentityStore, conformance green.
6. Cross-replica wake-ups: LISTEN/NOTIFY listener, poll safety net, cross-instance wake scenarios.
7. stigmerd wiring: backend selection, database URL handling, migrate command, admin commands on Postgres, docs for running it.
8. CI postgres job, two-replica e2e, ADRs 0012 to 0014, README and design section 15.
The design and the plan documents ride in task 1's PR.

## 11. Open items for the user
- Which Postgres major to pin in CI (suggest the newest widely deployed major).
- Whether the CI postgres job should be a required check from day one or after a trial week (suggest: required once green twice).
