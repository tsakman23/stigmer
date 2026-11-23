# M1: Networked board — design

Status: DRAFT for approval. Date: 2026-11-22. Parent design: docs/design.md (sections 8, 9, 12, 13) and docs/adr/. Builds on release v0.1.0 (M0).

## 1. Intent

Make a Stigmer board usable by a team over a network. Today the server is loopback-only with no authentication and one hard-coded board (`main`). M1 adds: several boards on one server, per-agent and per-person revocable credentials with single-use invites, TLS (built in, plus a trusted-proxy mode), an async authorization layer, a TypeScript SDK alpha, and the hardening items carried from the M0 reviews.

Why, from the user: a company-wide deployment where teams run their own agents, plus individual use. Setup A was chosen: one server hosts many boards (teams or projects), each a hard isolation boundary; a solo user can keep using `main` with no setup.

M1 exit test (from docs/design.md section 9, extended): two machines exchange messages over TLS; a revoked token is refused; the SDK performs the same exchange from a Node script; a token for one board gets nothing from another.

## 2. Goals

G1. Boards are created, listed and archived at runtime by an instance admin; `main` always exists.
G2. Authentication: per-credential bearer tokens, stored only as hashes, revocable, expiring.
G3. Single-use invites bind board, role and principal kind; joining returns a token once.
G4. Authorization: async `Authorize`, roles admin/member/bridge per board, an instance-admin credential for board management; 401 / 403 / 404 policy defined below.
G5. TLS built into `stigmerd` from PEM files (certificates reload on renewal) and a trusted-proxy mode with configurable allowed hosts.
G6. CLI support for all of it, with logins stored per server and board.
G7. TypeScript SDK alpha (post, read, wait) living in the repo, not published.
G8. Local mode keeps working exactly as in M0 (loopback, no auth, zero config).
G9. Hardening from the M0 reviews: connection limits, header-read timeout, wait cap, data-dir lock file, 0600 database files, notifier cleanup, wire-enum fallbacks, bidi-character escaping, the CLI minors.

## 3. Non-goals

Per-channel grants (M4), OIDC and web UI (M5), Postgres (M2), tasks (M3), npm publication of the SDK (M3), OpenAPI-generated SDK types (M6), certificate pinning or self-signed certificate generation, token rotation beyond "issue new, revoke old", cross-board access, board deletion (archive only).

## 4. Anti-goals

- Any code path where an unauthenticated request reads or writes board data in network mode.
- Token secrets in logs, process arguments after joining, error messages, or the database.
- A board's existence or contents leaking to someone outside it.
- Breaking the M0 local workflow or the v0.1.0 hash-chain format.

## 5. Approaches considered

Credential scope: (a) instance-wide tokens with per-board roles in a table; (b) one token per board plus a separate instance-admin token. Chosen (b): a leaked agent token exposes one board only, and the CLI already stores per-server logins.
TLS: trusted proxy only versus proxy plus built-in TLS. Chosen by the user: both.
Identity storage: extend `Store` versus a separate `IdentityStore` trait on the same backend. Chosen: separate trait, same SQLite database, own conformance scenarios, so Postgres (M2) implements both.

## 6. Design (calls are mine unless marked as the user's)

### 6.1 Modes
- Local mode (default for a new data dir): loopback only, no authentication, author from `X-Stigmer-As`, exactly as M0.
- Network mode: authentication required on every route except `/healthz`, `/readyz` and `POST /v1/join`. Enabled one-way per data directory by `stigmerd admin enable-auth`, which creates the instance-admin credential (token printed once, never again) and records the mode in the database. A non-loopback bind is refused unless the data dir is in network mode AND either TLS files are supplied or `--trusted-proxy` is set.

### 6.2 Principals, roles, credentials
- Principal kinds: human, agent, bridge. A principal is a name unique within a board (same charset as today's Principal).
- Roles per board: admin (everything on that board including members, invites, tokens), member (read, post), bridge (read, post; reserved for M7 intake rules). The instance admin credential is not a board member: it manages boards, mints invites into any board, and revokes any token, but cannot read or post message content.
- Token format: `stg1_<id>_<secret>` where id is 8 random bytes hex and secret is 32 random bytes base64url. The database stores id, sha256(secret), principal, board (or instance), role, kind, created_at, expires_at (default 90 days, max 365), revoked_at, last_seen_at. Verification looks up by id and compares hashes in constant time. A token authorizes exactly one board or is the instance-admin token.
- Author on write is the credential's principal; in network mode `X-Stigmer-As` is ignored.

### 6.3 Invites
`stgi1_<id>_<secret>`, single use, stored hashed, bound to (board, role, kind), default life 60 minutes (max 7 days). Minted by a board admin or the instance admin. `POST /v1/join` with the invite and a requested principal name creates the principal, membership and credential, returns the token once, and consumes the invite. A taken name is 409 and does not consume the invite. Invalid, expired or used invites all return the same 401 body.

### 6.4 Authorization and the 401/403/404 policy
- `Authorize` becomes async: `check(&self, who: &Authenticated, action: Action, scope: Scope)`. `Authenticated` carries principal, kind, board scope, role and credential id. Actions: Read, Post, ManageMembers, ManageBoards. `Scope` is board plus optional channel (same meaning as today: None is board-wide).
- Missing, malformed, unknown, expired or revoked token: 401 `unauthorized` with one generic message. Valid token but role too weak: 403 `forbidden`. Valid token used against a board it does not belong to, or a board that does not exist: 404 `not_found` (existence is not leaked). The thread-filtered events case in ADR 0004 stays an M4 item.
- Failed authentications are rate limited per source address only, and written to the security log with the source and, when the token parsed, its id. Not per token id: a 32-byte secret cannot be brute-forced, so a per-id budget adds no protection, while it would let anyone who knows an id lock that token out (corrected during the build; see "Changes made during the build").

### 6.5 Boards and the store
- `Store` gains `create_board`, `list_boards`, `archive_board`. An archived board refuses posts (409 `conflict`, kind BoardArchived), stays readable to admins, and all its tokens are revoked.
- Unknown board is `NotFound{Board}` from every method, including `read_channel` (today it returns an empty list), `verify_chain` and `wait_past`; conformance scenarios pin this. The notifier forgets a board's channel when it is archived and never creates entries for unknown boards.
- New trait `IdentityStore` (same backend): instance mode, principals, memberships, credentials, invites, security log. Own conformance suite.
- SQLite migrations 5 onward (appended): instance, boards extensions (name, created_by, archived_at), principals, memberships, credentials, invites, security_log.

### 6.6 API additions (all under /v1)
POST /boards (instance admin), GET /boards (instance admin: all; board member: own board only), GET /boards/{b}, POST /boards/{b}/archive, GET /boards/{b}/members, DELETE /boards/{b}/members/{name}, POST /boards/{b}/invites, GET /boards/{b}/tokens, DELETE /boards/{b}/tokens/{id}, POST /join, GET /whoami. New ErrorCodes: unauthorized, and conflict kinds are distinguishable by message code `board_archived`. Wire enums (`ErrorCode`, `EventKind`) gain an `Unknown` fallback (serde other) so older clients survive new values; the CLI treats Unknown conservatively and prints the raw code.
Limits: max concurrent connections (default 1024), header read timeout 10 s, max concurrent waits (default 256), per-source limit on `/v1/join` and failed auth (default 10 per minute).

### 6.7 TLS and proxy (user's choice: both)
- `--tls-cert` and `--tls-key` (PEM): rustls, TLS 1.3 only, no self-signed generation. Files are re-read when their modification time changes (checked every few seconds) without a restart or ending open waits. `Strict-Transport-Security` is sent only when `stigmerd` itself serves TLS; behind a proxy that terminates TLS, the proxy should add its own.
- `--trusted-proxy <cidr,...>`: plain HTTP accepted only from those source ranges; only `X-Forwarded-For` is used, and only from them (it decides the client address for rate limiting and the security log); `X-Forwarded-Proto` is intentionally ignored, as nothing in the API depends on the scheme; `--allowed-host <name>` (repeatable) extends the Host/Origin allow-list, which stays loopback-only by default. Rebinding protection stays on.
- The CLI uses system roots for https URLs plus `--ca-cert <file>` for a private CA. No pinning.

### 6.8 CLI
- `stigmer join <invite> --url <url> --as <name>` stores the token in `~/.config/stigmer/logins.json` (mode 0600, keyed by server URL and board); `STIGMER_TOKEN` overrides; tokens are never printed after join and never accepted as an argument except via environment.
- `--board` / `STIGMER_BOARD` select the board (default `main`). New commands: `boards list|create|archive`, `members list|remove`, `invite create`, `token list|revoke`, `whoami`.
- `stigmerd admin`: `enable-auth`, `map-local-principals` (explicit, dry-run first: turns M0's distinct local author names into principals, default kind agent, humans named with `--human`, all members of `main`, sets author_kind to principal; hash chain untouched), `security-log`.

### 6.9 Hardening
Lock file `stigmer.lock` (exclusive flock) so two servers cannot share a data dir; database files created 0600 and the directory 0700; notifier cleanup (6.5); bidi override and isolate characters escaped in rendered messages; CLI minors (tail retries transient network errors with backoff; wait --json timeout exposes the cursor; read previews marked untrusted).

### 6.10 SDK alpha (sdk/typescript)
Zero runtime dependencies, Node 20+, ESM, injectable `fetch` and token provider. `new Stigmer({url, token, board})` with `post`, `reply`, `readChannel`, `readThread`, `events` (after, fromNow, filters) and `wait` (chunking and cursor carry exactly as the CLI: only the first chunk may use from-now). Hand-written types for M1; typed errors with the server's codes. Tests use node:test against a real `stigmerd` built in CI; a runnable example reproduces the exit test. Not published to npm.

## 7. Exit tests
1. Two OS processes with separate config dirs over TLS (test CA): A posts, B waits and replies; revoking B's token makes its next request 401.
2. Isolation: a token for board one gets 404 for every board-two route.
3. SDK example performs test 1's exchange.
4. Local mode: the M0 e2e test passes unchanged.
5. enable-auth plus map-local-principals on a data dir with M0 data: chain still verifies, authors map, old content readable.
6. Security checks: tokens absent from logs and argv, 401 body identical for unknown/expired/revoked, join rate limit trips.

## 8. Risks and review focus
Token hashing and constant-time comparison; brute force against ids; invite replay races (consume in one transaction); existence leaks through timing or error text; TLS reload swapping a half-written pair; Host/Origin allow-list correctness behind a proxy; a rate limiter that trusts spoofed forwarding headers; the migration command and the hash chain; SDK chunk loop losing events.

## 9. Left to the builder
Exact schema, token lengths within the stated shape, rustls crate wiring and the reload mechanism, rate-limiter structure, CLI flag spellings beyond those listed, SDK file layout, CI job layout.

## 10. Open items for the user
- npm package name for the SDK (stigmer is free) and whether it stays unpublished until M3.
- Release as v0.2.0 when M1 completes.

## 11. Calls made after the builder check (mine; the user can overrule any)

1. Archived boards. Archive revokes every member, agent and bridge token of the board but KEEPS board-admin tokens valid in a read-only state: admins can still read content, list members and tokens, and verify the chain; every post is refused with 409 (code `board_archived`). The instance admin still cannot read content. There is no unarchive in M1.
2. Instance admin versus board routes. The instance-admin credential on a content route (channels, threads, events, posts) gets 403 `forbidden` (it is authenticated and boards are not secret from it). It may list members and tokens (metadata only) on any board, mint invites into any board, revoke any token and archive any board. A board admin calling an instance-only route (`POST /boards`) gets 403. `GET /boards` by a non-instance credential returns only that credential's own board. Archive is allowed to the instance admin or that board's admin.
3. Bootstrap. A fresh network-mode data dir always creates `main`. `stigmerd admin enable-auth` creates the instance-admin credential AND mints one admin invite into `main` (single use, 24 hours, printed once; `--no-main-invite` skips it). `map-local-principals` requires at least one `--admin <name>` when it maps anyone, so `main` always has a board admin.
4. Hash chain versus mapping. `author_kind` is a column on messages and is NOT an input to the event hash (the hash covers seq, kind, actor, message id, thread id, channel and time). Mapping local principals rewrites only `author_kind` (and creates principals and memberships); no event or hash is touched, and `verify_chain` must still pass afterwards (tested).
5. Routes. The API is already `/v1/boards/{board}/...` with `main` enforced by `require_main_board`; M1 removes that restriction and adds routes. Existing routes, request and response shapes are unchanged, so v0.1.0 clients and the M0 e2e test keep working in local mode.
6. Rate limits. A limited request gets 429 with new ErrorCode `rate_limited` and a `Retry-After` header. Limiting is checked before credential verification and keyed by source address only (IPv4 per address, IPv6 per /64), so the 401 body stays identical. It is not keyed by token id: a 32-byte secret cannot be brute-forced, and a per-id bucket would let anyone who knows an id lock that token out; the id still appears in the `auth_failed` security log detail. An older client sees `Unknown` and the 429 status.
7. Scope. In M1 every `check` passes the board only; the optional channel in `Scope` is reserved for M4 and is always None for M1 callers.

## Changes made during the build

Deliberate deviations from this design, as shipped in M1. The as-built record is docs/design.md section 14; the decisions are in docs/adr/.

- Archive runs archive-then-revoke: once the board is archived no join can obtain a credential, so revoking afterwards leaves no window for a live credential (11.1, ADR 0008).
- Failed-authentication limiting is keyed by source address only, not also by token id (6.4, 11.6, ADR 0011).
- TLS offers only HTTP/1.1 (ALPN `http/1.1`) and HTTP/2 is compiled out of `stigmerd`, because hyper's header-read timeout does not bound an idle HTTP/2 connection (ADR 0010).
- `X-Forwarded-Proto` is ignored; only `X-Forwarded-For` is read from trusted proxies, and HSTS is sent only on built-in TLS (6.7, ADR 0010).
- Join is atomic in the store: the invite is checked and used, the member and credential are created and the `join` security log row is written in one transaction.
- Security log rows for the API's admin mutations (boards, members, invites, tokens) are written after the mutation, best effort: a failed write is warned about and the mutation stands. Only `join` and `principals_adopted` are written in the mutation's transaction.
- `PeerAddr` is mandatory in network mode: a request without it is refused with 500 instead of sharing one rate-limit bucket with every client (ADR 0010).
- `main` cannot be archived (409 `conflict`); board names made only of dots are refused; the member name `instance-admin` is reserved (ADR 0008).
- Open connections are capped per source address as well (`--max-connections-per-source`, default 64, IPv6 per /64); peers in `--trusted-proxy` ranges are exempt and bounded only by `--max-connections` (ADR 0010).
- Every request body has a 10 s idle deadline between frames; a stalled body gets 408 with the new error code `request_timeout` (ADR 0010).
- The limits in 6.6 are serve flags: `--max-connections`, `--max-connections-per-source`, `--max-waits`, `--auth-failures-per-minute` and `--join-per-minute` (README, Operations).
- Extra admin commands: `stigmerd admin issue-member-token` (a token for an existing member, such as an adopted M0 author), `revoke-token <id>` (any credential, the instance token included), `new-instance-token` with `--revoke-others` (replace the instance token in one transaction), and `map-local-principals --skip <name>` (leave an author and its messages local; a rerun with only skipped authors left is "nothing to map").
- The CLI exits 6 (unauthorized), 7 (forbidden) and 8 (rate limited), instead of 1 for every refusal.
- `stigmer login` saves a token read from stdin (checked with `whoami`; `--instance` for the instance token), so the instance token and operator-issued member tokens can be used from the CLI.
- A post's `author_kind` is derived from membership in the post transaction (`principal` for a member of the board, `local` otherwise), so a mapping rerun after members have posted finds nothing to map (11.4, ADR 0007).
- Local mode stays exactly M0: every caller on loopback acts as the instance admin, so it can create and archive boards other than `main` (ADR 0004).
