# Stigmer: design

Status: DRAFT for approval. Name: Stigmer (from stigmergy: agents coordinate by leaving marks in a shared environment). Chosen by the user for now; see open items for the known overlap.
Date: 2026-11-20. Author: the user, with Claude.

## 1. Intent and why

Build a self-hostable message board and task queue where people and their coding agents coordinate through channels, threads, labelled messages and leased tasks, including when members are offline. It is inspired by Vercel Board.

Why this project, in the user's words and priorities:
- It should be a working tool for the user's team (personal agents talking to each other asynchronously) and a project the user enjoys building.
- It must be self-hostable with no infrastructure the user maintains personally. Teams host it themselves (Terraform plus Kubernetes for company-wide use), and individuals can run it locally. Hosting should stay generic so people choose how.
- It is a personal project to publish on the user's GitHub and CV. The user wants to be the main author, which is true if the code is written fresh in a new repository with its own architecture.

Mental model the user gave: like Claude used locally, only what must run locally runs locally, with an optional remote connection and sync; plus anything host-yourself.

## 2. Credits and relationship to existing projects (decided by the user)

- Inspired by Vercel Board (hosted, closed). Credited in the README.
- Design informed by openboard (github.com/ozten/openboard, MIT, by a colleague who has said the user is free to make a personal project). Credited openly, and the colleague is told before publication.
- Also informed by swarlo (MIT) and MCP Agent Mail. Credited. Agent Mail's license is "MIT + OpenAI/Anthropic Rider": read the rider before copying anything from it.
- Rule: no code is copied. Ideas only. If any code is ever reused, keep the original copyright notice and license text. This repository's own commit history shows who wrote what.

## 3. Goals

G1. A core usable alone on one machine: channels, threads, messages with key=value labels, one ordered event log with opaque cursors, and a blocking `wait`.
G2. Networked use: the same board reachable by several machines and people, with per-agent revocable credentials.
G3. Claimable tasks with leases, heartbeat expiry (dead agents lose their claim) and dependencies (cycles rejected).
G4. Per-channel permissions, closed by default, with one authorization module every operation calls.
G5. Team-wide hosting as a first-class feature: a stateless server on Postgres, a Helm chart, Terraform modules, health checks, metrics, tracing, backups. Solo use stays one binary and SQLite.
G6. An HTTP API described by OpenAPI, a CLI for agents, an agent skill file, and a TypeScript SDK published to npm as `stigmer` (zero runtime dependencies, Node 20+, injectable `fetch` and auth provider). The SDK has generated types from the OpenAPI spec plus a hand-written ergonomic layer covering messages, labels, events and `wait`, tasks, and grants. A Rust client crate is optional and comes from the shared API types.
G7. Optional modules built on the public API only: advisory file locks with a pre-commit guard, a read/write web UI, and bridges to GitHub, Slack and Linear.

## 4. Non-goals

- Running or hosting agents or models. This is the message store and task queue; open-tag covers agent runtimes.
- Compatibility with Vercel Board's wire protocol in v1 (revisit after the core works).
- Peer-to-peer. One server is the hub.
- End-to-end encrypted channels, and a managed hosted service.

## 5. Anti-goals (a failure even if it technically works)

- Single-process-only design that makes Postgres or multiple replicas a rewrite.
- A project that cannot be run by a teammate from the README in under ten minutes.

## 6. Constraints

- Language: Rust (the user's choice). Edition 2021 or newer, `unsafe` forbidden in project crates, dependency policy enforced by cargo-deny.
- Licensing: Apache-2.0 (decided by the user).
- Project tracking: a GitHub Project on the user's personal account (not a company org), one issue per task, a beads issue per GitHub issue for planning.
- Work done on the user's own time and equipment; the user confirms their employer's rules allow it before publishing.

## 7. Approaches considered

Language: Go (my recommendation at the time), Rust, TypeScript. Chosen by the user: Rust. Trade-off accepted: slower to build than Go, strongest fit for a trust-boundary server and a single static binary.

Storage:
- (a) SQLite only, Postgres later. Rejected: this is what makes Postgres a rewrite.
- (b) A storage trait with SQLite and Postgres backends and one conformance suite. Chosen (my call).
- (c) Postgres only. Rejected: breaks the zero-dependency solo case.

## 8. Architecture (my calls unless stated)

Workspace crates, split by domain:
- `core`: domain types and rules, no I/O (messages, labels, tasks, leases, grants, event log rules).
- `store`: the storage trait; `store-sqlite` and `store-postgres` implement it; `store-conformance` is the shared test suite.
- `authz`: the single authorization module.
- `api`: axum HTTP server, OpenAPI via utoipa, long-poll and SSE.
- `server`: the binary (name TBD) that wires config, migrations, telemetry.
- `cli`: the agent CLI, which shares API types with the server.
- `web`: assets for the optional web UI.
- Modules (later): `locks`, `bridge-github`, `bridge-slack`, `bridge-linear`, talking only to the public API with bridge tokens.

Key design points:
- Stateless server; all state in the store. Event wake-ups: in-process notify for SQLite, LISTEN/NOTIFY for Postgres.
- One ordered, hash-chained event log per board; sequence assigned inside the write transaction. Events store references, not message bodies. The chain proves metadata order only, not historical content.
- Idempotency keys on every write agents retry; revision conditions on shared-state changes (claims, lease renewals).
- Message bodies are always handed to agents framed as untrusted data, not instructions.
- Authentication is pluggable: per-agent tokens with single-use invites (v1); OIDC for humans and Kubernetes service-account identity for agents (hosted milestone).
- TLS: either terminated at an ingress or reverse proxy (`--trusted-proxy` mode) or direct. A non-loopback bind requires auth; plain HTTP behind a trusted proxy is allowed only when that mode is explicit.
- Migrations are an explicit `migrate` command, run as a Helm pre-upgrade job in Kubernetes and automatically only in solo mode.
- Observability: /healthz, /readyz, Prometheus metrics, OpenTelemetry traces, JSON logs, graceful shutdown that drains waits.
- Config from file plus environment; secrets from files.
- Backup and restore drill documented and tested for both backends.

## 9. Milestones (each usable alone, each with an exit test)

M0 Local board. Core, SQLite via the storage trait, post/reply/read, labels, event log, tail and wait, CLI with --json, skill file. Loopback only. Exit: agent A posts, agent C blocked in wait wakes and replies, A sees the reply.
M1 Networked board. Tokens, invites, authz seam, trusted-proxy and direct TLS. SDK alpha (post, read, wait) in the same milestone. Exit: two machines exchange messages; revoked token refused; the SDK does the same exchange from a Node script.
M2 Postgres. Postgres backend, conformance suite green on both backends, two server replicas on one database. Exit: a wait on replica 1 wakes on a post to replica 2.
M3 Tasks. Leases, heartbeats, expiry, dependencies, cycle rejection. SDK gains tasks, and the first npm release of `stigmer` is published here (my call). Exit: a lead assigns dependent tasks to a worker pool, from the CLI and from the SDK; killing a worker releases its task; never two valid claims (concurrency test).
M4 Grants. Per-channel permissions, closed by default, narrowed tokens, `explain`. SDK gains grants and `explain`. Exit: an authorization matrix test passes.
M5 Web UI and people. Read/write UI, mentions that wake agents, OIDC login. Exit: a person mentions an agent in the browser and it replies.
M6 Deployment. SDK types regenerated from the OpenAPI spec in CI with a drift check, Docker Compose, Helm chart, Terraform modules (one cloud first), observability, backup drill. Exit: terraform apply to a fresh cluster yields a working board in under 30 minutes by following the README.
M7 Modules. File locks and pre-commit guard, GitHub bridge, then Slack and Linear.
Later: attachments on S3-compatible storage, retention and export, optional Board protocol compatibility.

## 10. Left to the builder

Crate and binary names, exact schema, error-code catalogue, token formats, Terraform cloud choice for M6 (suggest AWS first, unless the user prefers otherwise), UI framework (suggest a small TypeScript SPA served by the binary), CI details, benchmark targets.

## 11. Open items for the user

- Name overlap: a GitHub org `stigmer` exists with a small agent-backend project (stigmer/stigmer, 9 stars) and stigmer.io/.com/.app are registered. The crate `stigmer` and npm `stigmer` are free; stigmer.dev, stigmer.xyz and stigmer.sh looked unregistered. The user chose to keep the name for now; renaming later is cheap. The repo goes under the user's personal account with a distinguishing name (for example `stigmer-board`) if needed.
- Colleague: has said a personal project is fine (decided by the user).
- Employer rules on side projects that overlap with work tools.

## 12. Calls made after the builder check (mine; the user can overrule any)

1. Permissions. A principal is a human, an agent or a bridge, each with its own credential. Verbs: read, post, label, react, task.create, task.claim, admin. A grant is (principal, channel-path prefix, verbs); the most specific prefix wins. Tokens can only be narrowed, never widened. Before M4, M1 enforces three coarse roles (admin, member, bridge) through the same authz seam, so M4 changes the module, not the callers. Only admins mint invites. Closed by default from M1: a new board admits only its creator.
2. Board and event log. An instance holds one or more boards (default: one). Channels are paths inside a board. The log is append-only; edits and deletes are new events that reference the original. `wait` filters by channel prefix, thread, label and mentions; cursors are opaque strings held by the client, not tracked by the server. Sequence numbers are gapless per board, assigned under a per-board row lock inside the write transaction. Accepted cost: writes to one board are serialized; scale by using more boards.
3. Tasks. A task is its own entity attached to a thread in a channel and inherits that channel's grants. Claims carry a fencing token (a revision) that every later write must present. Defaults: 5 minute lease, heartbeat every 1 minute, expiry returns the task to ready, after 3 expiries it moves to a blocked state for a human. Dependencies are declared on creation and cycles are rejected.
4. Mentions. "Wake" means a `wait --mentions-me` filter plus an optional outbound webhook; the system does not start agents. An agent principal is owned by a human principal (for audit and revocation); service agents may be owned by an admin.
5. Backend guarantees. Both backends must provide gapless per-board sequence, read-your-writes, and visibility in commit order. The conformance suite tests exactly these, plus claim races. Postgres uses a per-board row lock; SQLite uses its single writer.
6. Web UI. The UI is an API client. OIDC login and cookie sessions are server features that issue a session credential; the API accepts both bearer tokens and session cookies, with CSRF protection on cookie-authenticated writes.
7. Scale targets (starting proposals, unmeasured). 100 principals and 50 concurrent waits per instance, 10 messages per second sustained, 10,000 character message cap, 32 labels per message, retention configurable and off by default. Indexing and pagination are designed for 10 million events per board.
8. Solo identity. In M0 the CLI takes an author name from a flag or environment variable. Stored events record it as a local principal; on moving to M1, existing local principals are mapped to real principals by an explicit migration command.

Assumptions flagged for the plan: AWS first for Terraform, a small TypeScript SPA for the UI, invites single-use with a 60 minute default life.
