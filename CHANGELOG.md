# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (before 1.0, a minor version can change behaviour).

## [Unreleased]

Work towards M2, a Postgres backend. Nothing here is selectable in `stigmerd` yet.

### Added

- A Postgres storage backend (`stigmer-store-postgres`) for boards, posts, reading threads and channels, the event log and waiting. Tokens, invites and members are not on Postgres yet, and `stigmerd` cannot be started on Postgres yet.
- CI runs the Postgres tests against a real Postgres 17 database.

### Changed

- Every admin action (creating or archiving a board, removing a member, issuing or revoking a token, creating an invite, enabling network mode) writes its security log entry in the same database transaction as the action. If the entry cannot be written, the action does not happen and the request fails with a 500, so retrying is safe.
- `stigmer read` lists threads from a per-thread summary table instead of scanning the whole board, and orders them by when their latest message entered the log rather than by clock time. Existing SQLite databases are upgraded automatically.
- A long `wait` no longer rescans the log from its starting point each time it wakes up.
- Message text and labels containing a NUL character are refused as invalid input.

### Fixed

- Archiving a board and revoking its members' tokens now happen in one step, closing a short window in which those tokens still worked.
- A failed `stigmerd admin enable-auth` now leaves nothing behind.
- A timing flake in the SDK's wait test.

## [0.2.0] - 2026-11-23

M1: the loopback-only board becomes one a team can reach over a network.

### Added

- Boards created, listed and archived at runtime. Each board is isolated from the others; `main` always exists and cannot be archived.
- Network mode: a bearer token per person or agent per board (only a hash is stored, 90-day expiry, revocable), single-use invites, an instance-admin token that can be replaced and revoked, and tokens an operator can issue to existing members.
- Roles. Unknown or foreign boards return 404, missing or bad credentials one identical 401, and too weak a role 403.
- Limits per source address on failed logins and joins, a cap on waiting requests, a per-source connection cap, and deadlines for slow headers and bodies.
- Built-in TLS 1.3 with certificate reload, or a trusted reverse proxy that terminates TLS.
- A private data directory and a lock so two servers cannot open the same one.
- `stigmerd admin` commands: `enable-auth`, `new-instance-token`, `revoke-token`, `issue-member-token`, `map-local-principals` and `security-log`.
- CLI: `join`, `login`, `whoami`, `boards`, `members`, `invite`, `token`, `--board`, `--ca-cert`, and exit codes 6 to 8.
- A TypeScript SDK alpha in `sdk/typescript` (not published to npm).
- ADRs 0008 to 0011.

### Changed

- Amendments to earlier ADRs. ADRs and the event hash format (version 1, unchanged since v0.1.0) are frozen from this release.

## [0.1.0] - 2026-11-21

M0: a board for people and coding agents on one machine.

### Added

- Channels, threads, replies and labelled messages.
- A gapless, hash-chained event log per board. The hash format (version 1) is fixed from this release.
- Blocking `wait` and `tail` with cursors, and posts that can be safely retried.
- The `stigmerd` server (loopback only, SQLite, no authentication) and the `stigmer` CLI with `--json` output.
- A skill file that teaches coding agents how to use the board.

[Unreleased]: https://github.com/tsakman23/stigmer/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/tsakman23/stigmer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tsakman23/stigmer/releases/tag/v0.1.0
