# 0012. Postgres backend and backend selection

Status: Accepted
Date: 2026-11-27

## Context

Until M2 a Stigmer server kept its data in SQLite, in a data directory that one process locks
(`stigmer.lock`). That makes one server the limit: a second process on the same data, for a
rolling restart or a second replica behind a proxy, is refused. M2 adds a Postgres backend
(`stigmer-store-postgres`, which passes the same conformance suites as SQLite, see
[0001](0001-storage-behind-a-trait.md)) so several servers can share one database, with wake-ups
across them ([0013](0013-cross-replica-wake-ups.md)). The server has to choose a backend at
startup, take a connection string without exposing its password, secure the connection, and
cope with a database whose schema is not the one it was built for.

Options for choosing the backend: a config file, a `--backend` flag, or the presence of a
database URL. Options for the schema: migrate on every start (as SQLite does), or migrate only
on request and refuse to start otherwise.

## Decision

**SQLite stays the default.** With no database URL, `stigmerd` behaves exactly as before:
data directory, lock file, private file modes, migration when the database is opened.

**A database URL selects Postgres.** `serve` and every `admin` subcommand take the URL from
`--database-url`, else `--database-url-file`, else `STIGMER_DATABASE_URL`. With a URL there is no
data directory and no lock: `--data-dir` is ignored with one warning. Postgres-only flags
(`--db-max-connections`, default 16, 1 to 500; `--db-tls`; `--db-tls-ca`; the hidden
`--db-poll-interval-ms`, 100 to 60000) without a URL are a usage error, so a mistyped setup does
not silently run on SQLite. A `Backend` enum in `stigmerd` opens one or the other; the server
and admin code past that point are generic over the store traits, so the API is unchanged.

**The password never shows.** A URL with a password given as a command-line argument is refused
(exit 2) with a pointer to the variable and the file: every user of the machine can read argv.
Errors name the host, port and database only; the store redacts its own errors and `stigmerd`
redacts the driver's parse errors.

**TLS rules.** The connection is secured as `--db-tls` or the URL's `sslmode` says: `disable`,
`require` (encrypted, certificate not checked, as libpq's `require`) or `verify-full` (chain and
host name checked). Other `sslmode` values are refused, `prefer` and `allow` because they fall
back to plain text silently. The flag and the URL must agree. Without either, the mode is
`verify-full` when a CA bundle is given, `disable` when every host is this machine (a loopback
address, `localhost` or a Unix socket) and `require` otherwise: a plain connection leaves the
machine only when `disable` was asked for by name. A CA bundle (`--db-tls-ca` or the URL's
`sslrootcert`, PEM) replaces the platform's roots for `verify-full`, for servers with a
certificate from a private CA; with any other mode it is refused. `stigmerd` reads `sslmode`
and `sslrootcert` out of the URL and passes the rest to the driver, which cannot parse
`verify-full`. TLS is rustls with the ring provider, as everywhere else.

**Migrations run on request.** `stigmerd admin migrate` applies all pending Postgres migrations
in one transaction under an advisory lock and is safe to repeat; on SQLite it is a no-op that
says so. `serve`, and every other admin command, refuse (exit 1) a schema older than the build
("run stigmerd admin migrate") or newer ("this server is older than the database"). Migrations
are never run implicitly on Postgres: with several replicas, the operator decides when the
schema moves.

**Admin commands run next to servers on Postgres.** Each command's change is one store
transaction (`enable-auth` included, so two concurrent runs switch the mode once and the second
is told the instance is already in network mode). A running server reads the instance mode when
it starts, so `enable-auth` reminds the operator to restart running servers.

**Migrations are additive from M2 on.** A new migration adds tables, columns and indexes that an
older server can ignore; dropping or changing what an older version reads waits for a later
release (expand, then contract), so a future rollout can run adjacent versions side by side.

**Upgrading from v0.2 to v0.3 is stop, migrate, start.** Migration 8 (thread summaries,
[0015](0015-thread-summaries-and-sequence-ordering.md)) changes the write path, so v0.2 servers
would not maintain a table v0.3 servers read. Stop every server, run `stigmerd admin migrate`
with the new binary, start the new servers. (On SQLite, starting the new server migrates.)

## Consequences

- One server or several share one Postgres database; SQLite users see no change.
- An operator must run `admin migrate` before the first start and after each upgrade; a server
  that refuses to start says so.
- The password can still be read from the server's environment by its own user and root (for
  example `ps e`); `--database-url-file` with mode 0600 avoids even that.
- A failed safety-poll round of the Postgres wake-ups (the poll starts with the listener) is
  reported on stderr at most once a minute; the store itself logs nothing.
- Each server process opens up to `--db-max-connections` pooled connections, plus one listener
  connection from the first request that waits on ([0013](0013-cross-replica-wake-ups.md));
  an admin command opens no listener. The database's connection limit must cover every
  replica.
- Rate limits and wait caps stay per process, so with N replicas the instance-wide limits are N
  times the flags.
- Rolling upgrades across a schema change are not supported in M2; the additive rule exists so a
  later milestone can support them.
