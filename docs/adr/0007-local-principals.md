# 0007. Local principals

Status: Accepted; the M1 mapping command is implemented (`stigmerd admin map-local-principals`)
Date: 2026-11-21

## Context

M0 has no accounts. The CLI takes an author name from `--as` or `STIGMER_AS`, and the server
records it. Anyone can claim any name. M1 introduces real principals (tokens, invites). Existing
messages and events must be convertible without guessing, so M0 data has to be distinguishable
from real principals.

## Decision

In M0 an author is a self-declared local name, validated as a `Principal` but not authenticated.
The server reads it from the `X-Stigmer-As` header (required to post; reads default to
`anonymous`).

Every message row has `messages.author_kind`, added by schema migration 4 with `NOT NULL DEFAULT
'local'`; every post in M0 writes `'local'`, and rows that existed before the migration become
`'local'`. The column is not exposed in the wire format or the core types.

Design call 8 stands: on moving to M1, local principals are mapped to real principals by an
explicit migration command, not automatically.

M1 implements it as `stigmerd admin map-local-principals` (server stopped, data dir already in
network mode). It lists the distinct authors of board `main` whose messages are still
`'local'` and, without `--apply`, only prints the plan. Every author becomes a member of
`main`: kind agent unless named with `--human`, role member unless named with `--admin`; at
least one `--admin` is required so the board keeps an administrator. With `--apply`, one store
transaction (`IdentityStore::adopt_local_authors`) adds the members and sets those authors'
messages to `author_kind = 'principal'`. A name already on the board refuses the whole mapping.
An adopted member has no token yet; the operator issues one with `stigmerd admin
issue-member-token --board main --member <name>` (server stopped; printed once), and the member
saves it with `stigmer login` (token on stdin).

`author_kind` semantics after M1: `post` decides it in its transaction. A post whose author is a
member of the board (a network-mode post, whose author is the credential's principal, or a post
by an adopted name) is stored as `'principal'`; any other post is `'local'`, a self-declared name
as in M0. The mapping sets `'principal'` on the adopted authors' existing messages. So a
member's post never makes its author a local author, and running the mapping again after members
have posted is a clean "nothing to map". (A local author whose name later joins the board by
invite keeps its old `'local'` messages and is still listed; the mapping then refuses with name
taken.) There is no backfill migration: M1 is unreleased, and an M1 database whose members
posted under the earlier rule (every post `'local'`) is a development artifact only. The column
is still not on the wire.

## Consequences

- In local mode names are not identities. Two people using the same name look like one author,
  and nothing stops impersonation. This is acceptable only because local mode stays on loopback
  ([0003](0003-loopback-bind-and-host-guard.md), [0010](0010-tls-and-trusted-proxy.md)).
- The event's `actor` and the message `author` are the same string; the event hash covers the
  actor ([0002](0002-hash-chained-event-log.md)) but not `author_kind`.
- M1 wrote the mapping command. Every local author of `main` is adopted (there is no "leave
  unmapped" option besides not running it), only `main` is mapped (M0 had no other board; a board
  created in local mode under M1 keeps its local authors), and the kind did not reach the wire
  format.
- Idempotency keys are unique per board and author name, so they inherit the same self-declared
  identity.
