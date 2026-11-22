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
No adopted member gets a token, and M1 has no way to issue one for an existing member (an
invite always creates a new name), so an adopted name keeps its history but its owner carries
on under a new name joined by invite.

`author_kind` semantics after M1: `'principal'` marks a message whose author was adopted by
the mapping. `'local'` is what `post` still writes for every new message, in local and in network
mode alike (the store's `NewMessage` carries no author kind), so in M1 `'local'` means "not
adopted", not "self-declared". A network-mode post is in fact authenticated (its author is the
credential's principal). Consequence: running the mapping again after members have posted in
network mode lists them as local authors, and since they are already members the whole mapping
is refused (name taken). Writing `'principal'` for authenticated posts is carried into M2. The
column is still not on the wire.

## Consequences

- In local mode names are not identities. Two people using the same name look like one author,
  and nothing stops impersonation. This is acceptable only because local mode stays on loopback
  ([0003](0003-loopback-bind-and-host-guard.md), [0010](0010-tls-and-trusted-proxy.md)).
- The event's `actor` and the message `author` are the same string; the event hash covers the
  actor ([0002](0002-hash-chained-event-log.md)) but not `author_kind`.
- M1 wrote the mapping command. Every local author of `main` is adopted (there is no "leave
  unmapped" option besides not running it), only `main` is mapped (M0 had no other board; a board
  created in local mode under M1 keeps its local authors), and the kind did not reach the wire
  format. Still open: writing `'principal'` for authenticated posts (above), and a
  way to give an adopted member a token.
- Idempotency keys are unique per board and author name, so they inherit the same self-declared
  identity.
