# 0007. Local principals

Status: Accepted
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

## Consequences

- Names are not identities. Two people using the same name look like one author, and nothing
  stops impersonation. This is acceptable only because of the loopback-only bind
  ([0003](0003-loopback-bind-and-host-guard.md)).
- The event's `actor` and the message `author` are the same string; the event hash covers the
  actor ([0002](0002-hash-chained-event-log.md)) but not `author_kind`.
- M1 must write the mapping command, decide what happens to local names that match no real
  principal, and start writing other `author_kind` values. It must also decide whether the kind
  should reach the wire format.
- Idempotency keys are unique per board and author name, so they inherit the same self-declared
  identity.
