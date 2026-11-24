# 0014. Audit rows in the mutation transaction

Status: Accepted
Date: 2026-11-24

## Context

In M1 only two security log rows were written in the transaction of the change they record:
`Join` (`consume_invite`) and `principals_adopted` (`adopt_local_authors`). Every other admin
mutation (board create and archive, invite create, token revoke, member remove, and the
`stigmerd admin` token commands) changed the store first and appended its row afterwards with a
separate `log_security` call, best effort: a failed write left the mutation standing and printed
a warning ([0008](0008-board-isolation-and-credentials.md), whose context named this as M2
work). Archive was two store calls as well, archive then revoke, with a retry completing the
second step after a failure. `stigmerd admin enable-auth` ordered its calls (credential and
invite while still local, then the one-way switch, then the rows) so that a failure never
stranded the instance, and reported a log failure after the secrets were already valid.

With more than one replica (M2) a crash or failover between the mutation and its row loses the
row for good, and an operator reading the security log cannot tell a missing row from an action
that never happened. Two options were considered: keep the best-effort writes, or pass the row
into each mutating store method and write it in the same transaction. The second costs one
parameter per method and a different failure mode, and removes a class of half-done states.

## Decision

This replaces the best-effort rule for admin mutation rows recorded in
[0008](0008-board-isolation-and-credentials.md) (and its two-step archive) and the best-effort
assumption behind [0011](0011-authentication-policy-401-403-404.md)'s security log; 0011's
logging of failed authentications and rate-limited requests stands as written.

- Every audited mutation takes the security log row that records it and the store writes it in
  the same transaction: `Store::create_board` and `Store::archive_board` (which also gain a
  `now_ms` parameter instead of reading the store's clock), and `IdentityStore`'s
  `enable_network_mode`, `remove_member`, `create_credential`, `revoke_credential`,
  `replace_instance_credential` and `create_invite`. The row is stored as given, stamped
  `audit.at_ms`; callers pass the same instant as `now_ms`.
- A mutation that fails writes no row and changes nothing; one that changes nothing (archiving
  an archived board, revoking a revoked credential) writes no row; a row that cannot be written
  fails the mutation, which then changes nothing.
- New `IdentityStore::archive_board_revoking` archives a board and revokes every live non-admin
  credential on it, with its row, in one transaction. The API's archive route calls it once.
- New `IdentityStore::enable_network` stores the instance credential and the optional main admin
  invite, switches to network mode and writes the `ModeEnabled`, `InstanceTokenIssued` and
  optional `InviteCreated` rows in one transaction; an instance already in network mode is
  `AlreadyNetwork` and nothing is written. `stigmerd admin enable-auth` calls only this, so its
  secrets are printed only after everything committed, and a failure shows none and leaves
  local mode. `enable_network_mode` stays for direct use.
- The API returns the generic 500 body when a mutation's row cannot be written: the mutation did
  not happen, so the client may retry. `stigmerd admin` commands fail (exit 1) the same way and
  print no secret.
- `log_security` stays for events that record no mutation (failed authentication, rate limits,
  including the join limit). Those stay best effort: a failed write is a warning and the response
  is unchanged, because failing a 401 or 429 for want of a log row would change the answers that
  [0011](0011-authentication-policy-401-403-404.md) fixes and would let a log outage turn
  refusals into errors.
- `SecurityEvent` details keep coming only from the typed constructors in `stigmer-api`
  (`audit.rs`) and `stigmerd` (`admin`). The store composes a detail of its own in three places
  only: the two rows it already wrote itself (`Join`, `principals_adopted`) and one exception
  added here: when `replace_instance_credential` revokes other instance credentials, it writes,
  after the caller's row and in the same transaction, a `TokenRevoked` row (no board, the
  caller's principal and time, detail "revoked N other instance credentials"). N is only known
  inside the transaction, so the caller cannot build that row; when N is 0 there is no such row.

## Consequences

- No half-done admin mutation: the store holds the change and its row, or neither. The window in
  which an archived board still had live member credentials is gone.
- A security log that cannot be written now makes admin mutations fail (500) instead of
  succeeding silently; authentication and rate limiting are unaffected.
- `new-instance-token --revoke-others` keeps M1's two rows, `InstanceTokenIssued` for the new
  token and `TokenRevoked` with the count, now both in the replacing transaction.
- Every backend (the Postgres store of M2 included) must write these rows in its mutation
  transactions; the conformance suite checks one row per change, none for a repeat or a
  failure, and the all-or-nothing `enable_network`. SQLite's rollback on a failed row is
  tested with a trigger that refuses every `security_log` insert.
- Test doubles that wrap a store cannot make the in-transaction row fail; they fail the mutation
  instead, which is what a failed row looks like from outside.
