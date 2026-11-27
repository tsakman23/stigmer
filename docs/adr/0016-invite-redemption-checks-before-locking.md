# 0016. Invite redemption checks before locking

Status: Accepted
Date: 2026-11-27

## Context

Redeeming an invite (`IdentityStore::consume_invite`, behind the unauthenticated join route) must
be atomic: member, credential, used mark and `Join` row in one transaction
([0008](0008-board-isolation-and-credentials.md)), and an unknown id must cost the same hash work
as a wrong secret, compared in constant time against a dummy hash
([0009](0009-token-and-invite-format.md)).

SQLite meets both in one `BEGIN IMMEDIATE` transaction: every caller, whatever it sends, takes
the same database-wide write lock before anything is checked, so no path waits differently from
another. Postgres has row locks instead. The obvious port (read the invite's board, lock the board
row, lock the invite row `FOR UPDATE`, then check) has two flaws there:

- **A timing oracle.** An unknown id is refused at once, but a known id waits for the board row
  lock, which posts, archives and other joins hold. How long a refusal takes tells an
  unauthenticated caller whether an invite id exists and how busy its board is.
- **Lock taking by unauthenticated callers.** Every attempt, even with a made-up secret, locks a
  board row and queues behind writers, so anyone who can reach the join route can stall a board's
  posts (only the join rate limit of [0011](0011-authentication-policy-401-403-404.md) bounds it).

## Decision

The Postgres `consume_invite` checks before it locks:

1. One read on the connection, outside any transaction and without a lock: the invite's stored
   hash, board, role, kind, expiry and used mark, and its board's archived flag. The secret's
   hash is compared in constant time (against `UNKNOWN_INVITE_HASH` when the id is unknown), and
   an unknown id, a wrong secret, an expired or used invite and an archived board are all refused
   here with the same `NotFound`. A refusal costs this one round trip and never touches a lock.
2. Only a matching invite that looks usable starts the transaction: it locks the board row, then
   the invite row `FOR UPDATE` (the order every multi-row write on a board uses), re-checks use,
   expiry and archive under the locks, since another join or an archive may have committed since
   the read, and then writes the member, the credential, the used mark and the `Join` row. A
   failed re-check is the same `NotFound`.

The stored hash is never re-read under the lock: an invite's hash, board, role and kind never
change after it is created.

## Consequences

- A refused join reveals nothing through its timing about the invite or its board, and an
  unauthenticated caller who lacks a valid secret can no longer take or wait on a board lock.
- Only a caller holding a valid, unused invite secret ever locks the board, and it can do so once
  per invite.
- A successful join costs one extra round trip (the unlocked read) and checks usability twice.
- Concurrent redemptions of one invite still queue on the board and invite rows, and exactly one
  finds the invite unused; the conformance suite checks this on both backends.
- Postgres tests pin the behaviour: a wrong secret or unknown id is refused while the board and
  invite rows are held by another transaction, and a right secret waits, then joins or is refused
  if the board was archived or the invite used meanwhile.
- SQLite is unchanged: its single database lock already treats every path alike.
