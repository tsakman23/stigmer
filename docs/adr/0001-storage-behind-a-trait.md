# 0001. Storage behind a trait with a shared conformance suite

Status: Accepted; amended 2026-11-22 for M1 (unknown-board contract closed)
Date: 2026-11-21

## Context

The design promises SQLite for the solo case and Postgres for shared deployments (milestone M2),
with the same behaviour on both. The guarantees that matter are a gapless per-board event
sequence, read-your-writes and visibility in commit order. If each backend were tested only by
its own tests, they would drift.

## Decision

All storage goes through the `Store` trait in `stigmer-store`. Callers are generic over `S:
Store`; the trait is deliberately not object-safe (its methods return `impl Future`), so there
is no `dyn Store`. This avoids boxing every future and keeps the `Send` bound checked at compile
time.

SQLite (`stigmer-store-sqlite`) is the default and only backend in M0.

`stigmer-store-conformance` holds one suite of scenarios, run with `run_all` against a factory
that builds a fresh store. Every backend must pass the whole suite; a new backend is not
accepted without it.

Failures are the typed `StoreError` (`NotFound`, `InvalidCursor`, `Conflict`, `Backend`).
`NotFound` carries an `Entity` (`Board`, `Thread`, `Message`), and each trait method documents
which entity it reports. For example, an unknown board is `Entity::Board` for `post`,
`read_channel`, `events_after`, `head`, `wait_past` and `verify_chain`; and `read_thread`
reports `Entity::Thread` for any id that is not a thread root on the board, including any id on
an unknown board.

Postgres is planned for M2.

## Consequences

- Backends are interchangeable only as far as the suite goes. In M0 the suite did not test
  unknown-board handling in `verify_chain`, `wait_past` and `read_channel`, and `read_channel`
  returned an empty list for an unknown board. Since M1 an unknown board is `NotFound` with
  `Entity::Board` from every `Store` method that takes a board (still except `read_thread`,
  which reports the thread), and the conformance suite pins it for every method. Archived
  boards refuse `post` (and the identity writes) with `Conflict(BoardArchived)` while reads keep
  working; the archive is checked before the idempotency key, so a keyed retry of a post that
  had already committed gets 409 `board_archived`, which does not mean the original write
  failed ([0008](0008-board-isolation-and-credentials.md)).
- Generic callers mean the server binary picks its backend at compile time. Choosing a backend
  at runtime (config file in M1/M2) will need an enum wrapper or a generic entry point per
  backend.
- The `not found` entity contract is part of the trait and must be reproduced by every backend,
  including its odd case (the `read_thread` rule above).
- M2 must add the Postgres backend, run the same suite against it, and extend the suite with the
  cross-replica wake-up scenario, since the SQLite notifier is in-process only.
- The suite's timing-based scenarios use real sleeps and timeouts, which can be slow or flaky on
  loaded machines.
