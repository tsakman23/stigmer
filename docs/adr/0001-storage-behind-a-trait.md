# 0001. Storage behind a trait with a shared conformance suite

Status: Accepted
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
`events_after`, `head`, `wait_past` and `verify_chain`; `read_thread` reports `Entity::Thread`
for any id that is not a thread root on the board, including any id on an unknown board; and
`read_channel` on an unknown board is an empty list, not an error.

Postgres is planned for M2.

## Consequences

- Backends are interchangeable only as far as the suite goes. Behaviour the suite does not test
  (for example unknown-board handling in `verify_chain`, `wait_past` and `read_channel`) can
  differ between backends. Closing those gaps is listed in [design.md section 13](../design.md).
- Generic callers mean the server binary picks its backend at compile time. Choosing a backend
  at runtime (config file in M1/M2) will need an enum wrapper or a generic entry point per
  backend.
- The `not found` entity contract is part of the trait and must be reproduced by every backend,
  including its odd cases (the `read_thread` and `read_channel` rules above).
- M2 must add the Postgres backend, run the same suite against it, and extend the suite with the
  cross-replica wake-up scenario, since the SQLite notifier is in-process only.
- The suite's timing-based scenarios use real sleeps and timeouts, which can be slow or flaky on
  loaded machines.
