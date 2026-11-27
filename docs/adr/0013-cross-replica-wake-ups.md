# 0013. Cross-replica wake-ups

Status: Accepted, amended
Date: 2026-11-27

## Context

A wait (`Store::wait_past`, behind the long-poll events route of
[0005](0005-wait-semantics-and-cursors.md)) must wake when a post commits. SQLite does this with
an in-process notifier: one `watch` channel per board, bumped after the commit, and a waiter
that subscribes before it reads the head, so no commit falls between the read and the sleep. With
Postgres several server processes share one database, and a post through one replica must wake
waits on every other. Until this change the Postgres backend polled the head every 100 ms: correct,
but each waiting request cost ten queries a second, and a wake took up to 100 ms.

Options considered: (a) every replica polls the heads of the boards it has waiters on, on a short
interval; (b) Postgres LISTEN/NOTIFY with a slow poll as a safety net; (c) an external broker. (c)
adds a service to run for no gain over (b). (a) trades latency against load and never gets both.

## Decision

**NOTIFY inside the post's transaction.** The last statement of a post before its commit is
`SELECT pg_notify('stigmer_events', '<schema>:<board>:<seq>')`. Postgres delivers a
notification only when, and after, its transaction commits, so a listener never hears of a post
that rolled back, and by the time it hears of one the head it names is visible to every reader.
An idempotent replay writes nothing and notifies nothing.

**The payload names the schema.** NOTIFY channels are per database, not per schema. Stores in
different schemas of one database (every Postgres test does this, and a shared database could)
would otherwise wake each other's waits on boards with the same id. So the payload starts with
the posting connection's `current_schema()`, and a listener applies only payloads for its own
`current_schema()`; anything else, or anything malformed, is ignored. The channel name stays one
fixed `stigmer_events` (a channel per schema would run into the 63-byte identifier limit). The
payload carries the schema, the board id and the sequence number, never message content.

**One listener connection per process.** Each store handle (one per server process) opens a
dedicated connection, not taken from the pool, that runs `LISTEN stigmer_events` and feeds the
same per-board `watch` notifier SQLite uses, with the same contract: a wait subscribes, then
reads the head through the pool (one statement, connection returned at once), then sleeps on its
subscription. An entry exists only while a wait holds a receiver on it; a notification or poll
updates existing entries and never creates one, so notifications for unknown boards, archived
boards and boards nobody waits on leave nothing behind. Archiving a board through a handle drops
that handle's entry for it; on other handles the safety poll or a reconnect re-read does (it
sees the board archived). Either way the board's final head, read under the archive's row lock
or by the re-read, is delivered to the entry before it is dropped, so a wait for a post that
committed just before the archive, whose notification had not arrived yet, still wakes.

**Started by the first wait that sleeps.** `PgStore::connect` opens no listener connection and
starts no safety poll. The first wait that has to sleep starts both, after it has subscribed and
read the head; the listener's first re-read covers any commit in between. A wait that returns at
once (the head is already past its cursor, the cursor or board is invalid, the board is
archived) starts nothing, so one-shot users such as `stigmerd` admin commands, and stores that
never wait, open no connection beyond their pool. Concurrent first waits start exactly one
listener. If the listener cannot be started (say, behind a transaction-mode pooler), that wait
fails with a backend error naming the target and the need for a direct or session-pooled
connection; waits within the listener's backoff then fail at once with the same error, and the
first wait after it tries again. Each listener connection carries `application_name`
`stigmer-listener`.

**Reconnect, then re-read.** When the listener connection fails it reconnects with exponential
backoff from 100 ms doubling to 10 s; the backoff goes back to 100 ms only after a session has
stayed up for 10 s, so a connection that drops straight after LISTEN does not reconnect in a
tight loop. Opening the listener (connect, LISTEN, re-read) is bounded by a 10 s timeout, so an
address that swallows packets cannot stall the reconnect loop. Every (re)connect runs LISTEN
first and then re-reads the heads of the boards that have waiters: a post that committed before
LISTEN took effect is seen by the read, any later one is notified, so the gap in which the
listener was down loses no wake.

**A slow safety poll.** From the listener's start on, every poll interval (default 2 s, accepted
from 100 ms to 60 s, an option of `PgStore::connect`; the hidden `--db-poll-interval-ms` server
flag that sets it comes with backend selection in `stigmerd`, [0012](0012-postgres-backend-and-selection.md)), while any board has waiters, each
handle re-reads through the pool, in one statement, the heads of the boards that have waiters. It covers a listener that is down or silently cut off: such a wake is
late by at most the interval, never lost, and a dead listener never wedges a wait.

## Consequences

- A post wakes waits on every replica within one round trip of its commit in the normal case.
  The Postgres conformance run, whose stores poll only once an hour, went from about 10 s with
  100 ms polling to about 5 s, and its summary line now reports `cross_process_wake=true`: the
  cross-handle wake scenarios pass only because NOTIFY works.
- Idle waits cost nothing on the database; a board with waiters costs one indexed read per handle
  per poll interval, whatever the number of waiters on it.
- Each server process that has served a wait holds one extra database connection outside its
  pool; a process that never waits holds none. Connection budgets (`max_connections` on the
  server, a pooler's limits) must allow for it. A transaction-mode
  pooler such as PgBouncer in transaction mode does not support LISTEN; the listener needs a
  direct or session-mode connection. Because the listener starts lazily, such a setup shows up
  as waits failing with that backend error, not as a server that will not start.
- A wait never holds a pooled connection or a transaction while it sleeps, so many waits cannot
  starve writers of connections (tested with twenty waits on a pool of two).
- While the listener is down, a wake is late by at most the poll interval: the safety poll runs
  through the pool and does not depend on the listener or its reconnect backoff. A half-open TCP
  connection is noticed only by TCP keepalives; the safety poll bounds the delay meanwhile.
- NOTIFY payloads are queued in the database (8 GB by default) until every listening session
  has read them. A session that LISTENs but stops reading without disconnecting holds the queue
  back; when the queue is full, every post fails at commit with "too many notifications in the
  NOTIFY queue" and rolls back, so no post is lost but none can be made. The listener reads
  continuously into an in-process channel, so this takes a stuck process, not slow waiters.
  Operators monitor it: `pg_notification_queue_usage()` reports how full the queue is, and
  once it is half full Postgres logs warnings naming the session that holds it back.
- Tests can set the safety poll to an hour (a hidden constructor for tests only) to prove a wake
  came through NOTIFY, and terminate the listener's backend to prove a reconnect loses nothing.
  The wake-time assertion in those tests is a generous 5 s: the hourly poll, not the bound, is
  what proves NOTIFY delivered the wake.

## Amendments

- 2026-11-27: link the server flag for the poll interval to [0012](0012-postgres-backend-and-selection.md), which records it.
