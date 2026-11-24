# 0015. Thread summaries and sequence ordering

Status: Accepted
Date: 2026-11-24

## Context

`read_channel` lists the threads under a channel prefix, most recent activity first, with keyset
pagination on a thread id (`Page.before`). Through v0.2.0 the SQLite backend computed every
summary on each call: for each thread root, correlated subqueries counted its replies and took
the largest message time, and the listing was ordered by that time, then by thread id. The cost
grows with the number of messages under the prefix on every page, and the ordering depended on
wall clocks: posts in the same millisecond were ordered by their random ids, and a clock that
stepped back (or, in M2, two replicas whose clocks disagree) put a newer thread below an older
one. The board already has an order that does not depend on clocks: the per-board event
sequence ([0002](0002-hash-chained-event-log.md)).

Options considered: keep computing summaries per read and only change the ordering key (still a
scan of messages per page); a materialized summary maintained by triggers (backend-specific and
invisible in the code that posts); or a summary table written by the post transaction itself.

## Decision

- Each backend keeps a `threads` table, one row per thread root: board, thread id, channel,
  preview (the first 200 characters, not bytes, of the root text), reply count, the sequence
  of the thread's first event (the root's) and of its latest event, and the time of its latest
  message. The post transaction writes it, together with the message, labels, event and head:
  a new thread inserts its row (no replies, first and last sequence the new event's, the
  message time); a reply adds one to the count and sets the last sequence and time to its own.
  An idempotent replay and a refused post (archived board, unknown thread) write nothing.
- `read_channel` reads only this table: whole-segment prefix match as before (no `LIKE`),
  ordered by the last event sequence, descending, then by thread id, descending, with keyset
  pagination on that pair. `Page.before` stays a thread id; its last sequence is looked up in
  the table, and a `before` that is not a thread root on the board is still `NotFound` with
  `Entity::Thread`. `limit` is still clamped to 1..=200.
- The ordering key is the sequence, not the time. `ThreadSummary` and the wire shape do not
  change: `last_at_ms` is still the time of the latest message in the thread (root included),
  where "latest" means latest by sequence.
- SQLite migration 8 creates the table and backfills it in the same migration from `messages`
  and `events`, giving every existing thread exactly the row the write path would have produced
  for the same messages (reply count from messages, first sequence from the root's event, last
  sequence and time from the thread's latest event and its message). A thread root without an
  event fails the migration instead of disappearing from listings. The backfill is tested
  against a v7 database built with the shipped migrations, column by column.

## Consequences

- A channel page costs one index range read (`board_id, last_seq DESC, thread_id DESC`) instead
  of subqueries over every message under the prefix; a post costs one more row write.
- The ordering change is observable only for threads whose wall-clock order and sequence order
  disagree: posts within the same millisecond, or a clock that stepped back. For those, the
  thread with the later event now comes first, and `last_at_ms` can be earlier than that of a
  thread listed after it. Elsewhere the listing is unchanged.
- For such a thread, `last_at_ms` is now the latest message's time by sequence, not the largest
  time in the thread; the two differ only when a clock stepped back within the thread.
- The Postgres backend (M2) must create the same table in its schema, write it in its post
  transaction under the board row lock, and read it the same way; the conformance suite checks
  ordering with tied times, a reply moving its thread to the top, deep pagination, summaries
  under concurrent posts and after a seeded random mix of posts, replies and replays.
- A replica of an older version would not maintain the table, so upgrading across migration 8
  needs all replicas stopped first (design section 11, call 2).
