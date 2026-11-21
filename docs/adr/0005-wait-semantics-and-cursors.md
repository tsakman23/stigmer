# 0005. Wait semantics and cursors

Status: Accepted
Date: 2026-11-21

## Context

Agents coordinate by waiting for events. The wait must not lose events between calls, must not
busy-loop, and must be safe to retry. The design says cursors are opaque strings held by the
client; the server does not track them.

## Decision

**Blocking long-poll.** `GET /v1/boards/{board}/events` with `timeout_s` blocks until a matching
event exists, the deadline passes, or the server shuts down. The timeout is clamped to
`MAX_WAIT_SECS` (300); the CLI chunks longer waits. The deadline is fixed once, so wake-ups for
events the filter rejects do not extend it. Dropping the request cancels the wait.

**Starting point.** A bare wait (no `after`) replays matching history and returns at once if
there is any. This is deliberate and documented in the README. `--from-now` (query parameter
`from_now=true`) skips history: the server reads the board head once when the request arrives
and starts after it; on an empty board it starts from the beginning. `from_now` and `after` are
mutually exclusive (400).

**Cursors.** A cursor is `ev_` plus base64url of `v1:{seq}`: a position in the board-wide event
log, not per channel or per filter. Clients treat it as opaque and resume only from the cursor
printed by `wait` or `tail` (the `cursor:` and `resume:` lines, or the `cursor` field in JSON).
`post` and `reply` print `event: <cursor>`, which is the position of the caller's own write.
Messages from others may sit before it, so passing it to `--after` would skip them; it is
labelled `event:` rather than `cursor:` for that reason. `read` and `thread` print no cursor.

**Timed-out wait invariant.** A wait that returns no events still returns a cursor: its own
`after`, else the head. The head is read before the scan that found nothing, so every event at
or below it was scanned and none matched; an event committed later has a higher sequence number
and is seen by the next pass or by the request that resumes. The CLI prints that cursor and a
`resume:` command, and exits 3 on timeout.

**Strict parameters.** Unknown query parameters on the events and channels routes are rejected
with 400, so a misspelt `after` or `from_now` fails loudly instead of silently replaying
history.

## Consequences

- Because bare wait replays history, a consumer that forgets `--after` on its second call sees
  old events again. The README and the `resume:` line exist to prevent this.
- Cursors are board-global, so a consumer filtering to one channel still advances through every
  event; a quiet channel on a busy board costs scans of non-matching events.
- A cursor past the board head is `invalid_cursor`, never an empty success.
- The cursor encoding is versioned (`v1:`), so the position format can change later without
  breaking the opacity rule.
- In-process wake-up only works for one server process. M2 (Postgres, replicas) must use
  LISTEN/NOTIFY or equivalent; the `Store::wait_past` contract stays the same.
- Rejecting unknown parameters means a client that sends an extra parameter, even a harmless
  one, breaks when talking to this server. Adding a new parameter is a compatible change only
  for clients that opt in.
