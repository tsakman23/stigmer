# 0004. Authorization seam

Status: Accepted
Date: 2026-11-21

## Context

The design puts a single authorization module behind every request, and says M1 enforces coarse
roles through the same seam so that M4 (per-channel grants) changes the module and not the
callers. The design placed the seam in M1. Adding it later means touching every route, so M0
adds it now.

## Decision

`stigmer-api` defines the `Authorize` trait:

```rust
fn check(&self, who: &Principal, action: Action, channel: Option<&ChannelPath>)
    -> Result<(), Denied>;
```

`Action` is `Read` or `Post`. Every route that reads or writes board data calls `check` (reads
and posts alike); `/healthz` and `/readyz` do not. Handlers resolve the channel the request concerns,
then call `check` before returning data or writing. `channel` is `Some` when the request concerns one channel path (a channel prefix,
a thread's channel, the target channel of a post) and `None` for a board-wide read. `None` means
board-wide, not "no restriction"; an implementation that scopes by channel must decide what
board-wide means for the principal.

M0's only implementation is `AllowAll`, passed to the router by `stigmerd`. A denial is the
`forbidden` error.

Known weak point, to be fixed in M4: an events request filtered by thread but not by channel is
checked as board-wide today, because the route does not look up the thread's channel. With
grants, that route MUST resolve the thread's channel and check it, or a principal could read a
channel's events through a thread filter.

## Consequences

- The trait is synchronous. Real checks in M1 and later (token lookup, grant lookup in the
  store) will need I/O, so M1 will likely make `check` async. Routes call it in one place each,
  so the change is mechanical but touches every route and the trait's implementors.
- `Action` has two verbs. The design's verbs (label, react, task.create, task.claim, admin)
  arrive with their milestones.
- Replies and thread reads look up the thread in the store before authorization, because the
  channel comes from the stored thread. An unknown thread is therefore not found before it can be
  forbidden. M1 should decide whether that ordering leaks the existence of threads.
- `AllowAll` never denies. The API tests use a `DenyAll` test double to check that routes refuse;
  M1 must add coverage for its first real implementation.
