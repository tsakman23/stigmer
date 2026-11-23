# 0004. Authorization seam

Status: Accepted; amended 2026-11-22 for M1 (async check, roles)
Date: 2026-11-21

## Context

The design puts a single authorization module behind every request, and says M1 enforces coarse
roles through the same seam so that M4 (per-channel grants) changes the module and not the
callers. M0 added the seam early, with a synchronous `check` and an allow-all implementation, so
that adding it later would not mean touching every route. M1 needed real checks, with roles per
board and a credential that manages the instance.

## Decision

`stigmer-api` defines an async `Authorize` trait (since M1):

```rust
fn check(&self, who: &Authenticated, action: Action, scope: &Scope<'_>)
    -> impl Future<Output = Result<(), Denied>> + Send;
```

- `Authenticated` is who is calling, set once per request by the authentication middleware:
  principal, kind, credential scope (one board or the instance), role on that board (`None` for
  the instance credential) and credential id. In local mode it is the `X-Stigmer-As` name (reads
  default to `anonymous`) with the instance scope, the admin role and no credential.
- `Action` is `Read`, `Post`, `ManageMembers` (members, invites, tokens; archiving one's own
  board) or `ManageBoards` (create, list and archive any board).
- `Scope` is `Instance` or `Board { board, channel }`. `channel: None` means the whole board,
  not "no restriction". In M1 every caller passes `None`; per-channel grants arrive in M4.

Every route that reads or writes board data, and every management route, calls `check` once
after resolving the board (a board outside the caller's scope is 404 first,
[0011](0011-authentication-policy-401-403-404.md)) and before touching data. A denial is 403
`forbidden`. `/healthz`, `/readyz`, `/v1/whoami` and `POST /v1/join` do not call it.

Implementations: `AllowAll` (local mode, loopback only) and `RoleAuthorize` (network mode):

| Caller | Read | Post | ManageMembers | ManageBoards |
|---|---|---|---|---|
| board admin, own board | yes | yes | yes | no |
| board member or bridge, own board | yes | yes | no | no |
| any board credential, other board or instance scope | no | no | no | no |
| instance credential, any scope | no | no | yes | yes |

Known weak point, to be fixed in M4: an events request filtered by thread but not by channel is
checked as board-wide, because the route does not look up the thread's channel. With grants,
that route MUST resolve the thread's channel and check it, or a principal could read a channel's
events through a thread filter.

## Consequences

- Local mode stays exactly M0: loopback, no authentication. Every caller is the instance scope
  with the admin role under `AllowAll`, so anyone on the machine can create boards and archive
  any board but `main`. This is by design; network mode is the access-controlled mode.
- `check` is async so M4 can consult grants in the store; `RoleAuthorize` itself does no I/O
  (the membership and role were read during authentication).
- The design's other verbs (label, react, task.create, task.claim) arrive with their milestones;
  `Action` grows with them, and every implementation must decide each new verb.
- Authorization runs before any thread is looked up, so within a board a missing thread is 404
  only to callers allowed to read the board. M0's ordering question (does a thread lookup before
  authorization leak existence) is settled by this.
- The API tests use a deny-all test double to check that routes refuse, and a matrix test pins
  `RoleAuthorize`. M4 must replace the matrix with grant scenarios.

Amended 2026-11-22 (M1): the M0 trait was synchronous, `check(&self, who: &Principal, action,
channel: Option<&ChannelPath>)` with `Action` `Read` or `Post` and only `AllowAll`.
