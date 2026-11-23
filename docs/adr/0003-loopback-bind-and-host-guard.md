# 0003. Loopback-only bind and the Host/Origin guard

Status: Accepted, amended; partly superseded by [0010](0010-tls-and-trusted-proxy.md) (the loopback-only bind no longer holds in network mode)
Date: 2026-11-21

## Context

M0 has no accounts or tokens, so anyone who can reach the port can read and post. The only
protection is that the board is reachable from the local machine alone. Binding to 127.0.0.1 is
not enough on its own: a web page on another site can point its own domain at 127.0.0.1 (DNS
rebinding) and send requests from the user's browser. Such requests carry the foreign name in
the Host or Origin header.

## Decision

Two layers:

1. `require_loopback` refuses to start `stigmerd serve` on any address that is not loopback
   (127.0.0.0/8 or ::1), with a clear error.
2. A middleware in `stigmer-api` (`require_loopback_host`) answers 403 `forbidden` unless the
   Host header and the Origin header, each when present, name loopback. An accepted authority is
   exactly `127.0.0.1`, `[::1]` or `localhost` (any case), optionally with a numeric port.
   Look-alikes, userinfo, paths and longer names are refused. An Origin must be
   `scheme://authority` and nothing more.

A request with no Host header is allowed: a browser always sends Host, so absence does not open
the rebinding hole, and simple clients are not broken.

The guard is a layer on the whole router, so unknown routes and wrong methods are covered too.

## Consequences

- Any client that sets its own Host (a curl command with `-H`) passes the guard. That is
  intended: the guard stops browsers, not local programs. Local programs are inside the trust
  boundary in M0.
- The allowed names are fixed in code. M1 adds a trusted-proxy mode where requests arrive with a
  public Host; the allowed hosts must then be configurable, and the loopback-only bind rule must
  give way to "a non-loopback bind requires auth" as the design states.
- Reaching the board by another local name (for example a hostname alias for 127.0.0.1) is
  refused until configuration exists.
- The guard is not a substitute for authentication. M1 tokens are still required before any
  remote use.

## Amendments

v0.1.0 shipped this ADR unamended. The M1 changes below are recorded as amendments because v0.2.0 is the next release; after v0.2.0 ships, this ADR is frozen and a change needs a new ADR that supersedes it.

- 2026-11-22: the loopback-only bind rule is superseded by [0010](0010-tls-and-trusted-proxy.md), which also adds `--allowed-host` to this guard's allow-list. The Host/Origin guard itself stands; the rest of the text is as shipped.
- 2026-11-23: the status says "partly superseded by 0010", from the new status vocabulary.
