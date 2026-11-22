# Architecture decision records

An ADR is a short note that records one decision that shapes the design: what forced the choice, what was chosen, and what it costs. ADRs are written in the same branch that makes the change (see [CONTRIBUTING.md](../../CONTRIBUTING.md)). An accepted ADR is not edited to change history; a later decision supersedes it with a new record, and the old record's status becomes "Superseded by NNNN".

## Adding one

1. Copy [0000-template.md](0000-template.md) to `docs/adr/NNNN-short-title.md`, using the next free number.
2. Fill in Context, Decision and Consequences. Say what the decision costs and what a later milestone must change.
3. Add a row to the index below.

## Index

| Number | Title | Status |
|---|---|---|
| [0001](0001-storage-behind-a-trait.md) | Storage behind a trait with a shared conformance suite | Accepted; amended for M1 |
| [0002](0002-hash-chained-event-log.md) | Hash-chained, gapless per-board event log | Accepted |
| [0003](0003-loopback-bind-and-host-guard.md) | Loopback-only bind and the Host/Origin guard | Accepted; bind rule superseded by [0010](0010-tls-and-trusted-proxy.md) |
| [0004](0004-authorization-seam.md) | Authorization seam | Accepted; amended for M1 |
| [0005](0005-wait-semantics-and-cursors.md) | Wait semantics and cursors | Accepted; amended for M1 |
| [0006](0006-untrusted-data-framing.md) | Untrusted-data framing | Accepted; amended for M1 |
| [0007](0007-local-principals.md) | Local principals | Accepted; mapping implemented in M1 |
| [0008](0008-board-isolation-and-credentials.md) | Board isolation and credentials | Accepted; amended in the M1 final review |
| [0009](0009-token-and-invite-format.md) | Token and invite format | Accepted; amended in the M1 final review |
| [0010](0010-tls-and-trusted-proxy.md) | TLS and trusted proxies | Accepted; amended for M1 |
| [0011](0011-authentication-policy-401-403-404.md) | Authentication policy: 429, 401, 404, 403 | Accepted; amended in the M1 final review |
