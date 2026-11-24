# Architecture decision records

An ADR is a short note that records one decision that shapes the design: what forced the choice, what was chosen, and what it costs. ADRs are written in the same branch that makes the change (see [CONTRIBUTING.md](../../CONTRIBUTING.md)). Until the release that first ships an ADR, it may be amended in place; every amendment is listed in an Amendments section at the end of that ADR (date, one line what and why). After that release, a change needs a new ADR that supersedes it, and the old record's status becomes "Superseded by NNNN".

ADRs 0001 and 0003 to 0007 shipped in v0.1.0, before this rule existed, and were amended during M1. Their amendments are recorded the same way and they freeze when v0.2.0 ships.

## Status

- **Accepted**: as written when accepted.
- **Accepted, amended**: changed in place before its first release; the Amendments section lists each change.
- **Partly superseded by NNNN**: part of the decision is replaced by a later ADR, which is linked; the rest stands. Combined with the other statuses, for example "Accepted, amended; partly superseded by 0010".
- **Superseded by NNNN**: replaced by a later ADR, which is linked.

## Adding one

1. Copy [0000-template.md](0000-template.md) to `docs/adr/NNNN-short-title.md`, using the next free number.
2. Fill in Context, Decision and Consequences. Say what the decision costs and what a later milestone must change.
3. Add a row to the index below.
4. To amend an ADR that no release has shipped yet, edit it, set its status to "Accepted, amended", add a line to its Amendments section and update its row below. Once a release has shipped it, write a new ADR instead.

## Index

| Number | Title | Status |
|---|---|---|
| [0001](0001-storage-behind-a-trait.md) | Storage behind a trait with a shared conformance suite | Accepted, amended |
| [0002](0002-hash-chained-event-log.md) | Hash-chained, gapless per-board event log | Accepted |
| [0003](0003-loopback-bind-and-host-guard.md) | Loopback-only bind and the Host/Origin guard | Accepted, amended; partly superseded by [0010](0010-tls-and-trusted-proxy.md) |
| [0004](0004-authorization-seam.md) | Authorization seam | Accepted, amended |
| [0005](0005-wait-semantics-and-cursors.md) | Wait semantics and cursors | Accepted, amended |
| [0006](0006-untrusted-data-framing.md) | Untrusted-data framing | Accepted, amended |
| [0007](0007-local-principals.md) | Local principals | Accepted, amended |
| [0008](0008-board-isolation-and-credentials.md) | Board isolation and credentials | Accepted, amended; partly superseded by [0014](0014-audit-rows-in-the-mutation-transaction.md) |
| [0009](0009-token-and-invite-format.md) | Token and invite format | Accepted, amended |
| [0010](0010-tls-and-trusted-proxy.md) | TLS and trusted proxies | Accepted, amended |
| [0011](0011-authentication-policy-401-403-404.md) | Authentication policy: 429, 401, 404, 403 | Accepted, amended |
| [0014](0014-audit-rows-in-the-mutation-transaction.md) | Audit rows in the mutation transaction | Accepted |
| [0015](0015-thread-summaries-and-sequence-ordering.md) | Thread summaries and sequence ordering | Accepted |
