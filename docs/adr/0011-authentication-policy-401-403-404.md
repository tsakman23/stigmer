# 0011. Authentication policy: 429, 401, 404, 403

Status: Accepted; amended 2026-11-22 (M1 final review: join order, open waits)
Date: 2026-11-22

## Context

In network mode every request must be authenticated, and the answers must not help an attacker:
not by telling which tokens or invites exist, not by telling whether a board exists, and not by
allowing unlimited guessing. Clients still need distinct, predictable outcomes to act on (join
again, ask an admin, slow down). Design M1 sections 6.4 and 11.6 set the policy; this records
how it was built (`stigmer-api`: `routes.rs`, `auth.rs`, `ratelimit.rs`, `join_routes.rs`).

## Decision

- **Layer order.** In network mode a request without the server-set `PeerAddr` is refused first
  (500, [0010](0010-tls-and-trusted-proxy.md)). Then the host guard refuses a foreign Host or
  Origin (403, [0003](0003-loopback-bind-and-host-guard.md)). On board routes the
  authentication middleware answers 429, then 401. Each handler then answers 404 (board not
  visible), then 403 (the authorizer), and only then the request's own errors (400, a missing
  thread, 409).
- **One 401.** A missing, malformed, unknown, wrong-secret, expired or revoked token, and a token
  whose holder is no longer a member, all get the same 401 body (`unauthorized`, "invalid or
  expired credentials"). So does an events wait whose credential was revoked, expired or lost
  its membership while it waited: it re-checks the credential at every wake and never returns
  events to it. Each wake costs up to two store reads (`find_credential`, then `get_member`
  for a board token), so the extra load is bounded by `max_waits` times the board's event rate;
  if that ever matters, the re-check can be limited to wakes whose next read would return
  events. Likewise every unusable invite on `POST /v1/join` (unknown, wrong secret,
  expired, used, archived board) is the same 401. See [0009](0009-token-and-invite-format.md) for
  the constant-time comparison and the dummy hash.
- **Existence hiding.** A board credential gets the same 404 `no such board` for every other
  board name, existing or not, decided before the store is asked. Within its own board the
  authorizer runs before any thread is looked up, so a 404 for a thread says nothing to someone
  without access. The instance credential sees every board (404 only for one that does not
  exist) and gets 403 on content routes.
- **Rate limiting by source, atomically.** Failed authentications are limited per source (10 per
  minute; IPv4 per address, IPv6 per /64), checked before any credential is looked at. Every
  request reserves one token from its source's bucket under the same lock as the check, and a
  request that authenticates gives it back, so concurrent guesses cannot overrun the limit. The
  limit is keyed by source only, not by token id (the design said both): a 256-bit secret cannot
  be guessed, so a per-id limit adds no protection, while it would let anyone who knows an id
  (board admins see them in `token list`) lock that token out. A limited request gets 429 `rate_limited` with
  `Retry-After`; because the limit is checked first, the 401 body never varies.
- **Configurable budgets.** `stigmerd serve` sets the three request budgets:
  `--auth-failures-per-minute` (default 10, 1 to 10,000), `--join-per-minute` (default 10, 1 to
  10,000) and `--max-waits` (concurrent waiting event reads, default 256, 1 to 100,000; one more
  gets 429). A value out of range exits 2 before anything starts.
- **Bounded memory, failing closed.** At most 10,000 sources are tracked per limiter. When the
  table is full of busy buckets, a source not yet tracked is refused (429) until idle entries
  can be pruned, about a minute. The trade-off: an attacker with enough addresses can lock out
  new clients for that time, instead of growing memory without bound.
- **Join has its own budget.** `POST /v1/join` takes no token; every attempt, successful or not,
  spends one of 10 per source per minute, separate from the failed-authentication budget. The
  budget is reserved before the body is read, so a limited client gets its 429 at once and
  cannot hold the request open by sending its body slowly. A join body that does not parse gets
  one generic 400 ("invalid join request") that echoes nothing the caller sent, as a swapped
  field would otherwise put the invite into the error.
- **Security log.** Failed authentications and rate-limited requests are logged with the source
  (and a parsed token's id), at most once per source per minute per kind; never a secret.
- **Open routes.** `/healthz`, `/readyz` and `POST /v1/join` need no token. The unknown-route
  404 and wrong-method 405 fallbacks are unauthenticated by design: they reveal only the public
  shape of the API.

## Consequences

- Clients map outcomes to actions: the CLI exits 6 (401: join or log in again), 7 (403: ask a
  board admin), 4 (404: check the board and id) and 8 (429: wait `Retry-After` seconds).
- A user behind a shared address (NAT, a proxy not declared with `--trusted-proxy`) shares one
  failure budget with everyone there.
- Limiter state is in memory per process. M2 (replicas) multiplies the budget by the number of
  replicas unless the state moves to the database or a shared cache.
