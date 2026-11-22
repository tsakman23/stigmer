# 0010. TLS and trusted proxies

Status: Accepted; amended 2026-11-22 for M1 (HTTP/2 compiled out, PeerAddr, proxies, connection and body limits)
Date: 2026-11-22

## Context

ADR 0003 kept the M0 board on loopback with `require_loopback`. M1 adds tokens (network mode),
and the design (section 6.7) lets a board be reached from other machines either over TLS served
by `stigmerd` itself or through a reverse proxy that terminates TLS. Tokens must never cross a
network in clear text, a proxy's `X-Forwarded-For` must only be believed from the proxy, and
rate limiting needs the real peer address of every connection.

## Decision

- The bind rule replaces `require_loopback` (deleted from `stigmer-api`): a loopback bind is
  always allowed; any other bind needs network mode **and** either `--tls-cert`/`--tls-key` or
  `--trusted-proxy`, else `stigmerd serve` exits 2 naming what is missing. A missing data
  directory is local mode, so a non-loopback bind is refused before anything is created.
- `stigmerd` runs its own accept loop instead of `axum::serve`. Each connection inserts
  `PeerAddr` into its requests. `PeerAddr` is mandatory in network mode: the outermost layer of
  the router answers 500 `internal` to a request without it, and warns once on stderr, rather
  than putting every client into one shared rate-limit bucket (fail closed). The loop caps open
  connections (`--max-connections`, default 1024; the excess is dropped unanswered), caps them
  per source address too (`--max-connections-per-source`, default 64, 1 to 100000; IPv4 per
  address, IPv6 per /64 like the rate limiters; the excess is accepted and dropped at once, and a
  slot is released when its connection task ends, however it ends), and bounds the header read
  and TLS handshake to 10 s. Every request body has an idle deadline of 10 s between frames,
  enforced by a router middleware while the body is read: a body that stalls longer (sent
  slowly, or announced and never sent) is answered 408 `request_timeout` and hyper closes the
  connection, as the rest of the body was never read. A failed `accept` (a reset, or running out of file
  descriptors) is warned about on stderr by error kind only, at most once every 10 s; the loop
  pauses 50 ms and keeps accepting.
- Every connection is served by hyper's HTTP/1 connection builder, plain or TLS. HTTP/2 is not
  compiled in at all: the `http2` features of hyper and hyper-util (and hyper-util's
  `server-auto`, which implies them) are off, so no HTTP/2 path exists to reach by accident.
- Three serve flags exist for tests only and are hidden from `--help`:
  `--header-read-timeout-ms` and `--body-read-timeout-ms` (default 10000, 1 to 60000) and
  `--tls-reload-interval-ms` (default 5000, 1 to 3600000). They are not a supported interface.
- TLS is rustls with the ring provider, TLS 1.3 only, no client certificates, ALPN `http/1.1`
  only, and `Strict-Transport-Security: max-age=31536000` on every response the router produces
  over TLS (its 404 and 405 fallbacks included); the 400 and 431 responses hyper writes itself for
  malformed HTTP never reach the router and carry none. The pair
  is served through a resolver over a shared cell. Every 5 s the files' modification times are
  checked; on a change both files are loaded and swapped in only if they parse and the key
  matches the certificate, so a half-written pair is never served. A bad candidate keeps the old
  pair and is warned about once, by file name only. A key file readable by group or others is
  warned about at startup.
- `--trusted-proxy <cidr,...>` lists proxy ranges whose `X-Forwarded-For` is believed. Without
  TLS, plain HTTP is accepted only from those ranges; other peers are dropped before any HTTP is
  read. With TLS any peer may connect and the ranges only govern forwarding headers. A /0 range
  (`0.0.0.0/0` or `::/0`) makes every peer a proxy, so anyone can forge `X-Forwarded-For`:
  `stigmerd serve` prints one warning for it and still starts.
- `X-Forwarded-For` decides the client address used for rate limiting and the security log,
  nothing else. From an untrusted peer it is ignored. From a trusted proxy the hops (all header
  lines, comma separated) are walked from the right, skipping hops that are trusted proxies too;
  the first other hop is the client. Hops to its left were written by the client and are never
  believed, and a hop that is not an address ends the walk at the last trusted hop.
- `--allowed-host <name>` extends the Host/Origin allow-list of ADR 0003; rebinding protection
  stays on for every other name.

## Consequences

- Operators choose between direct TLS and a proxy; there is no plain-HTTP non-loopback mode
  without a declared proxy range.
- Certificates rotate without a restart and without ending open waits; a rotation tool must
  write both files, and the new pair is picked up within one check interval after the second
  write.
- HTTP/2 is deliberately not offered in M1, over TLS (ALPN) or plain (no h2c). Hyper's header
  read timeout covers HTTP/1 only; an HTTP/2 connection that completes its preface and then
  sends nothing would hold a connection slot indefinitely, and enough of them would exhaust
  `--max-connections`. Every connection, plain or TLS, is therefore HTTP/1.1 and bounded by the
  header read timeout. A client offering only `h2` is refused with a `no_application_protocol`
  alert; browsers fall back to HTTP/1.1. Offering HTTP/2 later needs an idle bound of its own
  (for example keep-alive pings with a timeout, or a per-connection idle deadline).
- `X-Forwarded-Proto` is not used: nothing in the API depends on the scheme yet.
- The key-permission warning runs only at startup; a key replaced later with looser permissions
  is reloaded without a new warning.
- Clients behind a proxy that is not declared share the proxy's address as their source, and so
  one failed-authentication budget ([0011](0011-authentication-policy-401-403-404.md)).
- The per-source connection cap counts the peer address, so behind a reverse proxy every
  proxied connection counts against the proxy: raise `--max-connections-per-source` to the
  proxy's connection pool size.

Amended 2026-11-22 (M1, Task 10): HTTP/2 compiled out; `PeerAddr`, accept-error, hidden-flag
and `X-Forwarded-For` rules recorded.

Amended 2026-11-22 (M1 final review): per-source connection cap, request body idle deadline
(408 `request_timeout`), and the warning for a /0 trusted proxy range.
