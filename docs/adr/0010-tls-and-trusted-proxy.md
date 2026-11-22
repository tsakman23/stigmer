# 0010. TLS and trusted proxies

Status: Accepted
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
- `stigmerd` runs its own accept loop (hyper-util) instead of `axum::serve`. Each connection
  inserts `PeerAddr` into its requests; in network mode the API answers 500 when it is missing
  rather than putting every client into one rate-limit bucket. The loop caps open connections
  (`--max-connections`, default 1024; the excess is dropped unanswered) and bounds the header
  read and TLS handshake to 10 s.
- TLS is rustls with the ring provider, TLS 1.3 only, no client certificates, ALPN `http/1.1`
  only, and `Strict-Transport-Security: max-age=31536000` on every TLS response. The pair
  is served through a resolver over a shared cell. Every 5 s the files' modification times are
  checked; on a change both files are loaded and swapped in only if they parse and the key
  matches the certificate, so a half-written pair is never served. A bad candidate keeps the old
  pair and is warned about once, by file name only.
- `--trusted-proxy <cidr,...>` lists proxy ranges whose `X-Forwarded-For` is believed. Without
  TLS, plain HTTP is accepted only from those ranges; other peers are dropped before any HTTP is
  read. With TLS any peer may connect and the ranges only govern forwarding headers.
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
