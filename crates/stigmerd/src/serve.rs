//! The accept loop: owns every connection so it can cap how many are open, bound how long a
//! client may take to send its request headers (and finish a TLS handshake), tag each request
//! with the peer address, add HSTS on TLS and end connections gracefully at shutdown.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::body::{Bytes, HttpBody};
use axum::extract::Request;
use axum::http::header::STRICT_TRANSPORT_SECURITY;
use axum::http::HeaderValue;
use axum::Router;
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use stigmer_api::{IpNet, PeerAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::tls::HSTS;

/// How long to back off after a failed accept (out of file descriptors, say) before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// At most one accept-failure warning per this period, however often accepts fail.
const ACCEPT_WARN_EVERY: Duration = Duration::from_secs(10);

/// Lets an event through at most once per period.
struct Throttle {
    every: Duration,
    last: Option<Instant>,
}

impl Throttle {
    fn new(every: Duration) -> Self {
        Self { every, last: None }
    }

    /// True (and the period restarts) when nothing was let through in the last period.
    fn allow(&mut self, now: Instant) -> bool {
        let due = self
            .last
            .is_none_or(|last| now.saturating_duration_since(last) >= self.every);
        if due {
            self.last = Some(now);
        }
        due
    }
}

/// How connections are accepted and limited.
pub(crate) struct Listen {
    /// Connections open at once; the excess is accepted and dropped without a response.
    pub(crate) max_connections: usize,
    /// Connections open at once from one source (see `source_key`); the excess is accepted and
    /// dropped without a response.
    pub(crate) max_connections_per_source: usize,
    /// How long a client may take to send complete request headers, and to finish a TLS
    /// handshake.
    pub(crate) header_read_timeout: Duration,
    /// Serve TLS (only) when set.
    pub(crate) tls: Option<TlsAcceptor>,
    /// When not empty, connections from peers outside these ranges are dropped unread.
    pub(crate) plain_from: Vec<IpNet>,
    /// Peers in these ranges (the trusted proxies) take no per-source slot: every client behind a
    /// proxy arrives from its address. Only `max_connections` bounds them.
    pub(crate) per_source_exempt: Vec<IpNet>,
}

/// What every connection task shares.
struct Shared {
    app: Router,
    /// HTTP/1 only, on plain and TLS connections alike, so the header read timeout bounds every
    /// connection (hyper has no such timeout for HTTP/2). HTTP/2 is not even compiled in: the
    /// hyper and hyper-util `http2` features are off.
    http1: Builder,
    tls: Option<TlsAcceptor>,
    handshake_timeout: Duration,
}

/// Serves `app` on `listener` until `shutdown` turns true, then lets every open connection
/// finish its in-flight requests and returns once all are closed. The caller bounds the drain.
pub(crate) async fn run(
    listener: TcpListener,
    app: Router,
    listen: Listen,
    mut shutdown: watch::Receiver<bool>,
) {
    // HTTP/1.1 is fixed rather than sniffed, so a client that sends nothing still meets the
    // header timeout; TLS offers only http/1.1 by ALPN for the same reason.
    let mut http1 = Builder::new();
    http1
        .timer(TokioTimer::new())
        .header_read_timeout(listen.header_read_timeout);
    let shared = Arc::new(Shared {
        app,
        http1,
        tls: listen.tls.clone(),
        handshake_timeout: listen.header_read_timeout,
    });
    let slots = Arc::new(Semaphore::new(listen.max_connections));
    let per_source = Arc::new(SourceSlots::new(listen.max_connections_per_source));
    // Every connection task holds a sender; the channel closes once the last one ends.
    let (alive, mut all_closed) = mpsc::channel::<()>(1);
    let mut accept_warning = Throttle::new(ACCEPT_WARN_EVERY);
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.wait_for(|stop| *stop) => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    // Per-connection failures (a reset before accept) and resource exhaustion
                    // (out of file descriptors) alike: nothing to answer, so say so now and
                    // then, pause briefly and keep accepting.
                    if accept_warning.allow(Instant::now()) {
                        eprintln!(
                            "stigmerd: warning: accepting a connection failed ({}); retrying",
                            err.kind()
                        );
                    }
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            },
        };
        if !admits(&listen.plain_from, peer.ip()) {
            drop(stream);
            continue;
        }
        // Over either cap: close at once, before reading a byte. The source's slot is taken
        // first, so a source at its cap never holds one of the shared slots.
        let source_permit = if admits_exempt(&listen.per_source_exempt, peer.ip()) {
            None
        } else {
            let Some(permit) = SourceSlots::try_acquire(&per_source, peer.ip()) else {
                drop(stream);
                continue;
            };
            Some(permit)
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        tokio::spawn(connection(
            stream,
            peer,
            Arc::clone(&shared),
            shutdown.clone(),
            (permit, source_permit),
            alive.clone(),
        ));
    }
    drop(listener);
    drop(alive);
    let _ = all_closed.recv().await;
}

/// The source a connection counts against: an IPv4 address (IPv4-mapped IPv6 included) as
/// itself, an IPv6 address as its /64, as the rate limiters group sources.
fn source_key(peer: IpAddr) -> IpAddr {
    match peer.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !(u128::MAX >> 64))),
        v4 => v4,
    }
}

/// Open connections per source, each source capped at `max`.
struct SourceSlots {
    max: usize,
    open: Mutex<HashMap<IpAddr, usize>>,
}

impl SourceSlots {
    fn new(max: usize) -> Self {
        Self {
            max,
            open: Mutex::new(HashMap::new()),
        }
    }

    /// A slot for a connection from `peer`, or `None` when its source has `max` open.
    fn try_acquire(slots: &Arc<Self>, peer: IpAddr) -> Option<SourcePermit> {
        let key = source_key(peer);
        let mut open = slots.lock();
        let count = open.entry(key).or_insert(0);
        if *count >= slots.max {
            return None;
        }
        *count += 1;
        Some(SourcePermit {
            slots: Arc::clone(slots),
            key,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
        // A count is changed in one step, so a panicking holder cannot leave one half-done.
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One open connection's slot; dropping it, on any exit path, frees the slot.
struct SourcePermit {
    slots: Arc<SourceSlots>,
    key: IpAddr,
}

impl Drop for SourcePermit {
    fn drop(&mut self) {
        let mut open = self.slots.lock();
        if let Some(count) = open.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.key);
            }
        }
    }
}

/// True when one of `ranges` holds `peer` (an empty list exempts no one).
fn admits_exempt(ranges: &[IpNet], peer: IpAddr) -> bool {
    ranges.iter().any(|range| range.contains(peer))
}

/// True when `ranges` is empty (no restriction) or one of them holds `peer`.
fn admits(ranges: &[IpNet], peer: IpAddr) -> bool {
    ranges.is_empty() || ranges.iter().any(|range| range.contains(peer))
}

/// Serves one accepted connection; the permits and the alive sender are held until it ends,
/// whichever way it ends.
async fn connection(
    stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<Shared>,
    shutdown: watch::Receiver<bool>,
    _permits: (OwnedSemaphorePermit, Option<SourcePermit>),
    _alive: mpsc::Sender<()>,
) {
    let Some(acceptor) = &shared.tls else {
        let service = tagged(&shared.app, peer.ip(), false);
        return drive(stream, &shared.http1, service, shutdown).await;
    };
    // A failed or slow handshake (plain HTTP, TLS 1.2, a stalled client) just ends here.
    let Ok(Ok(stream)) =
        tokio::time::timeout(shared.handshake_timeout, acceptor.accept(stream)).await
    else {
        return;
    };
    drive(
        stream,
        &shared.http1,
        tagged(&shared.app, peer.ip(), true),
        shutdown,
    )
    .await;
}

/// The router with `PeerAddr(peer)` inserted into every request's extensions and, on TLS
/// connections, `Strict-Transport-Security` added to every response the router produces
/// (including its 404 and 405 fallbacks).
///
/// Responses hyper writes itself for malformed HTTP (400, 431 for oversized headers) never reach
/// the router and carry no HSTS. That is accepted: such a client is not a browser that would
/// learn the policy, and every well-formed request gets it.
fn tagged<B>(
    app: &Router,
    peer: IpAddr,
    tls: bool,
) -> impl tower::Service<
    Request<B>,
    Response = axum::response::Response,
    Error = std::convert::Infallible,
    Future = impl Send,
> + Clone
       + Send
       + 'static
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<axum::BoxError>,
{
    app.clone()
        .map_request(move |mut request: Request<B>| {
            request.extensions_mut().insert(PeerAddr(peer));
            request
        })
        .map_response(move |mut response: axum::response::Response| {
            if tls {
                response
                    .headers_mut()
                    .insert(STRICT_TRANSPORT_SECURITY, HeaderValue::from_static(HSTS));
            }
            response
        })
}

/// Runs the HTTP connection to completion, switching to a graceful shutdown (finish the
/// in-flight request, accept no new one) once `shutdown` turns true.
async fn drive<I, S>(io: I, builder: &Builder, service: S, mut shutdown: watch::Receiver<bool>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: tower::Service<
            Request<Incoming>,
            Response = axum::response::Response,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let conn = builder.serve_connection(TokioIo::new(io), TowerToHyperService::new(service));
    tokio::pin!(conn);
    tokio::select! {
        // A client that goes away or breaks the protocol simply ends its connection.
        _ = conn.as_mut() => return,
        _ = shutdown.wait_for(|stop| *stop) => {}
    }
    conn.as_mut().graceful_shutdown();
    let _ = conn.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn tracked(slots: &Arc<SourceSlots>) -> usize {
        slots.lock().len()
    }

    #[test]
    fn per_source_slots_are_counted_per_source() {
        let slots = Arc::new(SourceSlots::new(2));
        let a1 = SourceSlots::try_acquire(&slots, ip("127.0.0.1"));
        let a2 = SourceSlots::try_acquire(&slots, ip("::ffff:127.0.0.1"));
        assert!(a1.is_some() && a2.is_some());
        assert!(SourceSlots::try_acquire(&slots, ip("127.0.0.1")).is_none());
        // Another source still connects.
        let b = SourceSlots::try_acquire(&slots, ip("127.0.0.2"));
        assert!(b.is_some());
        // IPv6 counts per /64.
        let c1 = SourceSlots::try_acquire(&slots, ip("2001:db8:1:2::1"));
        let c2 = SourceSlots::try_acquire(&slots, ip("2001:db8:1:2:ffff::9"));
        assert!(c1.is_some() && c2.is_some());
        assert!(SourceSlots::try_acquire(&slots, ip("2001:db8:1:2::3")).is_none());
        assert!(SourceSlots::try_acquire(&slots, ip("2001:db8:1:3::1")).is_some());
    }

    #[test]
    fn per_source_slots_are_released_when_permits_drop() {
        let slots = Arc::new(SourceSlots::new(1));
        let held = SourceSlots::try_acquire(&slots, ip("192.0.2.1"));
        assert!(held.is_some());
        assert!(SourceSlots::try_acquire(&slots, ip("192.0.2.1")).is_none());
        drop(held);
        let again = SourceSlots::try_acquire(&slots, ip("192.0.2.1"));
        assert!(again.is_some());
        drop(again);
        assert_eq!(tracked(&slots), 0, "an idle source costs nothing");
    }

    #[test]
    fn throttle_allows_one_warning_per_period() {
        let start = Instant::now();
        let mut throttle = Throttle::new(Duration::from_secs(10));
        assert!(throttle.allow(start));
        assert!(!throttle.allow(start));
        assert!(!throttle.allow(start + Duration::from_millis(9_999)));
        assert!(throttle.allow(start + Duration::from_secs(10)));
        assert!(!throttle.allow(start + Duration::from_secs(15)));
        assert!(throttle.allow(start + Duration::from_secs(21)));
    }
    use axum::body::Body;
    use axum::http::StatusCode;
    use stigmer_api::{router, ApiConfig, RoleAuthorize};
    use stigmer_store::IdentityStore;
    use stigmer_store_sqlite::SqliteStore;

    async fn bad_token_status(app: &Router, peer: &str) -> StatusCode {
        let request = Request::builder()
            .uri("/v1/boards/main/events")
            .header("authorization", "Bearer garbage")
            .body(Body::empty())
            .unwrap();
        let service = tagged(app, peer.parse().unwrap(), false);
        service.oneshot(request).await.unwrap().status()
    }

    /// The connection layer gives each connection its own source, so a burst from one client
    /// is limited without touching another.
    #[tokio::test]
    async fn each_connection_is_rate_limited_as_its_own_source() {
        let store = Arc::new(SqliteStore::open_memory().await.unwrap());
        store.enable_network_mode().await.unwrap();
        let (_tx, rx) = watch::channel(false);
        let config = ApiConfig::network();
        let budget = config.limits.auth_failures_per_minute;
        let app = router(store, RoleAuthorize, rx, config);
        for _ in 0..budget {
            assert_eq!(
                bad_token_status(&app, "192.0.2.1").await,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            bad_token_status(&app, "192.0.2.1").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            bad_token_status(&app, "192.0.2.2").await,
            StatusCode::UNAUTHORIZED
        );
    }
}
