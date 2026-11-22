//! The accept loop: owns every connection so it can cap how many are open, bound how long a
//! client may take to send its request headers, tag each request with the peer address and end
//! connections gracefully at shutdown.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Bytes, HttpBody};
use axum::extract::Request;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use stigmer_api::PeerAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tower::ServiceExt;

/// How long to back off after a failed accept (out of file descriptors, say) before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// How connections are accepted and limited.
pub(crate) struct Listen {
    /// Connections open at once; the excess is accepted and dropped without a response.
    pub(crate) max_connections: usize,
    /// How long a client may take to send complete request headers.
    pub(crate) header_read_timeout: Duration,
}

/// What every connection task shares.
struct Shared {
    app: Router,
    http1: Builder<TokioExecutor>,
}

/// Serves `app` on `listener` until `shutdown` turns true, then lets every open connection
/// finish its in-flight requests and returns once all are closed. The caller bounds the drain.
pub(crate) async fn run(
    listener: TcpListener,
    app: Router,
    listen: Listen,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut http1 = Builder::new(TokioExecutor::new()).http1_only();
    http1
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(listen.header_read_timeout);
    let shared = Arc::new(Shared { app, http1 });
    let slots = Arc::new(Semaphore::new(listen.max_connections));
    // Every connection task holds a sender; the channel closes once the last one ends.
    let (alive, mut all_closed) = mpsc::channel::<()>(1);
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.wait_for(|stop| *stop) => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(_) => {
                    // Per-connection failures (a reset before accept) and resource exhaustion
                    // alike: nothing to answer, so pause briefly and keep accepting.
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            },
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            // Over the cap: close at once, before reading a byte.
            drop(stream);
            continue;
        };
        tokio::spawn(connection(
            stream,
            peer,
            Arc::clone(&shared),
            shutdown.clone(),
            permit,
            alive.clone(),
        ));
    }
    drop(listener);
    drop(alive);
    let _ = all_closed.recv().await;
}

/// Serves one accepted connection; the permit and the alive sender are held until it ends.
async fn connection(
    stream: TcpStream,
    peer: SocketAddr,
    shared: Arc<Shared>,
    shutdown: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
    _alive: mpsc::Sender<()>,
) {
    drive(
        stream,
        &shared.http1,
        tagged(&shared.app, peer.ip()),
        shutdown,
    )
    .await;
}

/// The router with `PeerAddr(peer)` inserted into every request's extensions.
fn tagged<B>(
    app: &Router,
    peer: IpAddr,
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
    app.clone().map_request(move |mut request: Request<B>| {
        request.extensions_mut().insert(PeerAddr(peer));
        request
    })
}

/// Runs the HTTP connection to completion, switching to a graceful shutdown (finish the
/// in-flight request, accept no new one) once `shutdown` turns true.
async fn drive<I, S>(
    io: I,
    builder: &Builder<TokioExecutor>,
    service: S,
    mut shutdown: watch::Receiver<bool>,
) where
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
        let service = tagged(app, peer.parse().unwrap());
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
