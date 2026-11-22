//! An idle deadline on request bodies, so a client cannot hold a request (and its connection
//! slot) open by sending its body a byte at a time, or not at all after the headers.
//!
//! The deadline runs only while a handler is reading the body and restarts with every frame
//! that arrives. A body that stalls past it ends with an error, and the middleware answers
//! 408 `request_timeout` in place of whatever the handler made of that error. Hyper then
//! closes the connection, as the rest of the body was never read.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::BoxError;
use http_body::{Frame, SizeHint};
use tokio::time::Sleep;

use crate::error::ApiError;

/// Middleware: wraps every request body in the idle deadline `idle`.
pub(crate) async fn limit_body_idle(
    State(idle): State<Duration>,
    request: Request,
    next: Next,
) -> Response {
    let timed_out = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&timed_out);
    let request = request.map(|body| Body::new(IdleBody::new(body, idle, flag)));
    let response = next.run(request).await;
    if timed_out.load(Ordering::SeqCst) {
        return ApiError::request_timeout().into_response();
    }
    response
}

/// Why a body ended early: it stalled past the deadline.
#[derive(Debug)]
struct BodyStalled;

impl std::fmt::Display for BodyStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body stalled")
    }
}

impl std::error::Error for BodyStalled {}

/// A body that fails once `idle` passes, while it is being read, without a frame arriving.
struct IdleBody {
    inner: Body,
    idle: Duration,
    /// Armed by the first read that finds nothing, cleared by every frame.
    deadline: Option<Pin<Box<Sleep>>>,
    timed_out: Arc<AtomicBool>,
}

impl IdleBody {
    fn new(inner: Body, idle: Duration, timed_out: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            idle,
            deadline: None,
            timed_out,
        }
    }
}

impl HttpBody for IdleBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // Every field is Unpin (the timer is boxed), so the body can be used through `&mut`.
        let this = self.get_mut();
        if let Poll::Ready(frame) = Pin::new(&mut this.inner).poll_frame(cx) {
            this.deadline = None;
            return Poll::Ready(frame.map(|result| result.map_err(BoxError::from)));
        }
        let idle = this.idle;
        let deadline = this
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(idle)));
        match deadline.as_mut().poll(cx) {
            Poll::Ready(()) => {
                this.timed_out.store(true, Ordering::SeqCst);
                Poll::Ready(Some(Err(Box::new(BodyStalled))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
