//! Route handlers: thin glue that authorizes, then calls the store.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use stigmer_core::{
    parse_labels, BoardId, ChannelPath, ChannelsResponse, Cursor, ErrorCode, EventFilter,
    EventsResponse, MessageId, NewMessage, Page, PostRequest, Posted, Principal, Target, Thread,
};
use stigmer_store::Store;
use tokio::sync::watch;

use crate::authz::{Action, Authorize};
use crate::error::ApiError;
use crate::wait::read_events;

/// Largest accepted request body.
const MAX_BODY_BYTES: usize = 256 * 1024;
const DEFAULT_CHANNEL_LIMIT: u32 = 50;
const DEFAULT_EVENTS_LIMIT: u32 = 100;
const MAX_TIMEOUT_S: u64 = 300;
const ANONYMOUS: &str = "anonymous";

pub(crate) struct AppState<S, A> {
    pub(crate) store: Arc<S>,
    pub(crate) authz: A,
    pub(crate) shutdown: watch::Receiver<bool>,
}

// Manual impl: deriving would demand `S: Clone`, and the store sits behind an `Arc`.
impl<S, A: Clone> Clone for AppState<S, A> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            authz: self.authz.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

/// Builds the board's HTTP router. Flipping `shutdown` to `true` ends every pending wait.
pub fn router<S: Store, A: Authorize>(
    store: Arc<S>,
    authz: A,
    shutdown: watch::Receiver<bool>,
) -> Router {
    let state = AppState {
        store,
        authz,
        shutdown,
    };
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz::<S, A>))
        .route(
            "/v1/boards/{board}/messages",
            axum::routing::post(post_message::<S, A>),
        )
        .route("/v1/boards/{board}/channels", get(read_channels::<S, A>))
        .route("/v1/boards/{board}/events", get(read_events_route::<S, A>))
        .route("/v1/boards/{board}/threads/{id}", get(read_thread::<S, A>))
        .fallback(unknown_route)
        .method_not_allowed_fallback(wrong_method)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn unknown_route() -> ApiError {
    ApiError::not_found("no such route")
}

async fn wrong_method() -> ApiError {
    ApiError::new(ErrorCode::MethodNotAllowed, "method not allowed")
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz<S: Store, A: Authorize>(
    State(state): State<AppState<S, A>>,
) -> (StatusCode, &'static str) {
    match state.store.head(&BoardId::main()).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "store unavailable"),
    }
}

/// M0 has one board; any other name is unknown.
pub(crate) fn require_main_board(board: &str) -> Result<BoardId, ApiError> {
    if board == "main" {
        Ok(BoardId::main())
    } else {
        Err(ApiError::not_found(format!("no such board: {board}")))
    }
}

fn principal_header(headers: &HeaderMap) -> Result<Option<Principal>, ApiError> {
    let Some(value) = headers.get("x-stigmer-as") else {
        return Ok(None);
    };
    let raw = value
        .to_str()
        .map_err(|_| ApiError::invalid_input("X-Stigmer-As is not valid text"))?;
    Ok(Some(Principal::new(raw)?))
}

/// The caller of a read: the `X-Stigmer-As` principal, else `anonymous`.
pub(crate) fn reader(headers: &HeaderMap) -> Result<Principal, ApiError> {
    match principal_header(headers)? {
        Some(who) => Ok(who),
        None => Ok(Principal::new(ANONYMOUS)?),
    }
}

pub(crate) fn query_or_400<T>(query: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    query
        .map(|Query(q)| q)
        .map_err(|e| ApiError::invalid_input(e.body_text()))
}

pub(crate) fn path_or_400<T>(path: Result<Path<T>, PathRejection>) -> Result<T, ApiError> {
    path.map(|Path(p)| p)
        .map_err(|e| ApiError::invalid_input(e.body_text()))
}

pub(crate) fn parse_limit(raw: Option<&str>, default: u32) -> Result<u32, ApiError> {
    match raw {
        None => Ok(default),
        Some(s) => s
            .parse()
            .map_err(|_| ApiError::invalid_input(format!("limit must be a number, got {s:?}"))),
    }
}

async fn post_message<S: Store, A: Authorize>(
    State(state): State<AppState<S, A>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Posted>), ApiError> {
    let board = require_main_board(&path_or_400(path)?)?;
    let who = principal_header(&headers)?
        .ok_or_else(|| ApiError::invalid_input("X-Stigmer-As header is required"))?;
    let key = headers
        .get("idempotency-key")
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|_| ApiError::invalid_input("Idempotency-Key is not valid text"))
        })
        .transpose()?;
    let bytes = body.map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(ErrorCode::TooLarge, "request body too large")
        } else {
            ApiError::invalid_input(e.body_text())
        }
    })?;
    let req: PostRequest = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::invalid_input(format!("invalid body: {e}")))?;
    let target = match (req.channel, req.thread) {
        (Some(channel), None) => Target::NewThread { channel },
        (None, Some(thread)) => Target::Reply { thread },
        _ => {
            return Err(ApiError::invalid_input(
                "exactly one of channel or thread is required",
            ))
        }
    };
    let channel = match &target {
        Target::NewThread { channel } => channel.clone(),
        Target::Reply { thread } => state.store.read_thread(&board, thread).await?.root.channel,
    };
    let msg = NewMessage::new(board, target, who.clone(), req.text, req.labels, key)?;
    state.authz.check(&who, Action::Post, Some(&channel))?;
    let posted = state.store.post(msg).await?;
    let status = if posted.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(posted)))
}

#[derive(Deserialize)]
struct ChannelsQuery {
    prefix: Option<String>,
    limit: Option<String>,
    before: Option<String>,
}

async fn read_channels<S: Store, A: Authorize>(
    State(state): State<AppState<S, A>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    query: Result<Query<ChannelsQuery>, QueryRejection>,
) -> Result<Json<ChannelsResponse>, ApiError> {
    let board = require_main_board(&path_or_400(path)?)?;
    let who = reader(&headers)?;
    let q = query_or_400(query)?;
    let prefix = q
        .prefix
        .as_deref()
        .ok_or_else(|| ApiError::invalid_input("prefix is required"))?;
    let prefix = ChannelPath::new(prefix)?;
    let before = q.before.as_deref().map(MessageId::new).transpose()?;
    let limit = parse_limit(q.limit.as_deref(), DEFAULT_CHANNEL_LIMIT)?;
    state.authz.check(&who, Action::Read, Some(&prefix))?;
    let threads = state
        .store
        .read_channel(&board, &prefix, Page { limit, before })
        .await?;
    Ok(Json(ChannelsResponse { threads }))
}

async fn read_thread<S: Store, A: Authorize>(
    State(state): State<AppState<S, A>>,
    path: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
) -> Result<Json<Thread>, ApiError> {
    let (board, id) = path_or_400(path)?;
    let board = require_main_board(&board)?;
    let who = reader(&headers)?;
    let id = MessageId::new(&id)?;
    let thread = state.store.read_thread(&board, &id).await?;
    state
        .authz
        .check(&who, Action::Read, Some(&thread.root.channel))?;
    Ok(Json(thread))
}

#[derive(Deserialize)]
struct EventsQuery {
    after: Option<String>,
    channel: Option<String>,
    thread: Option<String>,
    label: Option<String>,
    timeout_s: Option<String>,
    limit: Option<String>,
}

async fn read_events_route<S: Store, A: Authorize>(
    State(state): State<AppState<S, A>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Json<EventsResponse>, ApiError> {
    let board = require_main_board(&path_or_400(path)?)?;
    let who = reader(&headers)?;
    let q = query_or_400(query)?;
    let after = q
        .after
        .map(|raw| {
            serde_json::from_value::<Cursor>(serde_json::Value::String(raw))
                .map_err(|e| ApiError::new(ErrorCode::InvalidCursor, e.to_string()))
        })
        .transpose()?;
    let filter = EventFilter {
        channel_prefix: q.channel.as_deref().map(ChannelPath::new).transpose()?,
        thread: q.thread.as_deref().map(MessageId::new).transpose()?,
        label: match q.label {
            Some(raw) => parse_labels(&[raw])?.into_iter().next(),
            None => None,
        },
    };
    let limit = parse_limit(q.limit.as_deref(), DEFAULT_EVENTS_LIMIT)?;
    let timeout_s = match q.timeout_s.as_deref() {
        None => 0,
        Some(s) => s.parse::<u64>().map_err(|_| {
            ApiError::invalid_input(format!("timeout_s must be a number, got {s:?}"))
        })?,
    };
    let timeout = Duration::from_secs(timeout_s.min(MAX_TIMEOUT_S));
    state
        .authz
        .check(&who, Action::Read, filter.channel_prefix.as_ref())?;
    let response = read_events(
        &*state.store,
        state.shutdown.clone(),
        &board,
        after,
        &filter,
        limit,
        timeout,
    )
    .await?;
    Ok(Json(response))
}
