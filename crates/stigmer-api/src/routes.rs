//! Route handlers: thin glue that resolves the board, authorizes, then calls the store.
//!
//! Every board route answers in the same order: 401 (from the authentication middleware), then
//! 404 when the board is outside the credential's scope or does not exist, then 403 when the
//! authorizer refuses, and only then anything about the request itself.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use stigmer_core::{
    parse_labels, BoardId, BoardInfo, ChannelPath, ChannelsResponse, Cursor, ErrorCode,
    EventFilter, EventsResponse, MessageId, NewMessage, Page, PostRequest, Posted, Principal,
    Target, Thread, MAX_WAIT_SECS,
};
use stigmer_store::{CredentialScope, IdentityStore, Mode, SecurityEvent, Store, StoreError};
use tokio::sync::{watch, Semaphore};

use crate::admin_routes;
use crate::auth::{authenticate, require_peer, PeerGuard};
use crate::authz::{Action, Authenticated, Authorize, Scope};
use crate::body_deadline::limit_body_idle;
use crate::config::ApiConfig;
use crate::error::ApiError;
use crate::host_guard::{require_allowed_host, AllowedHosts};
use crate::join_routes;
use crate::ratelimit::FailureLimiter;
use crate::wait::read_events;

/// Largest accepted request body.
const MAX_BODY_BYTES: usize = 256 * 1024;
const DEFAULT_CHANNEL_LIMIT: u32 = 50;
const DEFAULT_EVENTS_LIMIT: u32 = 100;
const ANONYMOUS: &str = "anonymous";

pub(crate) struct AppState<S, A> {
    pub(crate) store: Arc<S>,
    pub(crate) authz: A,
    pub(crate) shutdown: watch::Receiver<bool>,
    pub(crate) config: Arc<ApiConfig>,
    pub(crate) auth_failures: Arc<FailureLimiter>,
    /// Join attempts per source: its own budget, separate from failed authentications.
    pub(crate) joins: Arc<FailureLimiter>,
    pub(crate) waits: Arc<Semaphore>,
}

// Manual impl: deriving would demand `S: Clone`, and the store sits behind an `Arc`.
impl<S, A: Clone> Clone for AppState<S, A> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            authz: self.authz.clone(),
            shutdown: self.shutdown.clone(),
            config: Arc::clone(&self.config),
            auth_failures: Arc::clone(&self.auth_failures),
            joins: Arc::clone(&self.joins),
            waits: Arc::clone(&self.waits),
        }
    }
}

/// Builds the board's HTTP router. Flipping `shutdown` to `true` ends every pending wait.
///
/// `config.mode` decides authentication; pass `AllowAll` in local mode and `RoleAuthorize` in
/// network mode.
pub fn router<S: Store + IdentityStore, A: Authorize>(
    store: Arc<S>,
    authz: A,
    shutdown: watch::Receiver<bool>,
    config: ApiConfig,
) -> Router {
    let allowed_hosts = AllowedHosts::new(&config.allowed_hosts);
    let body_read_timeout = config.limits.body_read_timeout;
    let peer_guard =
        (config.mode == Mode::Network).then(|| PeerGuard::new(Arc::clone(&config.warn)));
    let state = AppState {
        store,
        authz,
        shutdown,
        auth_failures: Arc::new(FailureLimiter::new(
            config.limits.auth_failures_per_minute,
            config.limits.max_tracked_sources,
        )),
        joins: Arc::new(FailureLimiter::new(
            config.limits.join_per_minute,
            config.limits.max_tracked_sources,
        )),
        waits: Arc::new(Semaphore::new(config.limits.max_waits)),
        config: Arc::new(config),
    };
    let board_routes = Router::new()
        .merge(admin_routes::authenticated::<S, A>())
        .merge(join_routes::authenticated::<S, A>())
        .route("/v1/boards/{board}/messages", post(post_message::<S, A>))
        .route("/v1/boards/{board}/channels", get(read_channels::<S, A>))
        .route("/v1/boards/{board}/events", get(read_events_route::<S, A>))
        .route("/v1/boards/{board}/threads/{id}", get(read_thread::<S, A>))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authenticate::<S, A>,
        ));
    // The admin routes (boards, members, invites, tokens, whoami) join the authenticated group;
    // `POST /v1/join` is the one open route besides health, behind the host guard and its own
    // rate limit.
    // Request order: in network mode a request without the peer address is refused first (500);
    // then the host guard refuses foreign Host/Origin first; then, on board
    // routes only, the authentication layer answers 429 -> 401; then each handler answers 404
    // (board not visible) -> 403 (authorizer) -> the request's own errors. Health checks are
    // open, and the unknown-route 404 and wrong-method 405 fallbacks are unauthenticated by
    // design: they reveal only the public shape of the routes.
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz::<S, A>))
        .merge(board_routes)
        .merge(join_routes::open::<S, A>())
        .fallback(unknown_route)
        .method_not_allowed_fallback(wrong_method)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn_with_state(
            body_read_timeout,
            limit_body_idle,
        ))
        .layer(axum::middleware::from_fn_with_state(
            allowed_hosts,
            require_allowed_host,
        ))
        .with_state(state);
    // Outermost in network mode: without the peer address nothing else can be judged.
    match peer_guard {
        Some(guard) => app.layer(axum::middleware::from_fn_with_state(guard, require_peer)),
        None => app,
    }
}

impl<S: IdentityStore, A> AppState<S, A> {
    /// Appends `event` to the security log after the action it records has already happened.
    /// A failed write does not fail the request: it is reported through `config.warn` with the
    /// event's kind, board and principal only (never its detail, which may name a source).
    pub(crate) async fn audit_best_effort(&self, event: SecurityEvent) {
        let line = format!(
            "security log write failed: kind={} board={} principal={}",
            event.kind,
            event.board.as_ref().map_or("-", BoardId::as_str),
            event.principal.as_deref().unwrap_or("-"),
        );
        if self.store.log_security(event).await.is_err() {
            (self.config.warn)(&line);
        }
    }
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

/// The board named in the path, if the caller may know it exists.
///
/// A board credential only ever sees its own board: any other name, existing or not, is the same
/// 404 without the store being asked. The instance credential and local mode see every board
/// the store has.
pub(crate) async fn visible_board<S: Store>(
    store: &S,
    who: &Authenticated,
    raw: &str,
) -> Result<BoardId, ApiError> {
    visible_board_info(store, who, raw)
        .await
        .map(|(board, _)| board)
}

/// Like `visible_board`, and also the board's info when resolving it had to read it (the
/// instance credential and local mode), so the caller need not look it up again.
pub(crate) async fn visible_board_info<S: Store>(
    store: &S,
    who: &Authenticated,
    raw: &str,
) -> Result<(BoardId, Option<BoardInfo>), ApiError> {
    let no_such_board = || ApiError::not_found("no such board");
    let board = BoardId::new(raw).map_err(|_| no_such_board())?;
    match &who.scope {
        CredentialScope::Board(own) if *own == board => Ok((board, None)),
        CredentialScope::Board(_) => Err(no_such_board()),
        CredentialScope::Instance => match store.get_board(&board).await {
            Ok(info) => Ok((board, Some(info))),
            Err(StoreError::NotFound { .. }) => Err(no_such_board()),
            Err(err) => Err(err.into()),
        },
    }
}

/// The board as an authorization scope. M1 never narrows a check to a channel.
pub(crate) fn board_scope(board: &BoardId) -> Scope<'_> {
    Scope::Board {
        board,
        channel: None,
    }
}

/// Resolves the path's board for `who` and checks `action` on it: 404, then 403.
pub(crate) async fn authorize_board<S: Store, A: Authorize>(
    state: &AppState<S, A>,
    who: &Authenticated,
    action: Action,
    raw: &str,
) -> Result<BoardId, ApiError> {
    let board = visible_board(&*state.store, who, raw).await?;
    state.authz.check(who, action, &board_scope(&board)).await?;
    Ok(board)
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

/// The caller of a read in local mode: the `X-Stigmer-As` principal, else `anonymous`.
pub(crate) fn reader(headers: &HeaderMap) -> Result<Principal, ApiError> {
    match principal_header(headers)? {
        Some(who) => Ok(who),
        None => Ok(Principal::new(ANONYMOUS)?),
    }
}

/// The author of a post. In network mode it is the credential's principal and `X-Stigmer-As`
/// is ignored; in local mode the header is required.
fn author(mode: Mode, who: &Authenticated, headers: &HeaderMap) -> Result<Principal, ApiError> {
    match mode {
        Mode::Network => Ok(who.principal.clone()),
        Mode::Local => principal_header(headers)?
            .ok_or_else(|| ApiError::invalid_input("X-Stigmer-As header is required")),
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
    Extension(who): Extension<Authenticated>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Posted>), ApiError> {
    let board = authorize_board(&state, &who, Action::Post, &path_or_400(path)?).await?;
    let author = author(state.config.mode, &who, &headers)?;
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
    let msg = NewMessage::new(board, target, author, req.text, req.labels, key)?;
    let posted = state.store.post(msg).await?;
    let status = if posted.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(posted)))
}

// Unknown parameters are rejected: a misspelled `after` or `from_now` must fail loudly, not
// silently replay history.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelsQuery {
    prefix: Option<String>,
    limit: Option<String>,
    before: Option<String>,
}

async fn read_channels<S: Store, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<ChannelsQuery>, QueryRejection>,
) -> Result<Json<ChannelsResponse>, ApiError> {
    let board = authorize_board(&state, &who, Action::Read, &path_or_400(path)?).await?;
    let q = query_or_400(query)?;
    let prefix = q
        .prefix
        .as_deref()
        .ok_or_else(|| ApiError::invalid_input("prefix is required"))?;
    let prefix = ChannelPath::new(prefix)?;
    let before = q.before.as_deref().map(MessageId::new).transpose()?;
    let limit = parse_limit(q.limit.as_deref(), DEFAULT_CHANNEL_LIMIT)?;
    let threads = state
        .store
        .read_channel(&board, &prefix, Page { limit, before })
        .await?;
    Ok(Json(ChannelsResponse { threads }))
}

async fn read_thread<S: Store, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Json<Thread>, ApiError> {
    let (board, id) = path_or_400(path)?;
    let board = authorize_board(&state, &who, Action::Read, &board).await?;
    let id = MessageId::new(&id)?;
    let thread = state.store.read_thread(&board, &id).await?;
    Ok(Json(thread))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsQuery {
    after: Option<String>,
    from_now: Option<String>,
    channel: Option<String>,
    thread: Option<String>,
    label: Option<String>,
    timeout_s: Option<String>,
    limit: Option<String>,
}

/// Parses the `from_now` flag: absent or `false` is off, `true` is on.
fn parse_from_now(raw: Option<&str>) -> Result<bool, ApiError> {
    match raw {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(other) => Err(ApiError::invalid_input(format!(
            "from_now must be true or false, got {other:?}"
        ))),
    }
}

async fn read_events_route<S: Store, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Json<EventsResponse>, ApiError> {
    let board = authorize_board(&state, &who, Action::Read, &path_or_400(path)?).await?;
    let q = query_or_400(query)?;
    let from_now = parse_from_now(q.from_now.as_deref())?;
    if from_now && q.after.is_some() {
        return Err(ApiError::invalid_input(
            "from_now and after are mutually exclusive; pass one or the other",
        ));
    }
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
    let timeout = Duration::from_secs(timeout_s.min(MAX_WAIT_SECS));
    // Only a request that may wait holds a slot; it goes back when the response is sent or the
    // request is dropped.
    let _slot = if timeout.is_zero() {
        None
    } else {
        Some(
            state
                .waits
                .try_acquire()
                .map_err(|_| ApiError::rate_limited(1))?,
        )
    };
    // `from_now` is `after=<head>`, with the head read once here; on an empty board it is no
    // cursor at all, since nothing existed to skip.
    let after = if from_now {
        state.store.head(&board).await?
    } else {
        after
    };
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
