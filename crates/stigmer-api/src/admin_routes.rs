//! Board management, members, invites, tokens, join and whoami.
//!
//! Identity routes (members, invites, tokens, join) need network mode; in local mode they answer
//! 409. Board routes work in both modes. Every handler asks the async authorizer, resolves the
//! board with the same visibility rule as the content routes (a board credential never learns
//! whether another board exists), and writes one security log row per mutation.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::de::DeserializeOwned;
use stigmer_core::{
    generate_secret, BoardInfo, BoardSummary, BoardsResponse, CreateBoardRequest, ErrorCode,
    InviteRequest, InviteResponse, MemberInfo, MembersResponse, Principal, PrincipalKind, Role,
    SecretKind, TokenId, TokenInfo, TokensResponse,
};
use stigmer_store::{CredentialScope, IdentityStore, Mode, NewInvite, Store};

use crate::audit::Audit;
use crate::auth::{client_source, PeerAddr};
use crate::authz::{Action, Authenticated, Authorize, Scope};
use crate::error::ApiError;
use crate::ratelimit::Source;
use crate::routes::{
    authorize_board, board_scope, path_or_400, visible_board, visible_board_info, AppState,
};

const MINUTE_MS: i64 = 60_000;
const DEFAULT_INVITE_MINUTES: u32 = 60;
const MAX_INVITE_MINUTES: u32 = 7 * 24 * 60;
const LOCAL_MODE_MESSAGE: &str = "this server is in local mode; run stigmerd admin enable-auth";

/// Routes behind the authentication middleware.
pub(crate) fn authenticated<S: Store + IdentityStore, A: Authorize>() -> Router<AppState<S, A>> {
    Router::new()
        .route(
            "/v1/boards",
            post(create_board::<S, A>).get(list_boards::<S, A>),
        )
        .route("/v1/boards/{board}", get(get_board::<S, A>))
        .route("/v1/boards/{board}/archive", post(archive_board::<S, A>))
        .route("/v1/boards/{board}/members", get(list_members::<S, A>))
        .route(
            "/v1/boards/{board}/members/{name}",
            delete(remove_member::<S, A>),
        )
        .route("/v1/boards/{board}/invites", post(create_invite::<S, A>))
        .route("/v1/boards/{board}/tokens", get(list_tokens::<S, A>))
        .route(
            "/v1/boards/{board}/tokens/{id}",
            delete(revoke_token::<S, A>),
        )
}

/// The address a request is attributed to, for rate limiting and the security log.
pub(crate) struct ClientSource(pub(crate) Source);

impl<S: Store + IdentityStore, A: Authorize> FromRequestParts<AppState<S, A>> for ClientSource {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<S, A>,
    ) -> Result<Self, ApiError> {
        let peer = parts.extensions.get::<PeerAddr>().map(|p| p.0);
        Ok(Self(client_source(
            peer,
            &parts.headers,
            &state.config.trusted_proxies,
        )))
    }
}

pub(crate) fn now<S, A>(state: &AppState<S, A>) -> i64 {
    (state.config.clock)()
}

pub(crate) fn require_network<S, A>(state: &AppState<S, A>) -> Result<(), ApiError> {
    match state.config.mode {
        Mode::Network => Ok(()),
        Mode::Local => Err(ApiError::new(ErrorCode::Conflict, LOCAL_MODE_MESSAGE)),
    }
}

pub(crate) fn json_body<T: DeserializeOwned>(
    body: Result<Bytes, BytesRejection>,
) -> Result<T, ApiError> {
    let bytes = body.map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(ErrorCode::TooLarge, "request body too large")
        } else {
            ApiError::invalid_input(e.body_text())
        }
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::invalid_input(format!("invalid body: {e}")))
}

fn summary(info: &BoardInfo) -> BoardSummary {
    BoardSummary {
        id: info.id.clone(),
        archived: info.archived_at_ms.is_some(),
        created_at_ms: info.created_at_ms,
    }
}

/// What reading or managing a board means for this caller: the instance credential manages
/// boards, a board credential reads its own.
fn own_board_action(who: &Authenticated, board_credential: Action) -> Action {
    match who.scope {
        CredentialScope::Instance => Action::ManageBoards,
        CredentialScope::Board(_) => board_credential,
    }
}

async fn create_board<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    ClientSource(source): ClientSource,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<BoardSummary>), ApiError> {
    state
        .authz
        .check(&who, Action::ManageBoards, &Scope::Instance)
        .await?;
    let req: CreateBoardRequest = json_body(body)?;
    let info = state
        .store
        .create_board(&req.name, Some(&who.principal))
        .await?;
    let audit = Audit {
        at_ms: now(&state),
        source,
        by: &who.principal,
    };
    state.audit_best_effort(audit.board_created(&info.id)).await;
    Ok((StatusCode::CREATED, Json(summary(&info))))
}

async fn list_boards<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
) -> Result<Json<BoardsResponse>, ApiError> {
    let infos = match &who.scope {
        CredentialScope::Instance => {
            state
                .authz
                .check(&who, Action::ManageBoards, &Scope::Instance)
                .await?;
            state.store.list_boards().await?
        }
        // Its own board only, archived or not.
        CredentialScope::Board(own) => {
            state
                .authz
                .check(&who, Action::Read, &board_scope(own))
                .await?;
            vec![state.store.get_board(own).await?]
        }
    };
    Ok(Json(BoardsResponse {
        boards: infos.iter().map(summary).collect(),
    }))
}

async fn get_board<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<BoardSummary>, ApiError> {
    let (board, known) = visible_board_info(&*state.store, &who, &path_or_400(path)?).await?;
    let action = own_board_action(&who, Action::Read);
    state
        .authz
        .check(&who, action, &board_scope(&board))
        .await?;
    let info = match known {
        Some(info) => info,
        None => state.store.get_board(&board).await?,
    };
    Ok(Json(summary(&info)))
}

/// Archives a board, then revokes every non-admin credential on it.
///
/// The order matters: once the board is archived no join can get a new credential (the store
/// refuses invites into it), so the revoke step that follows sees every credential there will
/// ever be. Revoking first would leave a window in which a join gets a live credential that is
/// never revoked. Both steps are idempotent, so when the second fails (500) the board is
/// already archived and a retry completes the revoke.
async fn archive_board<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    ClientSource(source): ClientSource,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<BoardSummary>, ApiError> {
    let board = visible_board(&*state.store, &who, &path_or_400(path)?).await?;
    let action = own_board_action(&who, Action::ManageMembers);
    state
        .authz
        .check(&who, action, &board_scope(&board))
        .await?;
    let at_ms = now(&state);
    let info = state.store.archive_board(&board).await?;
    state
        .store
        .revoke_board_credentials(&board, true, at_ms)
        .await?;
    let audit = Audit {
        at_ms,
        source,
        by: &who.principal,
    };
    state.audit_best_effort(audit.board_archived(&board)).await;
    Ok(Json(summary(&info)))
}

async fn list_members<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<MembersResponse>, ApiError> {
    require_network(&state)?;
    let board = authorize_board(&state, &who, Action::ManageMembers, &path_or_400(path)?).await?;
    let members = state.store.list_members(&board).await?;
    let mut last_seen: HashMap<Principal, i64> = HashMap::new();
    for credential in state.store.list_credentials(&board).await? {
        if let Some(seen) = credential.last_seen_ms {
            let latest = last_seen.entry(credential.principal).or_insert(seen);
            *latest = (*latest).max(seen);
        }
    }
    Ok(Json(MembersResponse {
        members: members
            .into_iter()
            .map(|m| MemberInfo {
                last_seen_ms: last_seen.get(&m.name).copied(),
                name: m.name,
                kind: m.kind,
                role: m.role,
            })
            .collect(),
    }))
}

async fn remove_member<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    ClientSource(source): ClientSource,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    require_network(&state)?;
    let (board, name) = path_or_400(path)?;
    let board = authorize_board(&state, &who, Action::ManageMembers, &board).await?;
    let name = Principal::new(&name).map_err(|_| ApiError::not_found("no such member"))?;
    let at_ms = now(&state);
    state.store.remove_member(&board, &name, at_ms).await?;
    let audit = Audit {
        at_ms,
        source,
        by: &who.principal,
    };
    state
        .audit_best_effort(audit.member_removed(&board, &name))
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_invite<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    ClientSource(source): ClientSource,
    path: Result<Path<String>, PathRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<InviteResponse>), ApiError> {
    require_network(&state)?;
    let board = authorize_board(&state, &who, Action::ManageMembers, &path_or_400(path)?).await?;
    let req: InviteRequest = json_body(body)?;
    // A bridge is the one kind that has the bridge role, and the bridge role is only for it.
    if (req.kind == PrincipalKind::Bridge) != (req.role == Role::Bridge) {
        return Err(ApiError::invalid_input(
            "kind bridge and role bridge go together: use both or neither",
        ));
    }
    let minutes = req.expires_in_minutes.unwrap_or(DEFAULT_INVITE_MINUTES);
    if !(1..=MAX_INVITE_MINUTES).contains(&minutes) {
        return Err(ApiError::invalid_input(format!(
            "expires_in_minutes must be between 1 and {MAX_INVITE_MINUTES}"
        )));
    }
    let at_ms = now(&state);
    let expires_at_ms = at_ms.saturating_add(i64::from(minutes) * MINUTE_MS);
    let secret = generate_secret(SecretKind::Invite).map_err(|_| ApiError::internal())?;
    let invite = NewInvite {
        id: secret.id.clone(),
        secret_hash: secret.hash,
        board: board.clone(),
        role: req.role,
        kind: req.kind,
        created_by: who.principal.clone(),
        expires_at_ms,
    };
    state.store.create_invite(invite, at_ms).await?;
    let audit = Audit {
        at_ms,
        source,
        by: &who.principal,
    };
    let row = audit.invite_created(&board, &secret.id, req.kind, req.role);
    state.audit_best_effort(row).await;
    Ok((
        StatusCode::CREATED,
        Json(InviteResponse {
            invite: secret.full,
            expires_at_ms,
        }),
    ))
}

async fn list_tokens<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<TokensResponse>, ApiError> {
    require_network(&state)?;
    let board = authorize_board(&state, &who, Action::ManageMembers, &path_or_400(path)?).await?;
    let roles: HashMap<Principal, Role> = state
        .store
        .list_members(&board)
        .await?
        .into_iter()
        .map(|m| (m.name, m.role))
        .collect();
    // Only metadata: `TokenInfo` has no field that could hold a secret or a hash. Tokens of
    // removed members are revoked and have no role to show, so they are left out.
    let tokens = state
        .store
        .list_credentials(&board)
        .await?
        .into_iter()
        .filter_map(|c| {
            Some(TokenInfo {
                role: *roles.get(&c.principal)?,
                id: c.id,
                principal: c.principal,
                expires_at_ms: c.expires_at_ms,
                revoked: c.revoked_at_ms.is_some(),
                last_seen_ms: c.last_seen_ms,
            })
        })
        .collect();
    Ok(Json(TokensResponse { tokens }))
}

async fn revoke_token<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
    ClientSource(source): ClientSource,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    require_network(&state)?;
    let (board, id) = path_or_400(path)?;
    let board = authorize_board(&state, &who, Action::ManageMembers, &board).await?;
    let no_such_token = || ApiError::not_found("no such token");
    let id = TokenId::new(&id).map_err(|_| no_such_token())?;
    // Only this board's tokens: another board's, or the instance credential, look unknown.
    let credential = state
        .store
        .find_credential(&id)
        .await?
        .filter(|c| c.scope == CredentialScope::Board(board.clone()))
        .ok_or_else(no_such_token)?;
    let at_ms = now(&state);
    state.store.revoke_credential(&id, at_ms).await?;
    // A repeat revoke is allowed but is not a new event.
    if credential.revoked_at_ms.is_none() {
        let audit = Audit {
            at_ms,
            source,
            by: &who.principal,
        };
        let row = audit.token_revoked(&board, &id, &credential.principal);
        state.audit_best_effort(row).await;
    }
    Ok(StatusCode::NO_CONTENT)
}
