//! Join (an invite for a member and a token) and whoami.

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use stigmer_core::{
    generate_secret, hash_secret, parse_secret, JoinRequest, JoinResponse, SecretKind, WhoAmI,
};
use stigmer_store::{CredentialScope, IdentityStore, Mode, NewJoinCredential, Store, StoreError};

use crate::admin_routes::{json_body, now, require_network, ClientSource};
use crate::audit::join_rate_limited;
use crate::authz::{Authenticated, Authorize};
use crate::error::ApiError;
use crate::ratelimit::Logged;
use crate::routes::AppState;

/// How long a token from `join` lives.
const TOKEN_LIFETIME_MS: i64 = 90 * 24 * 60 * 60_000;

/// `whoami`, behind the authentication middleware.
pub(crate) fn authenticated<S: Store + IdentityStore, A: Authorize>() -> Router<AppState<S, A>> {
    Router::new().route("/v1/whoami", get(whoami::<S, A>))
}

/// `join`, which takes no token.
pub(crate) fn open<S: Store + IdentityStore, A: Authorize>() -> Router<AppState<S, A>> {
    Router::new().route("/v1/join", post(join::<S, A>))
}

/// Redeems an invite for a member and a 90 day token, shown once in the response.
///
/// Every invite problem is the same 401. The store does the whole join in one transaction (the
/// invite is checked and used, the member and the token's credential are created and the `Join`
/// log row is written), so a failure leaves nothing behind and the same invite can be tried
/// again. No token is stored, logged or echoed except in the success response.
async fn join<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    ClientSource(source): ClientSource,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<JoinResponse>), ApiError> {
    require_network(&state)?;
    let at_ms = now(&state);
    // Every attempt counts, successful or not; the reservation is never refunded.
    if let Err(retry_after) = state.joins.reserve(source, at_ms) {
        if state.joins.should_log(source, Logged::RateLimited, at_ms) {
            state
                .audit_best_effort(join_rate_limited(at_ms, source))
                .await;
        }
        return Err(ApiError::rate_limited(retry_after));
    }
    let req: JoinRequest = json_body(body)?;
    let (id, secret) =
        parse_secret(SecretKind::Invite, &req.invite).map_err(|_| ApiError::unauthorized())?;
    let token = generate_secret(SecretKind::Token).map_err(|_| ApiError::internal())?;
    let expires_at_ms = at_ms.saturating_add(TOKEN_LIFETIME_MS);
    let credential = NewJoinCredential {
        id: token.id,
        secret_hash: token.hash,
        expires_at_ms,
    };
    let consumed = match state
        .store
        .consume_invite(&id, &hash_secret(&secret), &req.name, at_ms, credential)
        .await
    {
        Ok(consumed) => consumed,
        Err(StoreError::NotFound { .. }) => return Err(ApiError::unauthorized()),
        Err(err) => return Err(err.into()),
    };
    Ok((
        StatusCode::CREATED,
        Json(JoinResponse {
            token: token.full,
            board: consumed.board,
            role: consumed.role,
            kind: consumed.kind,
            expires_at_ms,
        }),
    ))
}

/// Who the credential is. Needs any valid token and touches no board, so there is nothing to
/// authorize beyond authentication itself.
async fn whoami<S: Store + IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    Extension(who): Extension<Authenticated>,
) -> Json<WhoAmI> {
    let instance_admin =
        state.config.mode == Mode::Network && who.scope == CredentialScope::Instance;
    Json(WhoAmI {
        principal: who.principal,
        kind: who.kind,
        board: match who.scope {
            CredentialScope::Board(board) => Some(board),
            CredentialScope::Instance => None,
        },
        role: who.role,
        instance_admin,
    })
}
