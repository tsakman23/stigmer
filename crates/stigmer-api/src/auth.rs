//! Authentication: who is calling, established once per request by a middleware.
//!
//! Local mode trusts `X-Stigmer-As`. Network mode verifies `Authorization: Bearer <token>`:
//! parse, look up by id, compare the secret's hash in constant time, check expiry, revocation and
//! membership, then stamp the credential as seen. Every failure is the same 401. Nothing here
//! logs, echoes or stores the presented token.

use std::hint::black_box;

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use stigmer_core::{parse_secret, secrets_match, PrincipalKind, Role, SecretKind, TokenId};
use stigmer_store::{CredentialScope, IdentityStore, Mode, StoreError};

use crate::authz::{Authenticated, Authorize};
use crate::error::ApiError;
use crate::routes::{reader, AppState};

/// Compared against when a token id is unknown, so a miss costs the same hash work as a wrong
/// secret.
const DUMMY_HASH: [u8; 32] = [0x5a; 32];

/// Middleware on the board routes: puts the caller's `Authenticated` in the request extensions,
/// or answers 401 (network mode) or 400 (a malformed `X-Stigmer-As` in local mode).
pub(crate) async fn authenticate<S: IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    mut request: Request,
    next: Next,
) -> Response {
    let caller = match state.config.mode {
        Mode::Local => local_caller(request.headers()),
        Mode::Network => network_caller(&state, request.headers()).await,
    };
    match caller {
        Ok(who) => {
            request.extensions_mut().insert(who);
            next.run(request).await
        }
        Err(err) => err.into_response(),
    }
}

/// Local mode: the `X-Stigmer-As` principal (else `anonymous`), trusted as the instance admin.
fn local_caller(headers: &HeaderMap) -> Result<Authenticated, ApiError> {
    Ok(Authenticated {
        principal: reader(headers)?,
        kind: PrincipalKind::Agent,
        scope: CredentialScope::Instance,
        role: Some(Role::Admin),
        credential: None,
    })
}

async fn network_caller<S: IdentityStore, A: Authorize>(
    state: &AppState<S, A>,
    headers: &HeaderMap,
) -> Result<Authenticated, ApiError> {
    let now = (state.config.clock)();
    let parsed = bearer(headers).and_then(|raw| parse_secret(SecretKind::Token, raw).ok());
    match verify(&*state.store, parsed, now).await? {
        Some(who) => Ok(who),
        None => Err(ApiError::unauthorized()),
    }
}

/// The token of an `Authorization: Bearer <token>` header (scheme in any case), if any.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

/// The caller a parsed token stands for, or `None` for any reason to refuse it. Only storage
/// failures are errors.
async fn verify<S: IdentityStore>(
    store: &S,
    parsed: Option<(TokenId, String)>,
    now_ms: i64,
) -> Result<Option<Authenticated>, ApiError> {
    let Some((id, secret)) = parsed else {
        return Ok(None);
    };
    let Some(credential) = store.find_credential(&id).await? else {
        black_box(secrets_match(&secret, &DUMMY_HASH));
        return Ok(None);
    };
    let usable = secrets_match(&secret, &credential.secret_hash)
        && credential.revoked_at_ms.is_none()
        && now_ms < credential.expires_at_ms;
    if !usable {
        return Ok(None);
    }
    let (kind, role) = match &credential.scope {
        // The instance admin is a person, not a board member.
        CredentialScope::Instance => (PrincipalKind::Human, None),
        CredentialScope::Board(board) => {
            match store.get_member(board, &credential.principal).await {
                Ok(Some(member)) => (member.kind, Some(member.role)),
                Ok(None) | Err(StoreError::NotFound { .. }) => return Ok(None),
                Err(err) => return Err(err.into()),
            }
        }
    };
    store.touch_credential(&id, now_ms).await?;
    Ok(Some(Authenticated {
        principal: credential.principal,
        kind,
        scope: credential.scope,
        role,
        credential: Some(id),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn with_auth(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn bearer_accepts_any_case_scheme_and_refuses_others() {
        assert_eq!(bearer(&with_auth("Bearer abc")), Some("abc"));
        assert_eq!(bearer(&with_auth("bearer  abc ")), Some("abc"));
        assert_eq!(bearer(&with_auth("BEARER abc")), Some("abc"));
        assert_eq!(bearer(&with_auth("Basic abc")), None);
        assert_eq!(bearer(&with_auth("Bearer")), None);
        assert_eq!(bearer(&with_auth("Bearer ")), None);
        assert_eq!(bearer(&HeaderMap::new()), None);
    }
}
