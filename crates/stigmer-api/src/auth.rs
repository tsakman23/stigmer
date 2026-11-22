//! Authentication: who is calling, established once per request by a middleware.
//!
//! Local mode trusts `X-Stigmer-As`. Network mode verifies `Authorization: Bearer <token>`:
//! parse, look up by id, compare the secret's hash in constant time, check expiry, revocation and
//! membership, then stamp the credential as seen. Every failure is the same 401. Nothing here
//! logs, echoes or stores the presented token.
//!
//! Failed authentications are limited per source address and per token id, checked before any
//! credential is looked at, and written to the security log at most once a minute per source.

use std::hint::black_box;
use std::net::IpAddr;

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use stigmer_core::{parse_secret, secrets_match, PrincipalKind, Role, SecretKind, TokenId};
use stigmer_store::{
    CredentialScope, IdentityStore, Mode, SecurityEvent, SecurityEventKind, StoreError,
};

use crate::authz::{Authenticated, Authorize};
use crate::error::ApiError;
use crate::ipnet::IpNet;
use crate::ratelimit::{Key, Logged, Source};
use crate::routes::{reader, AppState};

/// The address of the connection a request came in on. The server inserts it as a request
/// extension; without it, every request shares one source for rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddr(pub IpAddr);

/// Compared against when a token id is unknown, so a miss costs the same hash work as a wrong
/// secret.
const DUMMY_HASH: [u8; 32] = [0x5a; 32];

/// Middleware on the board routes: puts the caller's `Authenticated` in the request extensions,
/// or answers 429 or 401 (network mode) or 400 (a malformed `X-Stigmer-As` in local mode).
pub(crate) async fn authenticate<S: IdentityStore, A: Authorize>(
    State(state): State<AppState<S, A>>,
    mut request: Request,
    next: Next,
) -> Response {
    let caller = match state.config.mode {
        Mode::Local => local_caller(request.headers()),
        Mode::Network => {
            let peer = request.extensions().get::<PeerAddr>().map(|p| p.0);
            let source = client_source(peer, request.headers(), &state.config.trusted_proxies);
            network_caller(&state, source, request.headers()).await
        }
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

/// Network mode: 429 when the source or the token id has no failures left, else the verified
/// caller, else 401 (and one failure taken from each).
async fn network_caller<S: IdentityStore, A: Authorize>(
    state: &AppState<S, A>,
    source: Source,
    headers: &HeaderMap,
) -> Result<Authenticated, ApiError> {
    let now = (state.config.clock)();
    let parsed = bearer(headers).and_then(|raw| parse_secret(SecretKind::Token, raw).ok());
    let token = parsed.as_ref().map(|(id, _)| id.clone());
    let mut keys = vec![Key::Source(source)];
    keys.extend(token.clone().map(Key::Token));
    if let Err(retry_after) = state.auth_failures.check(&keys, now) {
        if state
            .auth_failures
            .should_log(source, Logged::RateLimited, now)
        {
            state
                .store
                .log_security(rate_limited_event(now, source))
                .await?;
        }
        return Err(ApiError::rate_limited(retry_after));
    }
    if let Some(who) = verify(&*state.store, parsed, now).await? {
        return Ok(who);
    }
    state.auth_failures.record_failure(&keys, now);
    if state
        .auth_failures
        .should_log(source, Logged::AuthFailed, now)
    {
        state
            .store
            .log_security(auth_failed_event(now, source, token.as_ref()))
            .await?;
    }
    Err(ApiError::unauthorized())
}

/// A failed authentication: the source and, when the token parsed, its public id.
fn auth_failed_event(at_ms: i64, source: Source, token: Option<&TokenId>) -> SecurityEvent {
    let detail = match token {
        Some(id) => format!("source={source} token={id}"),
        None => format!("source={source}"),
    };
    security_event(at_ms, SecurityEventKind::AuthFailed, detail)
}

/// A request refused by the failed-authentication limit.
fn rate_limited_event(at_ms: i64, source: Source) -> SecurityEvent {
    security_event(
        at_ms,
        SecurityEventKind::RateLimited,
        format!("source={source}"),
    )
}

fn security_event(at_ms: i64, kind: SecurityEventKind, detail: String) -> SecurityEvent {
    SecurityEvent {
        at_ms,
        kind,
        board: None,
        principal: None,
        detail,
    }
}

/// The client a request is attributed to.
///
/// The peer itself, unless the peer is a trusted proxy: then `X-Forwarded-For` is walked from
/// the right, skipping hops that are trusted proxies too, and the first other hop is the client.
/// Hops to its left were written by the client and are never believed. A hop that is not an
/// address ends the walk at the last trusted hop. No peer at all is the shared unknown source.
fn client_source(peer: Option<IpAddr>, headers: &HeaderMap, trusted: &[IpNet]) -> Source {
    let Some(peer) = peer.map(|ip| ip.to_canonical()) else {
        return Source::Unknown;
    };
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(peer) {
        return Source::Ip(peer);
    }
    let mut client = peer;
    let lines: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    for hop in lines.iter().rev().flat_map(|line| line.rsplit(',')) {
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            break;
        };
        client = ip.to_canonical();
        if !is_trusted(client) {
            break;
        }
    }
    Source::Ip(client)
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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append("x-forwarded-for", HeaderValue::from_str(line).unwrap());
        }
        headers
    }

    #[test]
    fn client_source_believes_forwarding_only_from_trusted_proxies() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let at =
            |peer: Option<&str>, lines: &[&str]| client_source(peer.map(ip), &xff(lines), &trusted);
        let src = |s: &str| Source::Ip(ip(s));
        assert_eq!(at(None, &["192.0.2.1"]), Source::Unknown);
        assert_eq!(
            at(Some("198.51.100.1"), &["192.0.2.1"]),
            src("198.51.100.1")
        );
        assert_eq!(at(Some("10.0.0.1"), &[]), src("10.0.0.1"));
        assert_eq!(at(Some("10.0.0.1"), &["192.0.2.1"]), src("192.0.2.1"));
        assert_eq!(
            at(Some("10.0.0.1"), &["203.0.113.9, 192.0.2.1, 10.0.0.2"]),
            src("192.0.2.1")
        );
        // Several header lines are one list, in order.
        assert_eq!(
            at(Some("10.0.0.1"), &["203.0.113.9, 192.0.2.1", "10.0.0.2"]),
            src("192.0.2.1")
        );
        // Every hop trusted: the leftmost is as far as the walk can see.
        assert_eq!(
            at(Some("10.0.0.1"), &["10.0.0.3, 10.0.0.2"]),
            src("10.0.0.3")
        );
        // Garbage stops the walk at the last trusted hop.
        assert_eq!(
            at(Some("10.0.0.1"), &["192.0.2.1, nonsense"]),
            src("10.0.0.1")
        );
        assert_eq!(
            at(Some("10.0.0.1"), &["192.0.2.1, unknown, 10.0.0.2"]),
            src("10.0.0.2")
        );
        // IPv4-mapped peers are the IPv4 address.
        assert_eq!(at(Some("::ffff:198.51.100.1"), &[]), src("198.51.100.1"));
        assert_eq!(
            at(Some("::ffff:10.0.0.1"), &["192.0.2.1"]),
            src("192.0.2.1")
        );
    }

    #[test]
    fn security_events_name_the_source_and_token_id_only() {
        let id = TokenId::new("0123456789abcdef").unwrap();
        let failed = auth_failed_event(5, Source::Ip(ip("192.0.2.1")), Some(&id));
        assert_eq!(failed.kind, SecurityEventKind::AuthFailed);
        assert_eq!(failed.detail, "source=192.0.2.1 token=0123456789abcdef");
        assert_eq!(failed.at_ms, 5);
        let anonymous = auth_failed_event(5, Source::Unknown, None);
        assert_eq!(anonymous.detail, "source=unknown");
        let limited = rate_limited_event(6, Source::Ip(ip("::1")));
        assert_eq!(limited.kind, SecurityEventKind::RateLimited);
        assert_eq!(limited.detail, "source=::1");
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
