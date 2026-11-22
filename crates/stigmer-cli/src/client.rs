//! A blocking HTTP client for one board's API.

use std::io::ErrorKind;
use std::time::Duration;

use serde::de::DeserializeOwned;
use stigmer_core::{
    BoardId, ChannelPath, ChannelsResponse, ErrorBody, EventFilter, EventsResponse, MessageId,
    PostRequest, Posted, Principal, SecretKind, Thread,
};
use ureq::http::Response;
use ureq::tls::TlsConfig;
use ureq::{Agent, Body, RequestBuilder};

use crate::exit::{CliError, Exit};
use crate::wait::Start;

/// Time limit for requests that do not wait for events.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How much longer than its server-side wait an events request may take.
const WAIT_GRACE: Duration = Duration::from_secs(10);
/// How a request says who is calling.
#[derive(Debug)]
pub(crate) enum Auth {
    /// No credential (local mode): `X-Stigmer-As` names the caller when given.
    Local(Option<Principal>),
    /// `Authorization: Bearer`; `X-Stigmer-As` is never sent with it.
    Token(Token),
}

/// A token in the `stg1_<id>_<secret>` shape. Debug output redacts it.
pub(crate) struct Token(String);

impl Token {
    /// Checks the shape locally so a mistyped value never reaches the server; `source` names
    /// where it came from. The error never echoes the value.
    pub(crate) fn new(raw: &str, source: &str) -> Result<Self, CliError> {
        stigmer_core::parse_secret(SecretKind::Token, raw).map_err(|_| {
            CliError::new(
                Exit::Invalid,
                "invalid_input",
                format!("{source} does not hold a stigmer token"),
                "use a token saved by stigmer join or stigmer login, or unset STIGMER_TOKEN",
            )
        })?;
        Ok(Self(raw.to_owned()))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

pub(crate) struct Client {
    agent: Agent,
    base: String,
    board: BoardId,
    auth: Auth,
}

impl Client {
    /// A client for `board` on the server at `base_url`, identified by `auth`.
    pub(crate) fn new(base_url: &str, board: BoardId, auth: Auth, tls: TlsConfig) -> Self {
        let agent: Agent = Agent::config_builder()
            .tls_config(tls)
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Self {
            agent,
            base: base_url.trim_end_matches('/').to_owned(),
            board,
            auth,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/boards/{}/{path}", self.base, self.board)
    }

    /// A route of this client's board, such as `members`.
    pub(crate) fn board_route(&self, path: &str) -> String {
        self.url(path)
    }

    /// A route outside any board, such as `whoami` or `boards`.
    pub(crate) fn root_route(&self, path: &str) -> String {
        format!("{}/v1/{path}", self.base)
    }

    /// GETs `url` and decodes the JSON response.
    pub(crate) fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T, CliError> {
        self.finish(self.identify(self.agent.get(url)).call())
    }

    /// POSTs `body` as JSON to `url` and decodes the JSON response.
    pub(crate) fn post_json<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T, CliError> {
        self.finish(self.identify(self.agent.post(url)).send_json(body))
    }

    /// POSTs an empty body to `url` and decodes the JSON response.
    pub(crate) fn post_empty<T: DeserializeOwned>(&self, url: &str) -> Result<T, CliError> {
        self.finish(self.identify(self.agent.post(url)).send_empty())
    }

    /// DELETEs `url`; success has no body.
    pub(crate) fn delete(&self, url: &str) -> Result<(), CliError> {
        let sent = self.identify(self.agent.delete(url)).call();
        let response = sent.map_err(|e| self.network_error(e))?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(self.failure(response)?)
    }

    fn identify<B>(&self, request: RequestBuilder<B>) -> RequestBuilder<B> {
        match &self.auth {
            Auth::Local(Some(who)) => request.header("X-Stigmer-As", who.as_str()),
            Auth::Local(None) => request,
            Auth::Token(token) => {
                request.header("Authorization", format!("Bearer {}", token.expose()))
            }
        }
    }

    /// Posts a message. A replayed post (same idempotency key) comes back with `replayed` set.
    pub(crate) fn post(&self, body: &PostRequest, key: Option<&str>) -> Result<Posted, CliError> {
        let mut request = self.identify(self.agent.post(self.url("messages")));
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key);
        }
        self.finish(request.send_json(body))
    }

    /// Threads under a channel prefix, newest activity first.
    pub(crate) fn channels(&self, prefix: &ChannelPath) -> Result<ChannelsResponse, CliError> {
        let request = self
            .identify(self.agent.get(self.url("channels")))
            .query("prefix", prefix.as_str());
        self.finish(request.call())
    }

    /// A thread root and its replies.
    pub(crate) fn thread(&self, id: &MessageId) -> Result<Thread, CliError> {
        let request = self.identify(self.agent.get(self.url(&format!("threads/{id}"))));
        self.finish(request.call())
    }

    /// Events from `start` matching `filter`; with `timeout_s > 0` the server holds the
    /// request until a matching event lands or the timeout passes.
    pub(crate) fn events(
        &self,
        filter: &EventFilter,
        start: &Start,
        timeout_s: u64,
    ) -> Result<EventsResponse, CliError> {
        let mut request = self
            .identify(self.agent.get(self.url("events")))
            .query("timeout_s", timeout_s.to_string());
        match start {
            Start::Beginning => {}
            Start::After(after) => request = request.query("after", after.as_str()),
            Start::Now => request = request.query("from_now", "true"),
        }
        if let Some(channel) = &filter.channel_prefix {
            request = request.query("channel", channel.as_str());
        }
        if let Some(thread) = &filter.thread {
            request = request.query("thread", thread.as_str());
        }
        if let Some(label) = &filter.label {
            request = request.query("label", format!("{}={}", label.key, label.value));
        }
        let request = request
            .config()
            .timeout_global(Some(Duration::from_secs(timeout_s) + WAIT_GRACE))
            .build();
        self.finish(request.call())
    }

    fn finish<T: DeserializeOwned>(
        &self,
        sent: Result<Response<Body>, ureq::Error>,
    ) -> Result<T, CliError> {
        let mut response = sent.map_err(|e| self.network_error(e))?;
        let status = response.status();
        if status.is_success() {
            // serde's messages can quote a value from the body, which may be a secret, so a
            // decoding failure reports only where it happened.
            return response.body_mut().read_json::<T>().map_err(|e| match e {
                ureq::Error::Json(json) => self.bad_response(&format!(
                    "unexpected JSON at line {} column {}",
                    json.line(),
                    json.column()
                )),
                other => self.bad_response(&other.to_string()),
            });
        }
        Err(self.failure(response)?)
    }

    /// The error a non-success response describes.
    fn failure(&self, mut response: Response<Body>) -> Result<CliError, CliError> {
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| self.network_error(e))?;
        Ok(match serde_json::from_str::<ErrorBody>(&text) {
            Ok(body) => CliError::api(body.error, retry_after),
            Err(_) => self.bad_response(&format!("HTTP {status}")),
        })
    }

    fn bad_response(&self, what: &str) -> CliError {
        CliError::new(
            Exit::Failure,
            "internal",
            format!("unexpected response from {}: {what}", self.base),
            "check that --url (or STIGMER_URL) points at a stigmer server",
        )
    }

    fn network_error(&self, err: ureq::Error) -> CliError {
        match err {
            ureq::Error::Io(io) if io.kind() == ErrorKind::ConnectionRefused => CliError::new(
                Exit::Failure,
                "unavailable",
                format!("cannot connect to {}: connection refused", self.base),
                "start the server with: stigmerd serve",
            ),
            ureq::Error::Timeout(_) => CliError::new(
                Exit::Failure,
                "request_timeout",
                format!("request to {} timed out", self.base),
                "check that stigmerd is running and responsive, then retry",
            ),
            other => CliError::new(
                Exit::Failure,
                "network",
                format!("request to {} failed: {other}", self.base),
                format!(
                    "check --url or STIGMER_URL (now {}); start the server with: stigmerd serve",
                    self.base
                ),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_request_timeout_code_differs_from_wait_timeout() {
        let client = Client::new(
            "http://127.0.0.1:7878",
            BoardId::main(),
            Auth::Local(None),
            TlsConfig::default(),
        );
        let request = client.network_error(ureq::Error::Timeout(ureq::Timeout::Global));
        assert_eq!(
            (request.exit, request.code),
            (Exit::Failure, "request_timeout")
        );
        let json: serde_json::Value = serde_json::from_str(&request.render(true)).unwrap();
        assert_eq!(json["error"]["code"], "request_timeout");

        let wait = crate::wait::timed_out(Duration::from_secs(1), "stigmer wait".to_owned());
        assert_eq!((wait.exit, wait.code), (Exit::Timeout, "timeout"));
        let json: serde_json::Value = serde_json::from_str(&wait.render(true)).unwrap();
        assert_eq!(json["error"]["code"], "timeout");
    }
}
