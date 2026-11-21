//! A blocking HTTP client for one board's API.

use std::io::ErrorKind;
use std::time::Duration;

use serde::de::DeserializeOwned;
use stigmer_core::{
    ChannelPath, ChannelsResponse, Cursor, ErrorBody, EventFilter, EventsResponse, MessageId,
    PostRequest, Posted, Principal, Thread,
};
use ureq::http::Response;
use ureq::{Agent, Body, RequestBuilder};

use crate::exit::{CliError, Exit};

/// Time limit for requests that do not wait for events.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How much longer than its server-side wait an events request may take.
const WAIT_GRACE: Duration = Duration::from_secs(10);
/// The only board in M0.
const BOARD: &str = "main";

pub struct Client {
    agent: Agent,
    base: String,
    who: Option<Principal>,
}

impl Client {
    /// A client for the server at `base_url`, acting as `who` when given.
    pub fn new(base_url: &str, who: Option<Principal>) -> Self {
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Self {
            agent,
            base: base_url.trim_end_matches('/').to_owned(),
            who,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/boards/{BOARD}/{path}", self.base)
    }

    fn identify<B>(&self, request: RequestBuilder<B>) -> RequestBuilder<B> {
        match &self.who {
            Some(who) => request.header("X-Stigmer-As", who.as_str()),
            None => request,
        }
    }

    /// Posts a message. A replayed post (same idempotency key) comes back with `replayed` set.
    pub fn post(&self, body: &PostRequest, key: Option<&str>) -> Result<Posted, CliError> {
        let mut request = self.identify(self.agent.post(self.url("messages")));
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key);
        }
        self.finish(request.send_json(body))
    }

    /// Threads under a channel prefix, newest activity first.
    pub fn channels(&self, prefix: &ChannelPath) -> Result<ChannelsResponse, CliError> {
        let request = self
            .identify(self.agent.get(self.url("channels")))
            .query("prefix", prefix.as_str());
        self.finish(request.call())
    }

    /// A thread root and its replies.
    pub fn thread(&self, id: &MessageId) -> Result<Thread, CliError> {
        let request = self.identify(self.agent.get(self.url(&format!("threads/{id}"))));
        self.finish(request.call())
    }

    /// Events after `after` matching `filter`; with `timeout_s > 0` the server holds the
    /// request until a matching event lands or the timeout passes.
    pub fn events(
        &self,
        filter: &EventFilter,
        after: Option<&Cursor>,
        timeout_s: u64,
    ) -> Result<EventsResponse, CliError> {
        let mut request = self
            .identify(self.agent.get(self.url("events")))
            .query("timeout_s", timeout_s.to_string());
        if let Some(after) = after {
            request = request.query("after", after.as_str());
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
            return response
                .body_mut()
                .read_json::<T>()
                .map_err(|e| self.bad_response(&e.to_string()));
        }
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| self.network_error(e))?;
        match serde_json::from_str::<ErrorBody>(&text) {
            Ok(body) => Err(CliError::api(body.error)),
            Err(_) => Err(self.bad_response(&format!("HTTP {status}"))),
        }
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
                "timeout",
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
