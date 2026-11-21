//! `wait` and `tail`: long-poll the event feed and print each event's message framed.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Serialize;
use stigmer_core::{parse_labels, Cursor, Event, EventFilter, Message, MessageId, Thread};

use crate::client::Client;
use crate::commands::{channel, message_id, parse_arg, print_out, Ctx};
use crate::exit::{CliError, Exit};
use crate::render::render_message;

/// The longest wait the server grants one request.
const MAX_CHUNK_S: u64 = 300;

/// Filters and start position shared by `wait` and `tail`, as typed.
pub struct FeedArgs {
    pub channel: Option<String>,
    pub thread: Option<String>,
    pub label: Option<String>,
    pub after: Option<String>,
}

impl FeedArgs {
    /// Validates every argument before any request.
    fn parse(self) -> Result<(EventFilter, Option<Cursor>), CliError> {
        let label = match self.label {
            Some(raw) => parse_arg(
                &raw,
                |raw| parse_labels(&[raw.to_owned()]),
                "pass the label as --label key=value",
            )?
            .into_iter()
            .next(),
            None => None,
        };
        let filter = EventFilter {
            channel_prefix: self.channel.as_deref().map(channel).transpose()?,
            thread: self.thread.as_deref().map(message_id).transpose()?,
            label,
        };
        let after = self
            .after
            .map(|raw| {
                serde_json::from_value::<Cursor>(serde_json::Value::String(raw)).map_err(|e| {
                    CliError::new(
                        Exit::Invalid,
                        "invalid_cursor",
                        e.to_string(),
                        "pass a cursor printed by wait or tail, or drop --after",
                    )
                })
            })
            .transpose()?;
        Ok((filter, after))
    }
}

/// Seconds to ask the server to wait with `remaining` left: rounded up, at most 300.
pub fn chunk_secs(remaining: Duration) -> u64 {
    let secs = remaining.as_secs();
    let secs = if remaining.subsec_nanos() > 0 {
        secs.saturating_add(1)
    } else {
        secs
    };
    secs.min(MAX_CHUNK_S)
}

/// Parses `30s`, `5m`, `1h` or plain seconds.
pub fn parse_timeout(raw: &str) -> Result<Duration, String> {
    let bad = || format!("expected a duration like 30s, 5m, 1h or plain seconds, got {raw:?}");
    let (digits, unit_secs) = match raw.as_bytes().last() {
        Some(b's') => (&raw[..raw.len() - 1], 1),
        Some(b'm') => (&raw[..raw.len() - 1], 60),
        Some(b'h') => (&raw[..raw.len() - 1], 3_600),
        _ => (raw, 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let count: u64 = digits.parse().map_err(|_| bad())?;
    count
        .checked_mul(unit_secs)
        .map(Duration::from_secs)
        .ok_or_else(bad)
}

/// The command that continues a wait from `after` with the same filters.
pub fn resume_line(who: Option<&str>, after: Option<&Cursor>, filter: &EventFilter) -> String {
    let mut flags: Vec<(&str, String)> = Vec::new();
    if let Some(after) = after {
        flags.push(("--after", after.to_string()));
    }
    if let Some(channel) = &filter.channel_prefix {
        flags.push(("--channel", channel.to_string()));
    }
    if let Some(thread) = &filter.thread {
        flags.push(("--thread", thread.to_string()));
    }
    if let Some(label) = &filter.label {
        flags.push(("--label", format!("{}={}", label.key, label.value)));
    }
    let mut line = String::from("stigmer");
    if let Some(who) = who {
        line.push_str(&format!(" --as {}", shell_word(who)));
    }
    line.push_str(" wait");
    for (name, value) in flags {
        line.push_str(&format!(" {name} {}", shell_word(&value)));
    }
    line
}

/// `value` as one POSIX shell word, single-quoted unless it is plainly safe.
fn shell_word(value: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "._/=:@%+-".contains(c);
    if value.chars().all(plain) {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// A position in the event feed plus the threads already fetched for message text.
struct Feed {
    client: Client,
    filter: EventFilter,
    cursor: Option<Cursor>,
    threads: HashMap<MessageId, Thread>,
}

impl Feed {
    /// Long-polls in chunks of at most 300 s until events arrive or `deadline` passes
    /// (never, when None). An empty result means the deadline passed.
    fn next_batch(&mut self, deadline: Option<Instant>) -> Result<Vec<Event>, CliError> {
        loop {
            let secs = match deadline {
                Some(deadline) => chunk_secs(deadline.saturating_duration_since(Instant::now())),
                None => MAX_CHUNK_S,
            };
            let response = self
                .client
                .events(&self.filter, self.cursor.as_ref(), secs)?;
            if response.cursor.is_some() {
                self.cursor = response.cursor;
            }
            if !response.events.is_empty() {
                return Ok(response.events);
            }
            if secs == 0 || deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Ok(Vec::new());
            }
        }
    }

    /// The message an event refers to. Events carry no text, so its thread is fetched,
    /// once per thread, and again only if a newer reply is missing from the cached copy.
    fn message(&mut self, event: &Event) -> Result<Message, CliError> {
        if let Some(found) = self.cached(event) {
            return Ok(found);
        }
        let thread = self.client.thread(&event.thread_id)?;
        self.threads.insert(event.thread_id.clone(), thread);
        self.cached(event).ok_or_else(|| {
            CliError::new(
                Exit::Failure,
                "internal",
                format!(
                    "thread {} does not contain message {}",
                    event.thread_id, event.message_id
                ),
                "retry; if it persists, report this as a bug",
            )
        })
    }

    fn cached(&self, event: &Event) -> Option<Message> {
        let thread = self.threads.get(&event.thread_id)?;
        std::iter::once(&thread.root)
            .chain(&thread.replies)
            .find(|message| message.id == event.message_id)
            .cloned()
    }
}

/// A summary line, then the framed message.
fn render_event(event: &Event, message: &Message) -> String {
    format!(
        "{} in {} by {} (thread {})\n{}\n",
        event.kind.as_str(),
        event.channel,
        event.actor,
        event.thread_id,
        render_message(message)
    )
}

#[derive(Serialize)]
struct WaitOutput<'a> {
    events: &'a [Event],
    messages: &'a [Message],
    cursor: Option<&'a Cursor>,
}

/// The error of a wait that saw no matching event within `timeout` (exit 3).
pub fn timed_out(timeout: Duration, resume: String) -> CliError {
    CliError::new(
        Exit::Timeout,
        "timeout",
        format!("no matching events within {}s", timeout.as_secs()),
        resume,
    )
}

/// `wait`: blocks until matching events arrive (exit 0) or `timeout` passes (exit 3).
pub fn wait(ctx: &Ctx, args: FeedArgs, timeout: Duration) -> Result<Exit, CliError> {
    let (filter, after) = args.parse()?;
    let mut feed = Feed {
        client: ctx.client(None)?,
        filter,
        cursor: after,
        threads: HashMap::new(),
    };
    // A timeout too large to add to the clock waits until killed.
    let deadline = Instant::now().checked_add(timeout);
    let events = feed.next_batch(deadline)?;
    let resume = resume_line(ctx.who.as_deref(), feed.cursor.as_ref(), &feed.filter);
    let mut tail = String::new();
    if let Some(cursor) = &feed.cursor {
        tail.push_str(&format!("cursor: {cursor}\n"));
    }
    tail.push_str(&format!("resume: {resume}\n"));

    if events.is_empty() {
        if !ctx.json {
            print_out(&tail)?;
        }
        return Err(timed_out(timeout, resume));
    }
    let messages = events
        .iter()
        .map(|event| feed.message(event))
        .collect::<Result<Vec<_>, _>>()?;
    let mut text: String = events
        .iter()
        .zip(&messages)
        .map(|(event, message)| render_event(event, message))
        .collect();
    text.push_str(&tail);
    let output = WaitOutput {
        events: &events,
        messages: &messages,
        cursor: feed.cursor.as_ref(),
    };
    ctx.emit(&output, &text)?;
    Ok(Exit::Ok)
}

#[derive(Serialize)]
struct TailItem<'a> {
    event: &'a Event,
    message: &'a Message,
}

/// `tail`: prints events as they arrive until killed, or until `timeout` passes (exit 0).
/// With `--json` it prints one JSON object per event, one per line.
pub fn tail(ctx: &Ctx, args: FeedArgs, timeout: Option<Duration>) -> Result<Exit, CliError> {
    let (filter, after) = args.parse()?;
    let mut feed = Feed {
        client: ctx.client(None)?,
        filter,
        cursor: after,
        threads: HashMap::new(),
    };
    let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
    loop {
        let events = feed.next_batch(deadline)?;
        for event in &events {
            let message = feed.message(event)?;
            let item = TailItem {
                event,
                message: &message,
            };
            ctx.emit(&item, &render_event(event, &message))?;
        }
        if events.is_empty() || deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
    }
    if let (false, Some(cursor)) = (ctx.json, &feed.cursor) {
        print_out(&format!("cursor: {cursor}\n"))?;
    }
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stigmer_core::{ChannelPath, Label};

    #[test]
    fn wait_timeout_loop_chunks_are_planned_correctly() {
        assert_eq!(chunk_secs(Duration::ZERO), 0);
        assert_eq!(chunk_secs(Duration::from_millis(1)), 1);
        assert_eq!(chunk_secs(Duration::from_millis(1_500)), 2);
        assert_eq!(chunk_secs(Duration::from_secs(30)), 30);
        assert_eq!(chunk_secs(Duration::from_secs(300)), 300);
        assert_eq!(chunk_secs(Duration::from_secs(301)), 300);
        // A 12 minute wait in which nothing arrives asks for 300 s, 300 s, then 120 s.
        let mut remaining = Duration::from_secs(720);
        let mut chunks = vec![];
        while !remaining.is_zero() {
            let secs = chunk_secs(remaining);
            chunks.push(secs);
            remaining = remaining.saturating_sub(Duration::from_secs(secs));
        }
        assert_eq!(chunks, vec![300, 300, 120]);
    }

    #[test]
    fn timeout_accepts_suffixes_and_plain_seconds() {
        assert_eq!(parse_timeout("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_timeout("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_timeout("1h"), Ok(Duration::from_secs(3_600)));
        assert_eq!(parse_timeout("45"), Ok(Duration::from_secs(45)));
        assert_eq!(parse_timeout("0"), Ok(Duration::ZERO));
        for bad in ["", "s", "5x", "-1", "1.5m", "5 m", "99999999999999999999h"] {
            assert!(parse_timeout(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn resume_line_repeats_the_filters_and_quotes_odd_values() {
        let filter = EventFilter {
            channel_prefix: Some(ChannelPath::new("eng").unwrap()),
            thread: None,
            label: Some(Label::new("note", "it's on").unwrap()),
        };
        let cursor = Cursor::from_seq(7);
        assert_eq!(
            resume_line(Some("bob"), Some(&cursor), &filter),
            format!(
                "stigmer --as bob wait --after {cursor} --channel eng --label 'note=it'\\''s on'"
            )
        );
        assert_eq!(
            resume_line(None, None, &EventFilter::default()),
            "stigmer wait"
        );
    }
}
