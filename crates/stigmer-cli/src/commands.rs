//! The commands: validate arguments with stigmer-core, call the API, print the result.

use std::io::Write;

use stigmer_core::{
    BoardId, ChannelPath, CoreError, MessageId, NewMessage, PostRequest, Posted, Principal, Target,
    ThreadSummary, MAX_IDEMPOTENCY_KEY_CHARS, MAX_LABELS,
};

use crate::client::Client;
use crate::exit::{too_long_hint, CliError, Exit};
use crate::render::render_message;

/// Characters of a thread's root text shown by `read`.
const PREVIEW_CHARS: usize = 80;

const AS_HINT: &str = "export STIGMER_AS=<name> or pass --as <name>";

/// Global options every command sees.
pub(crate) struct Ctx {
    pub(crate) url: String,
    pub(crate) who: Option<String>,
    pub(crate) json: bool,
}

impl Ctx {
    /// The identity a write needs: required, and validated before any request.
    fn author(&self, verb: &str) -> Result<Principal, CliError> {
        let raw = self
            .who
            .as_deref()
            .ok_or_else(|| CliError::usage(format!("--as is required to {verb}"), AS_HINT))?;
        principal(raw)
    }

    /// A client acting as `who`, or as the optional `--as` identity when `who` is None.
    pub(crate) fn client(&self, who: Option<Principal>) -> Result<Client, CliError> {
        let who = match who {
            Some(who) => Some(who),
            None => self.who.as_deref().map(principal).transpose()?,
        };
        Ok(Client::new(&self.url, who))
    }

    /// Prints `value` as one JSON object with every message marked untrusted, or
    /// `text` otherwise.
    pub(crate) fn emit<T: serde::Serialize>(&self, value: &T, text: &str) -> Result<(), CliError> {
        if self.json {
            let encode_failed = |e: serde_json::Error| {
                CliError::new(
                    Exit::Failure,
                    "internal",
                    format!("cannot encode output: {e}"),
                    "report this as a bug",
                )
            };
            let mut value = serde_json::to_value(value).map_err(encode_failed)?;
            mark_untrusted(&mut value);
            let json = serde_json::to_string(&value).map_err(encode_failed)?;
            print_out(&format!("{json}\n"))
        } else {
            print_out(text)
        }
    }
}

/// Fields of the JSON outputs that hold one message (or thread summary) written by
/// another party.
const MESSAGE_FIELDS: [&str; 2] = ["message", "root"];
/// Fields of the JSON outputs that hold a list of them.
const MESSAGE_LIST_FIELDS: [&str; 3] = ["messages", "replies", "threads"];

/// Adds `"untrusted": true` to every message object in a top-level JSON output
/// (`Posted`, `Thread`, `ChannelsResponse`, and the wait and tail outputs), so a
/// program reading `--json` sees that the text is data from another party.
fn mark_untrusted(output: &mut serde_json::Value) {
    let Some(fields) = output.as_object_mut() else {
        return;
    };
    let mut mark = |value: &mut serde_json::Value| {
        if let Some(object) = value.as_object_mut() {
            object.insert("untrusted".to_owned(), serde_json::Value::Bool(true));
        }
    };
    for name in MESSAGE_FIELDS {
        if let Some(value) = fields.get_mut(name) {
            mark(value);
        }
    }
    for name in MESSAGE_LIST_FIELDS {
        if let Some(serde_json::Value::Array(items)) = fields.get_mut(name) {
            items.iter_mut().for_each(&mut mark);
        }
    }
}

/// Writes to stdout and flushes, so a closed pipe is a reported failure, not a panic.
pub(crate) fn print_out(text: &str) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|e| {
            CliError::new(
                Exit::Failure,
                "io",
                format!("cannot write to stdout: {e}"),
                "check where the output goes",
            )
        })
}

/// Parses `raw` with a stigmer-core constructor; a rejection is an invalid-input error
/// whose next step is `hint`.
pub(crate) fn parse_arg<T>(
    raw: &str,
    parse: impl FnOnce(&str) -> Result<T, CoreError>,
    hint: &str,
) -> Result<T, CliError> {
    parse(raw).map_err(|e| CliError::invalid(&e, hint))
}

fn principal(raw: &str) -> Result<Principal, CliError> {
    parse_arg(
        raw,
        Principal::new,
        "names are 1 to 64 characters of [a-z0-9._-]",
    )
}

/// Parses a channel argument; one trailing `/` is allowed (`research/` is `research`).
pub(crate) fn channel(raw: &str) -> Result<ChannelPath, CliError> {
    let trimmed = raw.strip_suffix('/').unwrap_or(raw);
    parse_arg(
        trimmed,
        ChannelPath::new,
        "channels are 1 to 8 segments of [a-z0-9._-] joined by /, for example eng/ops",
    )
}

fn core_hint(err: &CoreError) -> String {
    match err {
        CoreError::EmptyText => "pass the message text as an argument".to_owned(),
        CoreError::TooLong { .. } => too_long_hint(),
        CoreError::TooManyLabels { .. } | CoreError::BadLabel(_) => {
            format!("pass at most {MAX_LABELS} labels as --label key=value")
        }
        CoreError::BadIdempotencyKey(_) => {
            format!("keys are 1 to {MAX_IDEMPOTENCY_KEY_CHARS} characters of [A-Za-z0-9._:-]")
        }
        _ => "fix the arguments; run: stigmer --help".to_owned(),
    }
}

/// Text, labels and key of a write, validated by stigmer-core before any request.
pub(crate) struct WriteArgs {
    pub(crate) text: String,
    pub(crate) labels: Vec<String>,
    pub(crate) key: Option<String>,
}

fn validate(target: Target, author: Principal, args: WriteArgs) -> Result<NewMessage, CliError> {
    let labels = stigmer_core::parse_labels(&args.labels)
        .map_err(|e| CliError::invalid(&e, core_hint(&e)))?;
    NewMessage::new(BoardId::main(), target, author, args.text, labels, args.key)
        .map_err(|e| CliError::invalid(&e, core_hint(&e)))
}

fn send(ctx: &Ctx, msg: NewMessage) -> Result<Posted, CliError> {
    let (channel, thread) = match msg.target {
        Target::NewThread { channel } => (Some(channel), None),
        Target::Reply { thread } => (None, Some(thread)),
    };
    let body = PostRequest {
        channel,
        thread,
        text: msg.text,
        labels: msg.labels,
    };
    ctx.client(Some(msg.author))?
        .post(&body, msg.idempotency_key.as_deref())
}

fn report_posted(ctx: &Ctx, posted: &Posted, first: String) -> Result<Exit, CliError> {
    let replayed = if posted.replayed { " (replayed)" } else { "" };
    let text = format!("{first}{replayed}\ncursor: {}\n", posted.event.cursor);
    ctx.emit(posted, &text)?;
    Ok(Exit::Ok)
}

/// `post <channel> <text>`: starts a thread.
pub(crate) fn post(ctx: &Ctx, channel_arg: &str, args: WriteArgs) -> Result<Exit, CliError> {
    let author = ctx.author("post")?;
    let target = Target::NewThread {
        channel: channel(channel_arg)?,
    };
    let posted = send(ctx, validate(target, author, args)?)?;
    let m = &posted.message;
    let first = format!("posted {} in {} as {}", m.id, m.channel, m.author);
    report_posted(ctx, &posted, first)
}

pub(crate) fn message_id(raw: &str) -> Result<MessageId, CliError> {
    parse_arg(
        raw,
        MessageId::new,
        "ids look like msg_ and 24 hex digits; list threads with: stigmer read <channel>",
    )
}

/// `reply <thread> <text>`: answers in a thread.
pub(crate) fn reply(ctx: &Ctx, thread_arg: &str, args: WriteArgs) -> Result<Exit, CliError> {
    let author = ctx.author("reply")?;
    let target = Target::Reply {
        thread: message_id(thread_arg)?,
    };
    let posted = send(ctx, validate(target, author, args)?)?;
    let m = &posted.message;
    let first = format!(
        "replied {} in thread {} ({}) as {}",
        m.id, m.thread_id, m.channel, m.author
    );
    report_posted(ctx, &posted, first)
}

/// `read <channel-prefix>`: one line per thread.
pub(crate) fn read(ctx: &Ctx, prefix_arg: &str) -> Result<Exit, CliError> {
    let prefix = channel(prefix_arg)?;
    let listing = ctx.client(None)?.channels(&prefix)?;
    let text = if listing.threads.is_empty() {
        format!("no threads in {prefix}\n")
    } else {
        listing.threads.iter().map(summary_line).collect()
    };
    ctx.emit(&listing, &text)?;
    Ok(Exit::Ok)
}

/// `1 reply`, `2 replies`, `0 replies`.
fn reply_count(n: u64) -> String {
    if n == 1 {
        "1 reply".to_owned()
    } else {
        format!("{n} replies")
    }
}

/// `<id>  <channel>  <n> replies  "<preview>"`; the preview is quoted and escaped so
/// it stays on one line.
fn summary_line(summary: &ThreadSummary) -> String {
    let replies = reply_count(u64::from(summary.reply_count));
    let mut preview: String = summary
        .root_text_preview
        .chars()
        .take(PREVIEW_CHARS)
        .collect();
    if summary
        .root_text_preview
        .chars()
        .nth(PREVIEW_CHARS)
        .is_some()
    {
        preview.push('…');
    }
    format!(
        "{}  {}  {replies}  {preview:?}\n",
        summary.thread_id, summary.channel
    )
}

/// `thread <id>`: every message framed, oldest first.
pub(crate) fn thread(ctx: &Ctx, id_arg: &str) -> Result<Exit, CliError> {
    let id = message_id(id_arg)?;
    let thread = ctx.client(None)?.thread(&id)?;
    let replies = u64::try_from(thread.replies.len()).unwrap_or(u64::MAX);
    let mut text = format!(
        "thread {} in {} ({})\n",
        thread.root.id,
        thread.root.channel,
        reply_count(replies)
    );
    for message in std::iter::once(&thread.root).chain(&thread.replies) {
        text.push('\n');
        text.push_str(&render_message(message));
        text.push('\n');
    }
    ctx.emit(&thread, &text)?;
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stigmer_core::MAX_MESSAGE_CHARS;

    #[test]
    fn hints_quote_the_core_limits() {
        let too_long = CoreError::TooLong {
            max: MAX_MESSAGE_CHARS,
        };
        assert_eq!(
            core_hint(&too_long),
            format!("shorten the text to at most {MAX_MESSAGE_CHARS} characters")
        );
        let labels_hint = format!("pass at most {MAX_LABELS} labels as --label key=value");
        let too_many = CoreError::TooManyLabels { max: MAX_LABELS };
        assert_eq!(core_hint(&too_many), labels_hint);
        assert_eq!(core_hint(&CoreError::BadLabel("x".into())), labels_hint);
        assert_eq!(
            core_hint(&CoreError::BadIdempotencyKey("x".into())),
            format!("keys are 1 to {MAX_IDEMPOTENCY_KEY_CHARS} characters of [A-Za-z0-9._:-]")
        );
    }
}
