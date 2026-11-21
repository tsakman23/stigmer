//! The commands: validate arguments with stigmer-core, call the API, print the result.

use std::io::Write;

use stigmer_core::{
    BoardId, ChannelPath, CoreError, NewMessage, PostRequest, Posted, Principal, Target,
};

use crate::client::Client;
use crate::exit::{CliError, Exit};

const AS_HINT: &str = "export STIGMER_AS=<name> or pass --as <name>";

/// Global options every command sees.
pub struct Ctx {
    pub url: String,
    pub who: Option<String>,
    pub json: bool,
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
    fn client(&self, who: Option<Principal>) -> Result<Client, CliError> {
        let who = match who {
            Some(who) => Some(who),
            None => self.who.as_deref().map(principal).transpose()?,
        };
        Ok(Client::new(&self.url, who))
    }

    /// Prints `value` as one JSON object, or `text` otherwise.
    fn emit<T: serde::Serialize>(&self, value: &T, text: &str) -> Result<(), CliError> {
        if self.json {
            let json = serde_json::to_string(value).map_err(|e| {
                CliError::new(
                    Exit::Failure,
                    "internal",
                    format!("cannot encode output: {e}"),
                    "report this as a bug",
                )
            })?;
            print_out(&format!("{json}\n"))
        } else {
            print_out(text)
        }
    }
}

/// Writes to stdout and flushes, so a closed pipe is a reported failure, not a panic.
pub fn print_out(text: &str) -> Result<(), CliError> {
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

fn principal(raw: &str) -> Result<Principal, CliError> {
    Principal::new(raw)
        .map_err(|e| CliError::invalid(&e, "names are 1 to 64 characters of [a-z0-9._-]"))
}

/// Parses a channel argument; one trailing `/` is allowed (`research/` is `research`).
pub fn channel(raw: &str) -> Result<ChannelPath, CliError> {
    let trimmed = raw.strip_suffix('/').unwrap_or(raw);
    ChannelPath::new(trimmed).map_err(|e| {
        CliError::invalid(
            &e,
            "channels are 1 to 8 segments of [a-z0-9._-] joined by /, for example eng/ops",
        )
    })
}

fn core_hint(err: &CoreError) -> &'static str {
    match err {
        CoreError::EmptyText => "pass the message text as an argument",
        CoreError::TooLong { .. } => "shorten the text to at most 10000 characters",
        CoreError::TooManyLabels { .. } | CoreError::BadLabel(_) => {
            "pass at most 32 labels as --label key=value"
        }
        CoreError::BadIdempotencyKey(_) => "keys are 1 to 128 characters of [A-Za-z0-9._:-]",
        _ => "fix the arguments; see: stigmer --help",
    }
}

/// Text, labels and key of a write, validated by stigmer-core before any request.
pub struct WriteArgs {
    pub text: String,
    pub labels: Vec<String>,
    pub key: Option<String>,
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
pub fn post(ctx: &Ctx, channel_arg: &str, args: WriteArgs) -> Result<Exit, CliError> {
    let author = ctx.author("post")?;
    let target = Target::NewThread {
        channel: channel(channel_arg)?,
    };
    let posted = send(ctx, validate(target, author, args)?)?;
    let m = &posted.message;
    let first = format!("posted {} in {} as {}", m.id, m.channel, m.author);
    report_posted(ctx, &posted, first)
}
