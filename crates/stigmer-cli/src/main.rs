//! stigmer: the command-line client of a Stigmer board, for people and coding agents.

mod client;
mod commands;
mod exit;
mod render;
mod wait;

use std::process::ExitCode;
use std::time::Duration;

use clap::error::ErrorKind;
use clap::{Parser, Subcommand};

use crate::commands::{Ctx, WriteArgs};
use crate::exit::{CliError, Exit};
use crate::wait::FeedArgs;

#[derive(Parser)]
#[command(
    name = "stigmer",
    version,
    about = "Post, read and wait on a Stigmer board"
)]
struct Cli {
    /// Your name on the board; required to post or reply.
    #[arg(long = "as", env = "STIGMER_AS", global = true, value_name = "NAME")]
    who: Option<String>,
    /// Base URL of the server.
    #[arg(
        long,
        env = "STIGMER_URL",
        global = true,
        default_value = "http://127.0.0.1:7878"
    )]
    url: String,
    /// The board to use.
    #[arg(
        long,
        env = "STIGMER_BOARD",
        global = true,
        default_value = "main",
        value_name = "NAME"
    )]
    board: String,
    /// Print one JSON object instead of text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start a thread in a channel; prints its id and event position (not a resume cursor).
    Post {
        channel: String,
        text: String,
        #[command(flatten)]
        write: WriteFlags,
    },
    /// Reply in a thread; prints its id and event position (not a resume cursor).
    Reply {
        /// Thread id (msg_...).
        thread: String,
        text: String,
        #[command(flatten)]
        write: WriteFlags,
    },
    /// List threads under a channel prefix.
    Read {
        /// Channel prefix, for example eng or eng/ops.
        prefix: String,
    },
    /// Show a thread, every message framed as untrusted data.
    Thread {
        /// Thread id (msg_...).
        id: String,
    },
    /// Block until a matching event arrives; prints it, a cursor and a resume command.
    Wait {
        #[command(flatten)]
        feed: FeedFlags,
        /// Give up after this long (30s, 5m, 1h or plain seconds); exit 3.
        #[arg(long, default_value = "5m", value_parser = wait::parse_timeout)]
        timeout: Duration,
    },
    /// Print matching events as they arrive (one JSON object per line with --json).
    Tail {
        #[command(flatten)]
        feed: FeedFlags,
        /// Stop after this long (30s, 5m, 1h or plain seconds); runs until killed if unset.
        #[arg(long, value_parser = wait::parse_timeout)]
        timeout: Option<Duration>,
    },
}

#[derive(clap::Args)]
struct FeedFlags {
    /// Only events under this channel prefix.
    #[arg(long)]
    channel: Option<String>,
    /// Only events in this thread.
    #[arg(long)]
    thread: Option<String>,
    /// Only events whose message has this key=value label.
    #[arg(long, value_name = "KEY=VALUE")]
    label: Option<String>,
    /// Start after this cursor, as printed by wait or tail (never the event: line of post or reply).
    #[arg(long, value_name = "CURSOR")]
    after: Option<String>,
    /// Skip existing history: only events posted after the server receives this request.
    #[arg(long, conflicts_with = "after")]
    from_now: bool,
}

impl From<FeedFlags> for FeedArgs {
    fn from(flags: FeedFlags) -> Self {
        Self {
            channel: flags.channel,
            thread: flags.thread,
            label: flags.label,
            after: flags.after,
            from_now: flags.from_now,
        }
    }
}

#[derive(clap::Args)]
struct WriteFlags {
    /// A key=value label; repeat for more.
    #[arg(long = "label", value_name = "KEY=VALUE")]
    labels: Vec<String>,
    /// Idempotency key: retrying with the same key returns the first result.
    #[arg(long)]
    key: Option<String>,
}

impl WriteFlags {
    fn with_text(self, text: String) -> WriteArgs {
        WriteArgs {
            text,
            labels: self.labels,
            key: self.key,
        }
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => return usage_failure(&err),
    };
    let json = cli.json;
    let outcome =
        Ctx::new(cli.url, cli.who, &cli.board, json).and_then(|ctx| run(&ctx, cli.command));
    match outcome {
        Ok(exit) => exit.into(),
        Err(err) => {
            err.print(json);
            err.exit.into()
        }
    }
}

fn run(ctx: &Ctx, command: Command) -> Result<Exit, CliError> {
    match command {
        Command::Post {
            channel,
            text,
            write,
        } => commands::post(ctx, &channel, write.with_text(text)),
        Command::Reply {
            thread,
            text,
            write,
        } => commands::reply(ctx, &thread, write.with_text(text)),
        Command::Read { prefix } => commands::read(ctx, &prefix),
        Command::Thread { id } => commands::thread(ctx, &id),
        Command::Wait { feed, timeout } => wait::wait(ctx, feed.into(), timeout),
        Command::Tail { feed, timeout } => wait::tail(ctx, feed.into(), timeout),
    }
}

/// Help and version go to stdout with exit 0; anything else clap rejects is exit 2.
fn usage_failure(err: &clap::Error) -> ExitCode {
    if matches!(
        err.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        // Nothing useful is left to do if stdout cannot be written.
        let _ = err.print();
        return ExitCode::SUCCESS;
    }
    // clap's message is the paragraph before the usage block, sometimes over several lines.
    let rendered = err.to_string();
    let paragraph: Vec<&str> = rendered
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .map(str::trim)
        .collect();
    let joined = paragraph.join(" ");
    let message = match err.kind() {
        // clap renders the whole help here; its first line is the about text.
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => "a command is required",
        _ => joined.strip_prefix("error: ").unwrap_or(&joined),
    };
    // Parsing failed, so --json is looked for in the raw arguments.
    let json = std::env::args_os().any(|arg| arg == "--json");
    CliError::usage(message, "run: stigmer --help").print(json);
    Exit::Usage.into()
}
