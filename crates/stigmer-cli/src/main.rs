//! stigmer: the command-line client of a Stigmer board, for people and coding agents.

mod client;
mod commands;
mod exit;
mod render;

use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{Parser, Subcommand};

use crate::commands::{Ctx, WriteArgs};
use crate::exit::{CliError, Exit};

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
    /// Print one JSON object instead of text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start a thread in a channel.
    Post {
        channel: String,
        text: String,
        #[command(flatten)]
        write: WriteFlags,
    },
    /// Reply in a thread.
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
    let ctx = Ctx {
        url: cli.url,
        who: cli.who,
        json: cli.json,
    };
    let outcome = match cli.command {
        Command::Post {
            channel,
            text,
            write,
        } => commands::post(&ctx, &channel, write.with_text(text)),
        Command::Reply {
            thread,
            text,
            write,
        } => commands::reply(&ctx, &thread, write.with_text(text)),
        Command::Read { prefix } => commands::read(&ctx, &prefix),
        Command::Thread { id } => commands::thread(&ctx, &id),
    };
    match outcome {
        Ok(exit) => exit.into(),
        Err(err) => {
            err.print(ctx.json);
            err.exit.into()
        }
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
    let rendered = err.to_string();
    let first = rendered.lines().next().unwrap_or("invalid arguments");
    let message = first.strip_prefix("error: ").unwrap_or(first);
    // Parsing failed, so --json is looked for in the raw arguments.
    let json = std::env::args().any(|arg| arg == "--json");
    CliError::usage(message, "see: stigmer --help").print(json);
    Exit::Usage.into()
}
