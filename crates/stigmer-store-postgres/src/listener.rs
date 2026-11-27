//! Cross-replica wake-ups: NOTIFY on commit, one listener connection per store handle (per
//! server process), and a safety poll.
//!
//! A post runs `pg_notify('stigmer_events', '<schema>:<board>:<seq>')` inside its transaction,
//! so the notification is delivered only if, and after, the post commits. The payload carries
//! the schema, the board id and the sequence number, never message content. The channel is per
//! database, so the schema in the payload keeps stores in different schemas of one database
//! from waking each other: a listener applies only payloads for its own `current_schema()`.
//!
//! The listener connection is opened from the store's configuration, not taken from the pool.
//! When it fails it reconnects with exponential backoff (100 ms doubling to 10 s); after every
//! (re)connect, once LISTEN is in effect, it re-reads the heads of the boards that have waiters,
//! so a post that committed while it was down is not lost. Behind it, a safety poll re-reads
//! those heads every poll interval through the pool, so a listener that is down or silently
//! cut off delays a wake by at most that interval and never wedges a wait. Both hold a
//! connection only for the one statement.

use std::future::poll_fn;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use stigmer_core::BoardId;
use stigmer_store::StoreError;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_postgres::tls::MakeTlsConnect;
use tokio_postgres::{AsyncMessage, Client, Config, NoTls, Socket, Transaction};

use crate::error::{backend, db};
use crate::notify::Notifier;
use crate::{pool, tls, PgTls};

/// The one channel every store notifies and listens on.
const CHANNEL: &str = "stigmer_events";
const MIN_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// Inside a post's transaction, before its commit: tells every listener on this database that
/// `board`'s head reached `seq`, once (and only if) the transaction commits.
pub(crate) async fn notify(
    tx: &Transaction<'_>,
    board: &BoardId,
    seq: u64,
) -> Result<(), StoreError> {
    tx.execute(
        "SELECT pg_notify('stigmer_events', coalesce(current_schema(), '') || ':' || $1::text || ':' || $2::text)",
        &[&board.as_str(), &seq.to_string()],
    )
    .await
    .map_err(db)?;
    Ok(())
}

/// A store handle's listener and safety poll; dropping it stops both.
pub(crate) struct Background {
    _tasks: [AbortOnDrop; 2],
    /// The listener's backend process id, 0 while it is reconnecting.
    pid: Arc<AtomicI32>,
}

impl Background {
    /// The listener's backend process id, `None` while it is reconnecting.
    pub(crate) fn listener_pid(&self) -> Option<i32> {
        Some(self.pid.load(Ordering::SeqCst)).filter(|pid| *pid != 0)
    }
}

/// What the listener needs to (re)connect and to deliver.
#[derive(Clone)]
struct Link {
    config: Config,
    tls: PgTls,
    notifier: Arc<Notifier>,
    pid: Arc<AtomicI32>,
}

/// Opens the listener connection (failing if it cannot LISTEN, as a wrong address or password
/// fails `PgStore::connect`) and starts the listener and the safety poll on `pool`.
pub(crate) async fn start(
    config: &Config,
    tls: PgTls,
    target: &str,
    pool: Pool,
    notifier: Arc<Notifier>,
    poll_interval: Duration,
) -> Result<Background, StoreError> {
    let link = Link {
        config: config.clone(),
        tls,
        notifier: Arc::clone(&notifier),
        pid: Arc::default(),
    };
    let first = Session::open(&link).await.map_err(|e| {
        StoreError::Backend(format!(
            "cannot open the listener connection to {target}: {e}"
        ))
    })?;
    let pid = Arc::clone(&link.pid);
    let listener = tokio::spawn(listen(link, first));
    let poller = tokio::spawn(poll_heads(pool, notifier, poll_interval));
    Ok(Background {
        _tasks: [AbortOnDrop(listener), AbortOnDrop(poller)],
        pid,
    })
}

/// Runs sessions for ever: when one ends, waits out the backoff and opens the next.
async fn listen(link: Link, first: Session) {
    let mut session = Some(first);
    let mut backoff = MIN_BACKOFF;
    loop {
        if let Some(open) = session.take() {
            backoff = MIN_BACKOFF;
            open.run(&link.notifier).await;
            link.pid.store(0, Ordering::SeqCst);
        }
        tokio::time::sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        // A failure here is retried after the next backoff; the safety poll covers the gap.
        session = Session::open(&link).await.ok();
    }
}

/// Every `every`, re-reads the heads of the boards with waiters through the pool.
async fn poll_heads(pool: Pool, notifier: Arc<Notifier>, every: Duration) {
    // `interval` refuses a zero period; `PgStore::connect` never passes one anyway.
    let mut ticks = tokio::time::interval(every.max(Duration::from_millis(1)));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticks.tick().await; // The first tick is immediate.
    loop {
        ticks.tick().await;
        if notifier.entry_count() == 0 {
            continue;
        }
        // A failed round is retried at the next tick. Meanwhile the listener still wakes the
        // waits, and each is bounded by its own timeout.
        if let Ok(client) = pool::client(&pool).await {
            let _ = refresh(&client, &notifier).await;
        }
    }
}

/// Reads the heads of the boards with waiters and feeds them to `notifier`; an archived board
/// loses its entry, since its head can no longer move.
async fn refresh(client: &Client, notifier: &Notifier) -> Result<(), StoreError> {
    let boards = notifier.boards();
    if boards.is_empty() {
        return Ok(());
    }
    let ids: Vec<&str> = boards.iter().map(BoardId::as_str).collect();
    let rows = client
        .query(
            "SELECT id, head_seq, archived_at_ms IS NOT NULL FROM boards WHERE id = ANY($1)",
            &[&ids],
        )
        .await
        .map_err(db)?;
    for row in rows {
        let id: &str = row.try_get(0).map_err(db)?;
        let seq: i64 = row.try_get(1).map_err(db)?;
        let archived: bool = row.try_get(2).map_err(db)?;
        let board = BoardId::new(id).map_err(backend)?;
        if archived {
            notifier.forget(&board);
        } else {
            notifier.bump(&board, u64::try_from(seq).map_err(backend)?);
        }
    }
    Ok(())
}

/// One listener connection, LISTENing, with the payloads its driver forwards.
struct Session {
    _client: Client,
    payloads: mpsc::UnboundedReceiver<String>,
    _driver: AbortOnDrop,
    schema: String,
}

impl Session {
    /// Connects, LISTENs, then re-reads the heads of the boards with waiters: a commit before
    /// LISTEN took effect is seen by that read, any later one is notified.
    async fn open(link: &Link) -> Result<Session, StoreError> {
        let (client, payloads, driver) = match tls::connector(link.tls)? {
            None => connect(&link.config, NoTls).await?,
            Some(tls) => connect(&link.config, tls).await?,
        };
        let row = client
            .query_one(
                "SELECT coalesce(current_schema(), ''), pg_backend_pid()",
                &[],
            )
            .await
            .map_err(db)?;
        let schema: String = row.try_get(0).map_err(db)?;
        let pid: i32 = row.try_get(1).map_err(db)?;
        client
            .batch_execute(&format!("LISTEN {CHANNEL}"))
            .await
            .map_err(db)?;
        refresh(&client, &link.notifier).await?;
        link.pid.store(pid, Ordering::SeqCst);
        Ok(Session {
            _client: client,
            payloads,
            _driver: driver,
            schema,
        })
    }

    /// Applies payloads until the connection ends.
    async fn run(mut self, notifier: &Notifier) {
        while let Some(payload) = self.payloads.recv().await {
            apply(notifier, &self.schema, &payload);
        }
    }
}

/// Opens a connection and spawns its driver, which forwards this channel's payloads and ends
/// (closing the receiver) when the connection fails or closes.
async fn connect<T>(
    config: &Config,
    tls: T,
) -> Result<(Client, mpsc::UnboundedReceiver<String>, AbortOnDrop), StoreError>
where
    T: MakeTlsConnect<Socket>,
    T::Stream: Send + 'static,
{
    let (client, mut connection) = config.connect(tls).await.map_err(db)?;
    let (sender, payloads) = mpsc::unbounded_channel();
    let driver = tokio::spawn(async move {
        while let Some(Ok(message)) = poll_fn(|cx| connection.poll_message(cx)).await {
            if let AsyncMessage::Notification(note) = message {
                if note.channel() == CHANNEL && sender.send(note.payload().to_owned()).is_err() {
                    break;
                }
            }
        }
    });
    Ok((client, payloads, AbortOnDrop(driver)))
}

/// A task that stops when this is dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Applies one payload: a head for a board of `schema`. Payloads for other schemas, and
/// malformed ones, are ignored and not counted.
fn apply(notifier: &Notifier, schema: &str, payload: &str) {
    let Some((of, board, seq)) = parse(payload) else {
        return;
    };
    if of == schema {
        notifier.bump(&board, seq);
        notifier.count_handled();
    }
}

/// `<schema>:<board>:<seq>`; a board id has no colon, a schema name may.
fn parse(payload: &str) -> Option<(&str, BoardId, u64)> {
    let (rest, seq) = payload.rsplit_once(':')?;
    let (schema, board) = rest.rsplit_once(':')?;
    Some((schema, BoardId::new(board).ok()?, seq.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_name_schema_board_and_sequence() {
        let (schema, board, seq) = parse("public:main:42").unwrap();
        assert_eq!((schema, board.as_str(), seq), ("public", "main", 42));
        let (schema, board, _) = parse("odd:schema:ops.team-1:7").unwrap();
        assert_eq!((schema, board.as_str()), ("odd:schema", "ops.team-1"));
        assert_eq!(parse(":main:1").map(|p| p.0), Some(""));
        for bad in [
            "",
            "main:1",
            "public:main:x",
            "public:Bad Id:1",
            "public:main:-1",
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn only_this_schemas_payloads_are_applied_and_counted() {
        let notifier = Arc::new(Notifier::default());
        let main = BoardId::main();
        let sub = notifier.subscribe(&main);
        apply(&notifier, "mine", "theirs:main:5");
        apply(&notifier, "mine", "mine:main:not-a-number");
        assert_eq!(notifier.handled(), 0);
        apply(&notifier, "mine", "mine:main:3");
        apply(&notifier, "mine", "mine:unknown:9");
        assert_eq!(notifier.handled(), 2);
        assert_eq!(notifier.entry_count(), 1, "the unknown board got no entry");
        drop(sub);
    }
}
