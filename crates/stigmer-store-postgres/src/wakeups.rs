//! A store handle's wake-up machinery, started lazily.
//!
//! The notifier exists from the start, but the listener connection and the safety poll start
//! only when a wait first has to sleep: a store that never waits (an admin command, a caller
//! that only reads and writes) opens no connection beyond its pool. Concurrent first waits
//! start one listener: they queue on a lock and the first that gets it starts it. A failed
//! start fails that wait with a backend error and is retried by a later wait once the
//! listener's backoff (100 ms doubling to 10 s) has passed; waits before then fail at once
//! with the last error, so a database that refuses LISTEN is not hammered.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use stigmer_store::StoreError;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::listener::{self, Background, ListenerSetup};
use crate::notify::Notifier;

pub(crate) struct Wakeups {
    setup: ListenerSetup,
    notifier: Arc<Notifier>,
    /// The listener and the safety poll once started; dropping them stops both.
    running: OnceLock<Background>,
    /// Serialises starts and remembers a failed one.
    gate: Mutex<Gate>,
    /// Successful starts: at most one per handle.
    starts: AtomicU64,
}

impl Wakeups {
    pub(crate) fn new(setup: ListenerSetup) -> Wakeups {
        Wakeups {
            setup,
            notifier: Arc::default(),
            running: OnceLock::new(),
            gate: Mutex::new(Gate::new()),
            starts: AtomicU64::new(0),
        }
    }

    pub(crate) fn setup(&self) -> &ListenerSetup {
        &self.setup
    }

    pub(crate) fn notifier(&self) -> &Arc<Notifier> {
        &self.notifier
    }

    /// Starts the listener and the safety poll unless they run already. Call before a wait
    /// sleeps, after it has subscribed: the listener's first re-read covers any commit the
    /// wait's head read missed.
    pub(crate) async fn ensure_started(&self) -> Result<(), StoreError> {
        if self.running.get().is_some() {
            return Ok(());
        }
        let mut gate = self.gate.lock().await;
        if self.running.get().is_some() {
            return Ok(());
        }
        if let Some(refused) = gate.refusal(Instant::now()) {
            return Err(refused);
        }
        match listener::start(&self.setup, Arc::clone(&self.notifier)).await {
            Ok(background) => {
                // Under the gate, with `running` empty: this set cannot find a value.
                let _ = self.running.set(background);
                self.starts.fetch_add(1, Ordering::SeqCst);
                *gate = Gate::new();
                Ok(())
            }
            Err(err) => {
                gate.failed(Instant::now(), &err);
                Err(err)
            }
        }
    }

    /// The listener's backend process id; `None` before it starts and while it reconnects.
    pub(crate) fn listener_pid(&self) -> Option<i32> {
        self.running.get().and_then(Background::listener_pid)
    }

    /// How many times the listener was started.
    pub(crate) fn starts(&self) -> u64 {
        self.starts.load(Ordering::SeqCst)
    }
}

/// When the next start may be tried, after failed ones.
struct Gate {
    backoff: Duration,
    retry_at: Option<Instant>,
    last_error: String,
}

impl Gate {
    fn new() -> Gate {
        Gate {
            backoff: listener::MIN_BACKOFF,
            retry_at: None,
            last_error: String::new(),
        }
    }

    /// The error a wait gets at `now` instead of a start, while the last failure's backoff
    /// lasts.
    fn refusal(&self, now: Instant) -> Option<StoreError> {
        let retry_at = self.retry_at.filter(|at| now < *at)?;
        Some(StoreError::Backend(format!(
            "the wake-up listener is not running, next attempt in {} ms: {}",
            retry_at.saturating_duration_since(now).as_millis(),
            self.last_error
        )))
    }

    /// Records a failed start at `now`: the next may be tried after the backoff, which doubles.
    fn failed(&mut self, now: Instant, err: &StoreError) {
        self.retry_at = Some(now + self.backoff);
        self.backoff = listener::after_attempt(self.backoff);
        self.last_error = err.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pool, PgOptions, PgTls, DEFAULT_POLL_INTERVAL};

    #[test]
    fn a_failed_start_is_retried_only_after_the_backoff() {
        let mut gate = Gate::new();
        let t0 = Instant::now();
        assert!(
            gate.refusal(t0).is_none(),
            "a fresh gate lets the first start through"
        );
        let err = StoreError::Backend("refused".into());
        gate.failed(t0, &err);
        let refused = gate.refusal(t0 + Duration::from_millis(50)).unwrap();
        assert!(refused.to_string().contains("refused"), "{refused}");
        assert!(gate.refusal(t0 + Duration::from_millis(100)).is_none());
        gate.failed(t0 + Duration::from_millis(100), &err);
        assert!(
            gate.refusal(t0 + Duration::from_millis(250)).is_some(),
            "doubled to 200 ms"
        );
        assert!(gate.refusal(t0 + Duration::from_millis(300)).is_none());
    }

    #[tokio::test]
    async fn a_wait_that_cannot_start_the_listener_fails_with_a_clear_error() {
        // Port 1: nothing listens, so the listener cannot connect. Building the pool opens
        // nothing.
        let config: tokio_postgres::Config = "postgres://stigmer@127.0.0.1:1/stigmer_test"
            .parse()
            .unwrap();
        let options = PgOptions {
            max_connections: 1,
            tls: PgTls::Disable,
            poll_interval: DEFAULT_POLL_INTERVAL,
        };
        let wakeups = Wakeups::new(ListenerSetup {
            pool: pool::build(&config, options).unwrap(),
            config,
            tls: PgTls::Disable,
            target: "database stigmer_test on 127.0.0.1:1".into(),
            poll_interval: DEFAULT_POLL_INTERVAL,
        });
        let Err(StoreError::Backend(text)) = wakeups.ensure_started().await else {
            panic!("nothing listens on port 1");
        };
        assert!(
            text.contains("cannot open the listener connection"),
            "{text}"
        );
        assert!(text.contains("session-pooled"), "{text}");
        let Err(StoreError::Backend(text)) = wakeups.ensure_started().await else {
            panic!("within the backoff the next wait fails at once");
        };
        assert!(text.contains("next attempt in"), "{text}");
        assert_eq!((wakeups.starts(), wakeups.listener_pid()), (0, None));
    }
}
