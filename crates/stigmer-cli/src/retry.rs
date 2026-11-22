//! Retrying transient network failures, for `tail`.

use std::io::Write;
use std::time::{Duration, Instant};

use crate::exit::CliError;

/// The first pause before `tail` retries a failed request.
const FIRST_RETRY: Duration = Duration::from_secs(1);
/// The longest pause between retries.
const MAX_RETRY: Duration = Duration::from_secs(30);

/// The pause after `delay`: doubled, at most `MAX_RETRY`.
fn next_delay(delay: Duration) -> Duration {
    delay.saturating_mul(2).min(MAX_RETRY)
}

/// Runs `op` until it succeeds, retrying transient network failures with exponential backoff
/// and one stderr line per retry. Gives up only at `deadline` (then `None`); without one it
/// retries until the process is killed. Any other failure is returned at once.
pub(crate) fn retrying<T>(
    deadline: Option<Instant>,
    mut op: impl FnMut() -> Result<T, CliError>,
) -> Result<Option<T>, CliError> {
    let mut delay = FIRST_RETRY;
    loop {
        match op() {
            Ok(value) => return Ok(Some(value)),
            Err(err) if err.is_transient() => {
                let pause = match deadline {
                    Some(deadline) => delay.min(deadline.saturating_duration_since(Instant::now())),
                    None => delay,
                };
                if pause.is_zero() {
                    return Ok(None);
                }
                // Nothing useful is left to do if stderr itself cannot be written.
                let _ = writeln!(
                    std::io::stderr(),
                    "stigmer: {}; retrying in {}s",
                    err.message(),
                    pause.as_secs_f64().ceil()
                );
                std::thread::sleep(pause);
                delay = next_delay(delay);
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::Exit;

    #[test]
    fn retry_delays_double_from_one_second_to_thirty() {
        let mut delay = FIRST_RETRY;
        let mut seen = vec![delay.as_secs()];
        for _ in 0..7 {
            delay = next_delay(delay);
            seen.push(delay.as_secs());
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn retrying_returns_other_errors_at_once_and_gives_up_at_the_deadline() {
        let mut calls = 0;
        let usage = retrying(None, || -> Result<(), CliError> {
            calls += 1;
            Err(CliError::usage("bad", "fix"))
        });
        assert_eq!(usage.unwrap_err().code, "usage");
        assert_eq!(calls, 1);
        let passed = Instant::now();
        let gave_up = retrying(Some(passed), || -> Result<(), CliError> {
            Err(CliError::new(Exit::Failure, "network", "down", "retry"))
        });
        assert_eq!(gave_up, Ok(None));
    }
}
