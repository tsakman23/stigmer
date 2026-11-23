//! What admin commands print: plain text, secrets shown once, and the security log.

use std::io::Write;

use stigmer_core::BoardId;
use stigmer_store::SecurityEvent;

use crate::Failure;

pub(super) fn print_stdout(text: &str) -> Result<(), Failure> {
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| Failure::Runtime(format!("cannot write to stdout: {e}")))
}

/// Prints the secrets, then the note that they are shown once.
pub(super) fn write_once(out: &mut impl Write, secrets: &str) -> Result<(), Failure> {
    out.write_all(secrets.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| Failure::Runtime(format!("cannot write to stdout: {e}")))?;
    eprintln!("stigmerd: the secrets above are shown once and cannot be recovered; store them now");
    Ok(())
}

/// One tab-separated line per entry: time, kind, board, principal, detail.
pub(super) fn format_security_log(events: &[SecurityEvent]) -> String {
    let mut text = String::new();
    for e in events {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            format_utc(e.at_ms),
            e.kind,
            e.board.as_ref().map_or("-", BoardId::as_str),
            e.principal.as_deref().unwrap_or("-"),
            e.detail.replace(['\t', '\n'], " ")
        ));
    }
    text
}

/// `ms` since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days, proleptic Gregorian).
fn format_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400) + 719_468;
    let in_day = secs.rem_euclid(86_400);
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        in_day / 3600,
        in_day % 3600 / 60,
        in_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::format_utc;

    #[test]
    fn utc_formatting_matches_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_700_000_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_utc(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(-1000), "1969-12-31T23:59:59Z");
    }
}
