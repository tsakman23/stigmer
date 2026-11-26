//! The fixture a backend hands to [`run_all`](crate::run_all): fresh stores, and a second
//! handle on the same database as a store it made.

use std::future::Future;
use std::io::{self, Write};

use stigmer_core::BoardId;
use stigmer_store::{IdentityStore, Store};

/// How a backend makes stores for the conformance suites.
pub trait Fixture {
    /// The backend under test.
    type Store: Store + IdentityStore;

    /// Informational: true when separate handles are separate PROCESS-level notifiers
    /// (Postgres). [`run_all`](crate::run_all) prints it in its summary line, so a green run on
    /// a backend whose handles share one notifier is never read as proof of cross-process wakes.
    const CROSS_PROCESS_WAKE: bool;

    /// A fresh, empty store on its own database.
    fn fresh(&self) -> impl Future<Output = Self::Store> + Send;

    /// Another handle on the SAME database as `store`.
    fn second_handle(&self, store: &Self::Store) -> impl Future<Output = Self::Store> + Send;

    /// The number of `wait_past` callers currently subscribed to `board`'s wake-up channel on
    /// `store`'s handle. Lets a scenario post only once a waiter is known to be blocked.
    fn waiters(&self, store: &Self::Store, board: &BoardId) -> usize;
}

/// The one line [`run_all`](crate::run_all) prints when every suite has passed.
pub(crate) fn summary_line(cross_process_wake: bool) -> String {
    format!(
        "conformance: store+identity+cross_instance scenarios passed; \
         cross_process_wake={cross_process_wake}"
    )
}

/// Writes [`summary_line`] and a newline to `out`.
pub(crate) fn write_summary(out: &mut impl Write, cross_process_wake: bool) -> io::Result<()> {
    writeln!(out, "{}", summary_line(cross_process_wake))
}

#[cfg(test)]
mod tests {
    use super::write_summary;

    fn captured(cross_process_wake: bool) -> String {
        let mut out = Vec::new();
        write_summary(&mut out, cross_process_wake).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn fixture_summary_line_reports_cross_process_wake() {
        assert_eq!(
            captured(false),
            "conformance: store+identity+cross_instance scenarios passed; cross_process_wake=false\n"
        );
        assert_eq!(
            captured(true),
            "conformance: store+identity+cross_instance scenarios passed; cross_process_wake=true\n"
        );
    }
}
