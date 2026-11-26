//! The fixture a backend hands to [`run_all`](crate::run_all): fresh stores, and a second
//! handle on the same database as a store it made.

use std::future::Future;
use std::io::{self, Write};

use stigmer_core::BoardId;
use stigmer_store::Store;

/// How a backend makes stores for the conformance suites.
pub trait Fixture {
    /// The backend under test.
    type Store: Store;

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

/// Which suites a run covered, as its summary line names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Suites {
    /// [`run_all`](crate::run_all): every suite.
    All,
    /// [`run_store_suites`](crate::run_store_suites): the `Store` half only.
    StoreOnly,
}

/// The one line [`run_all`](crate::run_all) or [`run_store_suites`](crate::run_store_suites)
/// prints when every suite it ran has passed.
pub(crate) fn summary_line(suites: Suites, cross_process_wake: bool) -> String {
    let ran = match suites {
        Suites::All => "store+identity+cross_instance",
        Suites::StoreOnly => "store+cross_instance(store half; identity not run)",
    };
    format!("conformance: {ran} scenarios passed; cross_process_wake={cross_process_wake}")
}

/// Writes [`summary_line`] and a newline to `out`.
pub(crate) fn write_summary(
    out: &mut impl Write,
    suites: Suites,
    cross_process_wake: bool,
) -> io::Result<()> {
    writeln!(out, "{}", summary_line(suites, cross_process_wake))
}

#[cfg(test)]
mod tests {
    use super::{write_summary, Suites};

    fn captured(cross_process_wake: bool) -> String {
        captured_for(Suites::All, cross_process_wake)
    }

    fn captured_for(suites: Suites, cross_process_wake: bool) -> String {
        let mut out = Vec::new();
        write_summary(&mut out, suites, cross_process_wake).unwrap();
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

    #[test]
    fn store_only_summary_line_says_identity_did_not_run() {
        assert_eq!(
            captured_for(Suites::StoreOnly, true),
            "conformance: store+cross_instance(store half; identity not run) scenarios passed; \
             cross_process_wake=true\n"
        );
    }
}
