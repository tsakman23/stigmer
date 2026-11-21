//! The authorization seam: every route asks `Authorize::check` before touching the store.

use stigmer_core::{ChannelPath, Principal};
use thiserror::Error;

/// What a principal wants to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Post,
}

/// The principal may not do this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("forbidden")]
pub struct Denied;

/// Decides whether `who` may perform `action`. `channel` is `None` for a board-wide read.
pub trait Authorize: Clone + Send + Sync + 'static {
    fn check(
        &self,
        who: &Principal,
        action: Action,
        channel: Option<&ChannelPath>,
    ) -> Result<(), Denied>;
}

/// Allows everything. M0's only implementation: the board is loopback only.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl Authorize for AllowAll {
    fn check(&self, _: &Principal, _: Action, _: Option<&ChannelPath>) -> Result<(), Denied> {
        Ok(())
    }
}
