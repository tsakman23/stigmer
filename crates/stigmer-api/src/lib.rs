//! stigmer-api: the HTTP surface of a board, plus the loopback bind guard.

mod authz;
mod loopback;

pub use authz::{Action, AllowAll, Authorize, Denied};
pub use loopback::{require_loopback, BindError};
