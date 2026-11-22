//! stigmer-api: the HTTP surface of a board, plus the loopback bind guard.

mod authz;
mod error;
mod host_guard;
mod loopback;
mod routes;
mod wait;

pub use authz::{Action, AllowAll, Authenticated, Authorize, Denied, RoleAuthorize, Scope};
pub use loopback::{require_loopback, BindError};
pub use routes::router;
