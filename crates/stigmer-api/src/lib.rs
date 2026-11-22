//! stigmer-api: the HTTP surface of a board.

mod admin_routes;
mod audit;
mod auth;
mod authz;
mod config;
mod error;
mod host_guard;
mod ipnet;
mod join_routes;
mod limits;
mod ratelimit;
mod routes;
mod wait;

pub use auth::PeerAddr;
pub use authz::{Action, AllowAll, Authenticated, Authorize, Denied, RoleAuthorize, Scope};
pub use config::{ApiConfig, Clock, Warn};
pub use ipnet::{IpNet, IpNetError};
pub use limits::Limits;
pub use routes::router;
