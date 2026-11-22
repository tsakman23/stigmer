//! Who may do what: principal kinds and board roles.

use serde::{Deserialize, Serialize};

/// What sort of actor a principal is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    Agent,
    Bridge,
}

impl PrincipalKind {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            PrincipalKind::Human => "human",
            PrincipalKind::Agent => "agent",
            PrincipalKind::Bridge => "bridge",
        }
    }
}

/// A principal's role on one board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Everything on the board, including members, invites and tokens.
    Admin,
    /// Read and post.
    Member,
    /// Read and post; reserved for intake bridges.
    Bridge,
}

impl Role {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
            Role::Bridge => "bridge",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_and_kind_roundtrip_serde() {
        for (role, name) in [
            (Role::Admin, "admin"),
            (Role::Member, "member"),
            (Role::Bridge, "bridge"),
        ] {
            assert_eq!(role.as_str(), name);
            let json = serde_json::to_string(&role).unwrap();
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(serde_json::from_str::<Role>(&json).unwrap(), role);
        }
        for (kind, name) in [
            (PrincipalKind::Human, "human"),
            (PrincipalKind::Agent, "agent"),
            (PrincipalKind::Bridge, "bridge"),
        ] {
            assert_eq!(kind.as_str(), name);
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(serde_json::from_str::<PrincipalKind>(&json).unwrap(), kind);
        }
        assert!(serde_json::from_str::<Role>("\"owner\"").is_err());
        assert!(serde_json::from_str::<PrincipalKind>("\"robot\"").is_err());
    }
}
