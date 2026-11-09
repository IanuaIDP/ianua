//! An agent asking for a task token of its own, signed in by an assertion
//! its key signed.

use serde::Serialize;

use super::authority::Capabilities;

/// What an agent asks its token to carry: capabilities, capped to what it
/// was granted, and limits, held inside the grant's.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TokenAsk {
    /// The capabilities asked for.
    pub granted: Capabilities,
    /// The token's lifetime, in seconds.
    pub ttl_seconds: u32,
    /// How deep the token's authority may be passed on.
    pub max_depth: u8,
    /// The task the token is bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    /// Whether the token is bound to the key that signed the assertion.
    pub sender_constrained: bool,
}

impl TokenAsk {
    /// `granted` for `ttl_seconds`, passed on nowhere and bound to no key.
    #[must_use]
    pub fn bearer(granted: Capabilities, ttl_seconds: u32) -> Self {
        Self {
            granted,
            ttl_seconds,
            ..Self::default()
        }
    }

    /// The same ask, bound to the agent's key.
    #[must_use]
    pub fn key_bound(mut self) -> Self {
        self.sender_constrained = true;
        self
    }
}

/// `POST …/agents/{id}/token`: the assertion and the ask. Holds the
/// assertion, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct TokenRequest {
    /// The compact JWS the agent's key signed.
    pub assertion: String,
    /// What it asks for.
    #[serde(flatten)]
    pub ask: TokenAsk,
}
