//! A task token the agent holds, and what it reads of it: a holder may
//! read a token's claims, though only the platform can check them.

use std::fmt;

use serde_json::Value;

use crate::agent::keys::{Jwk, claims_of};
use crate::wire::agents::authority::{Budget, Capabilities, Granted};

/// A task token and the delegation it was signed for. `Debug` shows the
/// delegation and whether the token is bound, never the token.
#[derive(Clone)]
pub struct IssuedToken {
    granted: Granted,
    claims: Value,
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedToken")
            .field("delegation_id", &self.granted.delegation_id)
            .field("bound", &self.bound_key().is_some())
            .finish_non_exhaustive()
    }
}

impl IssuedToken {
    /// The token `granted` carries, its claims read as its holder reads
    /// them.
    #[must_use]
    pub fn of(granted: Granted) -> Self {
        let claims = claims_of(&granted.task_token).unwrap_or(Value::Null);
        Self { granted, claims }
    }

    /// The token itself, for `Authorization: Bearer`.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.granted.task_token
    }

    /// The delegation it was signed for.
    #[must_use]
    pub fn delegation_id(&self) -> &str {
        &self.granted.delegation_id
    }

    /// What it may do, as the platform capped it.
    #[must_use]
    pub fn granted(&self) -> &Capabilities {
        &self.granted.granted
    }

    /// Decoded payload for holder-side inspection; reading it does not verify it.
    #[must_use]
    pub fn claims(&self) -> &Value {
        &self.claims
    }

    /// The key it is bound to, `cnf.jwk`, when it is bound to one.
    #[must_use]
    pub fn bound_key(&self) -> Option<Jwk> {
        let jwk = self.claims.get("cnf")?.get("jwk")?;
        serde_json::from_value(jwk.clone()).ok()
    }

    /// The request budget it carries, `bmax` per `bwin` seconds: the
    /// agent's own budget, read from its token.
    #[must_use]
    pub fn budget(&self) -> Option<Budget> {
        let most = self.claims.get("bmax")?.as_u64()?;
        let window = self.claims.get("bwin")?.as_u64()?;
        Some(Budget::of(
            u32::try_from(most).ok()?,
            u32::try_from(window).ok()?,
        ))
    }

    /// The agent it names as acting, `act`.
    #[must_use]
    pub fn acting_agent(&self) -> Option<&str> {
        self.claims.get("act")?.as_str()
    }
}
