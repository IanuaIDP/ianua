//! Asking whether a caller the gateway found may pass: a person against a
//! stream route's policy, and whether any caller is one the tenant's
//! records know and let act now.
//!
//! Authentication and authorization are two steps with two ports. The
//! gateway finds out who is calling first, then asks this port about that
//! caller. The port answers; it never lets anyone in by itself.

use async_trait::async_trait;
use ianua_domain::domains::proxy::access::question::Standing;
use ianua_domain::domains::routing::policy::RoutePolicy;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalRef, UserId};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// What the policy decision point said about one person and one policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The person meets the policy.
    Permit,
    /// The person does not meet it.
    Deny,
    /// No decision could be made, such as for a person the tenant does not
    /// know. Every caller treats it as a refusal.
    Undecided,
}

impl PolicyDecision {
    /// Whether this lets the person through. Only a permit does.
    #[must_use]
    pub fn permits(self) -> bool {
        self == Self::Permit
    }
}

/// Dyn-safe port deciding whether a person meets a [`RoutePolicy`], and
/// whether a person, agent or consumer may act in a tenant at all.
///
/// The adapter reads the caller's account, agent or consumer record, and
/// what they hold, from the tenant's records, and must time out every call
/// it makes. A call that times out or fails returns an error, which every
/// caller treats as a refusal.
#[async_trait]
pub trait PolicyDecisionPoint: Send + Sync + TenantScoped {
    /// Whether `person` meets `policy` in `tenant_id` now.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] when the tenant's records
    /// cannot be read in time.
    async fn decide(
        &self,
        tenant_id: &ScopedTenant,
        person: &UserId,
        policy: &RoutePolicy,
    ) -> Result<PolicyDecision, DomainError>;

    /// Whether the tenant's records know `principal` and let it act now: a
    /// user whose account may sign in, an agent that may act, a consumer
    /// that is enabled. An organization member is not a caller a tenant's
    /// gateway serves, so it is unknown here.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] when the tenant's records
    /// cannot be read in time.
    async fn standing(
        &self,
        tenant_id: &ScopedTenant,
        principal: &PrincipalRef,
    ) -> Result<Standing, DomainError>;
}
