//! Agent authority: whether an agent may still act under one delegation,
//! asked again while something it opened stays open.
//!
//! A task token is checked when it arrives, but a WebSocket or a stream it
//! opened can outlive that check by hours. Suspending or revoking the agent,
//! or revoking its delegation, must close what it holds open, not only
//! refuse its next request. The gateway asks this on an interval for as
//! long as the connection lasts, and the request check asks the same rule
//! through [`authority_of`], so the two never answer differently.

use std::sync::Arc;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, DelegationId};

use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStandingCheck, DelegationRevocationCheck};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// The agent and the delegation it acts under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentAuthorityRequest {
    /// The agent acting, its token's `act`.
    pub agent_id: AgentId,
    /// The delegation it acts under, its token's `jti`.
    pub delegation_id: DelegationId,
}

/// Whether an agent's authority still holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentAuthority {
    /// It does: the agent may act, and its delegation stands.
    Holds,
    /// It does not, for this reason.
    Lost(AuthorityLoss),
}

/// Why an agent's authority no longer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityLoss {
    /// The agent may not act now: suspended, revoked, owing a fresh
    /// attestation, or unknown to the tenant.
    Standing,
    /// Its delegation was revoked or is gone.
    DelegationRevoked,
}

/// The ports [`CheckAgentAuthorityUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AgentAuthorityPorts {
    /// Whether the agent may act right now.
    pub standings: Arc<dyn AgentStandingCheck>,
    /// Whether the delegation was revoked.
    pub revocations: Arc<dyn DelegationRevocationCheck>,
}

/// Answers whether an agent's delegation and standing still hold.
pub struct CheckAgentAuthorityUseCase {
    ports: AgentAuthorityPorts,
}

impl CheckAgentAuthorityUseCase {
    /// A use case asking through `ports`.
    #[must_use]
    pub fn new(ports: AgentAuthorityPorts) -> Self {
        Self { ports }
    }
}

impl Query for CheckAgentAuthorityUseCase {
    type Caller = ScopedTenant;
    type Input = AgentAuthorityRequest;
    type Output = Result<AgentAuthority, AppError>;

    /// Whether `request`'s agent may still act under its delegation in
    /// `tenant`. The gateway closes what the agent holds open on anything
    /// but [`AgentAuthority::Holds`], an error included.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the standing or the delegation cannot
    ///   be read.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: AgentAuthorityRequest,
    ) -> Result<AgentAuthority, AppError> {
        authority_of(
            self.ports.standings.as_ref(),
            self.ports.revocations.as_ref(),
            tenant,
            request,
        )
        .await
        .or_internal()
    }
}

/// Whether `request`'s agent may act now in `tenant`, and its delegation
/// stands. The standing is asked first: a suspended agent is stopped
/// whatever its delegation says.
///
/// # Errors
///
/// - `DomainError::Infrastructure` when either cannot be read.
pub(crate) async fn authority_of(
    standings: &dyn AgentStandingCheck,
    revocations: &dyn DelegationRevocationCheck,
    tenant: &ScopedTenant,
    request: AgentAuthorityRequest,
) -> Result<AgentAuthority, DomainError> {
    let standing = standings.standing(tenant, &request.agent_id).await?;
    if !standing.permits_requests() {
        return Ok(AgentAuthority::Lost(AuthorityLoss::Standing));
    }
    if revocations
        .is_revoked(tenant, &request.delegation_id)
        .await?
    {
        return Ok(AgentAuthority::Lost(AuthorityLoss::DelegationRevoked));
    }
    Ok(AgentAuthority::Holds)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::agents::identity::standing::AgentStanding;

    use super::*;
    use crate::ports::TenantScoped;
    use crate::test_support::agents::{FakeAgentStandings, FakeDelegationRevocations};
    use crate::test_support::{block_on, test_ctx};

    fn runner() -> AgentAuthorityRequest {
        AgentAuthorityRequest {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
        }
    }

    fn ask(
        ports: AgentAuthorityPorts,
        request: AgentAuthorityRequest,
    ) -> Result<AgentAuthority, AppError> {
        block_on(CheckAgentAuthorityUseCase::new(ports).execute(&test_ctx().tenant(), request))
    }

    /// An active agent under a standing delegation retains its authority.
    #[test]
    fn an_active_agent_under_a_standing_delegation_holds() {
        let held = ask(AgentAuthorityPorts::fakes(), runner()).unwrap();

        assert_eq!(held, AgentAuthority::Holds);
    }

    /// Revoking the delegation reports authority lost for that delegation.
    #[test]
    fn a_revoked_delegation_is_lost() {
        let request = runner();
        let revocations = Arc::new(FakeDelegationRevocations::default());
        revocations.revoke(&test_ctx().tenant(), request.delegation_id);
        let ports = AgentAuthorityPorts {
            revocations,
            ..AgentAuthorityPorts::fakes()
        };

        let lost = ask(ports, request).unwrap();

        assert_eq!(lost, AgentAuthority::Lost(AuthorityLoss::DelegationRevoked));
    }

    /// Suspending the agent reports authority lost because of its standing.
    #[test]
    fn a_suspended_agent_is_lost() {
        let request = runner();
        let standings = Arc::new(FakeAgentStandings::default());
        standings.set(
            &test_ctx().tenant(),
            request.agent_id,
            AgentStanding::Suspended,
        );
        let ports = AgentAuthorityPorts {
            standings,
            ..AgentAuthorityPorts::fakes()
        };

        let lost = ask(ports, request).unwrap();

        assert_eq!(lost, AgentAuthority::Lost(AuthorityLoss::Standing));
    }

    struct Unreadable;

    impl TenantScoped for Unreadable {}

    #[async_trait]
    impl DelegationRevocationCheck for Unreadable {
        async fn is_revoked(
            &self,
            _: &ScopedTenant,
            _: &DelegationId,
        ) -> Result<bool, DomainError> {
            Err(DomainError::infra_msg("the delegations cannot be read"))
        }
    }

    /// An unreadable delegation returns an internal error from the authority
    /// check.
    #[test]
    fn an_unreadable_delegation_is_an_error() {
        let ports = AgentAuthorityPorts {
            revocations: Arc::new(Unreadable),
            ..AgentAuthorityPorts::fakes()
        };

        let failed = ask(ports, runner());

        assert!(matches!(failed, Err(AppError::Internal(_))));
    }
}
