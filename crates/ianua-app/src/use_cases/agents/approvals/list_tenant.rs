//! List tenant approvals: every agent's approval requests in the tenant,
//! newest first.
//!
//! One inbox for the people who decide: what every agent of the tenant
//! waits on, not one agent at a time. Only someone allowed to view agents
//! reads it, and only the requests they are cleared for.

use std::sync::Arc;

use ianua_domain::domains::agents::oversight::approval::ApprovalRequest;
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::ApprovalStore;
use crate::use_case::Query;

/// The ports [`ListTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListTenantPorts {
    /// Reads approval requests.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the approval requests of every agent in the tenant.
pub struct ListTenantUseCase {
    ports: ListTenantPorts,
}

impl ListTenantUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListTenantPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListTenantUseCase {
    type Caller = CallerContext;
    type Input = Option<ApprovalStatus>;
    type Output = Result<Vec<ApprovalRequest<ResolvedTenant>>, AppError>;

    /// The tenant's approval requests the caller is cleared to read, newest
    /// first, narrowed to `status` when one is given.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view agents.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::View))
            .map_err(AppError::from_domain)?;
        let requests = self
            .ports
            .approval_store
            .list_in_tenant(&ctx.tenant(), status)
            .await
            .or_internal()?;
        Ok(requests
            .into_iter()
            .filter(|approval| approval.readable_by(&authority))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::AgentId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeApprovalStore, agent_owned_by, opened_request, someone};
    use crate::test_support::{block_on, test_ctx};

    /// One request opened by hand for each of two agents.
    fn ports() -> ListTenantPorts {
        let approvals = FakeApprovalStore::empty();
        for owner in ["ann@corp.test", "bob@corp.test"] {
            let agent = agent_owned_by(AgentId::new(), someone(owner));
            let request = opened_request(&agent, someone("olga@corp.test"));
            block_on(approvals.save(&test_ctx().tenant(), &request)).unwrap();
        }
        ListTenantPorts {
            approval_store: Arc::new(approvals),
            ..ListTenantPorts::fakes()
        }
    }

    fn list(
        ports: ListTenantPorts,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, AppError> {
        block_on(ListTenantUseCase::new(ports).execute(&test_ctx(), status))
    }

    /// Carl, who may view agents, opens the tenant's inbox. He sees the
    /// pending requests of both agents.
    #[test]
    fn every_agents_pending_requests_are_listed() {
        let listed = list(ports(), Some(ApprovalStatus::Pending)).unwrap();

        assert_eq!(listed.len(), 2);
    }

    /// Reading the tenant's approval inbox requires agent-view permission.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let ports = ListTenantPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports()
        };

        let result = list(ports, None);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
    }

    /// A signed-out caller cannot read the tenant's approval inbox.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListTenantPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports()
        };

        assert!(matches!(list(ports, None), Err(AppError::Unauthenticated)));
    }
}
