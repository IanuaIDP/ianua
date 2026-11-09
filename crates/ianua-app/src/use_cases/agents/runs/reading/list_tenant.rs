//! List tenant runs: every agent's runs in the tenant, newest first.
//!
//! The view a person who looks after all agents needs: what is running,
//! paused or waiting on someone across the tenant, not one agent at a time.
//! Only someone allowed to view agents reads it, since a run shows what its
//! agent read.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::run::RunStatus;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::agents::{RunStore, RunSummary};
use crate::use_case::Query;

/// The ports [`ListTenantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListTenantPorts {
    /// Keeps the runs.
    pub run_store: Arc<dyn RunStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// The lifecycle filter and page of the tenant's run summaries.
pub struct ListTenantRequest {
    /// Narrows to one lifecycle state, when supplied.
    pub status: Option<RunStatus>,
    /// The requested page in newest-first order.
    pub page: PageRequest,
}

/// Lists the runs of every agent in the tenant.
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
    type Input = ListTenantRequest;
    type Output = Result<Page<RunSummary>, AppError>;

    /// One page of run summaries, newest first, with the requested status.
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
        request: ListTenantRequest,
    ) -> Result<Page<RunSummary>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .run_store
            .list_in_tenant(&ctx.tenant(), request.status, &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::AgentId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeRunStore, agent_owned_by, delegation_from, order_tool, paused_run, run_started_by,
        someone,
    };
    use crate::test_support::{block_on, test_ctx};

    /// A running run of Ann's agent and a run of Bob's agent waiting for
    /// approval.
    fn ports() -> ListTenantPorts {
        let (ann, bob) = (someone("ann@corp.test"), someone("bob@corp.test"));
        let anns = agent_owned_by(AgentId::new(), ann.clone());
        let bobs = agent_owned_by(AgentId::new(), bob.clone());
        let running = run_started_by(&ann, &anns, &delegation_from(&ann, *anns.id()));
        let waiting = paused_run(
            &bob,
            &bobs,
            &delegation_from(&bob, *bobs.id()),
            &order_tool("delete_order"),
        );
        let runs = FakeRunStore::empty();
        for run in [running, waiting] {
            block_on(runs.save(&test_ctx().tenant(), &run)).unwrap();
        }
        ListTenantPorts {
            run_store: Arc::new(runs),
            ..ListTenantPorts::fakes()
        }
    }

    fn list(
        ports: ListTenantPorts,
        status: Option<RunStatus>,
    ) -> Result<Vec<RunSummary>, AppError> {
        block_on(ListTenantUseCase::new(ports).execute(
            &test_ctx(),
            ListTenantRequest {
                status,
                page: PageRequest::default(),
            },
        ))
        .map(|page| page.items)
    }

    /// Twenty-one runs across the tenant produce only the usual first
    /// twenty, keeping the shared inbox bounded as history grows.
    #[test]
    fn the_tenants_run_listing_stops_at_the_default_page_size() {
        let owner = someone("ann@corp.test");
        let agent = agent_owned_by(AgentId::new(), owner.clone());
        let runs = Arc::new(FakeRunStore::empty());
        for _ in 0..21 {
            let run = run_started_by(&owner, &agent, &delegation_from(&owner, *agent.id()));
            block_on(runs.save(&test_ctx().tenant(), &run)).unwrap();
        }
        let ports = ListTenantPorts {
            run_store: runs,
            ..ListTenantPorts::fakes()
        };

        let found = list(ports, None).unwrap();

        assert_eq!(found.len(), 20);
    }

    /// Olga, who may view agents, lists every run. She sees both agents'
    /// runs.
    #[test]
    fn every_agents_runs_are_listed() {
        assert_eq!(list(ports(), None).unwrap().len(), 2);
    }

    /// Olga lists the runs waiting for approval across the tenant. She sees
    /// only Bob's.
    #[test]
    fn runs_are_narrowed_to_a_status() {
        let listed = list(ports(), Some(RunStatus::AwaitingApproval)).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state.status(), RunStatus::AwaitingApproval);
    }

    /// A caller without agent view rights cannot list runs across the tenant.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let ports = ListTenantPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports()
        };

        let result = list(ports, None);

        assert!(matches!(result, Err(AppError::Forbidden(_))), "{result:?}");
    }

    /// A signed-out session cannot list runs across the tenant.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListTenantPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports()
        };

        assert!(matches!(list(ports, None), Err(AppError::Unauthenticated)));
    }
}
