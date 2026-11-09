//! List approvals: the actions an agent paused for a person's decision.
//!
//! Covers both the inbox (what still needs deciding) and the history (what was
//! approved, denied, withdrawn or left to lapse), since an approval's value as
//! an audit record outlives the decision window. The agent's owner reads its
//! requests, and so does anyone allowed to view agents.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::oversight::approval::ApprovalRequest;
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, ApprovalStore};
use crate::use_case::Query;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The ports [`ListPendingUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPendingPorts {
    /// Reads approval requests.
    pub approval_store: Arc<dyn ApprovalStore>,
    /// The agent, whose owner may read its requests.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Whose approval requests to list, and which of them.
pub struct ListPendingRequest {
    /// The agent whose requests to list.
    pub agent_id: AgentId,
    /// Narrows to one lifecycle state; `None` returns the full history,
    /// resolved requests included.
    pub status: Option<ApprovalStatus>,
}

/// Lists an agent's approval requests, pending or decided.
pub struct ListPendingUseCase {
    ports: ListPendingPorts,
}

impl ListPendingUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPendingPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListPendingUseCase {
    type Caller = CallerContext;
    type Input = ListPendingRequest;
    type Output = Result<Vec<ApprovalRequest<ResolvedTenant>>, AppError>;

    /// The agent's approval requests the caller is cleared to read, newest
    /// first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may view agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListPendingRequest,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let reach = AgentReach::Acting(AgentAction::View);
        let agents = self.ports.agent_store.as_ref();
        let agent = owned_agent(agents, &tenant, &request.agent_id, &control, reach).await?;
        let requests = self
            .ports
            .approval_store
            .list_for_agent(&tenant, agent.id(), request.status)
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
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::agents::oversight::approval::Approver;
    use ianua_domain::domains::authorization::authority::TenantAuthority;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::Human;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeAgentStore, FakeApprovalStore, agent_owned_by, caller_person, opened_by_agent,
        opened_request, someone,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Ann's agent with one pending and one denied request, and Bob's agent
    /// with a pending one.
    struct Seeded {
        agents: Arc<FakeAgentStore>,
        approvals: Arc<FakeApprovalStore>,
        anns: AgentId,
        bobs: AgentId,
    }

    fn seeded() -> Seeded {
        let tenant = test_ctx().tenant();
        let anns = agent_owned_by(AgentId::new(), someone("ann@corp.test"));
        let bobs = agent_owned_by(AgentId::new(), someone("bob@corp.test"));
        let (agents, approvals) = (
            Arc::new(FakeAgentStore::empty()),
            Arc::new(FakeApprovalStore::empty()),
        );
        for agent in [&anns, &bobs] {
            block_on(agents.save(&tenant, agent)).unwrap();
        }
        let olga = someone("olga@corp.test");
        let denied = denied_request(&anns, olga.clone());
        for approval in [
            opened_request(&anns, olga.clone()),
            denied,
            opened_request(&bobs, olga),
        ] {
            block_on(approvals.save(&tenant, &approval)).unwrap();
        }
        Seeded {
            agents,
            approvals,
            anns: *anns.id(),
            bobs: *bobs.id(),
        }
    }

    /// Carol denies Olga's request for this agent, giving the history a resolved entry.
    fn denied_request(
        agent: &AgentIdentity<ResolvedTenant>,
        requester: Human,
    ) -> ApprovalRequest<ResolvedTenant> {
        let mut denied = opened_request(agent, requester);
        let decider = TenantAuthority::assumed(
            someone("carol@corp.test"),
            test_ctx().tenant_id(),
            SystemPermission::all(),
            &[],
        );
        denied
            .deny(&Approver::of(AgentControl::new(&decider)))
            .unwrap();
        denied
    }

    impl Seeded {
        fn ports(&self) -> ListPendingPorts {
            ListPendingPorts {
                approval_store: self.approvals.clone(),
                agent_store: self.agents.clone(),
                ..ListPendingPorts::fakes()
            }
        }
    }

    fn list(
        ports: ListPendingPorts,
        agent_id: AgentId,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, AppError> {
        block_on(
            ListPendingUseCase::new(ports)
                .execute(&test_ctx(), ListPendingRequest { agent_id, status }),
        )
    }

    /// Ann's inbox: asking for pending requests lists only the one still
    /// waiting.
    #[test]
    fn filtering_by_status_returns_only_that_state() {
        let seeded = seeded();

        let listed = list(seeded.ports(), seeded.anns, Some(ApprovalStatus::Pending)).unwrap();

        assert_eq!(listed.len(), 1);
        assert!(listed[0].is_pending());
    }

    /// The history: with no filter, the denied request is listed too.
    #[test]
    fn no_filter_returns_resolved_requests_too() {
        let seeded = seeded();

        let listed = list(seeded.ports(), seeded.anns, None).unwrap();

        assert_eq!(listed.len(), 2);
        assert!(
            listed
                .iter()
                .any(|approval| approval.status() == ApprovalStatus::Denied)
        );
    }

    /// Bob's agent's request never shows in the list for Ann's.
    #[test]
    fn another_agents_approvals_are_never_listed() {
        let seeded = seeded();

        let listed = list(seeded.ports(), seeded.anns, None).unwrap();

        assert!(
            listed
                .iter()
                .all(|approval| approval.agent_id() == &seeded.anns)
        );
        assert_ne!(seeded.anns, seeded.bobs);
    }

    /// Asking for an agent the tenant does not have is not found.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let seeded = seeded();

        let result = list(seeded.ports(), AgentId::new(), None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann reads her own agent's requests without any agent permission.
    #[test]
    fn the_owner_reads_their_agents_requests() {
        let seeded = seeded();
        let ann = test_ctx();
        let owned: AgentIdentity<ResolvedTenant> = agent_owned_by(AgentId::new(), caller_person());
        block_on(seeded.agents.save(&ann.tenant(), &owned)).unwrap();
        let ports = ListPendingPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..seeded.ports()
        };

        let listed = list(ports, *owned.id(), None).unwrap();

        assert!(listed.is_empty());
    }

    /// Listing another owner's approval requests without agent-view
    /// permission reports the agent as missing.
    #[test]
    fn a_caller_who_may_not_view_agents_is_refused() {
        let seeded = seeded();
        let ports = ListPendingPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..seeded.ports()
        };

        let result = list(ports, seeded.anns, None);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot list an agent's approval requests.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let seeded = seeded();
        let ports = ListPendingPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..seeded.ports()
        };

        let result = list(ports, seeded.anns, None);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A request quoting restricted data is omitted for an internal-cleared
    /// viewer and listed for a viewer cleared for restricted data.
    #[test]
    fn a_request_above_the_viewers_clearance_is_left_out() {
        let tenant = test_ctx().tenant();
        let anns = agent_owned_by(AgentId::new(), someone("ann@corp.test"));
        let (agents, approvals) = (
            Arc::new(FakeAgentStore::empty()),
            Arc::new(FakeApprovalStore::empty()),
        );
        block_on(agents.save(&tenant, &anns)).unwrap();
        block_on(approvals.save(&tenant, &opened_by_agent(&anns))).unwrap();
        let ports_for = |authorities: FakeTenantAuthorities| ListPendingPorts {
            approval_store: approvals.clone(),
            agent_store: agents.clone(),
            tenant_authorities: Arc::new(authorities),
            ..ListPendingPorts::fakes()
        };

        let sams = list(
            ports_for(FakeTenantAuthorities::holding(&[SystemPermission::Agents(
                AgentAction::View,
            )])),
            *anns.id(),
            None,
        )
        .unwrap();
        let carols = list(
            ports_for(FakeTenantAuthorities::holding_everything()),
            *anns.id(),
            None,
        )
        .unwrap();

        assert!(sams.is_empty());
        assert_eq!(carols.len(), 1);
    }
}
