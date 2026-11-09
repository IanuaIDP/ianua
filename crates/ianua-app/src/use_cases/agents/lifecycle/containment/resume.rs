//! Resume agent: let a suspended agent act again.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::AgentAction;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AgentId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, AgentVersion};
use crate::use_case::Command;
use crate::use_cases::agents::lookup::{AgentReach, owned_agent};

/// The ports [`ResumeAgentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResumeAgentPorts {
    /// Loads and saves agents.
    pub agent_store: Arc<dyn AgentStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Resumes one suspended agent of the caller's tenant.
pub struct ResumeAgentUseCase {
    ports: ResumeAgentPorts,
}

impl ResumeAgentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResumeAgentPorts) -> Self {
        Self { ports }
    }
}

impl Command for ResumeAgentUseCase {
    type Caller = CallerContext;
    type Input = AgentId;
    type Output = Result<(), AppError>;

    /// Resumes the suspended agent.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such agent, or the
    ///   caller neither owns it nor may update agents, so that an agent of
    ///   someone else's answers as one that does not exist.
    /// - `AppError::Domain` when the agent is revoked or already active.
    /// - `AppError::Conflict` when the agent changed since it was read.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        agent_id: AgentId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = AgentControl::new(&authority);
        let store = self.ports.agent_store.as_ref();
        let reach = AgentReach::Acting(AgentAction::Update);
        let mut agent = owned_agent(store, &tenant, &agent_id, &control, reach).await?;
        let read = AgentVersion::of(&agent);
        agent.resume(&control).map_err(AppError::from_domain)?;
        self.ports
            .agent_store
            .save_unchanged_since(&tenant, &agent, read)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ctx.actor(), agent.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::types::{Human, HumanAccount, PersonKey, UserId};

    use super::*;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, caller_person};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn suspended_agent_of(owner: Human) -> (AgentId, Arc<FakeAgentStore>) {
        let id = AgentId::new();
        let store = Arc::new(FakeAgentStore::empty());
        store.add_owned(id, owner, AgentStatus::Suspended);
        (id, store)
    }

    fn someone_else() -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("ann@example.test").unwrap(),
        )
    }

    fn resume(
        store: &Arc<FakeAgentStore>,
        authorities: FakeTenantAuthorities,
        sink: Arc<dyn EventDispatcher>,
        id: AgentId,
    ) -> Result<(), AppError> {
        let use_case = ResumeAgentUseCase::new(ResumeAgentPorts {
            agent_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink), id))
    }

    /// Ann resumes her own suspended agent. It is active again and the
    /// resume is recorded.
    #[test]
    fn the_owner_resumes_their_agent_and_it_is_recorded() {
        let (id, store) = suspended_agent_of(caller_person());
        let sink = Arc::new(FakeEventDispatcher::new());

        resume(
            &store,
            FakeTenantAuthorities::holding(&[]),
            sink.clone(),
            id,
        )
        .unwrap();

        assert!(store.find_by_id_direct(&id).unwrap().is_active());
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.agent_resumed"]
        );
    }

    /// Bob, who may update agents, resumes Ann's agent once the incident is
    /// over. It is active again.
    #[test]
    fn someone_allowed_to_update_agents_resumes_anothers() {
        let (id, store) = suspended_agent_of(someone_else());
        let bob = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::Update)]);

        resume(&store, bob, Arc::new(FakeEventDispatcher::new()), id).unwrap();

        assert!(store.find_by_id_direct(&id).unwrap().is_active());
    }

    /// A viewer cannot resume another person's agent; it appears missing
    /// and remains inactive.
    #[test]
    fn a_viewer_cannot_resume_anothers_agent() {
        let (id, store) = suspended_agent_of(someone_else());
        let sam = FakeTenantAuthorities::holding(&[SystemPermission::Agents(AgentAction::View)]);

        let result = resume(&store, sam, Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!store.find_by_id_direct(&id).unwrap().is_active());
    }

    /// A signed-out owner cannot resume their suspended agent.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (id, store) = suspended_agent_of(caller_person());

        let result = resume(
            &store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// The audit sink is down when Ann resumes her agent. The resume fails
    /// rather than going unrecorded.
    #[test]
    fn a_resume_that_cannot_be_recorded_fails() {
        let (id, store) = suspended_agent_of(caller_person());

        let result = resume(
            &store,
            FakeTenantAuthorities::holding(&[]),
            Arc::new(FailingEventDispatcher),
            id,
        );

        assert!(result.is_err());
    }
}
