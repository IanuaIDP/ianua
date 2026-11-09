//! Reset exposure: a person lowers a stopped agent's data mark.
//!
//! An agent's mark only ever rises: whatever it read, it may still carry.
//! That stays true while the agent runs, because its context holds what it
//! read. Once it is stopped and its context is gone, someone allowed to
//! manage agents may lower the mark so the agent can go back to less
//! sensitive work. The domain decides who may, that the agent is stopped and
//! that the mark only goes down; the store lowers it only if it is still the
//! mark the person saw.

use std::sync::Arc;

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::agents::identity::exposure_reset::{ExposureReset, LowerExposureParams};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AgentId, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentExposureGate, AgentStore};
use crate::services::lookup::existing_agent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// What the person asks for.
pub struct ResetExposureRequest {
    /// The identity whose exposure mark should be lowered.
    pub agent_id: AgentId,
    /// The mark to lower it to.
    pub to: DataClassLevel,
    /// Why.
    pub reason: Label,
}

/// The ports [`ResetExposureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResetExposurePorts {
    /// Loads the agent, to see it is stopped.
    pub agent_store: Arc<dyn AgentStore>,
    /// Holds the marks.
    pub exposure: Arc<dyn AgentExposureGate>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lowers a stopped agent's data mark.
pub struct ResetExposureUseCase {
    ports: ResetExposurePorts,
}

impl ResetExposureUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResetExposurePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResetExposureUseCase {
    type Caller = CallerContext;
    type Input = ResetExposureRequest;
    type Output = Result<(), AppError>;

    /// Lowers the mark of `req.agent_id` to `req.to`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for missing management rights, before reading the agent.
    /// - `AppError::NotFound` when the agent is outside the tenant.
    /// - `AppError::Domain` when the agent is active or the requested mark is not lower.
    /// - `AppError::Conflict` when the agent resumed or its mark changed concurrently; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: ResetExposureRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let agent = existing_agent(self.ports.agent_store.as_ref(), &tenant, &req.agent_id).await?;
        let mut reset = ordered_reset(&self.ports, &tenant, &authority, &agent, req).await?;
        apply_reset(&self.ports, &tenant, &reset).await?;

        auditor
            .dispatch_by(&ctx.actor(), reset.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// The reset the person asks for, from the mark the store holds now, once
/// the domain allows it.
async fn ordered_reset(
    ports: &ResetExposurePorts,
    tenant: &ScopedTenant,
    authority: &TenantAuthority,
    agent: &AgentIdentity<ResolvedTenant>,
    req: ResetExposureRequest,
) -> Result<ExposureReset<ResolvedTenant>, AppError> {
    let from = ports
        .exposure
        .current(tenant, agent.id())
        .await
        .or_internal()?;
    let params = LowerExposureParams {
        from,
        to: req.to,
        reason: req.reason,
    };
    ExposureReset::ordered(&AgentControl::new(authority), agent, params)
        .map_err(AppError::from_domain)
}

/// Lowers the mark as `reset` says, refusing when the store did not
/// apply it: the agent was resumed, or its mark moved, between the read and
/// the write.
async fn apply_reset(
    ports: &ResetExposurePorts,
    tenant: &ScopedTenant,
    reset: &ExposureReset<ResolvedTenant>,
) -> Result<(), AppError> {
    let lowered = ports.exposure.reset(tenant, reset).await.or_internal()?;
    if lowered {
        return Ok(());
    }
    Err(AppError::Conflict(message!(
        "agents-the-agent-was-resumed-or-its",
        "the agent was resumed or its mark changed; read it again before lowering it"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{FakeAgentStore, FakeExposureGate};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An agent of the test tenant with a confidential mark, and who asks to
    /// lower it.
    struct Fixture {
        agents: Arc<FakeAgentStore>,
        mark: Arc<FakeExposureGate>,
        authorities: Arc<FakeTenantAuthorities>,
        sink: Arc<FakeEventDispatcher>,
        agent: AgentId,
    }

    fn fixture(status: AgentStatus) -> Fixture {
        let agent = AgentId::new();
        let agents = Arc::new(FakeAgentStore::empty());
        agents.add_with_status(agent, status);
        let mark = Arc::new(FakeExposureGate::default());
        mark.set(&test_ctx().tenant(), agent, DataClassLevel::Confidential);
        Fixture {
            agents,
            mark,
            authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
            sink: Arc::new(FakeEventDispatcher::new()),
            agent,
        }
    }

    impl Fixture {
        fn held_by(self, authorities: FakeTenantAuthorities) -> Self {
            Self {
                authorities: Arc::new(authorities),
                ..self
            }
        }

        fn reset_agent(&self, agent: AgentId, to: DataClassLevel) -> Result<(), AppError> {
            let use_case = ResetExposureUseCase::new(ResetExposurePorts {
                agent_store: self.agents.clone(),
                exposure: self.mark.clone(),
                tenant_authorities: self.authorities.clone(),
            });
            block_on(use_case.execute(
                &test_ctx(),
                &test_auditor(self.sink.clone()),
                ResetExposureRequest {
                    agent_id: agent,
                    to,
                    reason: Label::new("reason", "context cleared after review").unwrap(),
                },
            ))
        }

        fn reset(&self, to: DataClassLevel) -> Result<(), AppError> {
            self.reset_agent(self.agent, to)
        }

        fn mark(&self) -> DataClassLevel {
            self.mark.of(&test_ctx().tenant(), &self.agent)
        }

        fn recorded(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    /// Ann, who may manage agents, lowers a suspended agent's mark from
    /// confidential to internal. The mark is internal, and the reset is
    /// recorded.
    #[test]
    fn a_stopped_agents_mark_is_lowered_and_recorded() {
        let f = fixture(AgentStatus::Suspended);

        f.reset(DataClassLevel::Internal).unwrap();

        assert_eq!(f.mark(), DataClassLevel::Internal);
        assert_eq!(f.recorded(), ["agents.exposure_reset"]);
    }

    /// Lowering an active agent's exposure fails, preserves its confidential
    /// mark, and records no reset.
    #[test]
    fn a_running_agents_mark_stays() {
        let f = fixture(AgentStatus::Active);

        let result = f.reset(DataClassLevel::Public);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(f.mark(), DataClassLevel::Confidential);
        assert!(f.recorded().is_empty());
    }

    /// An exposure store reporting that the agent resumed makes the reset
    /// conflict, preserving its confidential mark without recording a reset.
    #[test]
    fn a_reset_after_the_agent_was_resumed_lowers_nothing() {
        let f = fixture(AgentStatus::Suspended);
        f.mark.resume(&test_ctx().tenant(), f.agent);

        let result = f.reset(DataClassLevel::Internal);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(f.mark(), DataClassLevel::Confidential);
        assert!(f.recorded().is_empty());
    }

    /// Ann asks to "lower" a confidential mark to restricted, and then to
    /// confidential. Both are refused: a reset only lowers.
    #[test]
    fn a_reset_only_lowers() {
        let f = fixture(AgentStatus::Suspended);

        assert!(f.reset(DataClassLevel::Restricted).is_err());
        assert!(f.reset(DataClassLevel::Confidential).is_err());
        assert_eq!(f.mark(), DataClassLevel::Confidential);
    }

    /// Agent-view permission cannot lower a suspended agent's confidential
    /// mark, which remains unchanged.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let f = fixture(AgentStatus::Suspended).held_by(FakeTenantAuthorities::holding(&[
            SystemPermission::Agents(AgentAction::View),
        ]));

        let result = f.reset(DataClassLevel::Public);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.mark(), DataClassLevel::Confidential);
    }

    /// A signed-out caller cannot lower exposure; the confidential mark remains.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(AgentStatus::Suspended)
            .held_by(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = f.reset(DataClassLevel::Public);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.mark(), DataClassLevel::Confidential);
    }

    /// Resetting an unknown agent reports it as missing and preserves the
    /// existing agent's confidential mark.
    #[test]
    fn an_unknown_agent_is_not_found() {
        let f = fixture(AgentStatus::Suspended);

        let result = f.reset_agent(AgentId::new(), DataClassLevel::Public);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(f.mark(), DataClassLevel::Confidential);
    }
}
