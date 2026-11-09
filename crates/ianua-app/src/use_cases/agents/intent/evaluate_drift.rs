//! Evaluate intent drift: the closed-loop answer to an action outside the
//! intent a delegation was given for.
//!
//! A worker over `AgentActionAuthorized` and `AgentActionDenied` events,
//! never the request path, checks each action against its delegation's
//! bound intent envelope. `Enforce` is already blocked in the request at the
//! proxy, so this path closes the loop. It sees the refused actions too, so
//! an agent that keeps probing past its intent is answered rather than only
//! turned away each time. On a breach it records `AgentIntentDrift` and,
//! under `Enforce`, answers in proportion to the risk of the breached action:
//! a low-risk drift revokes only the offending delegation, a high-risk drift
//! suspends the agent outright. `Warn` observes without acting. The platform's
//! monitor acts here, so revoking and suspending need no person.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::delegation::{Delegation, Revoker};
use ianua_domain::domains::agents::authority::intent::DriftPolicy;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActingFor, ActionClass, ActorRef, AgentId, DelegationId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{AgentStore, DelegationStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::lifecycle::containment::suspension::suspend_agent;

/// The automated response taken when an action breaches its intent.
#[derive(Debug, PartialEq, Eq)]
pub enum DriftResponse {
    /// Observed and recorded only (the `Warn` policy).
    Warned,
    /// The offending delegation and its subtree were revoked: a low-risk
    /// drift, so the agent keeps its other authority.
    DelegationRevoked,
    /// The agent was suspended: a high-risk drift.
    AgentSuspended,
}

/// The outcome of a drift evaluation.
#[derive(Debug, PartialEq, Eq)]
pub enum DriftOutcome {
    /// The delegation carries no monitored intent binding, or drift is off.
    NotMonitored,
    /// The action stayed within the intent.
    WithinBounds,
    /// The action breached the intent; `response` records what the drift
    /// policy did about it.
    Drifted {
        /// The graduated response applied.
        response: DriftResponse,
    },
}

/// Request to evaluate one action against its delegation's bound intent.
pub struct EvaluateDriftRequest {
    /// The acting agent.
    pub agent_id: AgentId,
    /// The delegation the action was authorized under.
    pub delegation_id: DelegationId,
    /// The class the proxy judged the action as: the route's declared class
    /// when it has one, so a payments route declared `Financial` is judged
    /// financial here too, not by its path.
    pub action_class: ActionClass,
}

/// The ports [`EvaluateDriftUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EvaluateDriftPorts {
    /// Loads the delegation and its intent binding, and revokes it.
    pub delegation_store: Arc<dyn DelegationStore>,
    /// Loads and suspends the agent under `Enforce`.
    pub agent_store: Arc<dyn AgentStore>,
}

/// Answers an action that drifted from its delegation's intent.
pub struct EvaluateDriftUseCase {
    ports: EvaluateDriftPorts,
}

impl EvaluateDriftUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EvaluateDriftPorts) -> Self {
        Self { ports }
    }
}

impl Command for EvaluateDriftUseCase {
    type Caller = ScopedTenant;
    type Input = EvaluateDriftRequest;
    type Output = Result<DriftOutcome, AppError>;

    /// Checks the action against its intent and answers a breach as the
    /// binding's drift policy says.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the monitor may not suspend the agent or
    ///   revoke the delegation.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: EvaluateDriftRequest,
    ) -> Result<DriftOutcome, AppError> {
        let Some(mut delegation) = self
            .ports
            .delegation_store
            .find_by_id(tenant, &req.delegation_id)
            .await
            .or_internal()?
        else {
            return Ok(DriftOutcome::NotMonitored);
        };
        let policy = match breached_policy(&delegation, req.action_class) {
            Ok(policy) => policy,
            Err(outcome) => return Ok(outcome),
        };
        delegation.record_drift();
        let mut events = by_the_agent(delegation.take_events(tenant), &req.agent_id);
        let (response, follow_up) = match policy {
            DriftPolicy::Enforce(_) => {
                enforced_response(&self.ports, tenant, &req, &mut delegation).await?
            }
            DriftPolicy::Warn(_) | DriftPolicy::Off => (DriftResponse::Warned, Vec::new()),
        };
        events.extend(follow_up);
        auditor.dispatch(&events).await.or_internal()?;
        Ok(DriftOutcome::Drifted { response })
    }
}

/// The drift policy an action breaches, or the outcome when it breaches
/// nothing: the delegation binds no intent, monitors none, or permits it.
fn breached_policy(
    delegation: &Delegation<ResolvedTenant>,
    action_class: ActionClass,
) -> Result<DriftPolicy, DriftOutcome> {
    let Some(binding) = delegation.constraints().intent().limit() else {
        return Err(DriftOutcome::NotMonitored);
    };
    let policy = binding.drift_policy();
    if matches!(policy, DriftPolicy::Off) {
        return Err(DriftOutcome::NotMonitored);
    }
    if binding.permits(action_class) {
        return Err(DriftOutcome::WithinBounds);
    }
    Ok(policy)
}

/// The `Enforce` answer to a breach and the events recording it: a
/// high-risk action suspends the agent, anything else revokes the
/// delegation and every delegation descended from it, the system acting.
async fn enforced_response(
    ports: &EvaluateDriftPorts,
    tenant: &ScopedTenant,
    req: &EvaluateDriftRequest,
    delegation: &mut Delegation<ResolvedTenant>,
) -> Result<(DriftResponse, Vec<DomainEvent>), AppError> {
    if req.action_class.is_high_risk() {
        let suspended = suspend_agent(ports.agent_store.as_ref(), tenant, &req.agent_id).await?;
        return Ok((
            DriftResponse::AgentSuspended,
            suspended.into_iter().collect(),
        ));
    }
    revoke_subtree(ports.delegation_store.as_ref(), tenant, delegation.id()).await?;
    delegation
        .revoke(Revoker::Monitor)
        .map_err(AppError::from_domain)?;
    let revoked = delegation
        .take_events(tenant)
        .into_iter()
        .map(DomainEvent::system);
    Ok((DriftResponse::DelegationRevoked, revoked.collect()))
}

/// Revokes `root` and every delegation cut or minted from it.
async fn revoke_subtree(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    root: &DelegationId,
) -> Result<(), AppError> {
    let below = store
        .find_revocation_closure(tenant, root)
        .await
        .or_internal()?;
    for id in std::iter::once(root).chain(&below) {
        revoke_if_live(store, tenant, id).await?;
    }
    Ok(())
}

/// Revokes the delegation as the platform's monitor, unless it is gone or
/// already revoked. Each revoke is part of the one tear-down the root's
/// record stands for, so what it raises is not recorded on its own.
async fn revoke_if_live(
    store: &dyn DelegationStore,
    tenant: &ScopedTenant,
    delegation_id: &DelegationId,
) -> Result<(), AppError> {
    let Some(mut delegation) = store
        .find_by_id(tenant, delegation_id)
        .await
        .or_internal()?
    else {
        return Ok(());
    };
    if delegation.is_revoked() {
        return Ok(());
    }
    delegation
        .revoke(Revoker::Monitor)
        .map_err(AppError::from_domain)?;
    store.save(tenant, &delegation).await.or_internal()
}

/// `events`, attributed to the agent `agent_id` acting on its own.
fn by_the_agent(events: Vec<DomainEvent>, agent_id: &AgentId) -> Vec<DomainEvent> {
    let agent = ActorRef::Agent {
        id: *agent_id,
        on_behalf_of: ActingFor::Itself,
    };
    events
        .into_iter()
        .map(|event| event.with_actor(agent.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::intent::{
        DriftThreshold, IntentBinding, IntentDigest, IntentEnvelope, IntentStatement,
    };
    use ianua_domain::domains::agents::identity::status::AgentStatus;
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::types::{HttpMethod, Label};

    use super::*;
    use crate::test_support::agents::{FakeAgentStore, FakeDelegationStore, grant_to};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An intent to read the calendar, watched under `policy`.
    fn read_binding(policy: DriftPolicy) -> IntentBinding {
        IntentBinding::new(
            IntentStatement::new("read the calendar").unwrap(),
            IntentDigest::new([1u8; 32]),
            policy,
            IntentEnvelope::new([ActionClass::Read]),
        )
    }

    fn threshold() -> DriftThreshold {
        DriftThreshold::from_basis_points(5000).unwrap()
    }

    /// One active agent, its delegation, and what the monitor records.
    struct Fixture {
        agents: Arc<FakeAgentStore>,
        delegations: Arc<FakeDelegationStore>,
        sink: Arc<FakeEventDispatcher>,
        agent: AgentId,
        delegation: DelegationId,
    }

    fn fixture(policy: Option<DriftPolicy>, name: Option<&str>) -> Fixture {
        let agent = AgentId::new();
        let agents = Arc::new(FakeAgentStore::with_active(agent));
        let delegations = Arc::new(FakeDelegationStore::empty());
        let granted = grant_to(
            agent,
            policy.map(read_binding),
            name.map(|name| Label::new("name", name).unwrap()),
        );
        block_on(delegations.save(&test_ctx().tenant(), &granted)).unwrap();
        Fixture {
            agents,
            delegations,
            sink: Arc::new(FakeEventDispatcher::new()),
            agent,
            delegation: *granted.id(),
        }
    }

    impl Fixture {
        fn act(&self, method: HttpMethod, path: &str) -> DriftOutcome {
            let use_case = EvaluateDriftUseCase::new(EvaluateDriftPorts {
                delegation_store: self.delegations.clone(),
                agent_store: self.agents.clone(),
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.sink.clone()),
                EvaluateDriftRequest {
                    agent_id: self.agent,
                    delegation_id: self.delegation,
                    action_class: ActionClass::classify(method, path),
                },
            ))
            .unwrap()
        }

        fn agent_status(&self) -> AgentStatus {
            self.agents.find_by_id_direct(&self.agent).unwrap().status()
        }

        fn delegation_revoked(&self) -> bool {
            block_on(
                self.delegations
                    .find_by_id(&test_ctx().tenant(), &self.delegation),
            )
            .unwrap()
            .unwrap()
            .is_revoked()
        }

        fn recorded(&self) -> Vec<String> {
            self.sink.records.lock().unwrap().clone()
        }
    }

    fn drifted(response: DriftResponse) -> DriftOutcome {
        DriftOutcome::Drifted { response }
    }

    /// Ann's delegation binds no intent. Even a delete is not watched here.
    #[test]
    fn no_binding_is_not_monitored() {
        let f = fixture(None, None);

        let outcome = f.act(HttpMethod::Delete, "/anything");

        assert_eq!(outcome, DriftOutcome::NotMonitored);
    }

    /// The agent was given the delegation to read the calendar, and reads
    /// it. That is within its intent.
    #[test]
    fn on_purpose_action_is_within_bounds() {
        let f = fixture(Some(DriftPolicy::Warn(threshold())), None);

        let outcome = f.act(HttpMethod::Get, "/calendars/team");

        assert_eq!(outcome, DriftOutcome::WithinBounds);
        assert!(f.recorded().is_empty());
    }

    /// Under `Warn`, the agent deletes the team calendar. The drift is
    /// recorded, and the agent keeps running.
    #[test]
    fn warn_breach_records_drift_without_suspending() {
        let f = fixture(Some(DriftPolicy::Warn(threshold())), None);

        let outcome = f.act(HttpMethod::Delete, "/calendars/team");

        assert_eq!(outcome, drifted(DriftResponse::Warned));
        assert_eq!(f.recorded(), ["agents.intent_drift"]);
        assert_eq!(f.agent_status(), AgentStatus::Active);
    }

    /// The drift record names the delegation by its title, "Q1
    /// reconciliation delegation", not by its id.
    #[test]
    fn the_drift_record_names_the_delegation_by_its_title() {
        let f = fixture(
            Some(DriftPolicy::Warn(threshold())),
            Some("Q1 reconciliation delegation"),
        );

        f.act(HttpMethod::Delete, "/calendars/team");

        let payload = f.sink.payload_of("agents.intent_drift");
        let Some(FieldValue::Reference(reference)) = payload.value("delegation") else {
            panic!("expected a delegation reference");
        };
        assert_eq!(reference.label(), "Q1 reconciliation delegation");
    }

    /// A high-risk delete outside an enforced read intent suspends the agent
    /// and records both drift and suspension.
    #[test]
    fn enforce_high_risk_breach_suspends_the_agent() {
        let f = fixture(Some(DriftPolicy::Enforce(threshold())), None);

        let outcome = f.act(HttpMethod::Delete, "/calendars/team");

        assert_eq!(outcome, drifted(DriftResponse::AgentSuspended));
        assert_eq!(f.agent_status(), AgentStatus::Suspended);
        assert_eq!(
            f.recorded(),
            ["agents.intent_drift", "agents.agent_suspended"]
        );
    }

    /// A low-risk write outside an enforced read intent revokes the
    /// delegation while leaving the agent active, recording drift and
    /// revocation.
    #[test]
    fn enforce_low_risk_breach_revokes_only_the_delegation() {
        let f = fixture(Some(DriftPolicy::Enforce(threshold())), None);

        let outcome = f.act(HttpMethod::Post, "/calendars/team");

        assert_eq!(outcome, drifted(DriftResponse::DelegationRevoked));
        assert_eq!(f.agent_status(), AgentStatus::Active);
        assert!(f.delegation_revoked());
        assert_eq!(
            f.recorded(),
            ["agents.intent_drift", "agents.delegation_revoked"]
        );
    }

    /// The delegation the event names is gone. Nothing is watched, and
    /// nothing is recorded.
    #[test]
    fn a_missing_delegation_is_not_monitored() {
        let mut f = fixture(Some(DriftPolicy::Enforce(threshold())), None);
        f.delegation = DelegationId::new();

        let outcome = f.act(HttpMethod::Delete, "/calendars/team");

        assert_eq!(outcome, DriftOutcome::NotMonitored);
        assert!(f.recorded().is_empty());
    }
}
