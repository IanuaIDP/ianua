//! Record a task token bound to an agent's key presented without that
//! key's proof.
//!
//! Only the gateway sees it: a bound token sent bare, or proven by another
//! key, is a copy in hands that do not hold the agent's key. It is recorded
//! the way the API's token exchange records an attack on an agent's
//! sign-in, as `agents.token_attack_refused`, held back to one record a
//! window per agent and kind of attack that says how many attempts it
//! stands for. A proof that merely does not check out may be the agent's
//! own clock drifting, and records nothing.

use std::sync::Arc;

use ianua_domain::domains::agents::events::identity::AgentTokenAttackRefused;
use ianua_domain::domains::agents::identity::token_attack::{KeyProofFault, TokenAttack};
use ianua_domain::domains::notifications::alert::ALERT_WINDOW;
use ianua_domain::types::event_type::AgentsEvent;
use ianua_domain::types::{ActorRef, AgentId, EventType};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentStore;
use crate::ports::notifications::{AlertAbout, AlertKey, AlertPlane, AlertThrottle, AlertTurn};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// One bound task token refused for its key proof.
pub struct RecordStolenBindingRequest {
    /// The agent the token names.
    pub agent_id: AgentId,
    /// Why its key proof was refused.
    pub fault: KeyProofFault,
}

/// The ports [`RecordStolenBindingUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RecordStolenBindingPorts {
    /// The agents, for the name the record carries.
    pub agents: Arc<dyn AgentStore>,
    /// Holds records back to one a window per agent and kind of attack.
    pub attacks: Arc<dyn AlertThrottle>,
}

/// Records a bound task token presented without its key's proof.
pub struct RecordStolenBindingUseCase {
    ports: RecordStolenBindingPorts,
}

impl RecordStolenBindingUseCase {
    /// A use case recording through `ports`.
    #[must_use]
    pub fn new(ports: RecordStolenBindingPorts) -> Self {
        Self { ports }
    }
}

impl Command for RecordStolenBindingUseCase {
    type Caller = ScopedTenant;
    type Input = RecordStolenBindingRequest;
    type Output = Result<(), AppError>;

    /// Records `agents.token_attack_refused` in `tenant` when the refusal
    /// looks like a stolen token and no record of it went out this window.
    /// A refusal that may be the agent's own slip, one held back, and one
    /// naming an agent the tenant no longer has record nothing. It is one
    /// of the few events the gateway's inbox takes.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the agent cannot be read or the record
    ///   cannot be written. The request stays refused either way.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RecordStolenBindingRequest,
    ) -> Result<(), AppError> {
        let Some(attack) = req.fault.attack() else {
            return Ok(());
        };
        let key = alert_key(tenant, req.agent_id, attack);
        let AlertTurn::Raise { since_last } = self.ports.attacks.admit(&key, ALERT_WINDOW).await
        else {
            return Ok(());
        };
        let found = self
            .ports
            .agents
            .find_by_id(tenant, &req.agent_id)
            .await
            .or_internal()?;
        let Some(agent) = found else {
            return Ok(());
        };
        let attempts = since_last.unwrap_or(1);
        let recorded = AgentTokenAttackRefused::observed(**tenant, &agent, attack, attempts);
        auditor
            .dispatch_by(&ActorRef::Anonymous, vec![recorded])
            .await
            .or_internal()
    }
}

/// The key `attack` on `agent_id` is held back under: one record a window
/// per tenant, agent and kind of attack.
fn alert_key(tenant: &ScopedTenant, agent_id: AgentId, attack: TokenAttack) -> AlertKey {
    AlertKey {
        plane: AlertPlane::Tenant(**tenant),
        event_type: EventType::from(AgentsEvent::TokenAttackRefused),
        about: AlertAbout::AgentAttack { agent_id, attack },
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::agents::FakeAgentStore;
    use crate::test_support::notification_delivery::FakeAlertThrottle;
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    const ATTACKED: &str = "agents.token_attack_refused";

    fn use_case(
        agent_id: AgentId,
        throttle: &Arc<FakeAlertThrottle>,
    ) -> RecordStolenBindingUseCase {
        RecordStolenBindingUseCase::new(RecordStolenBindingPorts {
            agents: Arc::new(FakeAgentStore::with_active(agent_id)),
            attacks: throttle.clone(),
        })
    }

    fn record(
        use_case: &RecordStolenBindingUseCase,
        sink: &Arc<FakeEventDispatcher>,
        agent_id: AgentId,
        fault: KeyProofFault,
    ) -> Result<(), AppError> {
        block_on(use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(sink.clone()),
            RecordStolenBindingRequest { agent_id, fault },
        ))
    }

    /// Mallory copies the build agent's bound task token and sends it bare.
    /// It is recorded as a stolen binding of that agent.
    #[test]
    fn a_bound_token_sent_bare_is_recorded_as_stolen() {
        let agent_id = AgentId::new();
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(agent_id, &Arc::new(FakeAlertThrottle::default()));

        record(&use_case, &sink, agent_id, KeyProofFault::NotSent).unwrap();

        assert_eq!(sink.records.lock().unwrap().as_slice(), [ATTACKED]);
        assert_eq!(
            sink.payload_of(ATTACKED).value("attack"),
            Some(&FieldValue::Text("stolen_binding".to_owned()))
        );
    }

    /// The build agent's clock drifts and its proof is out of date. That
    /// may be its own slip, so nothing is recorded.
    #[test]
    fn a_proof_that_does_not_check_out_records_nothing() {
        let agent_id = AgentId::new();
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(agent_id, &Arc::new(FakeAlertThrottle::default()));

        record(&use_case, &sink, agent_id, KeyProofFault::NotChecked).unwrap();

        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Three wrong-key reports within one throttle window produce only one
    /// attack record.
    #[test]
    fn repeats_within_a_window_are_held_back() {
        let agent_id = AgentId::new();
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(agent_id, &Arc::new(FakeAlertThrottle::default()));

        for _ in 0..3 {
            record(&use_case, &sink, agent_id, KeyProofFault::ByAnotherKey).unwrap();
        }

        assert_eq!(sink.records.lock().unwrap().len(), 1);
    }

    /// Failure to persist a stolen-binding record returns an internal error.
    #[test]
    fn an_unwritten_record_is_an_error() {
        let agent_id = AgentId::new();
        let use_case = use_case(agent_id, &Arc::new(FakeAlertThrottle::default()));

        let recorded = block_on(use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            RecordStolenBindingRequest {
                agent_id,
                fault: KeyProofFault::NotSent,
            },
        ));

        assert!(matches!(recorded, Err(AppError::Internal(_))));
    }
}
