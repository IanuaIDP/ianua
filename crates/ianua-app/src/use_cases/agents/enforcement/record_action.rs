//! Record what the gateway decided about an agent's HTTP request: allowed
//! or refused.
//!
//! Evidence, drift and convergence are all built from these records. An
//! agent whose actions cannot be recorded is an agent nobody is watching,
//! so the gateway forwards an allowed action only once it is recorded, and
//! records a refused one so an agent probing past its task is seen even
//! when every probe is refused.

use ianua_domain::domains::agents::events::enforcement::{
    AgentActionAuthorized, AgentActionDenied, AgentAtWork,
};
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{
    ActingFor, ActionClass, ActorRef, AgentId, DeclaredAction, DelegationId, HttpMethod,
    UntrustedText,
};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// What the gateway decided about the action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    /// Let through, to be forwarded once recorded.
    Authorized,
    /// Refused, for this reason. The reason is the gateway's own, never
    /// text the agent sent.
    Denied(UntrustedText),
}

/// One agent action and what the gateway decided about it.
pub struct RecordActionRequest {
    /// The agent that made the request.
    pub agent_id: AgentId,
    /// The delegation its task token was minted from.
    pub delegation_id: DelegationId,
    /// The method of the request.
    pub method: HttpMethod,
    /// The normalized path policy decided on, without its query, so the
    /// monitors judge the action the gateway judged and not an encoding of
    /// it.
    pub path: String,
    /// The kind of action the matched route declares, if it declares one.
    pub declared: DeclaredAction,
    /// What the gateway decided.
    pub outcome: ActionOutcome,
    /// When it decided. The monitors rebuild the record at this instant.
    pub decided_at: OffsetDateTime,
}

/// Records the gateway's decision about an agent's action.
pub struct RecordActionUseCase;

impl Command for RecordActionUseCase {
    type Caller = ScopedTenant;
    type Input = RecordActionRequest;
    type Output = Result<(), AppError>;

    /// Records `agents.action_authorized` or `agents.action_denied`, by the
    /// agent acting for itself, in the tenant its task token was issued
    /// for. These are two of the few events the gateway's inbox takes.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the record cannot be written. For an
    ///   allowed action the gateway must then refuse it rather than forward
    ///   it unseen.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RecordActionRequest,
    ) -> Result<(), AppError> {
        let by_agent = ActorRef::Agent {
            id: req.agent_id,
            on_behalf_of: ActingFor::Itself,
        };
        auditor
            .dispatch_by(&by_agent, vec![observed(tenant, req)])
            .await
            .or_internal()
    }
}

/// What the gateway saw of the action, as its record.
fn observed(tenant: &ScopedTenant, req: RecordActionRequest) -> DomainEvent {
    let by = AgentAtWork::new(**tenant, req.agent_id, req.delegation_id);
    let action = UntrustedText::record(&format!("{} {}", req.method.as_str(), req.path));
    let class = ActionClass::for_route(req.method, &req.path, req.declared);
    match req.outcome {
        ActionOutcome::Authorized => {
            AgentActionAuthorized::observed(by, action, class, req.decided_at)
        }
        ActionOutcome::Denied(reason) => {
            AgentActionDenied::observed(by, action, class, reason, req.decided_at)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::shared::clock;
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn request(outcome: ActionOutcome) -> RecordActionRequest {
        RecordActionRequest {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            method: HttpMethod::Delete,
            path: "/orders/1".to_owned(),
            declared: DeclaredAction::Undeclared,
            outcome,
            decided_at: clock::now(),
        }
    }

    fn record(sink: &Arc<FakeEventDispatcher>, req: RecordActionRequest) -> Result<(), AppError> {
        block_on(RecordActionUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(sink.clone()),
            req,
        ))
    }

    fn text(sink: &FakeEventDispatcher, event: &str, key: &str) -> String {
        match sink.payload_of(event).value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not text: {other:?}"),
        }
    }

    /// The gateway lets an agent delete an order. The record names the
    /// action, the agent and the class the delete was judged as.
    #[test]
    fn an_allowed_action_is_recorded_as_authorized() {
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = request(ActionOutcome::Authorized);
        let agent = req.agent_id;

        record(&sink, req).unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.action_authorized"]
        );
        assert_eq!(
            text(&sink, "agents.action_authorized", "action"),
            "DELETE /orders/1"
        );
        assert_eq!(
            text(&sink, "agents.action_authorized", "agent_id"),
            agent.to_string()
        );
        assert_eq!(
            text(&sink, "agents.action_authorized", "action_class"),
            ActionClass::Delete.as_str()
        );
    }

    /// The gateway refuses an agent's delete. The refusal is recorded with
    /// the gateway's reason, so the drift monitor sees it.
    #[test]
    fn a_refused_action_is_recorded_with_its_reason() {
        let sink = Arc::new(FakeEventDispatcher::new());
        let reason = UntrustedText::record("outside the delegation");

        record(&sink, request(ActionOutcome::Denied(reason))).unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.action_denied"]
        );
        assert_eq!(
            text(&sink, "agents.action_denied", "reason"),
            "outside the delegation"
        );
    }

    /// Failure to persist an authorized-action record returns an internal
    /// error to the caller.
    #[test]
    fn an_unwritten_record_is_an_error() {
        let recorded = block_on(RecordActionUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            request(ActionOutcome::Authorized),
        ));

        assert!(matches!(recorded, Err(AppError::Internal(_))));
    }
}
