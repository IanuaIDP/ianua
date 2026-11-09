//! Receiving the gateway's questions about approvals, over the API's
//! internal listener.
//!
//! The gateway never writes approvals. It seals each question with a key
//! only it and the API derive for this channel, and the API opens it here
//! and answers it through [`HoldActionUseCase`] or [`SpendUseCase`].

use std::sync::Arc;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::agents::{
    APPROVAL_WIRE_VERSION, ApprovalWireAnswer, ApprovalWireQuestion, ApprovalWireRequest,
};
use crate::ports::authentication::{NonceLedger, RequestSeal};
use crate::services::gateway_relay::{AnswerSeal, RelayReply, Relayed, opened};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::approvals::hold_action::HoldActionUseCase;
use crate::use_cases::agents::approvals::spend::SpendUseCase;

/// The ports for receiving the gateway's questions.
#[derive(ianua_macros::Fakes)]
pub struct RelayPorts {
    /// Port for checking the gateway's seal, keyed for this channel alone.
    pub seal: Arc<dyn RequestSeal>,
    /// Port for refusing a question sent twice.
    pub nonces: Arc<dyn NonceLedger>,
}

/// A question the gateway relayed, as it arrived.
pub struct RelayRequest {
    /// The request body, exactly as sealed.
    pub body: Vec<u8>,
    /// The gateway's seal over the body, if it sent one.
    pub seal: Option<String>,
}

/// Opens a sealed question from the gateway and answers it.
pub struct RelayUseCase {
    ports: RelayPorts,
    hold: Arc<HoldActionUseCase>,
    spend: Arc<SpendUseCase>,
}

impl RelayUseCase {
    /// A use case opening questions through `ports` and answering them with
    /// `hold` or `spend`.
    #[must_use]
    pub fn new(ports: RelayPorts, hold: Arc<HoldActionUseCase>, spend: Arc<SpendUseCase>) -> Self {
        Self { ports, hold, spend }
    }

    /// The answer to `request`, an opened question, in the tenant the
    /// agent's token was issued for.
    async fn answer(
        &self,
        auditor: &RequestAuditor,
        request: ApprovalWireRequest,
    ) -> Result<ApprovalWireAnswer, AppError> {
        let tenant = ScopedTenant::from_verified_credential(request.tenant_id);
        let auditor = auditor.with_tenant(request.tenant_id);
        match request.question {
            ApprovalWireQuestion::Hold(action) => {
                let held = self.hold.execute(&tenant, &auditor, action.into()).await?;
                Ok(held.into())
            }
            ApprovalWireQuestion::Spend(action) => {
                let spending = self.spend.execute(&tenant, &auditor, action.into()).await?;
                Ok(spending.into())
            }
        }
    }
}

impl Command for RelayUseCase {
    type Caller = ();
    type Input = RelayRequest;
    type Output = RelayReply<ApprovalWireAnswer>;

    /// Checks that the question came from the gateway, recently and once,
    /// answers it in the tenant the agent's token was issued for, and hands
    /// back the seal binding the answer to the question.
    ///
    /// The answer is an error when:
    ///
    /// - `AppError::Unauthenticated`: the seal is missing or wrong, the
    ///   question is stale or was seen before, or it cannot be read. The
    ///   reply then carries no seal.
    /// - Anything [`HoldActionUseCase`] or [`SpendUseCase`] reports. The
    ///   listener answers every error as [`ApprovalWireAnswer::Refused`],
    ///   and the gateway refuses the action.
    async fn execute(
        &self,
        _: &(),
        auditor: &RequestAuditor,
        request: RelayRequest,
    ) -> RelayReply<ApprovalWireAnswer> {
        let RelayRequest { body, seal } = request;
        let relayed = Relayed {
            body: &body,
            seal: seal.as_deref(),
        };
        let request: ApprovalWireRequest = match opened(
            self.ports.seal.as_ref(),
            self.ports.nonces.as_ref(),
            relayed,
            APPROVAL_WIRE_VERSION,
        )
        .await
        {
            Ok(request) => request,
            Err(refused) => return RelayReply::unopened(refused),
        };
        let seal = AnswerSeal::new(request.nonce.clone(), self.ports.seal.clone());
        RelayReply {
            answer: self.answer(auditor, request).await,
            seal: Some(seal),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::delegation::Delegation;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{AgentId, DeclaredAction, DelegationId, HttpMethod, Nonce, Seconds};

    use super::*;
    use crate::ports::agents::{ApprovalWireAction, DelegationStore as _};
    use crate::test_support::agents::{FakeDelegationStore, delegation_row, someone};
    use crate::test_support::authentication::TagSeal;
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::agents::approvals::hold_action::{GatePolicy, HoldActionPorts};
    use crate::use_cases::agents::approvals::spend::SpendPorts;

    const POLICY: GatePolicy = GatePolicy {
        decision_window: Seconds::new(900),
        max_open_per_delegation: 20,
    };

    fn relay() -> RelayUseCase {
        relay_holding(HoldActionPorts::fakes())
    }

    /// A relay whose holds work through `hold`.
    fn relay_holding(hold: HoldActionPorts) -> RelayUseCase {
        RelayUseCase::new(
            RelayPorts::fakes(),
            Arc::new(HoldActionUseCase::new(POLICY, hold)),
            Arc::new(SpendUseCase::new(SpendPorts::fakes())),
        )
    }

    /// A payment by `agent_id` under `delegation_id`, as the gateway asks.
    fn payment(agent_id: AgentId, delegation_id: DelegationId) -> ApprovalWireAction {
        ApprovalWireAction {
            agent_id,
            delegation_id,
            method: HttpMethod::Post,
            target: "/payments".to_owned(),
            declared: DeclaredAction::Undeclared,
        }
    }

    /// `question`, as the gateway sends it for the test tenant.
    fn sent(question: ApprovalWireQuestion) -> Vec<u8> {
        let request = ApprovalWireRequest {
            v: APPROVAL_WIRE_VERSION,
            tenant_id: test_ctx().tenant_id(),
            ts: clock::now().unix_timestamp(),
            nonce: Nonce::new("relay-nonce-of-length").unwrap(),
            question,
        };
        serde_json::to_vec(&request).unwrap()
    }

    fn spend_question() -> Vec<u8> {
        sent(ApprovalWireQuestion::Spend(payment(
            AgentId::new(),
            DelegationId::new(),
        )))
    }

    fn reply(
        relay: &RelayUseCase,
        body: Vec<u8>,
        seal: Option<String>,
    ) -> RelayReply<ApprovalWireAnswer> {
        block_on(relay.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            RelayRequest { body, seal },
        ))
    }

    fn answer(
        relay: &RelayUseCase,
        body: Vec<u8>,
        seal: Option<String>,
    ) -> Result<ApprovalWireAnswer, AppError> {
        reply(relay, body, seal).answer
    }

    /// A spend question without the gateway's seal fails authentication.
    #[test]
    fn an_unsealed_question_is_refused() {
        let relay = relay();

        let answered = answer(&relay, spend_question(), None);

        assert!(matches!(answered, Err(AppError::Unauthenticated)));
    }

    /// A question with an invalid seal receives an unsealed reply.
    #[test]
    fn an_unopened_question_gets_no_seal() {
        let relay = relay();

        let replied = reply(&relay, spend_question(), Some("tag:0".to_owned()));

        assert!(replied.seal.is_none());
    }

    /// The gateway's sealed question is answered, and the answer's seal is
    /// bound to that question's nonce.
    #[test]
    fn the_answer_is_sealed_for_its_question() {
        let relay = relay();
        let body = spend_question();
        let seal = TagSeal.seal(&body);

        let replied = reply(&relay, body, Some(seal));

        let sealed = replied.seal.unwrap().seal(b"{}");
        let nonce = Nonce::new("relay-nonce-of-length").unwrap();
        assert!(TagSeal.verifies_answer(&nonce, b"{}", &sealed));
    }

    /// A correctly sealed spend question naming an unknown delegation
    /// returns a missing-delegation error.
    #[test]
    fn a_sealed_question_is_answered_by_the_spend() {
        let relay = relay();
        let body = spend_question();
        let seal = TagSeal.seal(&body);

        let answered = answer(&relay, body, Some(seal));

        assert!(matches!(answered, Err(AppError::NotFound(_))));
    }

    /// A correctly sealed hold question is refused when the plan enforcer
    /// rejects another approval request.
    #[test]
    fn relay_rejects_a_hold_when_plan_limit_reached() {
        let agent_id = AgentId::new();
        let delegation = Delegation::reconstitute(delegation_row(
            agent_id,
            someone("ann@corp.test").principal(),
        ))
        .unwrap();
        let delegations = Arc::new(FakeDelegationStore::empty());
        block_on(delegations.save(&test_ctx().tenant(), &delegation)).unwrap();
        let relay = relay_holding(HoldActionPorts {
            delegation_store: delegations,
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..HoldActionPorts::fakes()
        });
        let body = sent(ApprovalWireQuestion::Hold(payment(
            agent_id,
            *delegation.id(),
        )));
        let seal = TagSeal.seal(&body);

        let answered = answer(&relay, body, Some(seal));

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
    }
}
