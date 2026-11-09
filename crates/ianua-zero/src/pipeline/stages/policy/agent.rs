//! The controls the gateway applies only to agents, after the access
//! decision permitted their request, and the record of each action.
//!
//! The app's `AdmitActionUseCase` decides; this enforces its answer. An
//! action it admits is recorded through `RecordActionUseCase` before it may
//! go on, and one that cannot be recorded is refused: an agent whose
//! actions go unrecorded is an agent nobody is watching. A refused action
//! is recorded too, so an agent probing past its task is seen even when
//! every probe is refused; that record is the gateway's best effort, since
//! the request is refused either way. An action waiting on a person is not
//! recorded here: holding it recorded the approval request.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::use_case::Command;
use ianua_app::use_cases::agents::enforcement::{
    ActionOutcome, Admission, AdmitActionRequest, AdmitActionUseCase, AgentRefusal, AgentRoute,
    RecordActionRequest, RecordActionUseCase, TaskLimits,
};
use ianua_domain::domains::proxy::request::context::Caller;
use ianua_domain::domains::proxy::stages::decision::{AnswerAt, ChallengeType, StageDecision};
use ianua_domain::shared::clock;
use ianua_domain::types::{AgentId, DelegationId, DenialStatus, UntrustedText};

use super::carried::carried_values;
use crate::pipeline::facts::RequestFacts;

/// One agent's request, as its controls and its record read it.
pub(super) struct AgentAction<'a> {
    facts: &'a RequestFacts,
    agent_id: AgentId,
    delegation_id: DelegationId,
    limits: TaskLimits,
}

impl<'a> AgentAction<'a> {
    /// The action `caller` makes in the request `facts` describe, when the
    /// caller is an agent.
    pub(super) fn of(caller: Option<&Caller>, facts: &'a RequestFacts) -> Option<Self> {
        let Some(Caller::Agent {
            agent_id,
            delegation_id,
            limits,
            ..
        }) = caller
        else {
            return None;
        };
        Some(Self {
            facts,
            agent_id: *agent_id,
            delegation_id: *delegation_id,
            limits: TaskLimits {
                max_data_class: limits.max_data_class,
                approval: limits.approval,
            },
        })
    }

    fn admission_request(&self) -> AdmitActionRequest {
        let route = &self.facts.route;
        AdmitActionRequest {
            agent_id: self.agent_id,
            delegation_id: self.delegation_id,
            limits: self.limits,
            route: AgentRoute {
                data_class: route.data_class(),
                reach: route.reach(),
                parameter_rules: route.parameter_rules().to_vec(),
                declared: route.action_class(),
            },
            method: self.facts.admitted.method(),
            path: self.facts.admitted.path().as_str().to_owned(),
            carried: carried_values(self.facts),
        }
    }

    fn record_request(&self, outcome: ActionOutcome) -> RecordActionRequest {
        RecordActionRequest {
            agent_id: self.agent_id,
            delegation_id: self.delegation_id,
            method: self.facts.admitted.method(),
            path: self.facts.admitted.path().as_str().to_owned(),
            declared: self.facts.route.action_class(),
            outcome,
            decided_at: clock::now(),
        }
    }
}

/// An agent's action refused: the decision enforced, and the reason its
/// record keeps.
struct Refused {
    decision: StageDecision,
    recorded: String,
}

/// The agent controls and the record of each agent action, each call held
/// to `call_timeout`.
pub(super) struct AgentControls {
    admit: Arc<AdmitActionUseCase>,
    record: RecordActionUseCase,
    call_timeout: Duration,
}

impl AgentControls {
    pub(super) fn new(admit: Arc<AdmitActionUseCase>, call_timeout: Duration) -> Self {
        Self {
            admit,
            record: RecordActionUseCase,
            call_timeout,
        }
    }

    /// The refusal of an action the access decision permitted, or `None`
    /// when it may go on: the caller is no agent, or its action was
    /// admitted and recorded.
    pub(super) async fn refusal_of_permitted(
        &self,
        action: Option<&AgentAction<'_>>,
    ) -> Option<StageDecision> {
        let action = action?;
        let refused = match self.admission(action).await {
            Some(Admission::Admitted) => return self.unrecorded(action).await,
            Some(Admission::AwaitingApproval(approval_id)) => {
                tracing::info!(%approval_id, "agent action awaits a person's approval");
                return Some(awaiting_approval());
            }
            Some(Admission::Refused(refusal)) => refused(&refusal),
            None => controls_unanswered(),
        };
        self.record_refused(Some(action), &refused.recorded).await;
        Some(refused.decision)
    }

    /// Records that an agent's action was refused for `reason`, when the
    /// caller is an agent. A record that cannot be written is logged: the
    /// action is refused either way.
    pub(super) async fn record_refused(&self, action: Option<&AgentAction<'_>>, reason: &str) {
        let Some(action) = action else {
            return;
        };
        let outcome = ActionOutcome::Denied(UntrustedText::record(reason));
        if !self.recorded(action, outcome).await {
            tracing::warn!("a refused agent action could not be recorded");
        }
    }

    /// What the agent controls answered, or `None` when they gave no
    /// answer in time or failed.
    async fn admission(&self, action: &AgentAction<'_>) -> Option<Admission> {
        let facts = action.facts;
        let asked = self
            .admit
            .execute(&facts.tenant, &facts.auditor, action.admission_request());
        match tokio::time::timeout(self.call_timeout, asked).await {
            Ok(Ok(admission)) => Some(admission),
            Ok(Err(error)) => {
                tracing::warn!(%error, "agent controls failed; refusing");
                None
            }
            Err(_) => {
                tracing::warn!("agent controls did not answer in time; refusing");
                None
            }
        }
    }

    /// The refusal of an admitted action that could not be recorded, or
    /// `None` once it is.
    async fn unrecorded(&self, action: &AgentAction<'_>) -> Option<StageDecision> {
        if self.recorded(action, ActionOutcome::Authorized).await {
            return None;
        }
        tracing::error!("an admitted agent action could not be recorded; refusing");
        Some(StageDecision::Deny {
            status: DenialStatus::SERVICE_UNAVAILABLE,
            reason: "agent_action_unrecorded".to_owned(),
        })
    }

    /// Whether the action's record was written in time.
    async fn recorded(&self, action: &AgentAction<'_>, outcome: ActionOutcome) -> bool {
        let facts = action.facts;
        let writing = self.record.execute(
            &facts.tenant,
            &facts.auditor,
            action.record_request(outcome),
        );
        matches!(
            tokio::time::timeout(self.call_timeout, writing).await,
            Ok(Ok(()))
        )
    }
}

/// Held until a person decides, then retried: the retry of exactly this
/// action spends their approval.
fn awaiting_approval() -> StageDecision {
    StageDecision::Challenge {
        challenge_type: ChallengeType::Consent,
        answer_at: AnswerAt::Retry,
        reason: "agent_approval_pending".to_owned(),
    }
}

fn refused(refusal: &AgentRefusal) -> Refused {
    let code = match refusal {
        AgentRefusal::Parameters(_) => "agent_parameters_refused",
        AgentRefusal::AboveTask => "agent_above_task",
        AgentRefusal::AboveExposure => "agent_above_exposure",
        AgentRefusal::TooManyAwaiting => "agent_too_many_awaiting",
    };
    Refused {
        decision: StageDecision::Deny {
            status: DenialStatus::FORBIDDEN,
            reason: code.to_owned(),
        },
        recorded: refusal.reason(),
    }
}

fn controls_unanswered() -> Refused {
    let reason = "agent_controls_unanswered";
    Refused {
        decision: StageDecision::Deny {
            status: DenialStatus::SERVICE_UNAVAILABLE,
            reason: reason.to_owned(),
        },
        recorded: reason.to_owned(),
    }
}
