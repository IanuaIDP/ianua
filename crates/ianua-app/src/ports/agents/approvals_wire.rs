//! What the gateway and the API say to each other about approvals.
//!
//! The gateway asks as an [`ApprovalWireRequest`], sealed like an app
//! sign-in request (a [`RequestSeal`](crate::ports::authentication::RequestSeal)
//! keyed for this channel alone, the seal in
//! [`SEAL_HEADER`](crate::ports::authentication::SEAL_HEADER), a timestamp
//! within `MAX_SKEW_SECS`
//! and a nonce used once). The API answers with an [`ApprovalWireAnswer`].

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AgentId, ApprovalId, DeclaredAction, DelegationId, HttpMethod, Nonce, TenantId,
};
use serde::{Deserialize, Serialize};

use crate::ports::agents::{GatedAction, Held, RequestOpened, Spending};

/// The protocol version this build speaks.
pub const APPROVAL_WIRE_VERSION: u8 = 1;

/// The path on the API's internal listener questions are relayed to.
pub const APPROVAL_RELAY_PATH: &str = "/internal/agent-approvals";

/// A question about an approval as the gateway sends it.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalWireRequest {
    /// The protocol version.
    pub v: u8,
    /// The tenant the agent's task token was issued for.
    pub tenant_id: TenantId,
    /// When the gateway sent it, in Unix seconds.
    pub ts: i64,
    /// A value used once, so a captured request cannot be sent again.
    pub nonce: Nonce,
    /// What the gateway asks.
    pub question: ApprovalWireQuestion,
}

/// What the gateway asks about an action.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ask", rename_all = "snake_case")]
pub enum ApprovalWireQuestion {
    /// Find or open the request a person decides for the action.
    Hold(ApprovalWireAction),
    /// Spend a person's approval of exactly the action, once.
    Spend(ApprovalWireAction),
}

/// An agent action as it travels.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalWireAction {
    /// The agent attempting it.
    pub agent_id: AgentId,
    /// The delegation it acts under.
    pub delegation_id: DelegationId,
    /// The method of the call.
    pub method: HttpMethod,
    /// The normalized path, with its query.
    pub target: String,
    /// The kind of action the route declares.
    pub declared: DeclaredAction,
}

/// What the API answers.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ApprovalWireAnswer {
    /// The action awaits a person's decision on the named request.
    AwaitingDecision {
        /// The request a person decides.
        approval_id: ApprovalId,
        /// Whether this question opened it.
        opened: ApprovalWireOpened,
    },
    /// Too many requests are open under the delegation.
    TooManyOpen,
    /// The approval of the action was spent on it.
    Spent,
    /// No approval of the action was there to spend.
    NoneGranted,
    /// The API refused the question. Why is in its own records, never
    /// on the wire.
    Refused,
}

/// Whether a question opened the request it waits on, as it travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalWireOpened {
    /// This question opened it.
    Now,
    /// An earlier one did.
    Before,
}

impl From<&GatedAction> for ApprovalWireAction {
    fn from(action: &GatedAction) -> Self {
        Self {
            agent_id: action.agent_id,
            delegation_id: action.delegation_id,
            method: action.method,
            target: action.target.clone(),
            declared: action.declared,
        }
    }
}

impl From<ApprovalWireAction> for GatedAction {
    fn from(action: ApprovalWireAction) -> Self {
        Self {
            agent_id: action.agent_id,
            delegation_id: action.delegation_id,
            method: action.method,
            target: action.target,
            declared: action.declared,
        }
    }
}

impl From<RequestOpened> for ApprovalWireOpened {
    fn from(opened: RequestOpened) -> Self {
        match opened {
            RequestOpened::Now => Self::Now,
            RequestOpened::Before => Self::Before,
        }
    }
}

impl From<ApprovalWireOpened> for RequestOpened {
    fn from(opened: ApprovalWireOpened) -> Self {
        match opened {
            ApprovalWireOpened::Now => Self::Now,
            ApprovalWireOpened::Before => Self::Before,
        }
    }
}

impl From<Held> for ApprovalWireAnswer {
    fn from(held: Held) -> Self {
        match held {
            Held::AwaitingDecision {
                approval_id,
                opened,
            } => Self::AwaitingDecision {
                approval_id,
                opened: opened.into(),
            },
            Held::TooManyOpen => Self::TooManyOpen,
        }
    }
}

impl From<Spending> for ApprovalWireAnswer {
    fn from(spending: Spending) -> Self {
        match spending {
            Spending::Spent => Self::Spent,
            Spending::NoneGranted => Self::NoneGranted,
        }
    }
}

impl ApprovalWireAnswer {
    /// The answer to a question to hold an action.
    ///
    /// # Errors
    ///
    /// - `DomainError::Forbidden` when the API refused.
    /// - `DomainError::Infrastructure` when the answer is not one to a
    ///   hold, so it is read as no answer.
    pub fn into_held(self) -> Result<Held, DomainError> {
        match self {
            Self::AwaitingDecision {
                approval_id,
                opened,
            } => Ok(Held::AwaitingDecision {
                approval_id,
                opened: opened.into(),
            }),
            Self::TooManyOpen => Ok(Held::TooManyOpen),
            Self::Refused => Err(refused()),
            Self::Spent | Self::NoneGranted => Err(unanswered()),
        }
    }

    /// The answer to a question to spend an approval.
    ///
    /// # Errors
    ///
    /// As [`into_held`](Self::into_held), for an answer not one to a spend.
    pub fn into_spending(self) -> Result<Spending, DomainError> {
        match self {
            Self::Spent => Ok(Spending::Spent),
            Self::NoneGranted => Ok(Spending::NoneGranted),
            Self::Refused => Err(refused()),
            Self::AwaitingDecision { .. } | Self::TooManyOpen => Err(unanswered()),
        }
    }
}

fn refused() -> DomainError {
    DomainError::forbidden(message!(
        "app-the-api-refused-the-approval-question",
        "the API refused the approval question"
    ))
}

fn unanswered() -> DomainError {
    DomainError::infra_msg("the API answered another approval question")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The API answers a hold with the request it opened. The gateway reads
    /// it back as that request, newly opened.
    #[test]
    fn a_hold_answer_reads_back_as_the_request() {
        let approval_id = ApprovalId::new();
        let answer = ApprovalWireAnswer::from(Held::AwaitingDecision {
            approval_id,
            opened: RequestOpened::Now,
        });

        let held = answer.into_held().unwrap();

        assert_eq!(
            held,
            Held::AwaitingDecision {
                approval_id,
                opened: RequestOpened::Now
            }
        );
    }

    /// A refused approval-spend answer decodes to a forbidden error.
    #[test]
    fn a_refused_spend_reads_as_forbidden() {
        let spending = ApprovalWireAnswer::Refused.into_spending();

        assert!(matches!(spending, Err(DomainError::Forbidden(_))));
    }

    /// Hold and spend answers cannot be interchanged: both mismatches return
    /// infrastructure errors instead of approval results.
    #[test]
    fn an_answer_to_another_question_reads_as_none() {
        let spending = ApprovalWireAnswer::TooManyOpen.into_spending();
        let held = ApprovalWireAnswer::Spent.into_held();

        assert!(matches!(spending, Err(DomainError::Infrastructure(_))));
        assert!(matches!(held, Err(DomainError::Infrastructure(_))));
    }

    /// A spend question travels as JSON tagged with what it asks, and reads
    /// back as the same action.
    #[test]
    fn a_question_reads_back_as_sent() {
        let action = GatedAction {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            method: HttpMethod::Post,
            target: "/payments?amount=10".to_owned(),
            declared: DeclaredAction::Undeclared,
        };
        let sent = serde_json::to_string(&ApprovalWireQuestion::Spend((&action).into())).unwrap();

        let read: ApprovalWireQuestion = serde_json::from_str(&sent).unwrap();

        assert!(sent.contains(r#""ask":"spend""#));
        let ApprovalWireQuestion::Spend(read) = read else {
            panic!("a spend reads back as a spend");
        };
        assert_eq!(GatedAction::from(read), action);
    }
}
