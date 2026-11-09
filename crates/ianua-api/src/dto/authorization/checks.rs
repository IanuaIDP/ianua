//! Access check bodies: an app's question whether someone may do an action
//! on a resource type or one object of it, the answer with its reason, and
//! the record kept of every authorization decision.

use ianua_app::error::AppError;
use ianua_app::ports::authorization::{DecisionBasis, DecisionRecord, MatchedRule};
use ianua_app::use_cases::authorization::checks::CheckAccessRequest;
use ianua_domain::domains::authorization::access_check::{
    AccessDecision, AccessQuestion, AllowedBy, CheckTarget,
};
use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::authorization::policy::action::PolicyAction;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dto::agents::principal::OwnerDto;
use crate::dto::authorization::relationships::{ObjectBody, object_ref};
use crate::error::ApiError;

/// One question: may the subject do `action` on `resource_type`, or on the
/// object of it keyed `object_key`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AccessQuestionBody {
    /// The action, such as `read`.
    pub action: String,
    /// The declared resource type, such as `document`.
    pub resource_type: String,
    /// The object's key in the app. Left out, the question is about any
    /// object of the type: whether the subject holds the permission itself.
    pub object_key: Option<String>,
}

impl TryFrom<AccessQuestionBody> for AccessQuestion {
    type Error = ApiError;

    fn try_from(body: AccessQuestionBody) -> Result<Self, Self::Error> {
        let action = PermissionSegment::new("action", body.action).map_err(ApiError::validation)?;
        let Some(key) = body.object_key else {
            let resource_type = PermissionSegment::new("resource_type", body.resource_type)
                .map_err(ApiError::validation)?;
            return Ok(Self::new(action, CheckTarget::AnyOf(resource_type)));
        };
        let object = object_ref(&body.resource_type, &key)?;
        Ok(Self::new(action, CheckTarget::Object(object)))
    }
}

/// A single access check.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CheckAccessBody {
    /// The person, agent or app asked about.
    pub subject: OwnerDto,
    /// The action and resource the subject wants to access.
    #[serde(flatten)]
    pub question: AccessQuestionBody,
}

impl TryFrom<CheckAccessBody> for CheckAccessRequest {
    type Error = ApiError;

    fn try_from(body: CheckAccessBody) -> Result<Self, Self::Error> {
        Ok(Self {
            subject: body.subject.to_principal(),
            questions: vec![body.question.try_into()?],
        })
    }
}

/// Several access checks about one subject, answered in the order asked.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct BatchCheckAccessBody {
    /// The person, agent or app asked about.
    pub subject: OwnerDto,
    /// The questions, at most 100.
    pub checks: Vec<AccessQuestionBody>,
}

impl TryFrom<BatchCheckAccessBody> for CheckAccessRequest {
    type Error = ApiError;

    fn try_from(body: BatchCheckAccessBody) -> Result<Self, Self::Error> {
        Ok(Self {
            subject: body.subject.to_principal(),
            questions: body
                .checks
                .into_iter()
                .map(AccessQuestion::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

/// What let a request through.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AllowedByResponse {
    /// An app permission the subject holds, such as `document:read`.
    Permission(String),
    /// A relation the subject holds on the object, or on an object above
    /// it.
    Relation {
        /// The object the relation is held on.
        object: ObjectBody,
        /// The relation, such as `editor`.
        relation: String,
    },
}

impl From<&AllowedBy> for AllowedByResponse {
    fn from(allowed: &AllowedBy) -> Self {
        match allowed {
            AllowedBy::Permission(permission) => Self::Permission(permission.to_string()),
            AllowedBy::Relation { object, relation } => Self::Relation {
                object: object.into(),
                relation: relation.as_str().to_owned(),
            },
        }
    }
}

/// The answer to one access check.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub(crate) enum AccessDecisionResponse {
    /// The subject may.
    Allowed {
        /// What let it through.
        by: AllowedByResponse,
    },
    /// The subject may not.
    Denied {
        /// `unknown_resource_type`, `undeclared_action`, `not_held` or
        /// `too_deep`.
        reason: &'static str,
    },
}

impl From<&AccessDecision> for AccessDecisionResponse {
    fn from(decision: &AccessDecision) -> Self {
        match decision {
            AccessDecision::Allowed(by) => Self::Allowed { by: by.into() },
            AccessDecision::Denied(because) => Self::Denied {
                reason: because.as_str(),
            },
        }
    }
}

impl AccessDecisionResponse {
    /// The one answer a single check gets.
    ///
    /// # Errors
    ///
    /// An internal error when the app answered nothing, which it never
    /// does for one question.
    pub(crate) fn only(decisions: &[AccessDecision]) -> Result<Self, ApiError> {
        decisions
            .first()
            .map(Self::from)
            .ok_or_else(|| ApiError(AppError::internal_msg("an access check answered nothing")))
    }
}

/// The answers to a batch of access checks, in the order asked.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct BatchAccessDecisionResponse {
    /// One answer per question.
    pub decisions: Vec<AccessDecisionResponse>,
}

impl From<&[AccessDecision]> for BatchAccessDecisionResponse {
    fn from(decisions: &[AccessDecision]) -> Self {
        Self {
            decisions: decisions.iter().map(AccessDecisionResponse::from).collect(),
        }
    }
}

/// What a recorded decision was about and what decided it.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum DecisionBasisResponse {
    /// An app asked through the access check.
    AppCheck {
        /// The action asked about.
        action: String,
        /// The resource type asked about.
        resource_type: String,
        /// The object asked about, absent for a question about any object.
        #[serde(skip_serializing_if = "Option::is_none")]
        object_key: Option<String>,
        /// The answer given.
        answer: AccessDecisionResponse,
    },
    /// The tenant's policy decided a request at the gateway.
    Policy {
        /// The number of the policy version that decided.
        version: u32,
        /// The rule that decided, absent when the default action did.
        #[serde(skip_serializing_if = "Option::is_none")]
        matched_rule: Option<String>,
        /// What the policy did.
        #[schema(value_type = Object)]
        action: PolicyAction,
    },
}

impl From<&DecisionBasis> for DecisionBasisResponse {
    fn from(basis: &DecisionBasis) -> Self {
        match basis {
            DecisionBasis::AppCheck { question, decision } => Self::AppCheck {
                action: question.action().as_str().to_owned(),
                resource_type: question.target().resource_type().as_str().to_owned(),
                object_key: object_key(question.target()),
                answer: decision.into(),
            },
            DecisionBasis::Policy {
                version,
                matched,
                action,
            } => Self::Policy {
                version: version.number(),
                matched_rule: rule_name(matched),
                action: action.clone(),
            },
        }
    }
}

/// The key of the object `target` names, if it names one.
fn object_key(target: &CheckTarget) -> Option<String> {
    match target {
        CheckTarget::AnyOf(_) => None,
        CheckTarget::Object(object) => Some(object.key().as_str().to_owned()),
    }
}

/// The name of the rule that matched, if a rule did.
fn rule_name(matched: &MatchedRule) -> Option<String> {
    match matched {
        MatchedRule::Rule(name) => Some(name.as_str().to_owned()),
        MatchedRule::Default => None,
    }
}

/// One recorded authorization decision.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DecisionRecordResponse {
    /// Who asked: the app's caller, or the gateway, as an audit label.
    pub asked_by: String,
    /// Whom the decision was about.
    pub subject: OwnerDto,
    /// `allowed`, `denied` or `challenged`.
    pub verdict: &'static str,
    /// What it was about and what decided it.
    pub basis: DecisionBasisResponse,
    /// When it was decided.
    #[serde(with = "time::serde::rfc3339")]
    pub decided_at: OffsetDateTime,
}

impl From<&DecisionRecord> for DecisionRecordResponse {
    fn from(record: &DecisionRecord) -> Self {
        Self {
            asked_by: record.asked_by.audit_label(),
            subject: OwnerDto::from_principal(&record.subject),
            verdict: record.verdict().as_str(),
            basis: (&record.basis).into(),
            decided_at: record.decided_at,
        }
    }
}
