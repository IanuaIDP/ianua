//! Policy bodies: the tenant's access policy and its versions, the steps
//! that edit a draft, the moves through its lifecycle, and a simulated
//! decision against any version.

use std::net::IpAddr;

use ianua_app::error::AppError;
use ianua_app::use_cases::authorization::policies::{
    ChangeRuleRequest, Overview, SimulateRequest, SimulatedVersion, SwitchRuleRequest, Transition,
};
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authentication::risk_engine::step_up::{Familiarity, Sensitivity};
use ianua_domain::domains::authorization::permission::CustomPermission;
use ianua_domain::domains::authorization::policy::action::PolicyAction;
use ianua_domain::domains::authorization::policy::claims::{Claim, ClaimName, ClaimValue};
use ianua_domain::domains::authorization::policy::condition::{PolicyCondition, RiskThreshold};
use ianua_domain::domains::authorization::policy::rule::PolicyRule;
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::simulator::{
    DpopProof, RuleEvaluation, SimulationInput, SimulationResult,
};
use ianua_domain::domains::authorization::policy::status::PolicyStatus;
use ianua_domain::domains::authorization::policy::time_window::{TimeOfDay, ZonedTime};
use ianua_domain::domains::authorization::policy::version::{DraftStart, PolicyVersion};
use ianua_domain::message;
use ianua_domain::types::{
    CanonicalPath, CountryCode, Enablement, Fact, GroupId, HostName, HttpMethod, Label, RoleId,
    Timezone,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// One rule in the tenant's policy, as it is read back.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyRuleResponse {
    /// What the rule is called, shown in simulation results and the audit
    /// log.
    pub name: String,
    /// Every condition must hold for the rule to fire. An empty list matches
    /// every request.
    #[schema(value_type = Vec<Object>)]
    pub conditions: Vec<PolicyCondition>,
    /// What happens when the rule fires.
    #[schema(value_type = Object)]
    pub action: PolicyAction,
    /// Lower numbers are checked first.
    pub priority: u16,
    /// A disabled rule is kept but skipped, so a rule can be taken out of
    /// service without losing how it was written.
    pub enabled: bool,
}

impl From<&PolicyRule> for PolicyRuleResponse {
    fn from(rule: &PolicyRule) -> Self {
        Self {
            name: rule.name().as_str().to_owned(),
            conditions: rule.conditions().to_vec(),
            action: rule.action().clone(),
            priority: rule.priority(),
            enabled: rule.enabled(),
        }
    }
}

/// A rule of the draft policy: one to add, or the new shape of one already
/// there. An added rule is switched on; a changed one keeps whether it was.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct NewPolicyRuleBody {
    /// What the rule is called, unique in the policy.
    pub name: String,
    /// Every condition must hold for the rule to fire. An empty list matches
    /// every request, which makes the rule's action unconditional.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub conditions: Vec<PolicyCondition>,
    /// What happens when the rule fires.
    #[schema(value_type = Object)]
    pub action: PolicyAction,
    /// Lower numbers are checked first.
    pub priority: u16,
}

impl NewPolicyRuleBody {
    /// Putting this rule in place of the draft's rule `rule_name`.
    ///
    /// # Errors
    ///
    /// A validation error when the rule cannot mean what it says.
    pub(crate) fn replacing(self, rule_name: Label) -> Result<ChangeRuleRequest, ApiError> {
        Ok(ChangeRuleRequest {
            rule_name,
            rule: self.try_into()?,
        })
    }
}

impl TryFrom<NewPolicyRuleBody> for PolicyRule {
    type Error = ApiError;

    fn try_from(body: NewPolicyRuleBody) -> Result<Self, Self::Error> {
        let name = Label::new("name", body.name).map_err(ApiError::validation)?;
        Self::new(name, body.conditions, body.action, body.priority).map_err(ApiError::validation)
    }
}

/// One version of the tenant's access policy.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyResponse {
    /// The rules, already in the order they will be checked.
    pub rules: Vec<PolicyRuleResponse>,
    /// What happens to a request no rule matched.
    #[schema(value_type = Object)]
    pub default_action: PolicyAction,
    /// `Draft`, `Review`, `Active` or `Archived`. Only a draft is edited;
    /// only an active version decides real requests.
    #[schema(schema_with = crate::dto::schemas::policy_status)]
    pub status: PolicyStatus,
    /// Whether the rules can be edited right now, so a client does not have
    /// to re-derive the lifecycle to know whether to disable its form.
    pub editable: bool,
    /// The version's number, counting from 1.
    pub version: u32,
    /// Where the version started: `blank`, `copy` of another version, or
    /// `restore` of a past one.
    pub based_on: &'static str,
    /// The version it copied or restored, absent for a blank start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub based_on_version: Option<u32>,
}

impl PolicyResponse {
    /// The version an editor works on: the open draft, or the live version
    /// when there is no draft.
    ///
    /// # Errors
    ///
    /// Not found when the tenant has neither.
    pub(crate) fn current(overview: &Overview) -> Result<Self, ApiError> {
        found(overview.draft.as_ref().or(overview.live.as_ref()))
    }

    /// The version deciding requests now.
    ///
    /// # Errors
    ///
    /// Not found when nothing is live.
    pub(crate) fn live(overview: &Overview) -> Result<Self, ApiError> {
        found(overview.live.as_ref())
    }

    /// The draft open beside the live version.
    ///
    /// # Errors
    ///
    /// Not found when no draft is open.
    pub(crate) fn draft(overview: &Overview) -> Result<Self, ApiError> {
        found(overview.draft.as_ref())
    }
}

/// `policy` on the wire, or a refusal saying there is none.
fn found(policy: Option<&PolicySet>) -> Result<PolicyResponse, ApiError> {
    policy.map(PolicyResponse::from).ok_or_else(|| {
        ApiError(AppError::NotFound(message!(
            "api-the-tenant-has-no-such-policy",
            "the tenant has no such policy version; start a draft"
        )))
    })
}

impl From<&PolicySet> for PolicyResponse {
    fn from(policy: &PolicySet) -> Self {
        Self {
            rules: policy
                .rules()
                .iter()
                .map(PolicyRuleResponse::from)
                .collect(),
            default_action: policy.default_action().clone(),
            status: policy.status(),
            editable: policy.status().is_editable(),
            version: policy.version().number(),
            based_on: policy.based_on().as_str(),
            based_on_version: policy.based_on().source().map(PolicyVersion::number),
        }
    }
}

/// Where a new draft starts.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "from", rename_all = "snake_case")]
pub(crate) enum StartPolicyDraftBody {
    /// Empty, with this fallback for requests no rule matches.
    Blank {
        /// What happens to a request no rule matched. `Deny` is the
        /// deny-by-default posture.
        #[schema(value_type = Object)]
        default_action: PolicyAction,
    },
    /// The live version's rules and fallback, as the next version.
    NextVersion,
    /// A past version's rules and fallback, brought back as the next
    /// version.
    Restore {
        /// The number of the version to bring back.
        version: u32,
    },
}

impl TryFrom<StartPolicyDraftBody> for DraftStart {
    type Error = ApiError;

    fn try_from(body: StartPolicyDraftBody) -> Result<Self, Self::Error> {
        Ok(match body {
            StartPolicyDraftBody::Blank { default_action } => Self::Blank(default_action),
            StartPolicyDraftBody::NextVersion => Self::FromLive,
            StartPolicyDraftBody::Restore { version } => Self::Restore(policy_version(version)?),
        })
    }
}

/// The version numbered `number`, or a refusal for 0.
///
/// # Errors
///
/// A validation error when `number` is 0.
pub fn policy_version(number: u32) -> Result<PolicyVersion, ApiError> {
    PolicyVersion::parse(number).map_err(ApiError::validation)
}

/// What happens to a request no rule matched.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DefaultActionBody {
    /// `Deny` refuses anything no rule allowed; `Allow` means only the rules
    /// refuse anything.
    #[schema(value_type = Object)]
    pub default_action: PolicyAction,
}

/// Whether a rule is in service.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SwitchPolicyRuleBody {
    /// `true` puts the rule in service, `false` keeps it but skips it.
    pub enabled: bool,
}

impl SwitchPolicyRuleBody {
    /// Switching the rule `rule_name` as this body says.
    #[must_use]
    pub(crate) fn request(&self, rule_name: Label) -> SwitchRuleRequest {
        SwitchRuleRequest {
            rule_name,
            enablement: Enablement::from(self.enabled),
        }
    }
}

/// The order the draft's rules are checked in.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ReorderPolicyRulesBody {
    /// Every rule of the draft by name, first checked first. Each rule is
    /// named exactly once.
    pub names: Vec<String>,
}

impl TryFrom<ReorderPolicyRulesBody> for Vec<Label> {
    type Error = ApiError;

    fn try_from(body: ReorderPolicyRulesBody) -> Result<Self, Self::Error> {
        body.names
            .into_iter()
            .map(|name| Label::new("names", name).map_err(ApiError::validation))
            .collect()
    }
}

/// Which way to move a version of the policy through its lifecycle.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyTransitionBody {
    /// The open draft to review: freezes editing while it is looked over.
    SubmitForReview,
    /// The draft in review to live, in place of the live version.
    Activate,
    /// The draft in review back to draft, for more work.
    Reject,
    /// The open draft abandoned without going live.
    AbandonDraft,
    /// The live version taken out of use. `archive` is read the same way.
    #[serde(alias = "archive")]
    TakeOutOfUse,
}

impl From<PolicyTransitionBody> for Transition {
    fn from(body: PolicyTransitionBody) -> Self {
        match body {
            PolicyTransitionBody::SubmitForReview => Self::SubmitForReview,
            PolicyTransitionBody::Activate => Self::Activate,
            PolicyTransitionBody::Reject => Self::Reject,
            PolicyTransitionBody::AbandonDraft => Self::AbandonDraft,
            PolicyTransitionBody::TakeOutOfUse => Self::TakeOutOfUse,
        }
    }
}

/// An attribute or claim the made-up caller carries.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SimulatedClaimBody {
    /// The attribute or claim name, such as `department`.
    pub name: String,
    /// Its value, such as `finance`.
    pub value: String,
}

impl TryFrom<SimulatedClaimBody> for Claim {
    type Error = ApiError;

    fn try_from(body: SimulatedClaimBody) -> Result<Self, Self::Error> {
        Ok(Self::new(
            ClaimName::new(body.name).map_err(ApiError::validation)?,
            ClaimValue::new(body.value).map_err(ApiError::validation)?,
        ))
    }
}

/// The time of day the made-up request arrived, read in one timezone.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SimulatedLocalTimeBody {
    /// The IANA timezone, such as `Europe/Berlin`.
    pub zone: String,
    /// The hour there, 0 to 23.
    pub hour: u8,
    /// The minute there, 0 to 59.
    pub minute: u8,
}

impl TryFrom<SimulatedLocalTimeBody> for ZonedTime {
    type Error = ApiError;

    fn try_from(body: SimulatedLocalTimeBody) -> Result<Self, Self::Error> {
        Ok(Self::new(
            Timezone::new(body.zone).map_err(ApiError::validation)?,
            TimeOfDay::at(body.hour, body.minute).map_err(ApiError::validation)?,
        ))
    }
}

/// A request that never happened, and the version to run it against.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SimulatePolicyBody {
    /// `live` (the default), `draft`, or a version number such as `"3"`.
    pub version: Option<String>,
    /// The request path, such as `/admin/users`. Omitted is unknown.
    pub path: Option<String>,
    /// The HTTP method, such as `GET`. Omitted is unknown.
    pub method: Option<String>,
    /// The host the request was sent to. Omitted is unknown.
    pub host: Option<String>,
    /// The address the request came from. Omitted is unknown.
    #[schema(value_type = Option<String>)]
    pub source_ip: Option<IpAddr>,
    /// The ids of the roles the subject holds.
    #[serde(default)]
    pub roles: Vec<Uuid>,
    /// The ids of the groups the subject is in.
    #[serde(default)]
    pub groups: Vec<Uuid>,
    /// The tenant's own permissions the subject holds, each as
    /// `{ "resource", "action" }`.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub permissions: Vec<CustomPermission>,
    /// The attributes and claims the subject carries.
    #[serde(default)]
    pub claims: Vec<SimulatedClaimBody>,
    /// The time of day the request arrived, in each timezone a rule reads.
    #[serde(default)]
    pub local_times: Vec<SimulatedLocalTimeBody>,
    /// The subject's country, as an ISO 3166 code. Omitted is unknown.
    pub country: Option<String>,
    /// Whether the device has been seen and trusted before.
    #[serde(default)]
    pub device_known: bool,
    /// The current risk level.
    #[schema(schema_with = crate::dto::schemas::risk_threshold)]
    pub risk: RiskThreshold,
    /// The subject's current assurance level.
    #[schema(schema_with = crate::dto::schemas::assurance_level)]
    pub current_aal: AssuranceLevel,
    /// Whether the operation is a sensitive one.
    #[serde(default)]
    pub sensitive_operation: bool,
    /// Whether the request carries a `DPoP` proof.
    #[serde(default)]
    pub has_dpop: bool,
}

impl TryFrom<SimulatePolicyBody> for SimulateRequest {
    type Error = ApiError;

    fn try_from(body: SimulatePolicyBody) -> Result<Self, Self::Error> {
        Ok(Self {
            version: simulated_version(body.version.as_deref())?,
            scenario: scenario(body)?,
        })
    }
}

/// The version `token` names: `live` when absent.
fn simulated_version(token: Option<&str>) -> Result<SimulatedVersion, ApiError> {
    match token {
        None | Some("live") => Ok(SimulatedVersion::Live),
        Some("draft") => Ok(SimulatedVersion::Draft),
        Some(number) => {
            let number = number.parse::<u32>().map_err(|_| {
                ApiError::validation(message!(
                    "api-version-must-be-live-draft-or",
                    "version must be `live`, `draft` or a version number"
                ))
            })?;
            Ok(SimulatedVersion::Numbered(policy_version(number)?))
        }
    }
}

/// The made-up request `body` describes.
fn scenario(body: SimulatePolicyBody) -> Result<SimulationInput, ApiError> {
    Ok(SimulationInput {
        path: known(body.path.map(CanonicalPath::new).transpose())?,
        method: Fact::from_option(body.method.as_deref().map(method).transpose()?),
        roles: body.roles.into_iter().map(RoleId::from_uuid).collect(),
        country: known(body.country.map(CountryCode::new).transpose())?,
        device: familiarity(body.device_known),
        risk: body.risk,
        current_aal: body.current_aal,
        sensitive_operation: sensitivity(body.sensitive_operation),
        has_dpop: DpopProof::from(body.has_dpop),
        groups: body.groups.into_iter().map(GroupId::from_uuid).collect(),
        permissions: body.permissions,
        claims: each(body.claims)?,
        source_ip: Fact::from_option(body.source_ip),
        local_times: each(body.local_times)?,
        host: known(body.host.map(HostName::new).transpose())?,
    })
}

/// Every one of `bodies` read as a `T`.
fn each<B, T: TryFrom<B, Error = ApiError>>(bodies: Vec<B>) -> Result<Vec<T>, ApiError> {
    bodies.into_iter().map(T::try_from).collect()
}

/// What the policy would do with a request that never happened.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SimulationResponse {
    /// What would happen to the request.
    #[schema(value_type = Object)]
    pub action: PolicyAction,
    /// Which rule decided it, or absent when no rule matched and the default
    /// action applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// Every rule that was checked, in order, and why each one did or did
    /// not fire.
    pub evaluated_rules: Vec<RuleEvaluationResponse>,
    /// The number of the version the request was run against.
    pub policy_version: u32,
}

/// How one rule was judged during a simulation.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RuleEvaluationResponse {
    /// The rule's name.
    pub name: String,
    /// Whether every one of its conditions held.
    pub matched: bool,
    /// The conditions that did not hold. Empty when the rule matched.
    pub failed_conditions: Vec<String>,
}

impl From<&SimulationResult> for SimulationResponse {
    fn from(result: &SimulationResult) -> Self {
        Self {
            action: result.action(),
            matched_rule: result.matched_rule().map(|name| name.as_str().to_owned()),
            evaluated_rules: result
                .evaluated_rules()
                .iter()
                .map(RuleEvaluationResponse::from)
                .collect(),
            policy_version: result.policy_version().number(),
        }
    }
}

impl From<&RuleEvaluation> for RuleEvaluationResponse {
    fn from(evaluation: &RuleEvaluation) -> Self {
        Self {
            name: evaluation.name().as_str().to_owned(),
            matched: evaluation.matched(),
            failed_conditions: evaluation.failed_conditions().to_vec(),
        }
    }
}

/// A value the caller may leave out, checked when they give it.
fn known<T, E: Into<ianua_domain::shared::errors::DomainError>>(
    parsed: Result<Option<T>, E>,
) -> Result<Fact<T>, ApiError> {
    parsed.map(Fact::from_option).map_err(ApiError::validation)
}

/// The method `token` names, or a refusal for one the proxy does not know.
fn method(token: &str) -> Result<HttpMethod, ApiError> {
    HttpMethod::parse(token).ok_or_else(|| {
        ApiError::validation(message!(
            "api-unknown-http-method",
            format!("unknown HTTP method '{token}'")
        ))
    })
}

/// Whether the device is one the person has used before.
fn familiarity(known_device: bool) -> Familiarity {
    if known_device {
        return Familiarity::Known;
    }
    Familiarity::New
}

/// Whether the request touches something sensitive.
fn sensitivity(sensitive: bool) -> Sensitivity {
    if sensitive {
        return Sensitivity::Sensitive;
    }
    Sensitivity::Ordinary
}
