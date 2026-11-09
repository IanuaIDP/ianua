//! Delegation bodies: granting authority to an agent, passing part of it
//! on, the resources it covers, and reading it back.

use std::collections::{BTreeMap, HashSet};

use ianua_app::use_cases::agents::credentials::ExchangedToken;
use ianua_app::use_cases::agents::delegation::{
    AgentEffectiveCapabilities, AttenuateRequest, DescribedDelegation, GrantDelegationRequest,
    GrantResourceRequest, GrantedDelegation, IntentGrant, RequestRequest, ResourceGrantRequest,
    RevokeResourceRequest,
};
use ianua_domain::domains::agents::authority::capability::{
    AppAccess, AppReach, DelegationConstraints, ResourceScope, TaskBinding,
};
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::agents::authority::delegation_request::{
    DelegationReason, DelegationRequest, RequestState,
};
use ianua_domain::domains::agents::authority::intent::{
    DriftPolicy, DriftThreshold, IntentBinding, IntentStatement,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{
    AgentId, DelegationId, Label, PrincipalRef, Seconds, ServiceId, TaskTemplateId,
};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::capabilities::{BudgetDto, CapabilitySetDto, ResourceCapabilityDto};
use crate::dto::agents::principal::OwnerDto;
use crate::error::ApiError;

/// How to react when an agent's actions drift from the bound intent.
#[derive(Clone, Copy, Deserialize, Serialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DriftModeDto {
    /// No drift monitoring.
    Off,
    /// Record a drift event on breach, but keep the agent running.
    Warn,
    /// Refuse off-purpose actions in the request path, record a drift event
    /// and suspend the agent on breach. The default: an intent that is only
    /// watched lets every off-purpose action through first.
    #[default]
    Enforce,
}

/// An intent to bind to a delegation for drift monitoring.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct IntentGrantDto {
    /// The declared natural-language intent the token is for.
    pub statement: String,
    /// How drift from the intent is handled; `enforce` when left out.
    #[serde(default)]
    pub mode: DriftModeDto,
    /// Drift tolerance in basis points (`0` to `10000`) for `warn` and
    /// `enforce`; 2000 when left out.
    #[serde(default)]
    pub threshold_basis_points: Option<u16>,
}

impl IntentGrantDto {
    /// The intent named.
    ///
    /// # Errors
    ///
    /// - A validation error for an empty statement or a threshold out of
    ///   range.
    pub(crate) fn to_domain(&self) -> Result<IntentGrant, ApiError> {
        let statement =
            IntentStatement::new(self.statement.as_str()).map_err(ApiError::validation)?;
        let drift_policy = match self.mode {
            DriftModeDto::Off => DriftPolicy::Off,
            DriftModeDto::Warn => DriftPolicy::Warn(self.threshold()?),
            DriftModeDto::Enforce => DriftPolicy::Enforce(self.threshold()?),
        };
        Ok(IntentGrant {
            statement,
            drift_policy,
        })
    }

    /// How far a run may drift from its intent: the default unless the
    /// body names one, refused when the named one is out of range.
    fn threshold(&self) -> Result<DriftThreshold, ApiError> {
        self.threshold_basis_points
            .map_or(
                Ok(DriftThreshold::DEFAULT),
                DriftThreshold::from_basis_points,
            )
            .map_err(ApiError::validation)
    }
}

/// The limits a delegation is held to: its lifetime and depth, and every
/// option that narrows it further.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DelegationLimitsDto {
    /// Token lifetime in seconds.
    pub ttl_seconds: u32,
    /// Maximum sub-delegation depth.
    #[serde(default)]
    pub max_depth: u8,
    /// Optional task binding.
    #[serde(default)]
    pub task: Option<String>,
    /// Whether actions under this delegation pause for a person's approval.
    #[serde(default)]
    pub requires_approval: bool,
    /// Optional request budget: caps how many times the token may be used.
    #[serde(default)]
    pub budget: Option<BudgetDto>,
    /// Optional resource scope: URL path prefixes the token is confined to
    /// (e.g. `["/accounts/4821"]`).
    #[serde(default)]
    pub resource_scope: Option<Vec<String>>,
    /// The apps (service ids) the agent may call through the gateway. The
    /// token names each one's audience; without any, the agent reaches no
    /// app that requires sign-in.
    #[serde(default)]
    pub apps: Option<Vec<Uuid>>,
    /// Sender-constrain the token (DPoP): the proxy requires a proof of
    /// possession of the agent's credential key on every request.
    #[serde(default)]
    pub sender_constrained: bool,
}

impl DelegationLimitsDto {
    /// The delegation's limits: its lifetime and depth, and every option
    /// the body sets.
    ///
    /// # Errors
    ///
    /// - A validation error for a lifetime, depth, task, app, budget or
    ///   path prefix out of range or not valid.
    pub(crate) fn constraints(&self) -> Result<DelegationConstraints, ApiError> {
        let mut constraints = bounded(self.ttl_seconds, self.max_depth, self.task.as_deref())?;
        if let Some(apps) = app_reach(self.apps.as_deref())? {
            constraints = constraints.with_apps(apps);
        }
        if let Some(budget) = &self.budget {
            constraints = constraints.with_budget(budget.to_domain()?);
        }
        if let Some(prefixes) = &self.resource_scope {
            constraints = constraints.with_resource_scope(
                ResourceScope::new(prefixes.clone()).map_err(ApiError::validation)?,
            );
        }
        if self.requires_approval {
            constraints = constraints.requiring_approval();
        }
        if self.sender_constrained {
            constraints = constraints.sender_constrained();
        }
        Ok(constraints)
    }
}

/// The fields an agents body was sent that it does not know.
///
/// A body holding its limits flattened cannot refuse unknown fields through
/// serde, so they are gathered here and refused by name, as a problem the
/// caller can read. Ann sends `requires_aproval: true`. Without this, the
/// misspelt limit is dropped and her agent acts with no approval at all.
#[derive(Default, Deserialize)]
#[serde(transparent)]
pub(crate) struct UnknownFields(BTreeMap<String, IgnoredAny>);

impl UnknownFields {
    /// Refuses a body that was sent any field it does not know.
    ///
    /// # Errors
    ///
    /// - A validation error naming the first unknown field.
    pub(crate) fn ensure_none(&self) -> Result<(), ApiError> {
        let Some(name) = self.0.keys().next() else {
            return Ok(());
        };
        Err(ApiError::validation(message!(
            "api-unknown-field",
            format!("unknown field `{name}`")
        )))
    }
}

/// Request body for granting a delegation to an agent.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct GrantDelegationBody {
    /// Capabilities to grant, held to what the caller holds.
    pub granted: CapabilitySetDto,
    /// The lifetime, depth and options the delegation is held to.
    #[serde(flatten)]
    pub limits: DelegationLimitsDto,
    /// Optional intent, compiled and bound for drift monitoring.
    #[serde(default)]
    pub intent: Option<IntentGrantDto>,
    /// Optional title people see, such as `Q1 reconciliation delegation`.
    #[serde(default)]
    pub name: Option<String>,
    /// An approved task template the delegation must fit inside. The grant
    /// is narrowed to its ceiling; a lifetime, path, budget, data class or
    /// intent looser than the template's is refused (`403`).
    #[serde(default)]
    pub template_id: Option<Uuid>,
    /// Fields the body does not know, refused.
    #[serde(flatten)]
    #[schema(ignore)]
    pub unknown: UnknownFields,
}

impl GrantDelegationBody {
    /// The grant to `delegate` this body asks for.
    ///
    /// # Errors
    ///
    /// - A validation error for an unknown field, or any field out of range
    ///   or not valid.
    pub(crate) fn into_request(
        self,
        delegate: AgentId,
    ) -> Result<GrantDelegationRequest, ApiError> {
        self.unknown.ensure_none()?;
        Ok(GrantDelegationRequest {
            delegate,
            granted: self.granted.to_domain()?,
            constraints: self.limits.constraints()?,
            intent: self
                .intent
                .as_ref()
                .map(IntentGrantDto::to_domain)
                .transpose()?,
            name: title(self.name)?,
            template: self.template_id.map(TaskTemplateId::from_uuid),
        })
    }
}

/// Request body for an agent asking a person for a delegation, signed in as
/// itself.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RequestDelegationBody {
    /// The person asked: a tenant user or an organization member, who would
    /// grant the delegation.
    pub asked_of: OwnerDto,
    /// The capabilities the agent asks for.
    pub granted: CapabilitySetDto,
    /// The lifetime, depth and options the agent asks to be held to.
    #[serde(flatten)]
    pub limits: DelegationLimitsDto,
    /// Why it asks, in its own words, shown to the person asked.
    pub reason: String,
    /// Fields the body does not know, refused.
    #[serde(flatten)]
    #[schema(ignore)]
    pub unknown: UnknownFields,
}

impl TryFrom<RequestDelegationBody> for RequestRequest {
    type Error = ApiError;

    fn try_from(body: RequestDelegationBody) -> Result<Self, Self::Error> {
        body.unknown.ensure_none()?;
        Ok(Self {
            asked_of: body.asked_of.to_principal(),
            granted: body.granted.to_domain()?,
            constraints: body.limits.constraints()?,
            reason: DelegationReason::new(body.reason).map_err(ApiError::validation)?,
        })
    }
}

/// Where a request for a delegation stands.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DelegationRequestResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The agent asking.
    pub agent_id: Uuid,
    /// The person asked.
    pub asked_of: OwnerDto,
    /// The capabilities asked for.
    pub granted: CapabilitySetDto,
    /// The lifetime asked for, in seconds.
    pub ttl_seconds: u32,
    /// The sub-delegation depth asked for.
    pub max_depth: u8,
    /// Why the agent asks, in its own words. The agent wrote it: show it as
    /// text, never as markup.
    pub reason: String,
    /// `pending`, `approved` or `denied`.
    pub status: String,
    /// The delegation it became, once approved.
    pub delegation_id: Option<Uuid>,
    /// When it was answered, once it was.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub decided_at: Option<OffsetDateTime>,
    /// When a request still pending lapses unanswered.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl From<&DelegationRequest<ResolvedTenant>> for DelegationRequestResponse {
    fn from(request: &DelegationRequest<ResolvedTenant>) -> Self {
        let state = request.state();
        let (status, delegation_id) = match state {
            RequestState::Pending => ("pending", None),
            RequestState::Approved { delegation_id, .. } => {
                ("approved", Some(*delegation_id.as_uuid()))
            }
            RequestState::Denied { .. } => ("denied", None),
        };
        let constraints = request.constraints();
        Self {
            id: *request.id().as_uuid(),
            agent_id: *request.agent_id().as_uuid(),
            asked_of: OwnerDto::from_human(request.asked_of()),
            granted: CapabilitySetDto::from(request.granted()),
            ttl_seconds: constraints.ttl_seconds().get(),
            max_depth: constraints.max_depth(),
            reason: request.reason().as_str().to_owned(),
            status: status.to_owned(),
            delegation_id,
            decided_at: state.decided_at(),
            expires_at: request.expires_at(),
        }
    }
}

/// Request body for passing part of a delegation on to another agent.
///
/// The child is held inside its parent on every limit: a lifetime ending
/// no later than the parent's, a depth no higher, some of the parent's apps
/// (none when left out), a budget that fits beside the other children's in
/// the parent's, paths inside the parent's, and the parent's task, approval
/// rule and key binding. A budget or path scope left out takes the
/// parent's own; a limit wider than the parent's is refused (`403`).
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AttenuateDelegationBody {
    /// The agent receiving the child delegation.
    pub delegate: Uuid,
    /// Capabilities to grant, all granted by the parent.
    pub granted: CapabilitySetDto,
    /// The lifetime, depth and options the child is held to, inside the
    /// parent's.
    #[serde(flatten)]
    pub limits: DelegationLimitsDto,
    /// Optional title people see for the child.
    #[serde(default)]
    pub name: Option<String>,
    /// Fields the body does not know, refused.
    #[serde(flatten)]
    #[schema(ignore)]
    pub unknown: UnknownFields,
}

impl AttenuateDelegationBody {
    /// The child of `parent_id`, held by `agent_id`, this body asks for.
    ///
    /// # Errors
    ///
    /// - A validation error for an unknown field, or any field out of range
    ///   or not valid.
    pub(crate) fn into_request(
        self,
        agent_id: AgentId,
        parent_id: DelegationId,
    ) -> Result<AttenuateRequest, ApiError> {
        self.unknown.ensure_none()?;
        Ok(AttenuateRequest {
            agent_id,
            parent_id,
            delegate: AgentId::from_uuid(self.delegate),
            granted: self.granted.to_domain()?,
            constraints: self.limits.constraints()?,
            name: title(self.name)?,
        })
    }
}

/// A lifetime, a depth and an optional task binding.
fn bounded(
    ttl_seconds: u32,
    max_depth: u8,
    task: Option<&str>,
) -> Result<DelegationConstraints, ApiError> {
    let constraints = DelegationConstraints::new(Seconds::new(ttl_seconds), max_depth)
        .map_err(ApiError::validation)?;
    let Some(task) = task else {
        return Ok(constraints);
    };
    Ok(constraints.with_task(TaskBinding::new(task).map_err(ApiError::validation)?))
}

/// The apps a delegation reaches, if it names any.
fn app_reach(apps: Option<&[Uuid]>) -> Result<Option<AppReach>, ApiError> {
    apps.map(|apps| AppReach::new(apps.iter().copied().map(ServiceId::from_uuid)))
        .transpose()
        .map_err(ApiError::validation)
}

/// The title people see, if one was given.
fn title(name: Option<String>) -> Result<Option<Label>, ApiError> {
    name.map(|n| Label::new("name", n))
        .transpose()
        .map_err(ApiError::validation)
}

/// A delegation granted or minted, and the task token signed for it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct GrantDelegationResponse {
    /// The delegation's unique identifier.
    pub delegation_id: Uuid,
    /// The signed task token the agent presents to the proxy.
    pub task_token: String,
    /// The capabilities actually granted.
    pub granted: CapabilitySetDto,
    /// The principals this delegation acts for, nearest first.
    ///
    /// A root delegation has one entry: whoever granted it. A
    /// sub-delegation runs from the agent that handed the authority on,
    /// through every agent between, to the principal at the root.
    pub on_behalf_of: Vec<OwnerDto>,
    /// When the delegation expires.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// The title people see, if one was set.
    pub name: Option<String>,
}

impl GrantDelegationResponse {
    /// The answer to a grant: the new delegation, the task token the agent
    /// uses, and everyone it acts for back to the root.
    fn of(
        delegation: &Delegation<ResolvedTenant>,
        task_token: String,
        chain: &[PrincipalRef],
    ) -> Self {
        Self {
            delegation_id: *delegation.id().as_uuid(),
            task_token,
            granted: CapabilitySetDto::from(delegation.granted()),
            on_behalf_of: chain.iter().map(OwnerDto::from_principal).collect(),
            expires_at: delegation.expires_at(),
            name: delegation.name().map(|n| n.as_str().to_owned()),
        }
    }
}

impl From<GrantedDelegation> for GrantDelegationResponse {
    fn from(granted: GrantedDelegation) -> Self {
        Self::of(&granted.delegation, granted.task_token, &granted.chain)
    }
}

impl From<ExchangedToken> for GrantDelegationResponse {
    fn from(exchanged: ExchangedToken) -> Self {
        Self::of(
            &exchanged.delegation,
            exchanged.task_token,
            &exchanged.chain,
        )
    }
}

/// The intent bound to a delegation, for drift monitoring.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct IntentSummaryDto {
    /// Drift-handling mode: `off`, `warn`, or `enforce`.
    pub mode: String,
    /// The declared natural-language intent the token is for.
    pub statement: String,
    /// Drift tolerance in basis points (`0` to `10000`), when monitored.
    pub threshold_basis_points: Option<u16>,
}

impl From<&IntentBinding> for IntentSummaryDto {
    fn from(binding: &IntentBinding) -> Self {
        let (mode, threshold_basis_points) = match binding.drift_policy() {
            DriftPolicy::Off => ("off", None),
            DriftPolicy::Warn(t) => ("warn", Some(t.basis_points())),
            DriftPolicy::Enforce(t) => ("enforce", Some(t.basis_points())),
        };
        Self {
            mode: mode.to_owned(),
            statement: binding.statement().as_str().to_owned(),
            threshold_basis_points,
        }
    }
}

/// The authority granted to an agent, including its limits and chain position.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DelegationResponse {
    /// Unique identifier.
    pub delegation_id: Uuid,
    /// The delegating principal.
    pub delegator: OwnerDto,
    /// The agent holding it.
    pub delegate: Uuid,
    /// The parent delegation, for a sub-delegation.
    pub parent: Option<Uuid>,
    /// This delegation's own distance from the root of its chain (`0` for a
    /// root delegation), not the ceiling `max_depth` still allows below it.
    pub depth: u8,
    /// The granted capabilities.
    pub granted: CapabilitySetDto,
    /// Maximum sub-delegation depth this authority may travel.
    pub max_depth: u8,
    /// Whether actions under this delegation pause for a person's approval.
    pub requires_approval: bool,
    /// The task the token is bound to, if any.
    pub task: Option<String>,
    /// The bound intent and drift policy, if any.
    pub intent: Option<IntentSummaryDto>,
    /// The request budget, if any.
    pub budget: Option<BudgetDto>,
    /// The URL path prefixes the token is confined to, if any.
    pub resource_scope: Option<Vec<String>>,
    /// The apps (service ids) the agent may call through the gateway, if
    /// any.
    pub apps: Option<Vec<Uuid>>,
    /// Whether the token is sender-constrained (DPoP).
    pub sender_constrained: bool,
    /// When the delegation expires.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// When it was last renewed, or `null` if it never was.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub renewed_at: Option<OffsetDateTime>,
    /// Whether it has been revoked.
    pub revoked: bool,
    /// The title people see, if one was set.
    pub name: Option<String>,
}

impl From<Delegation<ResolvedTenant>> for DelegationResponse {
    fn from(d: Delegation<ResolvedTenant>) -> Self {
        let constraints = d.constraints();
        Self {
            delegation_id: *d.id().as_uuid(),
            delegator: OwnerDto::from_principal(d.delegator()),
            delegate: *d.delegate().as_uuid(),
            parent: d.parent().map(|p| *p.as_uuid()),
            depth: d.depth(),
            granted: CapabilitySetDto::from(d.granted()),
            max_depth: constraints.max_depth(),
            requires_approval: constraints.requires_approval(),
            task: constraints.task().map(|t| t.as_str().to_owned()),
            intent: constraints.intent().limit().map(IntentSummaryDto::from),
            budget: constraints.budget().limit().and_then(BudgetDto::of),
            resource_scope: constraints.resource_scope().limit().map(resource_prefixes),
            apps: match constraints.apps() {
                AppAccess::Listed(reach) => {
                    Some(reach.services().iter().map(|id| *id.as_uuid()).collect())
                }
                AppAccess::NoApps => None,
            },
            sender_constrained: constraints.is_sender_constrained(),
            expires_at: d.expires_at(),
            renewed_at: d.renewed().at(),
            revoked: d.is_revoked(),
            name: d.name().map(|n| n.as_str().to_owned()),
        }
    }
}

/// Every allowed path prefix in the order the delegation records it.
fn resource_prefixes(scope: &ResourceScope) -> Vec<String> {
    scope
        .prefixes()
        .iter()
        .map(|prefix| prefix.as_str().to_owned())
        .collect()
}

impl From<DescribedDelegation> for DelegationResponse {
    fn from(described: DescribedDelegation) -> Self {
        let mut response = Self::from(described.delegation);
        response.delegator.display_name = described.delegator_name;
        response.budget = response
            .budget
            .map(|budget| budget.used(described.used_requests));
        response
    }
}

/// What containing an agent would sever.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct BlastRadiusResponse {
    /// The agent at the root of the blast radius.
    pub agent_id: Uuid,
    /// How many delegations containment would revoke.
    pub delegation_count: u32,
    /// Distinct agents reachable through this agent's delegations.
    pub agent_count: u32,
    /// Every delegation in the radius: the roots the agent holds, each
    /// followed by its descendants.
    pub delegations: Vec<DelegationResponse>,
}

impl BlastRadiusResponse {
    /// The radius of `agent_id`: `delegations`, and how many there are and
    /// how many agents hold them.
    #[must_use]
    pub(crate) fn of(agent_id: AgentId, delegations: Vec<DescribedDelegation>) -> Self {
        let agents: HashSet<Uuid> = delegations
            .iter()
            .map(|d| *d.delegation.delegate().as_uuid())
            .collect();
        Self {
            agent_id: *agent_id.as_uuid(),
            delegation_count: count(delegations.len()),
            agent_count: count(agents.len()),
            delegations: delegations
                .into_iter()
                .map(DelegationResponse::from)
                .collect(),
        }
    }
}

/// A count on the wire, saturating at `u32::MAX`.
fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// A delegation and when it expires.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct DelegationRefDto {
    /// The delegation's unique identifier.
    pub delegation_id: Uuid,
    /// When the delegation expires.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// An agent's effective capabilities across its live delegations.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EffectiveCapabilitiesResponse {
    /// The agent's identifier.
    pub agent_id: Uuid,
    /// The union of what its live delegations grant.
    pub effective: CapabilitySetDto,
    /// The delegations contributing to the effective set.
    pub active_delegations: Vec<DelegationRefDto>,
    /// When the effective set was computed.
    #[serde(with = "time::serde::rfc3339")]
    pub computed_at: OffsetDateTime,
}

impl EffectiveCapabilitiesResponse {
    /// What `agent_id` may do now.
    #[must_use]
    pub(crate) fn of(agent_id: AgentId, result: &AgentEffectiveCapabilities) -> Self {
        Self {
            agent_id: *agent_id.as_uuid(),
            effective: CapabilitySetDto::from(&result.capabilities),
            active_delegations: result
                .active_delegations
                .iter()
                .map(|d| DelegationRefDto {
                    delegation_id: *d.id().as_uuid(),
                    expires_at: d.expires_at(),
                })
                .collect(),
            computed_at: clock::now(),
        }
    }
}

impl ResourceCapabilityDto {
    /// The grant of this resource onto `delegation_id`, held by `agent_id`.
    ///
    /// # Errors
    ///
    /// - A validation error when the relation or object is not valid.
    pub(crate) fn granted_onto(
        &self,
        agent_id: AgentId,
        delegation_id: DelegationId,
    ) -> Result<GrantResourceRequest, ApiError> {
        Ok(GrantResourceRequest {
            agent_id,
            delegation_id,
            capability: self.to_domain()?,
        })
    }

    /// The removal of this resource from `delegation_id`, held by
    /// `agent_id`.
    ///
    /// # Errors
    ///
    /// - A validation error when the relation or object is not valid.
    pub(crate) fn revoked_from(
        &self,
        agent_id: AgentId,
        delegation_id: DelegationId,
    ) -> Result<RevokeResourceRequest, ApiError> {
        let (relation, resource_ref) = self.parts()?;
        Ok(RevokeResourceRequest {
            agent_id,
            delegation_id,
            relation,
            resource_ref,
        })
    }
}

/// Request to grant or revoke a resource relation for a principal.
///
/// The subject is the principal receiving the authority, a person, an org
/// user or an agent, so a person's grants are recorded and delegation has
/// something authoritative to check against.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ResourceGrantBody {
    /// The principal receiving or losing the relation.
    pub subject: OwnerDto,
    /// The relation and object.
    #[serde(flatten)]
    pub capability: ResourceCapabilityDto,
}

impl TryFrom<ResourceGrantBody> for ResourceGrantRequest {
    type Error = ApiError;

    fn try_from(body: ResourceGrantBody) -> Result<Self, Self::Error> {
        Ok(Self {
            subject: body.subject.to_principal(),
            capability: body.capability.to_domain()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    /// The attenuation `body` asks for, of a new agent's delegation.
    fn attenuation(body: Value) -> Result<AttenuateRequest, ApiError> {
        let body: AttenuateDelegationBody = serde_json::from_value(body).unwrap();
        body.into_request(AgentId::new(), DelegationId::new())
    }

    /// The grant `body` asks for, to a new agent.
    fn grant(body: Value) -> Result<GrantDelegationRequest, ApiError> {
        let body: GrantDelegationBody = serde_json::from_value(body).unwrap();
        body.into_request(AgentId::new())
    }

    /// Ann passes part of her agent's delegation on to a helper, held to 40
    /// requests an hour, the reports path, her approval and the helper's
    /// key. Every one of those limits reaches the child she asks for.
    #[test]
    fn an_attenuation_carries_every_narrowing_limit() {
        let Ok(request) = attenuation(json!({
            "delegate": Uuid::now_v7(),
            "granted": {},
            "ttl_seconds": 300,
            "budget": {"max_requests": 40, "window_seconds": 3600},
            "resource_scope": ["/reports/"],
            "requires_approval": true,
            "sender_constrained": true
        })) else {
            panic!("a body naming only known limits is read");
        };

        let limits = &request.constraints;
        assert!(limits.budget().is_restricted());
        assert!(limits.resource_scope().is_restricted());
        assert!(limits.requires_approval());
        assert!(limits.is_sender_constrained());
    }

    /// Misspelling the approval requirement makes an attenuation request invalid.
    #[test]
    fn an_attenuation_with_a_misspelt_limit_is_refused() {
        let result = attenuation(json!({
            "delegate": Uuid::now_v7(),
            "granted": {},
            "ttl_seconds": 300,
            "requires_aproval": true
        }));

        assert!(result.is_err());
    }

    /// A grant with a misspelled budget field fails deserialization.
    #[test]
    fn a_grant_with_a_misspelt_limit_is_refused() {
        let result = grant(json!({
            "granted": {},
            "ttl_seconds": 300,
            "budgte": {"max_requests": 40, "window_seconds": 3600}
        }));

        assert!(result.is_err());
    }

    /// The body the dashboard sends for a grant, with every limit set, is
    /// read whole.
    #[test]
    fn a_grant_naming_only_known_fields_is_read() {
        let result = grant(json!({
            "apps": null,
            "budget": {"max_requests": 40, "window_seconds": 3600},
            "granted": {"http": [], "messaging": [], "resources": []},
            "intent": null,
            "max_depth": 1,
            "name": "Q1 reconciliation delegation",
            "requires_approval": true,
            "resource_scope": ["/reports/"],
            "sender_constrained": false,
            "task": null,
            "ttl_seconds": 300
        }));

        assert!(result.is_ok());
    }
}
