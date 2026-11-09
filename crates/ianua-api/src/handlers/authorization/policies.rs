//! Policy handlers: the tenant's access policy, its live version and the
//! draft beside it, its history of versions, the draft edited one step at
//! a time, moved through review into service, and any version simulated.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::authorization::AuthorizationState;

use crate::dto::authorization::policies::{
    DefaultActionBody, NewPolicyRuleBody, PolicyResponse, PolicyTransitionBody,
    ReorderPolicyRulesBody, SimulatePolicyBody, SimulationResponse, StartPolicyDraftBody,
    SwitchPolicyRuleBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::authorization::{PolicyRulePath, PolicyVersionPath};
use crate::response::Created;

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "The tenant has no policy yet", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get the tenant's authorization policy
///
/// The version an editor works on: the open draft when there is one,
/// otherwise the live version. The rules in the order they are checked,
/// what happens to a request none of them matched, where the version sits
/// in its lifecycle, and its number.
///
/// A tenant with neither answers `404`: start a draft with
/// `POST …/authorization/policy/draft` to open the editor. Read the two
/// apart with `GET …/policy/live` and `GET …/policy/draft`.
///
/// Requires `PolicySet(View)`.
pub(crate) async fn get_policy(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
) -> Result<Json<PolicyResponse>, ApiError> {
    let overview = authorization
        .policies
        .get
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(PolicyResponse::current(&overview)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/live",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Nothing is live", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get the live policy
///
/// The version deciding real requests now. `404` while nothing is live:
/// the gateway then decides by each route's own policy alone.
///
/// Requires `PolicySet(View)`.
pub(crate) async fn get_live_policy(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
) -> Result<Json<PolicyResponse>, ApiError> {
    let overview = authorization
        .policies
        .get
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(PolicyResponse::live(&overview)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/draft",
    tag = "Authorization",
    responses(
        (status = 200, description = "Success", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No draft is open", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get the draft policy
///
/// The draft open beside the live version, being written or in review.
/// `404` while none is open. Nothing a draft says decides a real request
/// until it is activated.
///
/// Requires `PolicySet(View)`.
pub(crate) async fn get_draft_policy(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
) -> Result<Json<PolicyResponse>, ApiError> {
    let overview = authorization
        .policies
        .get
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(PolicyResponse::draft(&overview)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/versions",
    tag = "Authorization",
    responses(
        (status = 200, description = "Every version, newest first", body = Vec<PolicyResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// List the policy's versions
///
/// Every version of the tenant's policy, newest first: the open draft, the
/// live version and the past ones, each with its rules and where it
/// started. Empty when the tenant never started one. Restore a past one
/// with `POST …/policy/draft` and `{"from": "restore", "version": n}`.
///
/// Requires `PolicySet(View)`.
pub(crate) async fn list_policy_versions(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<PolicyResponse>>, ApiError> {
    let versions = authorization
        .policies
        .versions
        .list
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(versions.iter().map(PolicyResponse::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/versions/{version}",
    tag = "Authorization",
    params(("version" = u32, Path, description = "The version's number")),
    responses(
        (status = 200, description = "Success", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such version", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Get one version of the policy
///
/// The version with this number, whatever its state, so two versions can
/// be read side by side. `404` when the tenant has no such version.
///
/// Requires `PolicySet(View)`.
pub(crate) async fn get_policy_version(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<PolicyVersionPath>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let version = authorization
        .policies
        .versions
        .get
        .execute(&tenant.caller, path.version()?)
        .await?;
    Ok(Json(PolicyResponse::from(&version)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/draft",
    tag = "Authorization",
    request_body = StartPolicyDraftBody,
    responses(
        (status = 201, description = "Draft started", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Nothing to copy or restore", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Start a draft policy
///
/// Opens a draft beside the live version, numbered one past the highest.
/// `{"from": "blank", "default_action": …}` starts empty with the given
/// fallback; `{"from": "next_version"}` copies the live version's rules and
/// fallback (`404` when nothing is live); `{"from": "restore", "version":
/// n}` brings a past version back as a new draft (`404` for a version the
/// tenant does not have). A draft already open, or a restore of the live
/// or open version, answers `409`. The live version keeps deciding
/// requests while the draft is written. Records
/// `authorization.policy_draft_started`.
///
/// Requires `PolicySet(Update)`.
pub(crate) async fn start_policy_draft(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<StartPolicyDraftBody>,
) -> Result<Created<PolicyResponse>, ApiError> {
    let policy = authorization
        .policies
        .versions
        .start_draft
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(PolicyResponse::from(&policy)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/rules",
    tag = "Authorization",
    request_body = NewPolicyRuleBody,
    responses(
        (status = 200, description = "The draft with the rule", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No draft is open", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Add a rule to the draft policy
///
/// Adds one rule, switched on, to the open draft. Rules are checked lowest
/// `priority` first; a matching deny refuses the request wherever it sits,
/// otherwise the first matching allow lets it through. A condition that
/// cannot mean what it says is `422`; a name the draft already has is
/// `409`.
///
/// Only a draft being written is edited: one in review answers `409`.
/// Editing does not change what is enforced until the draft is activated.
/// Answers the whole draft. Records `authorization.policy_rule_added`.
///
/// Requires `PolicySet(Update)`.
pub(crate) async fn add_policy_rule(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<NewPolicyRuleBody>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let policy = authorization
        .policies
        .rules
        .add
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Json(PolicyResponse::from(&policy)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/rules/{rule_name}",
    tag = "Authorization",
    request_body = NewPolicyRuleBody,
    responses(
        (status = 200, description = "The draft with the rule changed", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Change a rule of the draft policy
///
/// Rewrites the rule named in the path: its name, conditions, action and
/// priority, as the body gives them. Whether it is switched on is kept.
/// `404` when no draft is open or it has no such rule; `409` when the draft
/// is in review or the new name is another rule's. Answers the whole
/// draft. Records `authorization.policy_rule_changed`.
///
/// Requires `PolicySet(Update)`.
pub(crate) async fn change_policy_rule(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<PolicyRulePath>,
    Json(body): Json<NewPolicyRuleBody>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let policy = authorization
        .policies
        .rules
        .change
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.replacing(path.into_rule())?,
        )
        .await?;
    Ok(Json(PolicyResponse::from(&policy)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/rules/{rule_name}",
    tag = "Authorization",
    responses(
        (status = 200, description = "The draft without the rule", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Remove a rule from the draft policy
///
/// Takes the rule named out of the open draft. A draft in review answers
/// `409`. Answers the whole draft. Records
/// `authorization.policy_rule_removed`.
///
/// Requires `PolicySet(Update)`.
pub(crate) async fn remove_policy_rule(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<PolicyRulePath>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let policy = authorization
        .policies
        .rules
        .remove
        .execute(&tenant.caller, &tenant.auditor, path.into_rule())
        .await?;
    Ok(Json(PolicyResponse::from(&policy)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/rule-order",
    tag = "Authorization",
    request_body = ReorderPolicyRulesBody,
    responses(
        (status = 200, description = "The draft in its new order", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No draft is open", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Reorder the draft's rules
///
/// Puts the open draft's rules in the order `names` gives, first checked
/// first. Every rule is named exactly once, or the request is `422`. A
/// draft in review answers `409`. Answers the whole draft. Records
/// `authorization.policy_rules_reordered`.
///
/// Requires `PolicySet(Update)`.
pub(crate) async fn reorder_policy_rules(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<ReorderPolicyRulesBody>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let policy = authorization
        .policies
        .rules
        .reorder
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Json(PolicyResponse::from(&policy)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/rules/{rule_name}/enabled",
    tag = "Authorization",
    request_body = SwitchPolicyRuleBody,
    responses(
        (status = 200, description = "The draft with the rule switched", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Switch a draft rule on or off
///
/// Takes a rule out of service, or puts it back, without losing how it was
/// written: a switched-off rule is kept but skipped. A draft in review
/// answers `409`. Answers the whole draft. Records
/// `authorization.policy_rule_switched`.
///
/// Requires `PolicySet(Update)`.
pub(crate) async fn switch_policy_rule(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Path(path): Path<PolicyRulePath>,
    Json(body): Json<SwitchPolicyRuleBody>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let policy = authorization
        .policies
        .rules
        .switch
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.into_rule()),
        )
        .await?;
    Ok(Json(PolicyResponse::from(&policy)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/default-action",
    tag = "Authorization",
    request_body = DefaultActionBody,
    responses(
        (status = 200, description = "The draft with its new fallback", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No draft is open", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Change what the draft does with an unmatched request
///
/// **`default_action` is the posture.** `Deny` refuses anything no rule
/// allowed, which is the safe default for a zero-trust deployment. `Allow`
/// means only the rules refuse anything. A draft in review answers `409`.
/// Answers the whole draft. Records
/// `authorization.policy_default_action_changed`.
///
/// Requires `PolicySet(Update)`.
pub(crate) async fn change_default_action(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<DefaultActionBody>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let policy = authorization
        .policies
        .rules
        .change_default_action
        .execute(&tenant.caller, &tenant.auditor, body.default_action)
        .await?;
    Ok(Json(PolicyResponse::from(&policy)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/policy/status",
    tag = "Authorization",
    request_body = PolicyTransitionBody,
    responses(
        (status = 200, description = "The version moved", body = PolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Move a version of the policy through its lifecycle
///
/// `submit_for_review` freezes the open draft while it is looked over.
/// `activate` puts the draft in review live, in place of the live version,
/// which becomes a past one. `reject` sends it back to draft.
/// `abandon_draft` drops the open draft without it ever going live.
/// `take_out_of_use` (also read from `archive`) takes the live version out
/// of service.
///
/// Activation requires a different approver when the tenant has one available.
/// Taking the live version out leaves only each route's policy deciding traffic
/// until another version is activated.
///
/// Invalid transitions give `409`; valid ones record `authorization.policy_*`.
///
/// Submitting needs `PolicySet(Update)`; activating, rejecting and taking
/// out of use need `PolicySet(Activate)`: writing a rule and putting it in
/// front of live traffic are different amounts of trust.
pub(crate) async fn change_policy_status(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<PolicyTransitionBody>,
) -> Result<Json<PolicyResponse>, ApiError> {
    let policy = authorization
        .policies
        .versions
        .change_status
        .execute(&tenant.caller, &tenant.auditor, body.into())
        .await?;
    Ok(Json(PolicyResponse::from(&policy)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/authorization/simulate",
    tag = "Authorization",
    request_body = SimulatePolicyBody,
    responses(
        (status = 200, description = "Success", body = SimulationResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such version", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Simulate a policy decision
///
/// Evaluates supplied request, subject, time, location, device, risk, assurance
/// and `DPoP` facts without affecting live requests. Omitted facts stay unknown:
/// refusal rules can match them, allowance rules cannot, as at the gateway.
///
/// `version` picks what to run: `live` (the default) answers "what happens
/// now"; `draft` answers "what would happen if this went live", the
/// question to ask before approving it; a number runs that version.
/// `404` when there is no such version.
///
/// The result carries the final `action`, the `matched_rule` that decided
/// it (if any), the `evaluated_rules` trace, and the `policy_version` it
/// ran. Records `authorization.policy_simulated`.
///
/// Requires `PolicySet(View)`.
pub(crate) async fn simulate_policy(
    State(authorization): State<AuthorizationState>,
    tenant: TenantCaller,
    Json(body): Json<SimulatePolicyBody>,
) -> Result<Json<SimulationResponse>, ApiError> {
    let result = authorization
        .policies
        .simulate
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Json(SimulationResponse::from(&result)))
}
