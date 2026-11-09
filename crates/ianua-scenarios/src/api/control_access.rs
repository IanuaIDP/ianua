//! Who may do what in a tenant, beyond roles and groups as `policies` and
//! `roles` send them: the groups read and moved, access requests and
//! reviews, separation-of-duties and clearance rules, relationships and
//! access checks, the policy read and edited, and emergency access.

use serde::de::IgnoredAny;

use super::{Request, TenantPath, with_query};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::control_access::{
    AccessAnswer, AccessAnswers, AccessCheck, AccessCheckBatch, AccessRequestDetail,
    AccessRequestLimit, AccessReview, AppPermission, BreakGlass, BreakGlassGrant, BreakGlassPolicy,
    BreakGlassRevoke, ClearanceLevel, ClearanceRules, DecisionRecord, DefaultAction, DraftSource,
    GroupDetail, GroupPlacement, GroupRename, NewAccessReview, NewAppRole, NewClearanceRule,
    NewRelationship, NewResourceType, NewSeparationRule, PolicyDetail, PrincipalAccess,
    Relationship, ReviewDecision, RuleOrder, RuleRewrite, RuleSwitch, SeparationRule,
    SimulatedRequest, Simulation,
};
use crate::wire::policies::Policy;
use crate::wire::roles::RoleMade;

/// `GET …/authorization/groups`.
#[must_use]
pub fn list_groups(tenant: &TenantPath) -> Request<Page<GroupDetail>> {
    Request::of(Call::get(tenant.at("/authorization/groups")))
}

/// `GET …/authorization/groups/{id}`.
#[must_use]
pub fn get_group(tenant: &TenantPath, group_id: &str) -> Request<GroupDetail> {
    Request::of(Call::get(
        tenant.at(&format!("/authorization/groups/{group_id}")),
    ))
}

/// `PATCH …/authorization/groups/{id}`.
#[must_use]
pub fn rename_group(tenant: &TenantPath, group_id: &str, rename: &GroupRename) -> Request<()> {
    let path = tenant.at(&format!("/authorization/groups/{group_id}"));
    Request::of(Call::patch(path).json(rename))
}

/// `DELETE …/authorization/groups/{id}`.
#[must_use]
pub fn delete_group(tenant: &TenantPath, group_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/authorization/groups/{group_id}")),
    ))
}

/// `PUT …/authorization/groups/{id}/parent`: moves the group in the tree.
#[must_use]
pub fn move_group(tenant: &TenantPath, group_id: &str, place: &GroupPlacement) -> Request<()> {
    let path = tenant.at(&format!("/authorization/groups/{group_id}/parent"));
    Request::of(Call::put(path).json(place))
}

/// `GET …/authorization/principals/{kind}/{id}/access`: what a principal
/// holds now and from where.
#[must_use]
pub fn principal_access(tenant: &TenantPath, kind: &str, id: &str) -> Request<PrincipalAccess> {
    Request::of(Call::get(
        tenant.at(&format!("/authorization/principals/{kind}/{id}/access")),
    ))
}

/// `POST …/authorization/roles`: a role carrying app permissions.
#[must_use]
pub fn create_app_role(tenant: &TenantPath, role: &NewAppRole) -> Request<RoleMade> {
    Request::of(Call::post(tenant.at("/authorization/roles")).json(role))
}

/// `POST …/resource-types`: declares a resource type.
#[must_use]
pub fn declare_resource_type(
    tenant: &TenantPath,
    resource_type: &NewResourceType,
) -> Request<IgnoredAny> {
    Request::of(Call::post(tenant.at("/resource-types")).json(resource_type))
}

/// `GET …/authorization/policy`: the open draft, or else the live version.
#[must_use]
pub fn current_policy(tenant: &TenantPath) -> Request<PolicyDetail> {
    Request::of(Call::get(tenant.at("/authorization/policy")))
}

/// `GET …/authorization/policy/live`.
#[must_use]
pub fn live_policy(tenant: &TenantPath) -> Request<PolicyDetail> {
    Request::of(Call::get(tenant.at("/authorization/policy/live")))
}

/// `GET …/authorization/policy/draft`.
#[must_use]
pub fn draft_policy(tenant: &TenantPath) -> Request<PolicyDetail> {
    Request::of(Call::get(tenant.at("/authorization/policy/draft")))
}

/// `GET …/authorization/policy/versions`: every version, newest first.
#[must_use]
pub fn policy_versions(tenant: &TenantPath) -> Request<Vec<PolicyDetail>> {
    Request::of(Call::get(tenant.at("/authorization/policy/versions")))
}

/// `GET …/authorization/policy/versions/{version}`.
#[must_use]
pub fn policy_version(tenant: &TenantPath, version: u32) -> Request<PolicyDetail> {
    Request::of(Call::get(
        tenant.at(&format!("/authorization/policy/versions/{version}")),
    ))
}

/// `POST …/authorization/policy/draft`, from the live version or a past
/// one.
#[must_use]
pub fn start_draft_from(tenant: &TenantPath, source: &DraftSource) -> Request<Policy> {
    Request::of(Call::post(tenant.at("/authorization/policy/draft")).json(source))
}

/// `PUT …/authorization/policy/rules/{name}`: rewrites a draft rule.
#[must_use]
pub fn change_rule(tenant: &TenantPath, name: &str, rule: &RuleRewrite) -> Request<PolicyDetail> {
    let path = tenant.at(&format!("/authorization/policy/rules/{name}"));
    Request::of(Call::put(path).json(rule))
}

/// `DELETE …/authorization/policy/rules/{name}`.
#[must_use]
pub fn remove_rule(tenant: &TenantPath, name: &str) -> Request<PolicyDetail> {
    Request::of(Call::delete(
        tenant.at(&format!("/authorization/policy/rules/{name}")),
    ))
}

/// `PUT …/authorization/policy/rules/{name}/enabled`: switches a draft
/// rule on or off without losing how it was written.
#[must_use]
pub fn switch_rule(tenant: &TenantPath, name: &str, switch: &RuleSwitch) -> Request<PolicyDetail> {
    let path = tenant.at(&format!("/authorization/policy/rules/{name}/enabled"));
    Request::of(Call::put(path).json(switch))
}

/// `PUT …/authorization/policy/rule-order`.
#[must_use]
pub fn reorder_rules(tenant: &TenantPath, order: &RuleOrder) -> Request<PolicyDetail> {
    Request::of(Call::put(tenant.at("/authorization/policy/rule-order")).json(order))
}

/// `PUT …/authorization/policy/default-action`.
#[must_use]
pub fn change_default_action(tenant: &TenantPath, action: &DefaultAction) -> Request<PolicyDetail> {
    Request::of(Call::put(tenant.at("/authorization/policy/default-action")).json(action))
}

/// `POST …/authorization/simulate`: what a version would do with a made-up
/// request.
#[must_use]
pub fn simulate(tenant: &TenantPath, request: &SimulatedRequest) -> Request<Simulation> {
    Request::of(Call::post(tenant.at("/authorization/simulate")).json(request))
}

/// `GET …/authorization/access-requests`, every request or those `query`
/// narrows to.
#[must_use]
pub fn list_requests(
    tenant: &TenantPath,
    query: &[(&str, &str)],
) -> Request<Page<AccessRequestDetail>> {
    let path = with_query(&tenant.at("/authorization/access-requests"), query);
    Request::of(Call::get(path))
}

/// `POST …/authorization/access-requests/{id}/deny`.
#[must_use]
pub fn deny_request(tenant: &TenantPath, request_id: &str) -> Request<AccessRequestDetail> {
    Request::of(Call::post(
        tenant.at(&format!("/authorization/access-requests/{request_id}/deny")),
    ))
}

/// `POST …/authorization/access-requests/{id}/cancel`.
#[must_use]
pub fn cancel_request(tenant: &TenantPath, request_id: &str) -> Request<AccessRequestDetail> {
    Request::of(Call::post(tenant.at(&format!(
        "/authorization/access-requests/{request_id}/cancel"
    ))))
}

/// `GET …/authorization/access-request-policy`.
#[must_use]
pub fn request_limit(tenant: &TenantPath) -> Request<AccessRequestLimit> {
    Request::of(Call::get(tenant.at("/authorization/access-request-policy")))
}

/// `PUT …/authorization/access-request-policy`.
#[must_use]
pub fn change_request_limit(
    tenant: &TenantPath,
    limit: &AccessRequestLimit,
) -> Request<AccessRequestLimit> {
    Request::of(Call::put(tenant.at("/authorization/access-request-policy")).json(limit))
}

/// `POST …/authorization/access-reviews`.
#[must_use]
pub fn start_review(tenant: &TenantPath, review: &NewAccessReview) -> Request<AccessReview> {
    Request::of(Call::post(tenant.at("/authorization/access-reviews")).json(review))
}

/// `GET …/authorization/access-reviews`.
#[must_use]
pub fn list_reviews(tenant: &TenantPath) -> Request<Page<AccessReview>> {
    Request::of(Call::get(tenant.at("/authorization/access-reviews")))
}

/// `GET …/authorization/access-reviews/{id}`.
#[must_use]
pub fn get_review(tenant: &TenantPath, review_id: &str) -> Request<AccessReview> {
    Request::of(Call::get(
        tenant.at(&format!("/authorization/access-reviews/{review_id}")),
    ))
}

/// `POST …/authorization/access-reviews/{id}/decisions`.
#[must_use]
pub fn decide_review(
    tenant: &TenantPath,
    review_id: &str,
    decision: &ReviewDecision,
) -> Request<AccessReview> {
    let path = tenant.at(&format!(
        "/authorization/access-reviews/{review_id}/decisions"
    ));
    Request::of(Call::post(path).json(decision))
}

/// `POST …/authorization/access-reviews/{id}/complete`.
#[must_use]
pub fn complete_review(tenant: &TenantPath, review_id: &str) -> Request<AccessReview> {
    Request::of(Call::post(tenant.at(&format!(
        "/authorization/access-reviews/{review_id}/complete"
    ))))
}

/// `POST …/authorization/access-reviews/{id}/cancel`.
#[must_use]
pub fn cancel_review(tenant: &TenantPath, review_id: &str) -> Request<AccessReview> {
    Request::of(Call::post(
        tenant.at(&format!("/authorization/access-reviews/{review_id}/cancel")),
    ))
}

/// `POST …/authorization/separation-rules`.
#[must_use]
pub fn add_separation(tenant: &TenantPath, rule: &NewSeparationRule) -> Request<SeparationRule> {
    Request::of(Call::post(tenant.at("/authorization/separation-rules")).json(rule))
}

/// `GET …/authorization/separation-rules`: every rule, oldest first.
#[must_use]
pub fn separation_rules(tenant: &TenantPath) -> Request<Vec<SeparationRule>> {
    Request::of(Call::get(tenant.at("/authorization/separation-rules")))
}

/// `DELETE …/authorization/separation-rules/{id}`.
#[must_use]
pub fn lift_separation(tenant: &TenantPath, rule_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/authorization/separation-rules/{rule_id}")),
    ))
}

/// `POST …/authorization/relationships`.
#[must_use]
pub fn write_relationship(
    tenant: &TenantPath,
    relationship: &NewRelationship,
) -> Request<Relationship> {
    Request::of(Call::post(tenant.at("/authorization/relationships")).json(relationship))
}

/// `GET …/authorization/relationships`, every one or those `query` narrows
/// to.
#[must_use]
pub fn relationships(tenant: &TenantPath, query: &[(&str, &str)]) -> Request<Page<Relationship>> {
    let path = with_query(&tenant.at("/authorization/relationships"), query);
    Request::of(Call::get(path))
}

/// `DELETE …/authorization/relationships/{id}`.
#[must_use]
pub fn remove_relationship(tenant: &TenantPath, relationship_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/authorization/relationships/{relationship_id}")),
    ))
}

/// `POST …/authorization/check`.
#[must_use]
pub fn check(tenant: &TenantPath, check: &AccessCheck) -> Request<AccessAnswer> {
    Request::of(Call::post(tenant.at("/authorization/check")).json(check))
}

/// `POST …/authorization/check/batch`.
#[must_use]
pub fn check_batch(tenant: &TenantPath, batch: &AccessCheckBatch) -> Request<AccessAnswers> {
    Request::of(Call::post(tenant.at("/authorization/check/batch")).json(batch))
}

/// `GET …/authorization/decisions`, those `query` narrows to.
#[must_use]
pub fn decisions(tenant: &TenantPath, query: &[(&str, &str)]) -> Request<Page<DecisionRecord>> {
    let path = with_query(&tenant.at("/authorization/decisions"), query);
    Request::of(Call::get(path))
}

/// `GET …/authorization/clearance-rules`.
#[must_use]
pub fn clearance_rules(tenant: &TenantPath) -> Request<ClearanceRules> {
    Request::of(Call::get(tenant.at("/authorization/clearance-rules")))
}

/// `POST …/authorization/clearance-rules`.
#[must_use]
pub fn add_clearance(tenant: &TenantPath, rule: &NewClearanceRule) -> Request<ClearanceRules> {
    Request::of(Call::post(tenant.at("/authorization/clearance-rules")).json(rule))
}

/// `PUT …/authorization/clearance-rules/{resource}/{action}`.
#[must_use]
pub fn change_clearance(
    tenant: &TenantPath,
    permission: &AppPermission,
    level: &ClearanceLevel,
) -> Request<ClearanceRules> {
    let path = tenant.at(&format!(
        "/authorization/clearance-rules/{}/{}",
        permission.resource, permission.action
    ));
    Request::of(Call::put(path).json(level))
}

/// `DELETE …/authorization/clearance-rules/{resource}/{action}`.
#[must_use]
pub fn remove_clearance(
    tenant: &TenantPath,
    permission: &AppPermission,
) -> Request<ClearanceRules> {
    let path = tenant.at(&format!(
        "/authorization/clearance-rules/{}/{}",
        permission.resource, permission.action
    ));
    Request::of(Call::delete(path))
}

/// `POST …/auth/break-glass`: opens an emergency grant.
#[must_use]
pub fn break_glass(tenant: &TenantPath, grant: &BreakGlass) -> Request<BreakGlassGrant> {
    Request::of(Call::post(tenant.at("/auth/break-glass")).json(grant))
}

/// `POST …/auth/break-glass/revoke`: ends an emergency grant.
#[must_use]
pub fn revoke_break_glass(tenant: &TenantPath, grant_id: &str) -> Request<()> {
    let body = BreakGlassRevoke {
        grant_id: grant_id.to_owned(),
    };
    Request::of(Call::post(tenant.at("/auth/break-glass/revoke")).json(&body))
}

/// `PUT …/break-glass-policy`: what users may give themselves.
#[must_use]
pub fn change_break_glass_policy(tenant: &TenantPath, policy: &BreakGlassPolicy) -> Request<()> {
    Request::of(Call::put(tenant.at("/break-glass-policy")).json(policy))
}
