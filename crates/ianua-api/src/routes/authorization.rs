//! Authorization endpoints: a tenant's roles and who holds them, groups,
//! access policy and its versions, permission catalogue, separation of
//! duties, access requests and reviews, relationships, access checks with
//! their records, and clearance.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::agents::principal::OwnerDto;
use crate::dto::authorization::access_requests::{
    AccessRequestPolicyResponse, AccessRequestResponse, AskedAccessBody,
    ChangeAccessRequestPolicyBody, RequestAccessBody,
};
use crate::dto::authorization::access_reviews::{
    AccessReviewResponse, AccessReviewStatusResponse, DecideAccessReviewBody, ReviewChoiceBody,
    ReviewItemResponse, ReviewScopeBody, ReviewSuggestionResponse, StartAccessReviewBody,
    UnansweredBody,
};
use crate::dto::authorization::checks::{
    AccessDecisionResponse, AccessQuestionBody, AllowedByResponse, BatchAccessDecisionResponse,
    BatchCheckAccessBody, CheckAccessBody, DecisionBasisResponse, DecisionRecordResponse,
};
use crate::dto::authorization::clearance::{
    AddClearanceRuleBody, ChangeClearanceRuleBody, ClearanceRuleResponse, ClearanceRulesResponse,
};
use crate::dto::authorization::groups::{
    AddGroupMemberBody, AssignGroupRoleBody, CreateGroupBody, CreateGroupResponse,
    GroupMemberResponse, GroupResponse, MoveGroupBody, RenameGroupBody,
};
use crate::dto::authorization::holdings::{
    DirectMembershipResponse, DirectRoleResponse, HeldRoleResponse, PrincipalAccessResponse,
    RoleHolderResponse, RoleThroughGroupResponse,
};
use crate::dto::authorization::policies::{
    DefaultActionBody, NewPolicyRuleBody, PolicyResponse, PolicyRuleResponse, PolicyTransitionBody,
    ReorderPolicyRulesBody, RuleEvaluationResponse, SimulatePolicyBody, SimulatedClaimBody,
    SimulatedLocalTimeBody, SimulationResponse, StartPolicyDraftBody, SwitchPolicyRuleBody,
};
use crate::dto::authorization::relationships::{
    LinkBody, ObjectBody, RelationshipResponse, SubjectBody, SubjectKind, WriteRelationshipBody,
};
use crate::dto::authorization::resource_types::{
    ActionBody, ActionResponse, DeclareResourceTypeBody, DeclareResourceTypeResponse,
    ResourceTypeResponse, UpdateResourceTypeBody,
};
use crate::dto::authorization::roles::{
    AssignRoleBody, CreateRoleBody, CreateRoleResponse, DeleteRoleBody, PermissionEntry,
    PermissionGroup, RoleResponse, UpdateRoleBody,
};
use crate::dto::authorization::separation::{AddSeparationRuleBody, SeparationRuleResponse};
use crate::extractors::authorization::{RequestStatusParam, ReviewStatusParam, VerdictParam};
use crate::handlers::authorization::{
    access_requests, access_reviews, checks, clearance, groups, holdings, policies, relationships,
    resource_types, roles, separation,
};
use crate::method::{delete, get, patch, post, put, shared};
use crate::state::ApiState;

/// The authorization endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";
    let authz = format!("{tenant}/authorization");
    Router::new()
        .merge(role_routes(&authz))
        .merge(group_routes(&authz))
        .merge(policy_routes(&authz))
        .merge(governance_routes(&authz))
        .merge(check_routes(&authz))
        .route(
            &format!("{tenant}/resource-types"),
            post(resource_types::declare_resource_type)
                .get(shared(resource_types::list_resource_types)),
        )
        .route(
            &format!("{tenant}/resource-types/{{id}}"),
            patch(resource_types::update_resource_type)
                .delete(shared(resource_types::delete_resource_type)),
        )
}

/// The roles, who holds them, and what one principal holds.
fn role_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{authz}/permissions"),
            get(roles::list_permissions),
        )
        .route(
            &format!("{authz}/roles"),
            post(roles::create_role).get(shared(roles::list_roles)),
        )
        .route(
            &format!("{authz}/roles/{{id}}"),
            get(roles::get_role)
                .patch(shared(roles::update_role))
                .delete(shared(roles::delete_role)),
        )
        .merge(holding_routes(authz))
}

/// Direct assignments and the effective access held by principals.
fn holding_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{authz}/roles/{{id}}/assignments"),
            post(roles::assign_role),
        )
        .route(
            &format!("{authz}/roles/{{id}}/assignments/{{user_id}}"),
            delete(roles::revoke_role),
        )
        .route(
            &format!("{authz}/roles/{{id}}/holders"),
            get(holdings::list_role_holders),
        )
        .route(
            &format!("{authz}/principals/{{principal_kind}}/{{principal_id}}/access"),
            get(holdings::get_principal_access),
        )
}

/// The groups, their place in the tree, members and roles.
fn group_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{authz}/groups"),
            post(groups::create_group).get(shared(groups::list_groups)),
        )
        .route(
            &format!("{authz}/groups/{{id}}"),
            get(groups::get_group)
                .patch(shared(groups::rename_group))
                .delete(shared(groups::delete_group)),
        )
        .route(
            &format!("{authz}/groups/{{id}}/parent"),
            put(groups::move_group),
        )
        .merge(group_membership_routes(authz))
}

/// Members and roles attached to each group.
fn group_membership_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{authz}/groups/{{id}}/members"),
            post(groups::add_group_member).get(shared(groups::list_group_members)),
        )
        .route(
            &format!("{authz}/groups/{{id}}/members/{{principal_kind}}/{{principal_id}}"),
            delete(groups::remove_group_member),
        )
        .route(
            &format!("{authz}/groups/{{id}}/roles"),
            post(groups::assign_group_role),
        )
        .route(
            &format!("{authz}/groups/{{id}}/roles/{{role_id}}"),
            delete(groups::unassign_group_role),
        )
}

/// The access policy: its live version and draft, versions, rules,
/// lifecycle and simulation.
fn policy_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(&format!("{authz}/policy"), get(policies::get_policy))
        .route(
            &format!("{authz}/policy/live"),
            get(policies::get_live_policy),
        )
        .route(
            &format!("{authz}/policy/draft"),
            get(policies::get_draft_policy).post(shared(policies::start_policy_draft)),
        )
        .route(
            &format!("{authz}/policy/versions"),
            get(policies::list_policy_versions),
        )
        .route(
            &format!("{authz}/policy/versions/{{version}}"),
            get(policies::get_policy_version),
        )
        .merge(policy_rule_routes(authz))
}

/// Rule edits, activation, and simulation of the access policy.
fn policy_rule_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{authz}/policy/rules"),
            post(policies::add_policy_rule),
        )
        .route(
            &format!("{authz}/policy/rules/{{rule_name}}"),
            put(policies::change_policy_rule).delete(shared(policies::remove_policy_rule)),
        )
        .route(
            &format!("{authz}/policy/rules/{{rule_name}}/enabled"),
            put(policies::switch_policy_rule),
        )
        .route(
            &format!("{authz}/policy/rule-order"),
            put(policies::reorder_policy_rules),
        )
        .route(
            &format!("{authz}/policy/default-action"),
            put(policies::change_default_action),
        )
        .route(
            &format!("{authz}/policy/status"),
            post(policies::change_policy_status),
        )
        .route(
            &format!("{authz}/simulate"),
            post(policies::simulate_policy),
        )
}

/// Separation of duties, access requests and reviews, and clearance.
fn governance_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{authz}/separation-rules"),
            post(separation::add_separation_rule).get(shared(separation::list_separation_rules)),
        )
        .route(
            &format!("{authz}/separation-rules/{{id}}"),
            delete(separation::remove_separation_rule),
        )
        .merge(access_request_routes(authz))
        .merge(review_routes(authz))
        .route(
            &format!("{authz}/clearance-rules"),
            get(clearance::get_clearance_rules).post(shared(clearance::add_clearance_rule)),
        )
        .route(
            &format!("{authz}/clearance-rules/{{resource}}/{{action}}"),
            put(clearance::change_clearance_rule).delete(shared(clearance::remove_clearance_rule)),
        )
}

/// Requests for access and the policy governing their approval.
fn access_request_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{authz}/access-requests"),
            post(access_requests::request_access)
                .get(shared(access_requests::list_access_requests)),
        )
        .route(
            &format!("{authz}/access-requests/{{id}}/approve"),
            post(access_requests::approve_access_request),
        )
        .route(
            &format!("{authz}/access-requests/{{id}}/deny"),
            post(access_requests::deny_access_request),
        )
        .route(
            &format!("{authz}/access-requests/{{id}}/cancel"),
            post(access_requests::cancel_access_request),
        )
        .route(
            &format!("{authz}/access-request-policy"),
            get(access_requests::get_access_request_policy)
                .put(shared(access_requests::change_access_request_policy)),
        )
}

/// Access reviews.
fn review_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{authz}/access-reviews"),
            post(access_reviews::start_access_review)
                .get(shared(access_reviews::list_access_reviews)),
        )
        .route(
            &format!("{authz}/access-reviews/{{id}}"),
            get(access_reviews::get_access_review),
        )
        .route(
            &format!("{authz}/access-reviews/{{id}}/items"),
            get(access_reviews::list_access_review_items),
        )
        .route(
            &format!("{authz}/access-reviews/{{id}}/decisions"),
            post(access_reviews::decide_access_review),
        )
        .route(
            &format!("{authz}/access-reviews/{{id}}/complete"),
            post(access_reviews::complete_access_review),
        )
        .route(
            &format!("{authz}/access-reviews/{{id}}/cancel"),
            post(access_reviews::cancel_access_review),
        )
}

/// Relationships, the access check and the decision records.
fn check_routes(authz: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{authz}/relationships"),
            post(relationships::write_relationship).get(shared(relationships::list_relationships)),
        )
        .route(
            &format!("{authz}/relationships/{{id}}"),
            delete(relationships::delete_relationship),
        )
        .route(&format!("{authz}/check"), post(checks::check_access))
        .route(
            &format!("{authz}/check/batch"),
            post(checks::check_access_batch),
        )
        .route(&format!("{authz}/decisions"), get(checks::search_decisions))
}

/// The authorization part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        roles::list_permissions,
        roles::create_role,
        roles::list_roles,
        roles::get_role,
        roles::update_role,
        roles::delete_role,
        roles::assign_role,
        roles::revoke_role,
        holdings::list_role_holders,
        holdings::get_principal_access,
        groups::create_group,
        groups::list_groups,
        groups::get_group,
        groups::rename_group,
        groups::move_group,
        groups::delete_group,
        groups::add_group_member,
        groups::list_group_members,
        groups::remove_group_member,
        groups::assign_group_role,
        groups::unassign_group_role,
        policies::get_policy,
        policies::get_live_policy,
        policies::get_draft_policy,
        policies::list_policy_versions,
        policies::get_policy_version,
        policies::start_policy_draft,
        policies::add_policy_rule,
        policies::change_policy_rule,
        policies::remove_policy_rule,
        policies::reorder_policy_rules,
        policies::switch_policy_rule,
        policies::change_default_action,
        policies::change_policy_status,
        policies::simulate_policy,
        separation::add_separation_rule,
        separation::list_separation_rules,
        separation::remove_separation_rule,
        access_requests::request_access,
        access_requests::list_access_requests,
        access_requests::approve_access_request,
        access_requests::deny_access_request,
        access_requests::cancel_access_request,
        access_requests::get_access_request_policy,
        access_requests::change_access_request_policy,
        access_reviews::start_access_review,
        access_reviews::list_access_reviews,
        access_reviews::get_access_review,
        access_reviews::list_access_review_items,
        access_reviews::decide_access_review,
        access_reviews::complete_access_review,
        access_reviews::cancel_access_review,
        relationships::write_relationship,
        relationships::list_relationships,
        relationships::delete_relationship,
        checks::check_access,
        checks::check_access_batch,
        checks::search_decisions,
        clearance::get_clearance_rules,
        clearance::add_clearance_rule,
        clearance::change_clearance_rule,
        clearance::remove_clearance_rule,
        resource_types::declare_resource_type,
        resource_types::list_resource_types,
        resource_types::update_resource_type,
        resource_types::delete_resource_type,
    ),
    components(schemas(
        CreateRoleBody,
        UpdateRoleBody,
        DeleteRoleBody,
        AssignRoleBody,
        RoleResponse,
        CreateRoleResponse,
        PermissionEntry,
        PermissionGroup,
        OwnerDto,
        RoleHolderResponse,
        HeldRoleResponse,
        DirectRoleResponse,
        DirectMembershipResponse,
        RoleThroughGroupResponse,
        PrincipalAccessResponse,
        CreateGroupBody,
        RenameGroupBody,
        MoveGroupBody,
        AddGroupMemberBody,
        AssignGroupRoleBody,
        GroupResponse,
        CreateGroupResponse,
        GroupMemberResponse,
        PolicyResponse,
        PolicyRuleResponse,
        NewPolicyRuleBody,
        StartPolicyDraftBody,
        DefaultActionBody,
        SwitchPolicyRuleBody,
        ReorderPolicyRulesBody,
        PolicyTransitionBody,
        SimulatePolicyBody,
        SimulatedClaimBody,
        SimulatedLocalTimeBody,
        SimulationResponse,
        RuleEvaluationResponse,
        AddSeparationRuleBody,
        SeparationRuleResponse,
        AskedAccessBody,
        RequestAccessBody,
        AccessRequestResponse,
        RequestStatusParam,
        AccessRequestPolicyResponse,
        ChangeAccessRequestPolicyBody,
        ReviewScopeBody,
        UnansweredBody,
        StartAccessReviewBody,
        ReviewChoiceBody,
        DecideAccessReviewBody,
        AccessReviewStatusResponse,
        ReviewItemResponse,
        ReviewSuggestionResponse,
        AccessReviewResponse,
        ReviewStatusParam,
        ObjectBody,
        SubjectKind,
        SubjectBody,
        LinkBody,
        WriteRelationshipBody,
        RelationshipResponse,
        AccessQuestionBody,
        CheckAccessBody,
        BatchCheckAccessBody,
        AllowedByResponse,
        AccessDecisionResponse,
        BatchAccessDecisionResponse,
        DecisionBasisResponse,
        DecisionRecordResponse,
        VerdictParam,
        AddClearanceRuleBody,
        ChangeClearanceRuleBody,
        ClearanceRuleResponse,
        ClearanceRulesResponse,
        ActionBody,
        ActionResponse,
        DeclareResourceTypeBody,
        UpdateResourceTypeBody,
        ResourceTypeResponse,
        DeclareResourceTypeResponse,
    ))
)]
pub(crate) struct Document;
