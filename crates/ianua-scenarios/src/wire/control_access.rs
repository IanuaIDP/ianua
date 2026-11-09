//! Who may do what in a tenant, beyond roles and groups as `policies` and
//! `roles` write them: the groups as they read back, access requests and
//! reviews, separation-of-duties and clearance rules, relationships and
//! access checks, the policy read and edited, and emergency access.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::roles::SystemPermission;

/// A group as the API reads it back.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupDetail {
    /// Handle used to change it, list its members and bind its roles.
    pub id: String,
    /// What people see the group as, unique in the tenant.
    pub name: String,
    /// The group above it, or `None` at the top of the tree.
    #[serde(default)]
    pub parent_id: Option<String>,
    /// The roles bound to the group, which every member holds.
    #[serde(default)]
    pub role_ids: Vec<String>,
}

/// `PATCH …/authorization/groups/{id}`: a new name.
#[derive(Debug, Clone, Serialize)]
pub struct GroupRename {
    /// The new name.
    pub name: String,
}

/// `PUT …/authorization/groups/{id}/parent`: where the group moves.
#[derive(Debug, Clone, Serialize)]
pub struct GroupPlacement {
    /// The group to move it under, or `None` for the top of the tree.
    pub parent_id: Option<String>,
}

/// One rule of a policy, as it reads back.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    /// What the rule is called, unique in the policy.
    pub name: String,
    /// What must hold for it to fire, as the API writes conditions.
    #[serde(default)]
    pub conditions: Vec<Value>,
    /// What happens when it fires.
    pub action: Value,
    /// Lower numbers are checked first.
    pub priority: u16,
    /// Whether it is switched on.
    pub enabled: bool,
}

/// A version of the policy, read back with its rules.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyDetail {
    /// The rules, in the order they are checked.
    pub rules: Vec<PolicyRule>,
    /// What happens to a request no rule matched.
    pub default_action: Value,
    /// `Draft`, `Review`, `Active` or `Archived`.
    pub status: String,
    /// Whether the rules can be edited now.
    pub editable: bool,
    /// Its number.
    pub version: u32,
    /// `blank`, `copy` or `restore`.
    pub based_on: String,
    /// The version it copied or restored, when one.
    #[serde(default)]
    pub based_on_version: Option<u32>,
}

/// `POST …/authorization/policy/draft`: a draft copied from the live
/// version or restored from a past one.
#[derive(Debug, Clone, Serialize)]
pub struct DraftSource {
    /// `next_version` or `restore`.
    pub from: String,
    /// The version to bring back, for `restore`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

/// `PUT …/authorization/policy/rules/{name}`: a rule's new shape.
#[derive(Debug, Clone, Serialize)]
pub struct RuleRewrite {
    /// Its name after the change.
    pub name: String,
    /// What must hold for it to fire.
    pub conditions: Vec<Value>,
    /// What happens when it fires.
    pub action: Value,
    /// Where it stands among the rules.
    pub priority: u16,
}

/// `PUT …/authorization/policy/rules/{name}/enabled`.
#[derive(Debug, Clone, Serialize)]
pub struct RuleSwitch {
    /// Whether the rule is in service.
    pub enabled: bool,
}

/// `PUT …/authorization/policy/rule-order`.
#[derive(Debug, Clone, Serialize)]
pub struct RuleOrder {
    /// Every rule of the draft by name, first checked first.
    pub names: Vec<String>,
}

/// `PUT …/authorization/policy/default-action`.
#[derive(Debug, Clone, Serialize)]
pub struct DefaultAction {
    /// What a request no rule matched gets, as the API writes an action.
    pub default_action: Value,
}

/// `POST …/authorization/simulate`: a request that never happened.
#[derive(Debug, Clone, Serialize)]
pub struct SimulatedRequest {
    /// `live`, `draft` or a version number, as a string.
    pub version: String,
    /// The request path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The groups the made-up caller is in.
    pub groups: Vec<String>,
    /// `Low`, `Medium`, `High` or `Critical`.
    pub risk: String,
    /// The made-up caller's assurance level, such as `Aal1`.
    pub current_aal: String,
}

/// What the policy would do with a simulated request.
#[derive(Debug, Clone, Deserialize)]
pub struct Simulation {
    /// What would happen, as the API writes an action.
    pub action: Value,
    /// The rule that decided, absent when the default action did.
    #[serde(default)]
    pub matched_rule: Option<String>,
    /// Every rule checked, in order.
    pub evaluated_rules: Vec<RuleEvaluation>,
    /// The version it ran against.
    pub policy_version: u32,
}

/// How one rule was judged in a simulation.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleEvaluation {
    /// The rule's name.
    pub name: String,
    /// Whether every condition held.
    pub matched: bool,
}

/// An access request read back with its answer.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessRequestDetail {
    /// Handle used to answer or withdraw it.
    pub id: String,
    /// `pending`, `approved`, `denied`, `cancelled` or `expired`.
    pub status: String,
    /// Who answered it, absent until someone did.
    #[serde(default)]
    pub answered_by: Option<Principal>,
}

/// A principal as the API names it in a request or decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// `user`, `org_user`, `agent` or `consumer`.
    pub kind: String,
    /// What a decision on the request names.
    pub id: String,
}

/// `PUT …/authorization/access-request-policy`, and its answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequestLimit {
    /// The longest a request may ask for, in seconds.
    pub longest_seconds: i64,
}

/// `POST …/authorization/access-reviews`.
#[derive(Debug, Clone, Serialize)]
pub struct NewAccessReview {
    /// What it is called.
    pub name: String,
    /// The role or group it covers.
    pub scope: ReviewScope,
    /// The tenant users who decide.
    pub reviewer_ids: Vec<String>,
    /// When it is due, in RFC 3339.
    pub due: String,
    /// `keep_access` or `remove_access`, for whoever nobody decided on.
    pub unanswered: String,
}

/// What a review covers.
#[derive(Debug, Clone, Serialize)]
pub struct ReviewScope {
    /// `role` or `group`.
    pub kind: String,
    /// What deciding on the review names.
    pub id: String,
}

/// An access review as it reads back.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessReview {
    /// Handle used to read, decide and close it.
    pub id: String,
    /// `open`, `completed` or `cancelled`.
    pub status: String,
    /// How many holders it listed when it started.
    pub holder_count: u64,
    /// How many have no decision yet.
    pub pending_count: u64,
    /// How many are marked to go.
    pub remove_count: u64,
}

/// `POST …/authorization/access-reviews/{id}/decisions`.
#[derive(Debug, Clone, Serialize)]
pub struct ReviewDecision {
    /// `user`, `org_user`, `agent` or `consumer`.
    pub holder_kind: String,
    /// The holder's id.
    pub holder_id: String,
    /// `keep` or `remove`.
    pub choice: String,
}

/// `POST …/authorization/separation-rules`.
#[derive(Debug, Clone, Serialize)]
pub struct NewSeparationRule {
    /// What the rule is called.
    pub name: String,
    /// One of the two roles.
    pub first_role_id: String,
    /// The other role.
    pub second_role_id: String,
}

/// A separation-of-duties rule as it reads back.
#[derive(Debug, Clone, Deserialize)]
pub struct SeparationRule {
    /// Handle used to lift it.
    pub id: String,
    /// One of the two roles.
    pub first_role_id: String,
    /// The other role.
    pub second_role_id: String,
}

/// A permission of the tenant's own app, as a role or check names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPermission {
    /// The resource type's key.
    pub resource: String,
    /// What the relation lets the subject do to the object.
    pub action: String,
}

/// `POST …/authorization/roles`: a role carrying app permissions.
#[derive(Debug, Clone, Serialize)]
pub struct NewAppRole {
    /// Label shown when assigning it.
    pub name: String,
    /// The app permissions it carries.
    pub custom_permissions: Vec<AppPermission>,
}

/// `POST …/resource-types`.
#[derive(Debug, Clone, Serialize)]
pub struct NewResourceType {
    /// Its key, left of the colon in `resource:action`.
    pub key: String,
    /// What an operator sees.
    pub display_name: String,
    /// The verbs it accepts.
    pub actions: Vec<NewAction>,
    /// `Public`, `Internal`, `Confidential` or `Restricted`.
    pub data_class: String,
}

/// One verb a resource type accepts.
#[derive(Debug, Clone, Serialize)]
pub struct NewAction {
    /// What grants and rules name the level by.
    pub key: String,
    /// What an operator sees.
    pub display_name: String,
    /// Other actions on the same resource it confers.
    pub implies: Vec<String>,
}

/// One object of the tenant's app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppObject {
    /// The declared resource type.
    pub resource_type: String,
    /// Its key in the app.
    pub key: String,
}

/// Who holds a relation on an object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationSubject {
    /// `user`, `org_user`, `agent`, `consumer` or `group`.
    pub kind: String,
    /// What closing the grant names.
    pub id: String,
}

/// How an object is related.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationLink {
    /// `subject` holds `relation` on the object.
    Holds {
        /// One of the actions the object's type declares.
        relation: String,
        /// Who holds it.
        subject: RelationSubject,
    },
    /// The object sits under this parent.
    Under(AppObject),
}

/// `POST …/authorization/relationships`.
#[derive(Debug, Clone, Serialize)]
pub struct NewRelationship {
    /// The object the fact is about.
    pub object: AppObject,
    /// How it is related.
    pub link: RelationLink,
}

/// A relationship as it reads back.
#[derive(Debug, Clone, Deserialize)]
pub struct Relationship {
    /// Handle used to remove it.
    pub id: String,
    /// The object the fact is about.
    pub object: AppObject,
    /// How it is related.
    pub link: RelationLink,
}

/// One access question, in the check endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct AccessQuestion {
    /// The action, such as `read`.
    pub action: String,
    /// The declared resource type.
    pub resource_type: String,
    /// The object's key, or `None` for any object of the type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_key: Option<String>,
}

/// `POST …/authorization/check`: one question about one subject.
#[derive(Debug, Clone, Serialize)]
pub struct AccessCheck {
    /// The person, agent or app asked about.
    pub subject: Principal,
    /// What was asked, as the record keeps it.
    #[serde(flatten)]
    pub question: AccessQuestion,
}

/// `POST …/authorization/check/batch`.
#[derive(Debug, Clone, Serialize)]
pub struct AccessCheckBatch {
    /// The person, agent or app asked about.
    pub subject: Principal,
    /// The questions, in order.
    pub checks: Vec<AccessQuestion>,
}

/// The answer to one access check.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessAnswer {
    /// `allowed` or `denied`.
    pub decision: String,
    /// Why not, for a denial: `unknown_resource_type`, `undeclared_action`,
    /// `not_held` or `too_deep`.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The answers to a batch, in the order asked.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessAnswers {
    /// One answer per question.
    pub decisions: Vec<AccessAnswer>,
}

/// One recorded authorization decision.
#[derive(Debug, Clone, Deserialize)]
pub struct DecisionRecord {
    /// Whom it was about.
    pub subject: Principal,
    /// `allowed`, `denied` or `challenged`.
    pub verdict: String,
    /// What it was about and what decided it, as the API writes it.
    pub basis: Value,
}

/// `POST …/authorization/clearance-rules`.
#[derive(Debug, Clone, Serialize)]
pub struct NewClearanceRule {
    /// The app permission that clears.
    pub permission: AppPermission,
    /// `Confidential` or `Restricted`.
    pub up_to: String,
}

/// `PUT …/authorization/clearance-rules/{resource}/{action}`.
#[derive(Debug, Clone, Serialize)]
pub struct ClearanceLevel {
    /// `Confidential` or `Restricted`.
    pub up_to: String,
}

/// A rule letting holders of an app permission see data up to a level.
#[derive(Debug, Clone, Deserialize)]
pub struct ClearanceRules {
    /// Every rule; empty when nobody wrote one.
    pub rules: Vec<ClearanceRule>,
}

/// A rule letting holders of an app permission see data up to a level.
#[derive(Debug, Clone, Deserialize)]
pub struct ClearanceRule {
    /// The app permission that clears.
    pub permission: AppPermission,
    /// The highest data class it clears for.
    pub up_to: String,
}

/// What one principal holds now, and from where.
#[derive(Debug, Clone, Deserialize)]
pub struct PrincipalAccess {
    /// The roles given straight, each with its end.
    pub direct_roles: Vec<DirectRole>,
    /// The groups it was put in straight, each with its end.
    pub memberships: Vec<DirectMembership>,
    /// Every group it is in, straight or through a group above.
    pub groups: Vec<String>,
    /// The roles it holds through those groups.
    pub through_groups: Vec<RoleThroughGroup>,
}

/// A role given straight.
#[derive(Debug, Clone, Deserialize)]
pub struct DirectRole {
    /// The role the rule lifts clearance for.
    pub role: HeldRole,
    /// When it stops counting, or `None` for good.
    #[serde(default)]
    pub until: Option<String>,
}

/// A place in a group given straight.
#[derive(Debug, Clone, Deserialize)]
pub struct DirectMembership {
    /// The group's id.
    pub group_id: String,
    /// When it stops counting, or `None` for good.
    #[serde(default)]
    pub until: Option<String>,
}

/// A role held through a group.
#[derive(Debug, Clone, Deserialize)]
pub struct RoleThroughGroup {
    /// The group carrying it.
    pub group_id: String,
    /// The role that gave the caller this clearance.
    pub role: HeldRole,
}

/// A role by id and name.
#[derive(Debug, Clone, Deserialize)]
pub struct HeldRole {
    /// The role's id.
    pub id: String,
    /// The role's name.
    pub name: String,
}

/// `POST …/auth/break-glass`.
#[derive(Debug, Clone, Serialize)]
pub struct BreakGlass {
    /// The user who gets the access.
    pub user_id: String,
    /// Why it is needed.
    pub reason: String,
    /// How long it lasts, in seconds.
    pub duration_seconds: i64,
    /// The built-in permissions it grants.
    pub system_permissions: Vec<SystemPermission>,
}

/// The grant a break-glass request opened.
#[derive(Debug, Clone, Deserialize)]
pub struct BreakGlassGrant {
    /// Handle used to close it early.
    pub grant_id: String,
}

/// `POST …/auth/break-glass/revoke`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BreakGlassRevoke {
    /// The grant to close.
    pub grant_id: String,
}

/// `PUT …/break-glass-policy`: what a user may give themselves in an
/// emergency.
#[derive(Debug, Clone, Serialize)]
pub struct BreakGlassPolicy {
    /// Built-in permissions a user may give themselves.
    pub system_permissions: Vec<SystemPermission>,
    /// The tenant's own permissions a user may give themselves.
    pub custom_permissions: Vec<AppPermission>,
}
