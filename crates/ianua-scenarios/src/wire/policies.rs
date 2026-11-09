//! A tenant's policy, the rules every request through the gateway is held
//! to beside its route's, and the groups its rules name.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `POST …/authorization/groups`.
#[derive(Debug, Clone, Serialize)]
pub struct NewGroup {
    /// Label shown when selecting the group for grants and policy conditions.
    pub name: String,
}

/// A group made.
#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    /// Handle used to add members and assign roles to this group.
    pub id: String,
}

/// Principal reference returned by group membership and access-review listings.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupMember {
    /// `user` for a tenant user.
    pub kind: String,
    /// Identifier resolved according to the accompanying principal kind.
    pub id: String,
}

/// `POST …/authorization/groups/{id}/members`: a tenant user in a group.
#[derive(Debug, Clone, Serialize)]
pub struct NewGroupMember {
    /// `user` for a tenant user.
    pub kind: String,
    /// Tenant account to add to the group's membership.
    pub id: String,
}

/// `POST …/authorization/groups/{id}/roles`: the role a group holds.
#[derive(Debug, Clone, Serialize)]
pub struct GroupRole {
    /// The role's id.
    pub role_id: String,
}

/// `POST …/authorization/policy/draft`: a blank draft letting through
/// what no rule refuses.
#[derive(Debug, Clone, Serialize)]
pub struct BlankDraft {
    /// `blank`.
    pub from: String,
    /// What a request no rule matches gets, as the API writes an action.
    pub default_action: Value,
}

/// `POST …/authorization/policy/rules`.
#[derive(Debug, Clone, Serialize)]
pub struct NewRule {
    /// Label explaining this condition and action in the policy editor.
    pub name: String,
    /// What a request must match, as the API writes conditions.
    pub conditions: Vec<Value>,
    /// What a matching request gets.
    pub action: Value,
    /// Where it stands among the rules.
    pub priority: u16,
}

/// `POST …/authorization/access-requests`: a place in a group asked for,
/// why, and for how long.
#[derive(Debug, Clone, Serialize)]
pub struct AskForGroup {
    /// The group asked for.
    pub asked: AskedGroup,
    /// Why it is needed.
    pub reason: String,
    /// How long it is needed, in seconds from the approval.
    pub length_seconds: i64,
}

/// A group, as an access request names it.
#[derive(Debug, Clone, Serialize)]
pub struct AskedGroup {
    /// `group`, or `role` to ask for a role instead.
    pub kind: &'static str,
    /// The group's id.
    pub id: String,
}

/// Approval progress for a person's request to join a group temporarily.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessRequest {
    /// Handle used to decide, cancel or inspect the pending request.
    pub id: String,
    /// `pending`, `approved`, `denied`, `cancelled` or `expired`.
    pub status: String,
}

/// A version of the policy.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    /// `Draft`, `InReview`, `Active` and so on.
    pub status: String,
    /// Its number.
    pub version: u32,
}

/// One holder an access review lists, what was decided and what is
/// suggested beside them.
#[derive(Debug, Clone, Deserialize)]
pub struct ReviewItem {
    /// Principal whose continued membership the reviewer must decide.
    pub holder: GroupMember,
    /// `keep` or `remove` once a reviewer decided.
    #[serde(default)]
    pub choice: Option<String>,
    /// What is suggested beside them, when anything is.
    #[serde(default)]
    pub suggestion: Option<ReviewSuggestion>,
}

/// Keep or remove suggested beside a holder, and why.
#[derive(Debug, Clone, Deserialize)]
pub struct ReviewSuggestion {
    /// `keep` or `remove`.
    pub choice: String,
    /// Why.
    pub reason: String,
}
