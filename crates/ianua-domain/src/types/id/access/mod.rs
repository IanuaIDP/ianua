//! Ids of who may do what: roles, groups, relationships and the governance around them.

/// Id of an emergency access grant.
pub(crate) mod break_glass_grant;
/// Id of a recorded authorization decision.
pub(crate) mod decision_record;
/// Id of a group of users.
pub(crate) mod group;
/// Id of one relationship on an object of a tenant's app.
pub(crate) mod relationship;
/// Id of a request for just-in-time access.
pub(crate) mod request;
/// Id of a resource type in a tenant's permission catalogue.
pub(crate) mod resource_type;
/// Id of an access review campaign.
pub(crate) mod review;
/// Id of a role.
pub(crate) mod role;
/// Id of a separation-of-duties rule.
pub(crate) mod separation_rule;

pub use break_glass_grant::BreakGlassGrantId;
pub use decision_record::DecisionRecordId;
pub use group::GroupId;
pub use relationship::RelationshipId;
pub use request::AccessRequestId;
pub use resource_type::ResourceTypeId;
pub use review::AccessReviewId;
pub use role::RoleId;
pub use separation_rule::SeparationRuleId;
