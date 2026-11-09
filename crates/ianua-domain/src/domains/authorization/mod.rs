/// Whether someone may do an action on a resource type or one object of
/// it, as a tenant's app asks.
pub mod access_check;
/// Just-in-time access: asking for a role or a group for a while.
pub mod access_request;
/// Access reviews: who keeps a role or a group, decided by reviewers.
pub mod access_review;
/// A person's account as the records hold it now, and what it holds in a
/// tenant while nobody is signed in.
/// What a person holds, answering who may change the tenant's custom
/// attributes and how much of them they see.
pub mod attribute_schema;
pub mod authority;
/// Emergency break-glass access: what it grants, and who approved it.
pub mod break_glass;
/// Data clearance from the app permissions a person holds.
pub mod clearance;
/// The tenant's own directory, saying who belongs to which of its groups.
pub mod directory;
/// Domain events for the authorization bounded context.
pub mod events;
/// What a person holds, answering the rules of signing keys, classification
/// rules and signal streams.
pub mod foundation_rights;
/// What someone handing out permissions holds, and how far they may go.
pub mod granter;
pub mod group;
pub mod group_tree;
pub mod held;
/// Who is given a role or a group, and until when.
pub mod holding;
pub mod inviter;
/// What an API key may do in a tenant, worked out from its creator.
pub mod key_authority;
pub(crate) mod ladder;
/// Permissions: built-in system permissions and tenant-defined custom ones.
pub mod permission;
/// Policy-as-code: access rules and their simulation.
pub mod policy;
/// Who holds what on single objects of a tenant's app.
pub mod relationship;
/// The longest a tenant lets its people ask for access.
pub mod request_policy;
pub mod resource_type;
/// Who an overdue access review takes access from.
pub mod review_removals;
/// Roles: named sets of permissions within a tenant.
pub mod role;
pub mod role_assignment;
pub mod role_reassignment;
/// What a workflow run may do in a tenant, as the person it acts for.
pub mod run_authority;
/// Separation of duties: roles nobody may hold together.
pub mod separation;
pub mod stewardship;
/// What a support admin holds while acting as a tenant user.
pub mod support_acting;

#[cfg(test)]
pub(crate) mod fixtures;
