//! Authorization use cases: roles, groups, policies, assignments, and the
//! governance around them: access requests and reviews, separation of
//! duties, relationships, access checks and clearance.

/// Just-in-time access: asking for a role or a group for a while.
pub mod access_requests;
/// Access reviews: who keeps a role or a group.
pub mod access_reviews;
mod audit_labels;
/// Access checks for a tenant's apps, and decision records.
pub mod checks;
/// Data clearance from the tenant's own app permissions.
pub mod clearance;
/// Groups, their members and the roles they carry.
pub mod groups;
/// Who holds what, and the sweep that clears ended holdings.
pub mod holdings;
mod lookup;
/// Access policies: managing them and trying them out.
pub mod policies;
/// Relationships on single objects of a tenant's app.
pub mod relationships;
/// The resource types a tenant declares for its own permissions.
pub mod resource_types;
/// Roles: creating them, changing them and handing them out.
pub mod roles;
/// Separation of duties: roles nobody holds together.
pub mod separation;
mod stewardship;
mod sweeps;
