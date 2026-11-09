//! The stores of the authorization context: a tenant's roles, groups,
//! policies and the decisions made under them, each table under row-level
//! security.
//!
//! A ports file holding one store has it here; one holding several has a
//! folder of the same name, so the context reads as the app's ports do.
//! How a principal is kept in columns is written once, in `principals`.

mod access_requests;
mod access_reviews;
mod clearance;
mod decisions;
pub(crate) mod groups;
mod policies;
pub(crate) mod principals;
mod relationships;
mod resource_types;
pub(crate) mod roles;
mod separation;

pub use access_requests::{PgAccessRequestPolicyStore, PgAccessRequestStore};
pub use access_reviews::PgAccessReviewStore;
pub use clearance::PgClearanceRuleStore;
pub use decisions::PgDecisionRecordStore;
pub use groups::{PgGroupMembershipStore, PgGroupStore};
pub use policies::{PgAccessRecordStore, PgPolicyStore};
pub use relationships::PgRelationshipStore;
pub use resource_types::PgResourceTypeStore;
pub use roles::{
    PgRoleAssignmentStore, PgRoleDeletionUnitOfWork, PgRoleHolderQueries, PgRoleStore,
};
pub use separation::PgSeparationRuleStore;
