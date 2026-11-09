//! Delegations scoped to one resource or relation.

pub(crate) mod grant;
pub(crate) mod grant_relation;
pub(crate) mod revoke;
pub(crate) mod revoke_relation;
pub(in crate::use_cases::agents) mod sharing;
pub(in crate::use_cases::agents) mod usage;

pub use grant::{GrantResourcePorts, GrantResourceRequest, GrantResourceUseCase};
pub use grant_relation::{GrantResourceRelationUseCase, ResourceGrantPorts, ResourceGrantRequest};
pub use revoke::{RevokeResourcePorts, RevokeResourceRequest, RevokeResourceUseCase};
pub use revoke_relation::RevokeResourceRelationUseCase;
