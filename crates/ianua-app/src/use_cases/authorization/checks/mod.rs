//! Access checks for a tenant's apps, and the records of every
//! authorization decision.

pub(crate) mod access;
pub(crate) mod search_decisions;

pub use access::{AccessPorts, AccessUseCase, CheckAccessRequest};
pub use search_decisions::{SearchDecisionsPorts, SearchDecisionsRequest, SearchDecisionsUseCase};
