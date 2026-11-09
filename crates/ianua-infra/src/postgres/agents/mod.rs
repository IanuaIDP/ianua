//! The stores of the agents context, each table under row-level security:
//! who an agent is, the keys it signs in with and the delegations it acts
//! under, the delegations it asks people for, what it may reach, the
//! agents seen at work that nobody registered, the checks the proxy makes
//! on every agent request, the runs and the approvals they wait on, the
//! reviews of an agent, and the models and tools it works with.
//!
//! A ports file holding one store has it here; one holding several has a
//! folder of the same name, so the context reads as the app's ports do.

pub(crate) mod identity;
mod model;
mod oversight;
mod reach;
mod requests;
mod run;
mod sightings;
mod standing;

pub use identity::{
    PgAgentAssertionReplayGuard, PgAgentCredentialStore, PgAgentStore, PgAttestationChallengeStore,
    PgDelegationStore,
};
pub use model::{PgModelProviderStore, PgToolStore};
pub use oversight::{PgAgentActivityStore, PgApprovalStore, PgReviewAssignmentStore};
pub use reach::{PgRelationshipResolver, PgResourceGrantStore, PgTaskTemplateStore};
pub use requests::PgDelegationRequestStore;
pub use run::{PgRunCancellation, PgRunLease, PgRunStore};
pub use sightings::PgAgentSightingStore;
pub use standing::{PgAgentExposureGate, PgAgentStandingCheck, PgDelegationRevocationCheck};
