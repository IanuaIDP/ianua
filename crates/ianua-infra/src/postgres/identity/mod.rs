//! The stores of the identity context: a tenant's users and what belongs
//! to them, each table under row-level security.
//!
//! A ports file holding one store has it in a file named after what it
//! keeps; one holding several stores of the same rows keeps them together.

mod attributes;
mod consents;
mod erasures;
mod exports;
mod impersonations;
mod imports;
mod invitations;
mod links;
pub(crate) mod users;

pub use attributes::{PgMetadataStore, PgUserAttributeStore};
pub use consents::PgConsentStore;
pub use erasures::PgErasureRequestStore;
pub use exports::PgDataExportStore;
pub use impersonations::PgSupportImpersonationStore;
pub use imports::PgUserImportStore;
pub use invitations::PgInvitationStore;
pub use links::{PgSignInLinkStore, PgVerificationTokenStore};
pub use users::PgUserStore;
