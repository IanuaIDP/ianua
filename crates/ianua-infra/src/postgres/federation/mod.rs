//! The stores of the federation context: a tenant's connections to outside
//! identity providers, the accounts linked through them, SAML apps and
//! SCIM provisioning, each table under row-level security.
//!
//! A ports file holding one store has it here; one holding several has a
//! folder of the same name, so the context reads as the app's ports do.

pub(crate) mod connections;
mod oidc;
mod saml;
mod saml_idp;
mod saml_messages;
mod scim;

pub use connections::{
    PgConnectionStore, PgFederatedLinkStore, PgMappedHoldingsStore, PgMetadataFollowers,
};
pub use oidc::PgOidcFlowStore;
pub use saml::{PgSamlAssertionLedger, PgSamlRequestStore};
pub use saml_idp::{PgHeldSamlSignInStore, PgSamlAppSessionStore, PgSamlServiceProviderStore};
pub use saml_messages::{PgProviderSessionStore, PgSamlLogoutLedger, PgSentLogoutRequestStore};
pub use scim::{PgScimGroupQueries, PgScimStore, PgScimUserQueries};
