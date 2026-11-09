//! The organization's own identity provider, the dashboard sign-ins waiting
//! on its answer, and the SAML assertions it has spent: the stores of
//! `ports/organization/identity_providers.rs`.

mod connections;
mod saml_assertions;
mod sso_requests;

pub use connections::PgOrgIdentityProviderStore;
pub use saml_assertions::PgOrgSamlAssertionLedger;
pub use sso_requests::PgOrgSsoRequestStore;
