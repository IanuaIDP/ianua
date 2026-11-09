//! Fakes for the federation ports, by topic: connections and the accounts
//! linked through them, SAML as service provider and as identity provider,
//! the SAML messages peers send, OIDC, SCIM, and the sign-in codes a
//! federated sign-in hands back.

mod connections;
mod holdings;
mod oidc;
mod records;
mod saml;
mod saml_idp;
mod saml_messages;
mod scim;
mod scim_queries;
mod sessions;

pub use connections::*;
pub use holdings::*;
pub use oidc::*;
pub use records::*;
pub use saml::*;
pub use saml_idp::*;
pub use saml_messages::*;
pub use scim::*;
pub use scim_queries::*;
pub use sessions::*;
