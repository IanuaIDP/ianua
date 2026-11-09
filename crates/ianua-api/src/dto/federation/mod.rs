//! Federation bodies, by app area: connections and what they let their
//! provider do, links, home realm discovery, the SCIM switch, the tenant's
//! SAML apps, SAML messages and metadata, and where it all lives.

pub mod connections;
pub mod discovery;
pub mod encryption;
pub mod groups;
pub mod idp;
pub mod links;
pub mod messages;
pub mod provider_config;
pub mod scim;
pub mod service_providers;
pub mod site;
