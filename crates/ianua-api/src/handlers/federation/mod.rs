//! Federation handlers, by app area: connections, links, the SCIM switch,
//! the tenant as a SAML identity provider and its SAML apps, and single
//! logout.

pub mod connections;
pub mod idp;
pub mod links;
pub mod logout;
pub mod scim;
pub mod service_providers;
