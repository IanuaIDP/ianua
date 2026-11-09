//! Federation use cases: identity provider connections, the accounts
//! linked through them, SCIM provisioning, this platform answering the
//! tenant's SAML apps as their identity provider, and single logout both
//! ways.

pub mod connections;
pub mod idp;
pub mod links;
pub mod logout;
pub(crate) mod lookup;
pub mod scim;
pub mod service_providers;
