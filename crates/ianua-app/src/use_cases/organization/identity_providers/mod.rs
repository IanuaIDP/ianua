//! The organization's own identity provider: the company directory its
//! members sign in to the dashboard through, over SAML or OIDC.
//!
//! An organization has one. It is added switched off and trusting nothing
//! the provider says; an owner or admin then checks it, switches it on,
//! and decides how far its word on addresses and factors counts.

pub(crate) mod add;
pub(crate) mod change;
pub(crate) mod get;
pub(in crate::use_cases::organization) mod lookup;
pub(in crate::use_cases::organization) mod provider_config;
pub(crate) mod remove;
pub(crate) mod switch;

pub use add::{AddOrgPorts, AddOrgRequest, AddOrgUseCase};
pub use change::{ChangeOrgPorts, ChangeOrgRequest, ChangeOrgUseCase, OrgProviderEdit};
pub use get::{GetOrgPorts, GetOrgUseCase};
pub use remove::{RemoveOrgPorts, RemoveOrgUseCase};
pub use switch::{SwitchOrgPorts, SwitchOrgRequest, SwitchOrgUseCase};
