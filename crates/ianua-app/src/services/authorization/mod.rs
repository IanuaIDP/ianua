//! Roles and grants several use cases share: who administers a tenant,
//! catalogue checks, separation of duties on every grant, what a principal
//! holds for the gateway, the roles a new user starts with, what a provider
//! hands out with nobody choosing, and revoking grants.

pub(crate) mod administrators;
pub(crate) mod catalogue_check;
pub(crate) mod duties;
pub mod grant_revocation;
pub(crate) mod held;
pub(crate) mod provider_grants;
pub(crate) mod starting_roles;
