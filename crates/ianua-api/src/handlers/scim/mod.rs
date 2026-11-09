//! SCIM 2.0 provisioning handlers (RFC 7644), called by a tenant's
//! directory with the tenant's SCIM bearer token and answering in SCIM's
//! own format: discovery, users and groups.

pub mod discovery;
pub mod groups;
pub mod users;
