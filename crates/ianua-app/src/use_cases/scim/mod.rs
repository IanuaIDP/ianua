//! SCIM 2.0 provisioning: the tenant's directory, such as Okta or an HR
//! system, keeps the tenant's users and groups in step with its own.
//!
//! The directory signs in with the tenant's SCIM bearer token, and only
//! while the tenant keeps SCIM switched on. No person is signed in, so the
//! domain decides what the directory may do from the endpoint itself: it
//! opens accounts, edits profiles, lets in and shuts out accounts that hold
//! no built-in permission, and keeps the members of the groups it made. It
//! never proves an address, so every one it sends is confirmed by link, and
//! it never touches a group a person keeps in the dashboard.
//!
//! Protocol details, JSON shapes, filters and paging parameters, are the
//! HTTP adapter's concern. These use cases take and return domain values.

/// The directory's groups and who is in them.
pub mod groups;
mod sync;
/// The directory's users.
pub mod users;
