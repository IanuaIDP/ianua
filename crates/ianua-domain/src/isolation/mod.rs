//! Scope markers for the two identity planes.
//!
//! A type parameter says which plane an entity belongs to:
//! - **Tenant** (`T: TenantScope`): a tenant's users, roles, routes and
//!   the rest of what the tenant runs.
//! - **Organization** (`ResolvedOrganization`): the people who administer
//!   an organization and its tenants.
//!
//! The types keep the planes apart. A tenant entity cannot be used where an
//! organization one is expected. A tenant-scoped entity exists only once a
//! tenant has been resolved.
//!
//! The types do not keep one tenant's entity apart from another tenant's.
//! Every tenant is the same type,
//! [`ResolvedTenant`](crate::isolation::scope::ResolvedTenant), so the
//! compiler cannot tell two tenants apart. That separation happens at run
//! time. The application opens its stores for the tenant it resolved, and
//! the database's row-level security filters every read and write by that
//! tenant. Code that compares two tenant-scoped records must compare their
//! tenant ids itself.
//!
//! Security records both planes share (`MfaEnrollment`, `RecoveryCodeSet`,
//! `TrustedDevice`) use [`SecurityScope`](crate::isolation::SecurityScope).
//! [`ResolvedTenant`](crate::isolation::scope::ResolvedTenant) and
//! [`ResolvedOrganization`](organization::scope::ResolvedOrganization)
//! implement it.

pub mod organization;
mod tenant;

/// Marker trait for the security records both identity planes share.
///
/// Both [`ResolvedTenant`](crate::isolation::scope::ResolvedTenant) and
/// [`ResolvedOrganization`](organization::scope::ResolvedOrganization)
/// implement it. So `MfaEnrollment<S>`, `RecoveryCodeSet<S>` and
/// `TrustedDevice<S>` work for both planes, and a tenant record and an
/// organization record stay different types.
pub trait SecurityScope: Send + Sync + 'static {}

/// The tenant scope proof every tenant-branded type carries.
pub use tenant::scope;
