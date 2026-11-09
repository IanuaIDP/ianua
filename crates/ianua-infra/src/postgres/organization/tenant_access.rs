//! Which organization a tenant belongs to, and the access it grants its
//! members: the stores of `ports/organization/tenant_access.rs`.

mod standing;
mod tenant_grants;

pub use standing::PgTenantMemberRoster;
pub use tenant_grants::PgOrgTenantGrantStore;
