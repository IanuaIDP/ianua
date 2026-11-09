//! The stores of the tenant context, in the platform database: the
//! tenants, their setups, teardowns and clones, the schemas some live in
//! and how every node routes to them, and the removal of a deleted
//! tenant's rows.

mod clones;
mod copies;
pub(crate) mod databases;
mod purger;
mod setups;
mod teardowns;
mod tenants;

pub use clones::PgTenantCloneStore;
pub use copies::PgClonePartCopier;
pub use databases::{
    PgTenantDatabaseProvisioner, TenantDatabaseFollower, TenantSchemaAccess, load_tenant_databases,
    migrate_tenant_schemas,
};
pub use purger::PgTenantDataPurger;
pub use setups::PgTenantSetupStore;
pub use teardowns::PgTenantTeardownStore;
pub use tenants::PgTenantStore;
