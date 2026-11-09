//! Whether a user or any principal exists: the reads other contexts ask
//! before they link to one, within a tenant and across tenants.

mod principals;
mod users;

pub use principals::PgPrincipalExistenceChecker;
pub use users::{PgCrossTenantUserChecker, PgUserExistenceChecker};
