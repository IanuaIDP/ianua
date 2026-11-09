//! Reading the attribute schema a tenant declared, which every use case that
//! resolves a value, filter or sort against it starts from.

use ianua_domain::domains::identity::attribute::MetadataSchema;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserAttributeStore;
use crate::tenancy::ScopedTenant;

/// Every attribute the tenant declared, archived ones included, as a schema
/// to resolve against.
///
/// # Errors
///
/// Returns `AppError::Internal` on storage failure.
pub(in crate::use_cases::identity) async fn declared_schema(
    store: &dyn UserAttributeStore,
    tenant: &ScopedTenant,
) -> Result<MetadataSchema<ResolvedTenant>, AppError> {
    let declared = store.load_schema(tenant).await.or_internal()?;
    Ok(MetadataSchema::new(declared))
}
