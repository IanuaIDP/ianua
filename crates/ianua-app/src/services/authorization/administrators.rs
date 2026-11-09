//! Who administers a tenant, as its access records show.

use ianua_domain::types::UserId;

use crate::error::AppError;
use crate::ports::authorization::AccessRecords;
use crate::tenancy::ScopedTenant;

/// The administrators `records` show in `tenant`.
///
/// # Errors
///
/// `AppError::Domain` when the records do not hold together.
pub(crate) fn administrators_in(
    records: &AccessRecords,
    tenant: &ScopedTenant,
) -> Result<Vec<UserId>, AppError> {
    records
        .access(**tenant)
        .grants
        .administrators()
        .map_err(AppError::from_domain)
}
