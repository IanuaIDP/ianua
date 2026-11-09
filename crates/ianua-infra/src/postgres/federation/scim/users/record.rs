//! The users a SCIM filter picks, read back through the identity context's
//! own mapper of the users table, so a user reads the same however it was
//! found.

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;

use crate::postgres::identity::users::record::UserRecord;

/// The users `records` hold, each name checked against `limits`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first record that does
/// not read back.
pub(super) fn users_from(
    records: Vec<UserRecord>,
    limits: &DomainLimits,
) -> Result<Vec<User<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(|record| record.into_user(limits))
        .collect()
}
