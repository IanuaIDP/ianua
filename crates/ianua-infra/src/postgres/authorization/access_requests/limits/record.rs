//! A tenant's limit on access requests as its row holds it: read back
//! into the aggregate.

use ianua_domain::domains::authorization::request_policy::{
    AccessRequestPolicy, AccessRequestPolicyRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Lifetime;
use time::OffsetDateTime;

use crate::postgres::foundation::stored::Stored;

const REQUEST_POLICY: Stored = Stored("access request policy");

/// The limit as it is read. The store's checked queries fill it.
pub(super) struct RequestPolicyRecord {
    pub(super) longest_seconds: i64,
    pub(super) updated_at: OffsetDateTime,
}

impl RequestPolicyRecord {
    /// The policy the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the length is not one, or
    /// is longer than anyone may ask for.
    pub(super) fn into_policy(self) -> Result<AccessRequestPolicy<ResolvedTenant>, DomainError> {
        AccessRequestPolicy::reconstitute(AccessRequestPolicyRow {
            longest: REQUEST_POLICY.value("longest", Lifetime::seconds(self.longest_seconds))?,
            updated_at: self.updated_at,
        })
    }
}
