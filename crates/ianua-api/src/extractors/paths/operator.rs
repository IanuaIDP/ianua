//! The operator, key, impersonation grant and dead job a platform request
//! names.

use ianua_domain::types::{ImpersonationGrantId, JobId, KeyPrefix, OperatorId};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

/// `/api/v1/operators/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct OperatorPath {
    id: Uuid,
}

impl OperatorPath {
    /// The operator named.
    #[must_use]
    pub(crate) fn operator(&self) -> OperatorId {
        OperatorId::from_uuid(self.id)
    }
}

/// `/api/v1/operators/{id}/keys/{key_prefix}/...`.
#[derive(Deserialize)]
pub(crate) struct OperatorKeyPath {
    key_prefix: String,
}

impl OperatorKeyPath {
    /// The key named, by its visible start.
    ///
    /// # Errors
    ///
    /// `422` when the segment is not a valid key prefix.
    pub(crate) fn key(&self) -> Result<KeyPrefix, ApiError> {
        KeyPrefix::new(self.key_prefix.as_str()).map_err(ApiError::validation)
    }
}

/// `/api/v1/operators/dead-jobs/{id}/...`.
#[derive(Deserialize)]
pub(crate) struct DeadJobPath {
    id: Uuid,
}

impl DeadJobPath {
    /// The job named.
    #[must_use]
    pub(crate) fn job(&self) -> JobId {
        JobId::from_uuid(self.id)
    }
}

/// `/api/v1/operators/grants/{id}`.
#[derive(Deserialize)]
pub(crate) struct ImpersonationGrantPath {
    id: Uuid,
}

impl ImpersonationGrantPath {
    /// The grant named.
    #[must_use]
    pub(crate) fn grant(&self) -> ImpersonationGrantId {
        ImpersonationGrantId::from_uuid(self.id)
    }
}
