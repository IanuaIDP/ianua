//! The signing key a crypto request names.

use ianua_domain::types::KeyId;
use serde::Deserialize;

use crate::error::ApiError;

/// `.../crypto/keys/{id}/...`: a key by its `kid`.
#[derive(Deserialize)]
pub(crate) struct SigningKeyPath {
    id: String,
}

impl SigningKeyPath {
    /// The key named.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the path does not hold a valid `kid`.
    pub(crate) fn key(&self) -> Result<KeyId, ApiError> {
        KeyId::new(self.id.as_str()).map_err(ApiError::validation)
    }
}
