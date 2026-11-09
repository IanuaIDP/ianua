//! The file a download, logo or integration picture address names.

use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::shared::security::secret::Secret;
use serde::Deserialize;

use crate::error::ApiError;

/// `/api/v1/files/download/{token}`: the sealed ticket a download link
/// carries.
#[derive(Deserialize)]
pub(crate) struct DownloadPath {
    token: String,
}

impl DownloadPath {
    /// The ticket, checked by the use case and never printed.
    #[must_use]
    pub(crate) fn into_token(self) -> Secret {
        Secret::new(self.token)
    }
}

/// `/api/v1/files/logos/{key}`: the tenant a logo address names.
#[derive(Deserialize)]
pub(crate) struct LogoPath {
    key: String,
}

impl LogoPath {
    /// The key, checked by the use case.
    #[must_use]
    pub(crate) fn into_key(self) -> String {
        self.key
    }
}

/// `/api/v1/files/integrations/{integration}/picture.svg`: the integration
/// whose picture is asked for.
#[derive(Deserialize)]
pub(crate) struct IntegrationPicturePath {
    integration: String,
}

impl IntegrationPicturePath {
    /// The integration named.
    ///
    /// # Errors
    ///
    /// - `422` when it is not an integration's name.
    pub(crate) fn integration(&self) -> Result<IntegrationKey, ApiError> {
        IntegrationKey::new(self.integration.as_str()).map_err(ApiError::validation)
    }
}
