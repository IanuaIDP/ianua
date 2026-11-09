//! Integration picture: the picture an installed integration carries, for
//! anyone, since it is the same on every deployment and holds nothing of a
//! tenant's.

use std::sync::Arc;

use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::integration::profile::IntegrationPicture;
use ianua_domain::message;

use crate::error::{AppError, OrInternal};
use crate::ports::workflows::IntegrationCatalog;
use crate::use_case::Query;

/// The ports [`IntegrationPictureUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct IntegrationPicturePorts {
    /// The integrations installed.
    pub catalog: Arc<dyn IntegrationCatalog>,
}

/// Answers an installed integration's picture.
pub struct IntegrationPictureUseCase {
    ports: IntegrationPicturePorts,
}

impl IntegrationPictureUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: IntegrationPicturePorts) -> Self {
        Self { ports }
    }
}

impl Query for IntegrationPictureUseCase {
    type Caller = ();
    type Input = IntegrationKey;
    type Output = Result<IntegrationPicture, AppError>;

    /// The picture the integration installed under `key` carries, checked
    /// to hold only shapes when the integration was built. A step the
    /// platform itself offers carries none: the dashboard draws it.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when no integration is installed under `key`,
    ///   or the one installed is the platform's own.
    /// - `AppError::Internal` when the catalog cannot be read.
    async fn execute(&self, (): &(), key: IntegrationKey) -> Result<IntegrationPicture, AppError> {
        let installed = self.ports.catalog.installed().await.or_internal()?;
        installed
            .into_iter()
            .find(|profile| profile.key() == &key)
            .and_then(|profile| profile.picture().cloned())
            .ok_or_else(|| AppError::NotFound(message!("workflows-integration", "integration")))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::integration::OperationSpec;
    use ianua_domain::types::ActionClass;

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::workflows::{FakeIntegrationCatalog, SHEETS, append_row};

    fn use_case(offered: Vec<OperationSpec>) -> IntegrationPictureUseCase {
        IntegrationPictureUseCase::new(IntegrationPicturePorts {
            catalog: Arc::new(FakeIntegrationCatalog::offering(offered)),
        })
    }

    /// Sheets is installed: its own picture comes back.
    #[test]
    fn an_installed_integration_s_picture_is_answered() {
        let sheets = IntegrationKey::new(SHEETS).unwrap();

        let picture = block_on(use_case(vec![append_row(ActionClass::Write)]).execute(&(), sheets));

        assert!(picture.unwrap().as_str().starts_with("<svg"));
    }

    /// Requesting a picture for an uninstalled integration returns not found.
    #[test]
    fn an_integration_not_installed_has_no_picture() {
        let picture =
            block_on(use_case(Vec::new()).execute(&(), IntegrationKey::new("gitea").unwrap()));

        assert!(matches!(picture, Err(AppError::NotFound(_))), "{picture:?}");
    }
}
