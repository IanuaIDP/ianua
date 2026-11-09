//! The catalog of what the installed integrations offer: their operations
//! and the events their services send, each with its guide.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::workflows::IntegrationCatalog;
use ianua_domain::domains::workflows::integration::events::{ServiceEventGuide, ServiceEventSpec};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationSpec};
use ianua_domain::shared::errors::DomainError;

use crate::integrations::installed::Installed;

/// Answers what the installed integrations offer, as they declare and
/// explain it now.
pub struct InstalledIntegrationCatalog {
    installed: Arc<Installed>,
}

impl InstalledIntegrationCatalog {
    /// A catalog of `installed`, the set the runner makes calls through.
    #[must_use]
    pub fn new(installed: Arc<Installed>) -> Self {
        Self { installed }
    }
}

#[async_trait]
impl IntegrationCatalog for InstalledIntegrationCatalog {
    async fn installed(&self) -> Result<Vec<IntegrationProfile>, DomainError> {
        Ok(self.installed.profiles())
    }

    async fn guides(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<OperationGuide>, DomainError> {
        Ok(self
            .installed
            .find(integration)
            .map(|found| found.guides().to_vec())
            .unwrap_or_default())
    }

    async fn offered(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<OperationSpec>, DomainError> {
        Ok(self
            .installed
            .find(integration)
            .map(|found| found.operations().to_vec())
            .unwrap_or_default())
    }

    async fn events(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<ServiceEventSpec>, DomainError> {
        Ok(self
            .installed
            .find(integration)
            .map(|found| found.events().to_vec())
            .unwrap_or_default())
    }

    async fn event_guides(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<ServiceEventGuide>, DomainError> {
        Ok(self
            .installed
            .find(integration)
            .map(|found| found.event_guides().to_vec())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::integration::AccountNeed;
    use ianua_integration::Integration;

    use super::*;
    use crate::integrations::installed::tests::{Idle, spec};

    fn catalog() -> InstalledIntegrationCatalog {
        let sheets = Idle::offering(
            "sheets",
            vec![
                spec("sheets", "append-row", AccountNeed::Account),
                spec("sheets", "read-range", AccountNeed::Account),
            ],
        );
        let chat = Idle::offering("chat", vec![spec("chat", "send", AccountNeed::Account)]);
        let integrations: Vec<Arc<dyn Integration>> = vec![Arc::new(sheets), Arc::new(chat)];
        let installed = Installed::new(integrations).unwrap();
        InstalledIntegrationCatalog::new(Arc::new(installed))
    }

    /// Every installed integration is listed once, as it presents itself.
    #[tokio::test]
    async fn every_installed_integration_is_listed_once() {
        let catalog = catalog();

        let profiles = catalog.installed().await.unwrap();

        let names: Vec<&str> = profiles
            .iter()
            .map(|profile| profile.title().as_str())
            .collect();
        assert_eq!(names, ["sheets", "chat"]);
    }

    /// An integration offers exactly the operations it declares, each with
    /// its guide.
    #[tokio::test]
    async fn an_integration_offers_what_it_declares() {
        let catalog = catalog();
        let sheets = IntegrationKey::new("sheets").unwrap();

        let offered = catalog.offered(&sheets).await.unwrap();
        let guides = catalog.guides(&sheets).await.unwrap();

        let names: Vec<&str> = offered
            .iter()
            .map(|spec| spec.operation().as_str())
            .collect();
        assert_eq!(names, ["append-row", "read-range"]);
        assert_eq!(guides.len(), 2);
    }

    /// An uninstalled integration has no catalog operations or guides.
    #[tokio::test]
    async fn an_integration_not_installed_offers_nothing() {
        let catalog = catalog();
        let payments = IntegrationKey::new("payments").unwrap();

        assert!(catalog.offered(&payments).await.unwrap().is_empty());
        assert!(catalog.guides(&payments).await.unwrap().is_empty());
    }
}
