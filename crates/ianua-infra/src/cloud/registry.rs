//! The clouds this deployment drives: the factories the server configured
//! at start, answered from memory, so asking never waits.

use std::sync::Arc;

use ianua_app::ports::cloud::{CloudProviderFactory, CloudProviderRegistry};
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

/// The clouds the server configured, each with its factory, in the order
/// they were added.
#[derive(Default)]
pub struct ConfiguredCloudProviderRegistry {
    factories: Vec<Arc<dyn CloudProviderFactory>>,
}

impl ConfiguredCloudProviderRegistry {
    /// A registry driving no cloud yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// This registry with `factory` added, in place of one already added
    /// for the same cloud.
    #[must_use]
    pub fn with(mut self, factory: Arc<dyn CloudProviderFactory>) -> Self {
        let provider = factory.provider();
        self.factories.retain(|held| held.provider() != provider);
        self.factories.push(factory);
        self
    }
}

impl CloudProviderRegistry for ConfiguredCloudProviderRegistry {
    fn factory(
        &self,
        provider: CloudProvider,
    ) -> Result<Arc<dyn CloudProviderFactory>, DomainError> {
        self.factories
            .iter()
            .find(|held| held.provider() == provider)
            .cloned()
            .ok_or_else(|| {
                DomainError::invalid(message!(
                    "infra-this-deployment-does-not-connect-to",
                    format!(
                        "this deployment does not connect to {} accounts",
                        provider.as_str()
                    )
                ))
            })
    }

    fn available(&self) -> Vec<CloudProvider> {
        self.factories.iter().map(|held| held.provider()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::{CloudEndpoint, DigitalOceanCloudProviderFactory, GcpCloudProviderFactory};

    fn digital_ocean() -> Arc<dyn CloudProviderFactory> {
        Arc::new(DigitalOceanCloudProviderFactory::new(CloudEndpoint::Public).unwrap())
    }

    fn gcp() -> Arc<dyn CloudProviderFactory> {
        Arc::new(GcpCloudProviderFactory::new(CloudEndpoint::Public).unwrap())
    }

    /// A configured cloud is answered with its own factory.
    #[test]
    fn a_configured_cloud_is_served() {
        let registry = ConfiguredCloudProviderRegistry::new().with(digital_ocean());

        let factory = registry.factory(CloudProvider::DigitalOcean).unwrap();

        assert_eq!(factory.provider(), CloudProvider::DigitalOcean);
    }

    /// Selecting an unconfigured cloud returns a validation error even when another provider exists.
    #[test]
    fn an_unconfigured_cloud_is_refused() {
        let registry = ConfiguredCloudProviderRegistry::new().with(digital_ocean());

        let result = registry.factory(CloudProvider::Aws);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The clouds offered are the ones configured, in the order added, each
    /// once.
    #[test]
    fn the_clouds_offered_are_the_configured_ones() {
        let registry = ConfiguredCloudProviderRegistry::new()
            .with(gcp())
            .with(digital_ocean())
            .with(gcp());

        assert_eq!(
            registry.available(),
            vec![CloudProvider::DigitalOcean, CloudProvider::Gcp]
        );
    }

    /// An empty registry offers nothing and refuses every cloud.
    #[test]
    fn an_empty_registry_offers_nothing() {
        let registry = ConfiguredCloudProviderRegistry::new();

        assert!(registry.available().is_empty());
        assert!(registry.factory(CloudProvider::Gcp).is_err());
    }
}
