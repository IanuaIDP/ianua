//! Where an address is, on a deployment that names no city database: never
//! known, so the risk checks that read a country read none, rather than a
//! guess.

use async_trait::async_trait;
use ianua_app::ports::authentication::Geolocator;
use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::IpAddress;

/// A geolocator with no database: every address is unknown.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGeolocator;

#[async_trait]
impl Geolocator for NoGeolocator {
    async fn locate(&self, _ip: &IpAddress) -> Result<Option<IpGeolocation>, DomainError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a geolocation database, an address returns no location.
    #[tokio::test]
    async fn every_address_is_unknown() {
        let address = IpAddress::new("203.0.113.7").unwrap();

        let located = NoGeolocator.locate(&address).await.unwrap();

        assert!(located.is_none());
    }
}
