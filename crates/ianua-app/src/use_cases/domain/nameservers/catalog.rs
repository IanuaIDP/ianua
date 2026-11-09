//! Load the catalog: every zone tenants delegated to us, settled by the
//! domain's rules on which of them answer.
//!
//! Asked by the nameservers on a timer, with no one behind the question: a
//! resolver's query carries no caller, and the catalog answers every
//! resolver alike.

use std::sync::Arc;

use ianua_domain::domains::tenant::custom_domains::dns_zone::{Authority, ZoneCatalog};

use crate::error::AppError;
use crate::ports::domain::DnsZoneReader;
use crate::use_case::Query;

/// The ports [`LoadCatalogUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct LoadCatalogPorts {
    /// Reads every zone, whichever tenant holds it.
    pub zones: Arc<dyn DnsZoneReader>,
}

/// Loads the catalog the nameservers answer from.
pub struct LoadCatalogUseCase {
    ports: LoadCatalogPorts,
    authority: Authority,
}

impl LoadCatalogUseCase {
    /// A use case reading through `ports`, every zone answering under
    /// `authority`.
    #[must_use]
    pub fn new(ports: LoadCatalogPorts, authority: Authority) -> Self {
        Self { ports, authority }
    }
}

impl Query for LoadCatalogUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<ZoneCatalog, AppError>;

    /// Reads every zone and keeps the ones the domain lets answer: proven
    /// zones only, and of two tenants' zones nesting, the enclosing one.
    ///
    /// # Errors
    ///
    /// [`AppError::Internal`] when the zones cannot be read.
    async fn execute(&self, (): &(), (): ()) -> Self::Output {
        let zones = self
            .ports
            .zones
            .load_all_zones()
            .await
            .map_err(AppError::from_domain)?;
        Ok(ZoneCatalog::new(zones, self.authority.clone()))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::custom_domains::dns_zone::{
        HeldZone, QueryKind, RecordKind, RecordSet, RecordValue, Resolution, Serial, Ttl, Zone,
        ZoneStanding,
    };
    use ianua_domain::test_support::builders::{domain_name, record_name};
    use ianua_domain::types::{IpAddress, TenantId};

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::domain::FakeDnsZoneReader;

    fn authority() -> Authority {
        Authority::new(record_name("hostmaster.ianua.test"))
    }

    /// Acme's zone for `auth.acme.test`, answering `api.auth.acme.test`
    /// with one address, standing as `standing` says.
    fn acme_zone(standing: ZoneStanding) -> HeldZone {
        let address = RecordSet::new(
            record_name("api.auth.acme.test"),
            Ttl::standard(),
            vec![RecordValue::Address(
                IpAddress::new("198.51.100.1").unwrap(),
            )],
        )
        .unwrap();
        let zone = Zone::new(
            domain_name("auth.acme.test"),
            Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()),
            vec![address],
            vec![domain_name("abc123.ns1.ianua.test")],
        )
        .unwrap();
        HeldZone {
            zone,
            owner: TenantId::new(),
            standing,
        }
    }

    fn load(reader: FakeDnsZoneReader) -> Result<ZoneCatalog, AppError> {
        let use_case = LoadCatalogUseCase::new(
            LoadCatalogPorts {
                zones: Arc::new(reader),
            },
            authority(),
        );
        block_on(use_case.execute(&(), ()))
    }

    fn answers_api(catalog: &ZoneCatalog) -> bool {
        let found = catalog.answer(
            &record_name("api.auth.acme.test"),
            QueryKind::Record(RecordKind::A),
        );
        matches!(found, Resolution::Found { .. })
    }

    /// Acme proved `auth.acme.test`. The catalog answers for it.
    #[test]
    fn a_proven_zone_answers() {
        let catalog = load(FakeDnsZoneReader::Holding(vec![acme_zone(
            ZoneStanding::Proven,
        )]))
        .unwrap();

        assert!(answers_api(&catalog));
    }

    /// An unproven zone contributes no catalog entries or address answers,
    /// even when its stored records contain the requested name.
    #[test]
    fn an_unproven_zone_is_loaded_but_answers_nothing() {
        let catalog = load(FakeDnsZoneReader::Holding(vec![acme_zone(
            ZoneStanding::Unproven,
        )]))
        .unwrap();

        assert!(!answers_api(&catalog));
        assert!(catalog.is_empty());
    }

    /// A store that cannot be read fails the load, so the nameservers keep
    /// answering from the catalog they hold.
    #[test]
    fn an_unreachable_store_fails_the_load() {
        let loaded = load(FakeDnsZoneReader::Unreachable);

        assert!(matches!(loaded, Err(AppError::Internal(_))));
    }
}
