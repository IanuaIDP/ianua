//! The catalog the listeners answer from, and the loop that loads it from
//! the database, for a nameserver in the cluster.
//!
//! It is loaded whole and swapped whole, never edited, so a query is
//! answered from one version of every zone. A load that fails keeps the
//! catalog loaded before it: zones a few seconds old still answer
//! correctly, where an emptied catalog would refuse every name we hold.
//!
//! Before the first load the catalog is empty and every query is refused.
//! A resolver retries a refusal, where it would cache a made-up `NXDOMAIN`
//! for the whole negative TTL.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ianua_app::use_case::Query;
use ianua_app::use_cases::domain::nameservers::LoadCatalogUseCase;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{Authority, ZoneCatalog};
use ianua_domain::shared::errors::causes;

/// The catalog the listeners answer from, swapped whole on each load.
///
/// [`ArcSwap`] rather than a lock: reads far outnumber writes, and a query
/// must never wait on a load.
pub(crate) type SharedCatalog = Arc<ArcSwap<ZoneCatalog>>;

/// The first wait after a load failed. It doubles on each failure, up to
/// the refresh interval.
const FIRST_RETRY: Duration = Duration::from_millis(250);

/// How a load went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Loaded {
    /// A new catalog is answering.
    Swapped,
    /// The load failed, and the catalog before it keeps answering.
    Kept,
}

/// Loads the catalog through the use case and swaps it in.
pub(crate) struct CatalogLoader {
    catalog: SharedCatalog,
    load: LoadCatalogUseCase,
    refresh: Duration,
}

/// A catalog holding nothing, answered for by `authority`, which refuses
/// every query until the first load swaps zones in.
pub(crate) fn empty_catalog(authority: Authority) -> SharedCatalog {
    Arc::new(ArcSwap::from_pointee(ZoneCatalog::empty(authority)))
}

impl CatalogLoader {
    /// A loader swapping `load`'s catalog into `catalog` every `refresh`.
    pub(crate) fn new(load: LoadCatalogUseCase, catalog: SharedCatalog, refresh: Duration) -> Self {
        Self {
            catalog,
            load,
            refresh,
        }
    }

    /// Loads the catalog once and swaps it in, or keeps the one before it
    /// when the load fails.
    pub(crate) async fn load(&self) -> Loaded {
        match self.load.execute(&(), ()).await {
            Ok(loaded) => {
                tracing::info!(zones = loaded.len(), "dns zones loaded");
                self.catalog.store(Arc::new(loaded));
                Loaded::Swapped
            }
            Err(error) => {
                tracing::error!(cause = %causes(&error), "dns zones not loaded; the catalog before keeps answering");
                Loaded::Kept
            }
        }
    }

    /// Loads the catalog every refresh interval for ever, sooner again
    /// after a load that failed, starting from how the first load went.
    pub(crate) async fn keep_fresh(self, first: Loaded) {
        let mut backoff = Backoff::new(self.refresh);
        let mut loaded = first;
        loop {
            tokio::time::sleep(backoff.after(loaded)).await;
            loaded = self.load().await;
        }
    }
}

/// How long to wait before the next load.
#[derive(Debug)]
struct Backoff {
    refresh: Duration,
    retry: Duration,
}

impl Backoff {
    /// Waits of `refresh` while loads succeed.
    fn new(refresh: Duration) -> Self {
        Self {
            refresh,
            retry: FIRST_RETRY.min(refresh),
        }
    }

    /// The wait after a load that went as `loaded`: the refresh interval
    /// after a swap; after a failure [`FIRST_RETRY`] at first, doubling
    /// while loads keep failing, never past the refresh interval.
    fn after(&mut self, loaded: Loaded) -> Duration {
        match loaded {
            Loaded::Swapped => {
                self.retry = FIRST_RETRY.min(self.refresh);
                self.refresh
            }
            Loaded::Kept => {
                let wait = self.retry;
                self.retry = (self.retry * 2).min(self.refresh);
                wait
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::domain::FakeDnsZoneReader;
    use ianua_app::use_cases::domain::nameservers::LoadCatalogPorts;
    use ianua_domain::domains::tenant::custom_domains::dns_zone::{
        HeldZone, QueryKind, RecordKind, RecordName, RecordSet, RecordValue, Resolution, Serial,
        Ttl, Zone, ZoneStanding,
    };
    use ianua_domain::types::{DomainName, IpAddress, TenantId};

    use super::*;

    const REFRESH: Duration = Duration::from_secs(15);

    fn authority() -> Authority {
        Authority::new(RecordName::new("hostmaster.ianua.test").unwrap())
    }

    fn acme() -> HeldZone {
        let set = RecordSet::new(
            RecordName::new("api.auth.acme.test").unwrap(),
            Ttl::standard(),
            vec![RecordValue::Address(
                IpAddress::new("198.51.100.1").unwrap(),
            )],
        )
        .unwrap();
        HeldZone {
            zone: Zone::new(
                DomainName::new("auth.acme.test").unwrap(),
                Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()),
                vec![set],
                vec![DomainName::new("abc123.ns1.ianua.test").unwrap()],
            )
            .unwrap(),
            owner: TenantId::new(),
            standing: ZoneStanding::Proven,
        }
    }

    fn loader(reader: FakeDnsZoneReader, catalog: &SharedCatalog) -> CatalogLoader {
        let load = LoadCatalogUseCase::new(
            LoadCatalogPorts {
                zones: Arc::new(reader),
            },
            authority(),
        );
        CatalogLoader::new(load, Arc::clone(catalog), REFRESH)
    }

    fn answers_api(catalog: &SharedCatalog) -> bool {
        let found = catalog.load().answer(
            &RecordName::new("api.auth.acme.test").unwrap(),
            QueryKind::Record(RecordKind::A),
        );
        matches!(found, Resolution::Found { .. })
    }

    /// Before the first load nothing is answered: every query is refused.
    #[test]
    fn the_catalog_refuses_before_the_first_load() {
        let catalog = empty_catalog(authority());

        assert!(!answers_api(&catalog));
        assert!(catalog.load().is_empty());
    }

    /// A load swaps the new catalog in for the listeners.
    #[tokio::test]
    async fn a_load_swaps_the_catalog_in() {
        let catalog = empty_catalog(authority());
        let loader = loader(FakeDnsZoneReader::Holding(vec![acme()]), &catalog);

        let loaded = loader.load().await;

        assert_eq!(loaded, Loaded::Swapped);
        assert!(answers_api(&catalog));
    }

    /// An unreachable database leaves the loaded catalog in place, so
    /// Acme's API name still resolves.
    #[tokio::test]
    async fn a_failed_load_keeps_the_catalog_before() {
        let catalog = empty_catalog(authority());
        loader(FakeDnsZoneReader::Holding(vec![acme()]), &catalog)
            .load()
            .await;
        let failing = loader(FakeDnsZoneReader::Unreachable, &catalog);

        let loaded = failing.load().await;

        assert_eq!(loaded, Loaded::Kept);
        assert!(answers_api(&catalog));
    }

    /// After a swap the next load waits the whole refresh interval.
    #[test]
    fn a_swap_waits_the_refresh_interval() {
        let mut backoff = Backoff::new(REFRESH);

        assert_eq!(backoff.after(Loaded::Swapped), REFRESH);
    }

    /// Failed loads start with a short retry, double the next wait and
    /// grow monotonically to the refresh interval.
    #[test]
    fn failures_back_off_up_to_the_refresh_interval() {
        let mut backoff = Backoff::new(REFRESH);

        let waits: Vec<Duration> = (0..10).map(|_| backoff.after(Loaded::Kept)).collect();

        assert_eq!(waits[0], FIRST_RETRY);
        assert_eq!(waits[1], FIRST_RETRY * 2);
        assert!(waits.windows(2).all(|pair| pair[1] >= pair[0]));
        assert_eq!(waits[9], REFRESH);
    }

    /// A load that works again after failures starts the next run of
    /// failures from the first short wait.
    #[test]
    fn a_swap_resets_the_backoff() {
        let mut backoff = Backoff::new(REFRESH);
        for _ in 0..5 {
            backoff.after(Loaded::Kept);
        }

        backoff.after(Loaded::Swapped);

        assert_eq!(backoff.after(Loaded::Kept), FIRST_RETRY);
    }
}
