//! Following the control plane's zone stream, for a nameserver on a host of
//! its own that cannot reach the database.
//!
//! Such a host holds a client certificate the deployment's own authority
//! signed, and nothing else: no database login, no bus credential. Taken
//! over, it gives away public DNS data. It checks the control plane's
//! certificate against that same authority, never a public root, so a
//! connection rerouted to anyone else feeds it nothing.
//!
//! The stream sends the whole catalog the control plane settled, and again
//! whenever it changes. Each one is swapped in whole. A stream that ends,
//! a control plane that is down, or a catalog that does not read keeps the
//! catalog this host already answers from, and the link is tried again,
//! waiting longer after each attempt that got nothing.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    Authority, RecordKind, RecordName, RecordSet, RecordValue, Serial, Ttl, Zone, ZoneCatalog,
};
use ianua_domain::shared::errors::{DomainError, causes};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::DomainName;
use ianua_proto::dns::v1::dns_zones_client::DnsZonesClient;
use ianua_proto::dns::v1::{
    CONTRACT_VERSION, NameserverReport, WatchRequest, Zone as WireZone, ZoneCatalog as WireCatalog,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::catalog::SharedCatalog;

/// The first wait before trying the link again.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// The longest the wait grows to, so a control plane down for an hour is
/// followed again within this of coming back.
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// How long connecting, the handshake included, may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the stream's first catalog may take after connecting.
const FIRST_CATALOG_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a report may take. It is bookkeeping, and never holds up the
/// stream for longer.
const REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// How often a quiet connection is pinged: a load balancer between the
/// two ends reads a quiet connection as dead and cuts it.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// How long a ping may go unanswered before the connection is dropped.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the control plane is, and how this host proves itself to it.
/// `Debug` shows no key.
#[derive(Clone)]
pub(crate) struct ControlPlaneLink {
    /// `CONTROL_PLANE_ENDPOINT`, such as `https://grpc.ianua.io:50051`.
    pub endpoint: String,
    /// `CONTROL_PLANE_SERVER_NAME`, the name the control plane's
    /// certificate is checked against; the endpoint's host by default.
    pub server_name: String,
    /// `CONTROL_PLANE_CLIENT_CERT`: this host's certificate, PEM.
    pub certificate_pem: String,
    /// `CONTROL_PLANE_CLIENT_KEY`: this host's private key, PEM.
    pub private_key_pem: Secret,
    /// `CONTROL_PLANE_CA_CERT`: the deployment's own authority, PEM.
    pub authority_pem: String,
}

impl fmt::Debug for ControlPlaneLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlPlaneLink")
            .field("endpoint", &self.endpoint)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// Why one attempt at the link ended. Each is a reason to try again.
#[derive(Debug, thiserror::Error)]
enum LinkError {
    /// The endpoint or the certificates could not be used, or nothing
    /// answered.
    #[error("the control plane could not be reached")]
    Connect(#[source] tonic::transport::Error),
    /// The control plane refused the stream, or the stream failed.
    #[error("the zone stream failed")]
    Stream(#[source] tonic::Status),
    /// No catalog came in time after connecting.
    #[error("the control plane sent no catalog in time")]
    Silent,
    /// The control plane ended the stream.
    #[error("the control plane closed the zone stream")]
    Closed,
}

/// What an attempt at the link handed over before it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Yielded {
    /// At least one catalog: it was a working link.
    Catalog,
    /// No catalog arrived, so the retry delay continues to grow.
    Nothing,
}

/// How one attempt at the link ended.
#[derive(Debug)]
struct Ended {
    cause: LinkError,
    yielded: Yielded,
}

impl Ended {
    /// An attempt that ended for `cause` before handing over anything.
    fn early(cause: LinkError) -> Self {
        Self {
            cause,
            yielded: Yielded::Nothing,
        }
    }
}

/// Follows the control plane's stream into `catalog`.
pub(crate) struct Follower {
    link: ControlPlaneLink,
    catalog: SharedCatalog,
    authority: Authority,
}

impl Follower {
    /// A follower swapping what `link` sends into `catalog`, every zone
    /// answering under `authority`.
    pub(crate) fn new(
        link: ControlPlaneLink,
        catalog: SharedCatalog,
        authority: Authority,
    ) -> Self {
        Self {
            link,
            catalog,
            authority,
        }
    }

    /// Follows the stream for ever, trying the link again after each end.
    /// Nothing here ever empties the catalog already answering.
    pub(crate) async fn follow(self) {
        install_crypto_provider();
        let mut backoff = Backoff::new();
        loop {
            let ended = self.stream_once().await;
            tracing::warn!(
                cause = %causes(&ended.cause),
                "the zone stream ended; the zones held keep answering"
            );
            tokio::time::sleep(backoff.after(ended.yielded)).await;
        }
    }

    /// Follows one connection until it ends.
    async fn stream_once(&self) -> Ended {
        let channel = match self.connected().await {
            Ok(channel) => channel,
            Err(cause) => return Ended::early(cause),
        };
        let mut client = DnsZonesClient::new(channel);
        let opened = tokio::time::timeout(FIRST_CATALOG_TIMEOUT, client.watch(WatchRequest {}));
        let mut stream = match opened.await {
            Err(_) => return Ended::early(LinkError::Silent),
            Ok(Err(status)) => return Ended::early(LinkError::Stream(status)),
            Ok(Ok(response)) => response.into_inner(),
        };
        tracing::info!(endpoint = %self.link.endpoint, "following the zone stream");
        let mut yielded = Yielded::Nothing;
        loop {
            let catalog = match stream.message().await {
                Err(status) => return ended(LinkError::Stream(status), yielded),
                Ok(None) => return ended(LinkError::Closed, yielded),
                Ok(Some(catalog)) => catalog,
            };
            yielded = Yielded::Catalog;
            self.apply(&catalog, &mut client).await;
        }
    }

    /// Swaps `catalog` in and reports it, or keeps the catalog answering
    /// when it does not read: the control plane's fault, not the link's.
    async fn apply(&self, catalog: &WireCatalog, client: &mut DnsZonesClient<Channel>) {
        let zones = match hydrate(catalog) {
            Ok(zones) => zones,
            Err(error) => {
                tracing::error!(cause = %causes(&error), "a zone catalog did not read; the zones held keep answering");
                return;
            }
        };
        let serial = zones.iter().map(|zone| zone.serial().as_u32()).max();
        let count = zones.len();
        self.catalog.store(Arc::new(ZoneCatalog::from_served(
            zones,
            self.authority.clone(),
        )));
        tracing::info!(zones = count, "zone catalog received");
        report(client, serial.unwrap_or(0), count).await;
    }

    /// A channel to the control plane, both ends checked against the
    /// deployment's own authority.
    async fn connected(&self) -> Result<Channel, LinkError> {
        let tls = ClientTlsConfig::new()
            .domain_name(self.link.server_name.clone())
            .ca_certificate(Certificate::from_pem(&self.link.authority_pem))
            .identity(Identity::from_pem(
                &self.link.certificate_pem,
                self.link.private_key_pem.expose(),
            ));
        Endpoint::from_shared(self.link.endpoint.clone())
            .and_then(|endpoint| endpoint.tls_config(tls))
            .map_err(LinkError::Connect)?
            .connect_timeout(CONNECT_TIMEOUT)
            .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
            .connect()
            .await
            .map_err(LinkError::Connect)
    }
}

/// Selects the rustls crypto provider before the first handshake: more
/// than one is reachable across the dependency graph and rustls refuses to
/// guess. A second install only says one is in place already.
fn install_crypto_provider() {
    if tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a TLS crypto provider was installed already");
    }
}

/// An attempt that ended for `cause`, having handed over as `yielded`.
fn ended(cause: LinkError, yielded: Yielded) -> Ended {
    Ended { cause, yielded }
}

/// How long to wait before trying the link again.
#[derive(Debug)]
struct Backoff(Duration);

impl Backoff {
    fn new() -> Self {
        Self(RECONNECT_DELAY)
    }

    /// The wait after an attempt that handed over as `yielded`: one that
    /// handed over a catalog was a working link, so the wait starts over;
    /// otherwise it doubles, never past [`MAX_RECONNECT_DELAY`].
    fn after(&mut self, yielded: Yielded) -> Duration {
        if yielded == Yielded::Catalog {
            self.0 = RECONNECT_DELAY;
        }
        let wait = self.0;
        self.0 = (self.0 * 2).min(MAX_RECONNECT_DELAY);
        wait
    }
}

/// Tells the control plane what this host now serves, and says so in this
/// host's log when the control plane expects a newer contract. Never
/// fatal: a host that cannot report still answers correctly.
async fn report(client: &mut DnsZonesClient<Channel>, catalog_serial: u32, zone_count: usize) {
    let sent = tokio::time::timeout(
        REPORT_TIMEOUT,
        client.report(NameserverReport {
            contract_version: CONTRACT_VERSION,
            catalog_serial,
            zone_count: u32::try_from(zone_count).unwrap_or(u32::MAX),
        }),
    )
    .await;
    let Ok(Ok(ack)) = sent else {
        tracing::debug!("the control plane took no report");
        return;
    };
    if ack.into_inner().contract_version > CONTRACT_VERSION {
        tracing::error!(
            mine = CONTRACT_VERSION,
            "the control plane sends a newer contract than this nameserver reads; its answers \
             miss what it cannot read until it is deployed again"
        );
    }
}

/// The domain's zones the wire catalog carries, refused whole when any
/// part does not read: serving part of a zone sends a name to the wrong
/// place rather than nowhere.
///
/// # Errors
///
/// `DomainError::Infrastructure` naming what did not read.
fn hydrate(catalog: &WireCatalog) -> Result<Vec<Zone>, DomainError> {
    catalog.zones.iter().map(hydrate_zone).collect()
}

/// Validates wire names, serial and record sets before admitting an entire zone.
fn hydrate_zone(zone: &WireZone) -> Result<Zone, DomainError> {
    let apex = DomainName::new(zone.apex.as_str()).map_err(DomainError::infra)?;
    let changed_at = time::OffsetDateTime::from_unix_timestamp(i64::from(zone.serial))
        .map_err(DomainError::infra)?;
    let sets = zone
        .records
        .iter()
        .map(hydrate_set)
        .collect::<Result<Vec<_>, _>>()?;
    let nameservers = zone
        .nameservers
        .iter()
        .map(|name| DomainName::new(name.as_str()).map_err(DomainError::infra))
        .collect::<Result<Vec<_>, _>>()?;
    Zone::new(apex, Serial::at(changed_at), sets, nameservers).map_err(DomainError::infra)
}

/// One record set.
fn hydrate_set(set: &ianua_proto::dns::v1::RecordSet) -> Result<RecordSet, DomainError> {
    let name = RecordName::new(set.name.as_str()).map_err(DomainError::infra)?;
    let kind = RecordKind::parse(&set.record_type).map_err(DomainError::infra)?;
    let ttl = Ttl::seconds(set.ttl_seconds).map_err(DomainError::infra)?;
    let values = set
        .values
        .iter()
        .map(|value| RecordValue::parse(kind, value))
        .collect::<Result<Vec<_>, _>>()
        .map_err(DomainError::infra)?;
    RecordSet::new(name, ttl, values).map_err(DomainError::infra)
}

#[cfg(test)]
mod tests {
    use ianua_proto::dns::v1::RecordSet as WireSet;

    use super::*;

    fn wire_zone(records: Vec<WireSet>) -> WireCatalog {
        WireCatalog {
            zones: vec![WireZone {
                nameservers: vec!["abc123.ns1.ianua.test".to_owned()],
                apex: "auth.acme.test".to_owned(),
                serial: 1_700_000_000,
                records,
            }],
        }
    }

    fn wire_set(name: &str, record_type: &str, values: &[&str]) -> WireSet {
        WireSet {
            name: name.to_owned(),
            record_type: record_type.to_owned(),
            ttl_seconds: 300,
            values: values.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    /// A catalog rebuilds into the domain's zones, every value kept.
    #[test]
    fn a_catalog_rebuilds_into_zones() {
        let catalog = wire_zone(vec![wire_set(
            "api.auth.acme.test",
            "A",
            &["198.51.100.1", "198.51.100.2"],
        )]);

        let zones = hydrate(&catalog).unwrap();

        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].apex().as_str(), "auth.acme.test");
        assert_eq!(zones[0].sets()[0].values().len(), 2);
        assert_eq!(zones[0].serial().as_u32(), 1_700_000_000);
    }

    /// Every record type rebuilds, or the nameserver answers with less than
    /// the control plane sent.
    #[test]
    fn every_record_type_rebuilds() {
        let catalog = wire_zone(vec![
            wire_set("auth.acme.test", "A", &["198.51.100.1"]),
            wire_set("v6.auth.acme.test", "AAAA", &["2001:db8::1"]),
            wire_set("www.auth.acme.test", "CNAME", &["elsewhere.example.com"]),
            wire_set("auth.acme.test", "TXT", &["v=spf1 -all"]),
            wire_set("auth.acme.test", "MX", &["10 mx1.acme.test"]),
            wire_set(
                "_sip._tcp.auth.acme.test",
                "SRV",
                &["10 5 443 sip.acme.test"],
            ),
            wire_set(
                "caa.auth.acme.test",
                "CAA",
                &["0 issue \"letsencrypt.org\""],
            ),
        ]);

        let zones = hydrate(&catalog).unwrap();

        assert_eq!(zones[0].sets().len(), 7);
    }

    /// One malformed address refuses the catalog even when another
    /// record in the same zone is valid.
    #[test]
    fn a_catalog_that_does_not_read_is_refused_whole() {
        let catalog = wire_zone(vec![
            wire_set("auth.acme.test", "A", &["198.51.100.1"]),
            wire_set("bad.auth.acme.test", "A", &["not-an-address"]),
        ]);

        assert!(hydrate(&catalog).is_err());
    }

    /// A record outside the declared zone refuses catalog reconstruction.
    #[test]
    fn a_record_outside_its_zone_is_refused() {
        let catalog = wire_zone(vec![wire_set("evil.example.com", "A", &["198.51.100.1"])]);

        assert!(hydrate(&catalog).is_err());
    }

    /// Repeated attempts yielding no catalog double the initial retry
    /// delay and eventually reach the configured maximum.
    #[test]
    fn failed_attempts_back_off_to_a_bound() {
        let mut backoff = Backoff::new();

        let waits: Vec<Duration> = (0..10).map(|_| backoff.after(Yielded::Nothing)).collect();

        assert_eq!(waits[0], RECONNECT_DELAY);
        assert_eq!(waits[1], RECONNECT_DELAY * 2);
        assert_eq!(waits[9], MAX_RECONNECT_DELAY);
    }

    /// A load balancer cutting an idle link is routine; a link that worked
    /// starts the wait over, so a change is not a minute late for ever.
    #[test]
    fn a_link_that_worked_starts_the_wait_over() {
        let mut backoff = Backoff::new();
        for _ in 0..5 {
            backoff.after(Yielded::Nothing);
        }

        assert_eq!(backoff.after(Yielded::Catalog), RECONNECT_DELAY);
    }
}
