//! Streams the zone catalog to the authoritative nameservers.
//!
//! The nameservers run outside the cluster, so they cannot reach Postgres.
//! They are given the zones over the wire instead — and given nothing else.
//! That is deliberate: they face the open internet unauthenticated over UDP,
//! so a compromised one should hold DNS records, not a database credential.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::Stream;
use ianua_app::ports::domain::DnsZoneReader;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{RecordValue, Zone, served_zones};
use ianua_domain::shared::errors::causes;
use ianua_proto::dns::v1::dns_zones_server::DnsZones;
use ianua_proto::dns::v1::{
    CONTRACT_VERSION, NameserverReport, RecordSet, ReportAck, WatchRequest, ZoneCatalog,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

/// How often the catalog is re-read to see whether anything changed.
///
/// Only how quickly the server notices; the push to the nameservers is
/// immediate. Polling the local database rather than subscribing to events
/// because a missed event leaves a nameserver stale with nothing to correct
/// it, where a missed poll is late by one interval.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How many streams are held open at once. Each reads the zones every
/// poll, and a deployment runs a handful of nameservers, so a caller
/// opening streams without end is refused rather than let load the
/// database.
const MAX_WATCHERS: usize = 16;

/// The stream `Watch` returns.
type CatalogStream = Pin<Box<dyn Stream<Item = Result<ZoneCatalog, Status>> + Send>>;

/// Streams zones to the nameservers.
pub struct DnsZonesService {
    reader: Arc<dyn DnsZoneReader>,
    poll: Duration,
    watchers: Arc<Semaphore>,
    ending: CancellationToken,
}

impl DnsZonesService {
    /// Serves the zones `reader` loads.
    #[must_use]
    pub fn new(reader: Arc<dyn DnsZoneReader>) -> Self {
        Self {
            reader,
            poll: POLL_INTERVAL,
            watchers: Arc::new(Semaphore::new(MAX_WATCHERS)),
            ending: CancellationToken::new(),
        }
    }

    /// The same service, every stream it opened ending once `ending` is
    /// cancelled.
    #[must_use]
    pub(crate) fn ending_on(self, ending: CancellationToken) -> Self {
        Self { ending, ..self }
    }

    /// The same service noticing changes every `poll` instead.
    #[must_use]
    pub fn polling_every(self, poll: Duration) -> Self {
        Self { poll, ..self }
    }
}

#[tonic::async_trait]
impl DnsZones for DnsZonesService {
    type WatchStream = CatalogStream;

    /// Sends the catalog now, and again whenever it changes.
    ///
    /// The first message goes out before anything is compared, so a
    /// nameserver that has just started can begin answering immediately.
    ///
    /// # Errors
    ///
    /// Returns `unavailable` if that first load fails. Sending an empty
    /// catalog instead would tell the nameserver it holds no zones, and it
    /// would answer `REFUSED` for every hostname it is authoritative for —
    /// which resolvers cache. Refusing the stream makes it retry.
    async fn watch(
        &self,
        _request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let Ok(permit) = Arc::clone(&self.watchers).try_acquire_owned() else {
            return Err(Status::resource_exhausted("too many zone streams are open"));
        };
        let first = catalog(self.reader.as_ref()).await?;
        let feed = Feed {
            reader: Arc::clone(&self.reader),
            poll: self.poll,
            ending: self.ending.clone(),
            permit,
        };
        Ok(Response::new(Box::pin(changes(feed, first))))
    }

    /// Records what a nameserver says it is serving.
    ///
    /// Logged at `warn` when its contract revision is behind ours, because
    /// that is the state nothing else reports: such a host keeps answering,
    /// keeps looking healthy, and silently drops every field it was not built
    /// to read.
    ///
    /// # Errors
    ///
    /// Never. A nameserver that cannot file a report is still serving DNS
    /// correctly, and must not treat itself as broken for it.
    async fn report(
        &self,
        request: Request<NameserverReport>,
    ) -> Result<Response<ReportAck>, Status> {
        let report = request.into_inner();

        if report.contract_version < CONTRACT_VERSION {
            tracing::warn!(
                nameserver_contract = report.contract_version,
                expected_contract = CONTRACT_VERSION,
                zones = report.zone_count,
                "nameserver was built against an older contract and is dropping \
                 fields it cannot read — redeploy it"
            );
        } else {
            tracing::debug!(
                contract = report.contract_version,
                catalog_serial = report.catalog_serial,
                zones = report.zone_count,
                "nameserver reported in"
            );
        }

        Ok(Response::new(ReportAck {
            contract_version: CONTRACT_VERSION,
        }))
    }
}

/// `first`, then every catalog that differs from the one sent before it,
/// read every `feed.poll`, holding `feed.permit` for as long as the stream
/// is open.
///
/// A read that fails leaves the nameserver on what it has, which still
/// answers correctly; ending the stream would only make it reconnect into
/// the same failure.
///
/// The stream ends when `feed.ending` is cancelled, at the listener's
/// stop, so the stop is not held open by a stream that never ends on its
/// own.
fn changes(
    feed: Feed,
    first: ZoneCatalog,
) -> impl Stream<Item = Result<ZoneCatalog, Status>> + Send {
    async_stream::stream! {
        let Feed { reader, poll, ending, permit } = feed;
        let _permit = permit;
        let mut sent = first.clone();
        yield Ok(first);
        loop {
            tokio::select! {
                () = ending.cancelled() => break,
                () = tokio::time::sleep(poll) => {}
            }
            let Ok(current) = catalog(reader.as_ref()).await else {
                continue;
            };
            if current != sent {
                sent = current.clone();
                yield Ok(current);
            }
        }
    }
}

/// What one open stream reads from, and the place it holds among the
/// streams allowed open.
struct Feed {
    reader: Arc<dyn DnsZoneReader>,
    poll: Duration,
    ending: CancellationToken,
    permit: OwnedSemaphorePermit,
}

/// Reads every zone and maps the served ones onto the wire.
///
/// # Errors
///
/// `unavailable` when the zones cannot be read; why goes to the log, not
/// to the caller.
async fn catalog(reader: &dyn DnsZoneReader) -> Result<ZoneCatalog, Status> {
    let zones = reader.load_all_zones().await.map_err(|error| {
        tracing::warn!(cause = %causes(&error), "the zones could not be read for the stream");
        Status::unavailable("the zones could not be read")
    })?;

    Ok(ZoneCatalog {
        zones: served_zones(zones).iter().map(as_wire).collect(),
    })
}

/// One zone as the contract carries it.
fn as_wire(zone: &Zone) -> ianua_proto::dns::v1::Zone {
    ianua_proto::dns::v1::Zone {
        apex: zone.apex().as_str().to_owned(),
        serial: zone.serial().as_u32(),
        records: zone.sets().iter().map(as_wire_set).collect(),
        nameservers: zone
            .nameservers()
            .iter()
            .map(|n| n.as_str().to_owned())
            .collect(),
    }
}

/// One record set as the contract carries it.
fn as_wire_set(
    set: &ianua_domain::domains::tenant::custom_domains::dns_zone::RecordSet,
) -> RecordSet {
    RecordSet {
        name: set.name().as_str().to_owned(),
        record_type: set.kind().as_str().to_owned(),
        ttl_seconds: set.ttl().as_seconds(),
        values: set
            .values()
            .iter()
            .map(RecordValue::as_presentation)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use futures_util::StreamExt;
    use ianua_domain::domains::tenant::custom_domains::dns_zone::{
        HeldZone, RecordName, RecordSet as DomainSet, Serial, Ttl, ZoneStanding,
    };
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{DomainName, IpAddress, TenantId};

    use super::*;

    /// Short enough to keep tests quick, long enough not to race the runtime.
    const TEST_POLL: Duration = Duration::from_millis(10);

    /// Long enough for several polls to have happened.
    const SETTLE: Duration = Duration::from_millis(120);

    fn zone(address: &str) -> HeldZone {
        held(
            zone_with(vec![RecordValue::Address(IpAddress::new(address).unwrap())]),
            ZoneStanding::Proven,
        )
    }

    fn held(zone: Zone, standing: ZoneStanding) -> HeldZone {
        HeldZone {
            zone,
            owner: TenantId::new(),
            standing,
        }
    }

    fn zone_with(values: Vec<RecordValue>) -> Zone {
        Zone::new(
            DomainName::new("auth.acme.test").unwrap(),
            Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()),
            vec![
                DomainSet::new(
                    RecordName::new("api.auth.acme.test").unwrap(),
                    Ttl::standard(),
                    values,
                )
                .unwrap(),
            ],
            vec![DomainName::new("abc123.ns1.ianua.test").unwrap()],
        )
        .unwrap()
    }

    /// What one load should do.
    ///
    /// `DomainError` is not `Clone`, so the script records the *outcome* to
    /// produce rather than a prepared `Result`.
    #[derive(Clone)]
    enum Answer {
        Catalog(Vec<HeldZone>),
        Failure,
    }

    /// A reader following a script, repeating its last answer once spent.
    struct ScriptedReader {
        answers: Mutex<VecDeque<Answer>>,
    }

    impl ScriptedReader {
        fn answering(answers: impl IntoIterator<Item = Answer>) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers.into_iter().collect()),
            })
        }

        /// The next answer, with the last one repeating for ever after.
        ///
        /// A database that is down stays down, and a catalog that has settled
        /// stays settled — so the script describes the changes and the fake
        /// holds the final state.
        fn next_answer(&self) -> Answer {
            let mut answers = self.answers.lock().unwrap();

            let Some(next) = answers.pop_front() else {
                return Answer::Failure;
            };

            if answers.is_empty() {
                answers.push_back(next.clone());
            }

            next
        }
    }

    #[async_trait::async_trait]
    impl DnsZoneReader for ScriptedReader {
        async fn load_all_zones(&self) -> Result<Vec<HeldZone>, DomainError> {
            match self.next_answer() {
                Answer::Catalog(zones) => Ok(zones),
                Answer::Failure => Err(DomainError::infra_msg("scripted failure")),
            }
        }
    }

    /// Opens a watch stream over a scripted reader.
    async fn watching(answers: impl IntoIterator<Item = Answer>) -> CatalogStream {
        DnsZonesService::new(ScriptedReader::answering(answers))
            .polling_every(TEST_POLL)
            .watch(Request::new(WatchRequest {}))
            .await
            .expect("the stream should open")
            .into_inner()
    }

    /// The single address in the first record set of a catalog.
    fn address_in(catalog: &ZoneCatalog) -> &str {
        &catalog.zones[0].records[0].values[0]
    }

    // ── Starting up ──────────────────────────────────────────

    /// A nameserver must be able to start answering without waiting for
    /// something to change.
    #[tokio::test]
    async fn the_catalog_is_sent_before_anything_changes() {
        let mut stream = watching([Answer::Catalog(vec![zone("198.51.100.1")])]).await;

        let first = stream.next().await.unwrap().unwrap();

        assert_eq!(first.zones.len(), 1);
        assert_eq!(first.zones[0].apex, "auth.acme.test");
        assert_eq!(address_in(&first), "198.51.100.1");
    }

    /// A nameserver off the cluster must not answer for a name its
    /// registrant has not proved is delegated to us, just as one on it does
    /// not.
    #[tokio::test]
    async fn an_unproven_zone_is_never_sent() {
        let unproven = held(
            zone_with(vec![RecordValue::Address(
                IpAddress::new("198.51.100.1").unwrap(),
            )]),
            ZoneStanding::Unproven,
        );
        let mut stream = watching([Answer::Catalog(vec![unproven])]).await;

        let first = stream.next().await.unwrap().unwrap();

        assert!(first.zones.is_empty());
    }

    /// Told "no zones", a nameserver answers `REFUSED` for every hostname it
    /// holds, and resolvers cache that. Refusing the stream makes it retry.
    #[tokio::test]
    async fn a_failed_first_load_refuses_the_stream() {
        let opened = DnsZonesService::new(ScriptedReader::answering([Answer::Failure]))
            .watch(Request::new(WatchRequest {}))
            .await;

        assert!(opened.is_err());
    }

    /// Opening a stream at capacity returns resource exhausted; closing
    /// one existing stream makes room for another.
    #[tokio::test]
    async fn streams_past_the_bound_are_refused_until_one_closes() {
        let service = DnsZonesService::new(ScriptedReader::answering([Answer::Catalog(vec![])]));
        let mut open = Vec::new();
        for _ in 0..MAX_WATCHERS {
            open.push(service.watch(Request::new(WatchRequest {})).await.unwrap());
        }

        let refused = service.watch(Request::new(WatchRequest {})).await;
        open.pop();
        let reopened = service.watch(Request::new(WatchRequest {})).await;

        assert!(matches!(refused, Err(status) if status.code() == tonic::Code::ResourceExhausted));
        assert!(reopened.is_ok());
    }

    // ── Staying up to date ───────────────────────────────────

    /// The point of a stream: the nameserver is told, rather than asking.
    #[tokio::test]
    async fn a_change_is_pushed_without_being_asked() {
        let mut stream = watching([
            Answer::Catalog(vec![zone("198.51.100.1")]),
            Answer::Catalog(vec![zone("198.51.100.2")]),
        ])
        .await;

        let first = stream.next().await.unwrap().unwrap();
        let second = tokio::time::timeout(SETTLE, stream.next())
            .await
            .expect("the change should have been pushed")
            .unwrap()
            .unwrap();

        assert_eq!(address_in(&first), "198.51.100.1");
        assert_eq!(address_in(&second), "198.51.100.2");
    }

    /// Resending an unchanged catalog every poll would make the stream a
    /// slower, chattier version of the polling it replaced.
    #[tokio::test]
    async fn an_unchanged_catalog_is_not_resent() {
        let mut stream = watching([Answer::Catalog(vec![zone("198.51.100.1")])]).await;
        stream.next().await.unwrap().unwrap();

        let resent = tokio::time::timeout(SETTLE, stream.next()).await;

        assert!(resent.is_err(), "an unchanged catalog should stay quiet");
    }

    /// A database blip must not disconnect every nameserver at once — they
    /// would all reconnect into the same failure, and each would refuse the
    /// stream and go dark.
    #[tokio::test]
    async fn a_failed_reload_leaves_the_stream_open() {
        let mut stream = watching([
            Answer::Catalog(vec![zone("198.51.100.1")]),
            Answer::Failure,
            Answer::Catalog(vec![zone("198.51.100.2")]),
        ])
        .await;

        stream.next().await.unwrap().unwrap();
        let recovered = tokio::time::timeout(SETTLE, stream.next())
            .await
            .expect("the stream should have survived the failure")
            .unwrap()
            .unwrap();

        assert_eq!(address_in(&recovered), "198.51.100.2");
    }

    // ── The mapping ──────────────────────────────────────────

    /// Every value has to reach the wire, or a round-robin loses half its
    /// addresses on the way to the nameserver.
    #[test]
    fn a_set_carries_all_of_its_values() {
        let wire = as_wire(&zone_with(vec![
            RecordValue::Address(IpAddress::new("198.51.100.1").unwrap()),
            RecordValue::Address(IpAddress::new("198.51.100.2").unwrap()),
        ]));

        assert_eq!(wire.records[0].name, "api.auth.acme.test");
        assert_eq!(wire.records[0].record_type, "A");
        assert_eq!(wire.records[0].ttl_seconds, 300);
        assert_eq!(wire.records[0].values, ["198.51.100.1", "198.51.100.2"]);
    }

    /// The nameserver rebuilds its own serial from this number, and a serial
    /// that disagreed between two of them would make secondaries fetch in a
    /// loop.
    #[test]
    fn the_serial_survives_the_wire() {
        assert_eq!(as_wire(&zone("198.51.100.1").zone).serial, 1_700_000_000);
    }

    /// The type is read off the value, so an `AAAA` cannot arrive labelled
    /// `A` — a resolver asking for one and given the other gets an address it
    /// cannot use.
    #[test]
    fn an_ipv6_value_is_carried_as_aaaa() {
        let wire = as_wire(&zone_with(vec![RecordValue::Address(
            IpAddress::new("2001:db8::1").unwrap(),
        )]));

        assert_eq!(wire.records[0].record_type, "AAAA");
    }

    /// The ack tells the nameserver what is expected, so a host built against
    /// an older contract can say so in its own logs. Without that the only
    /// party who knows is the control plane, whose logs are read by someone
    /// else at another time.
    #[tokio::test]
    async fn a_report_is_answered_with_the_expected_contract() {
        let service = DnsZonesService::new(ScriptedReader::answering([Answer::Catalog(vec![])]));

        let ack = service
            .report(Request::new(NameserverReport {
                contract_version: 1,
                catalog_serial: 7,
                zone_count: 3,
            }))
            .await
            .unwrap();

        assert_eq!(ack.into_inner().contract_version, CONTRACT_VERSION);
    }

    /// A nameserver that cannot file a report is still answering DNS
    /// correctly, so nothing here may fail it.
    #[tokio::test]
    async fn a_report_from_a_current_nameserver_is_accepted() {
        let service = DnsZonesService::new(ScriptedReader::answering([Answer::Catalog(vec![])]));

        let sent = service
            .report(Request::new(NameserverReport {
                contract_version: CONTRACT_VERSION,
                catalog_serial: 1,
                zone_count: 0,
            }))
            .await;

        assert!(sent.is_ok());
    }
}
