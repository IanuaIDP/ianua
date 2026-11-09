//! Starting the gateway: the platform built, what runs beside the requests
//! started, and the listeners opened, in the order each needs the last.
//!
//! The tables start empty and the follower fills them, so until its first
//! full reload every host is unknown and the status listener answers not
//! ready. The stream listeners start after the tables, since they end TLS
//! for the names the tables serve; the follower starts last, so its first
//! install already reaches them. The connector listener opens last of all:
//! until the follower hands in a tenant's connectors, its links are
//! refused, and the connector dials again.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::pages::PageRenderer;
use ianua_app::ports::runtime::{FleetCounters, MetricsExporter, RequestObserver};
use ianua_app::use_cases::routing::services::{OpenClientKeyPorts, OpenClientKeyUseCase};
use ianua_app::use_cases::runtime::CheckReadinessPorts;
use ianua_boot::shutdown::Shutdown;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, DomainName};
use ianua_infra::bus::{BusNotificationPublisher, BusReadinessProbe};
use ianua_infra::cache::{CacheBackendHealthReports, CacheFleetCounters, CacheReadinessProbe};
use ianua_infra::dns::DnsBackendDiscovery;
use ianua_infra::pages::TemplatePageRenderer;
use ianua_infra::postgres::runtime::PgReadinessProbe;
use ianua_infra::postgres::tenant::TenantDatabaseFollower;
use ianua_infra::runtime::{LocalDroppedRecords, LocalMetricsExporter, LocalRequestObserver};
use prometheus::Registry;
use tokio::net::TcpListener;
use tokio_rustls::rustls::crypto::{CryptoProvider, ring};
use tokio_util::sync::CancellationToken;

use crate::boot::foundation::Foundation;
use crate::boot::stages::{self, StageInputs};
use crate::boot::stores::Stores;
use crate::boot::tables::ServedTables;
use crate::boot::use_cases::UseCases;
use crate::config::Config;
use crate::config::internal::{InternalListen, InternalTransport};
use crate::config::listen::{MainTransport, ProxyProtocol as Peers};
use crate::connectors::{
    ConnectorLinks, ConnectorListener, ConnectorListenerParts, LinkLimits, server_config,
};
use crate::error::{GatewayError, PlatformError};
use crate::fleet::{FleetMember, FleetPublisher, VerdictSeal, VerdictSink};
use crate::follow::{
    ConfigFollower, FollowPorts, FollowSettings, Seals, SnapshotStores, StoreSnapshotSource,
};
use crate::forward::{
    Clients, DiscoverySettings, DiscoveryWatch, ForwardSettings, Forwarder, HealthChecks,
    ProbeSettings, ServicePools, TunnelLimits,
};
use crate::handler::{Gateway, GatewayParts, RequestBounds};
use crate::listen::{
    AcmeResponder, CertificateTable, ClientAuthTable, ConnectionPermits, Handler, HttpLimits,
    InternalTls, ListenLimits, Listener, ListenerPem, PlatformCertificate, ProxyProtocol,
    ServedNames, ServedPem, StreamTls, StreamTlsSources, TlsSources, TlsTerminator, Transport,
    mutual_server_config, server_only_config,
};
use crate::observability::{BatchLimits, LogSink, Reporting, StreamLog, TraceCollector};
use crate::pipeline::executor::StageDispatch;
use crate::pipeline::stages::counters::HeldVerdicts;
use crate::request::{ListenerRole, Scheme};
use crate::resolve::{Tables, TablesParts};
use crate::runtime::{self, RuntimePorts, TablesLoaded};
use crate::serve::Serving;
use crate::stream::{
    DataEntry, StreamPorts, StreamReload, StreamSettings, StreamSources, StreamSupervisor,
    TunnelChecks,
};
use crate::wasm::{WasmBounds, WasmEngine, WasmRuntime};

/// How many blocks and flags this instance holds.
const HELD_VERDICTS: usize = 100_000;

/// How many health probes and name lookups run at once.
const OUTBOUND_CHECKS: NonZeroUsize = NonZeroUsize::MIN.saturating_add(31);

/// How many HTTP/2 streams one connection may hold open.
const STREAMS_PER_CONNECTION: u32 = 256;

/// The longest an ACME challenge lookup may take.
const CHALLENGE_LOOKUP: Duration = Duration::from_secs(2);

/// Builds the gateway `config` describes and starts it serving under
/// `shutdown`, answering where it listens once every listener listens.
///
/// # Errors
///
/// [`GatewayError`] for the first part that could not be built or the
/// first listener that could not be opened.
pub(crate) async fn start(config: &Config, shutdown: &Shutdown) -> Result<Serving, GatewayError> {
    let foundation = Foundation::build(config, shutdown).await?;
    follow_tenant_databases(&foundation, config, shutdown);
    let stores = Stores::new(&foundation, config);
    let use_cases = UseCases::new(&foundation, &stores, config)?;
    let metrics = Metrics::register()?;
    let startup = Startup {
        foundation: &foundation,
        stores: &stores,
        use_cases: &use_cases,
        config,
        shutdown,
    };
    let prepared = startup.prepare(&metrics)?;
    let streams = startup.start_streams(&prepared, &metrics);
    startup.listen(&prepared, streams, &metrics).await
}

/// Shared startup dependencies, retained through listener initialization.
struct Startup<'a> {
    foundation: &'a Foundation,
    stores: &'a Stores,
    use_cases: &'a UseCases,
    config: &'a Config,
    shutdown: &'a Shutdown,
}

/// The request path and TLS tables assembled before listeners open.
struct Prepared {
    observer: Arc<dyn RequestObserver>,
    tls: Tls,
    tables: Arc<Tables>,
    links: Arc<ConnectorLinks>,
    pools: Arc<ServicePools>,
    dispatch: Arc<StageDispatch>,
}

/// Live stream ports and the workflow entry point sharing their supervisor.
struct RunningStreams {
    ports: StreamPorts,
    data: Arc<DataEntry>,
}

impl Startup<'_> {
    /// Starts reporting, backend discovery and fleet membership before building the stages.
    fn prepare(&self, metrics: &Metrics) -> Result<Prepared, PlatformError> {
        let observer = reporting(self, metrics);
        let (tls, tables) = tls_tables(self.config)?;
        let links = Arc::new(ConnectorLinks::new(link_limits(self.config)));
        let pools = service_pools(self.foundation, self.config, &links, self.shutdown)?;
        let (held, publisher) = fleet(self.foundation, self.config, self.shutdown);
        let dispatch = self.dispatch(held, publisher)?;
        Ok(Prepared {
            observer,
            tls,
            tables,
            links,
            pools,
            dispatch,
        })
    }

    /// Starts the WASM clock and connects every stage to the shared stores and fleet.
    fn dispatch(
        &self,
        held: Arc<HeldVerdicts>,
        publisher: FleetPublisher,
    ) -> Result<Arc<StageDispatch>, PlatformError> {
        Ok(Arc::new(stages::dispatch(
            StageInputs {
                shared_state: Arc::clone(&self.foundation.shared_state),
                shared_root: &self.foundation.keys.shared_root,
                stores: self.stores,
                use_cases: self.use_cases,
                wasm: wasm(self.stores, self.shutdown)?,
                held,
                publisher,
            },
            self.config,
        )))
    }

    /// Starts stream listeners and their reconciliation before the follower can install routes.
    fn start_streams(&self, prepared: &Prepared, metrics: &Metrics) -> RunningStreams {
        let streams = StreamSupervisor::new(
            stream_sources(self, &prepared.tls, metrics),
            stream_settings(self.config),
        );
        let ports = streams.ports();
        let data = Arc::new(streams.data_entry(
            Arc::clone(&self.stores.stream_routes),
            Arc::clone(&self.use_cases.passes),
        ));
        let reload = streams.start(self.shutdown);
        reconcile_streams_on_timer(&reload, self.config, self.shutdown);
        prepared.tables.tell_streams(reload);
        RunningStreams { ports, data }
    }

    /// Starts the follower and status listener before opening request and connector listeners.
    async fn listen(
        &self,
        prepared: &Prepared,
        streams: RunningStreams,
        metrics: &Metrics,
    ) -> Result<Serving, GatewayError> {
        let status = self.status(prepared, metrics).await?;
        let gateway = self.gateway(prepared)?;
        let public = open_public(self, &prepared.tls, &gateway).await?;
        let acme = open_acme(self).await?;
        let runners = open_runners(self, &prepared.tls, &gateway).await?;
        let workflows = open_workflows(self, &prepared.tls, &gateway, streams.data).await?;
        let connectors = open_connectors(
            self.config,
            ConnectorSide {
                stores: self.stores,
                links: &prepared.links,
                provider: &prepared.tls.provider,
            },
            self.shutdown,
        )
        .await?;
        Ok(Serving {
            public,
            status,
            acme,
            runners,
            workflows,
            streams: streams.ports,
            connectors,
        })
    }

    /// Starts table following and exposes its readiness through the status listener.
    async fn status(
        &self,
        prepared: &Prepared,
        metrics: &Metrics,
    ) -> Result<SocketAddr, GatewayError> {
        let served = Served {
            tables: &prepared.tables,
            pools: &prepared.pools,
            links: &prepared.links,
        };
        let loaded = follow(self, &served)?;
        Ok(runtime::serve(
            runtime_ports(self.foundation, metrics, loaded),
            self.config.listen.status,
            self.shutdown,
        )
        .await?)
    }

    /// Builds the common request handler after the status listener has opened.
    fn gateway(&self, prepared: &Prepared) -> Result<Gateway, PlatformError> {
        let config = self.config;
        let use_cases = self.use_cases;
        Ok(Gateway::new(GatewayParts {
            tables: Arc::clone(&prepared.tables),
            dispatch: Arc::clone(&prepared.dispatch),
            forwarder: Arc::new(Forwarder::new(&forward_settings(config))),
            pools: Arc::clone(&prepared.pools),
            pages: pages()?,
            observer: Arc::clone(&prepared.observer),
            events: Arc::clone(&use_cases.inbox),
            sign_in: use_cases.sign_in.clone(),
            counters: fleet_counters(self.foundation),
            sign_assertion: Arc::clone(&use_cases.sign_assertion),
            published_keys: Arc::clone(&use_cases.published_keys),
            agent_authority: Arc::clone(&use_cases.agent_authority),
            recheck_connection: Arc::clone(&use_cases.recheck_connection),
            trusted_proxies: config.listen.trusted_proxies.clone(),
            scheme: stages::scheme(config),
            listener: ListenerRole::ByHost,
            passes: Arc::clone(&use_cases.passes),
            bounds: bounds(config),
            data: None,
        }))
    }
}

/// Creates the empty routing and certificate tables shared by TLS and the follower.
fn tls_tables(config: &Config) -> Result<(Tls, Arc<Tables>), PlatformError> {
    let provider = Arc::new(ring::default_provider());
    let certificates = Arc::new(certificate_table(&provider, config)?);
    let client_auth = Arc::new(ClientAuthTable::new(Arc::clone(&provider)));
    let tables = Arc::new(Tables::new(TablesParts {
        addressing: config.deployment.platform_addressing,
        base_domain: config.deployment.base_domain.clone(),
        client_auth: Arc::clone(&client_auth),
        certificates: Arc::clone(&certificates),
    }));
    let names: Arc<dyn ServedNames> = tables.clone();
    let tls = Tls {
        provider,
        certificates,
        client_auth,
        names,
    };
    Ok((tls, tables))
}

/// What the request path's tables are filled with.
struct Served<'a> {
    tables: &'a Arc<Tables>,
    pools: &'a Arc<ServicePools>,
    links: &'a Arc<ConnectorLinks>,
}

/// What the connector listener is built from.
struct ConnectorSide<'a> {
    stores: &'a Stores,
    links: &'a Arc<ConnectorLinks>,
    provider: &'a Arc<CryptoProvider>,
}

/// What connector links are held to.
fn link_limits(config: &Config) -> LinkLimits {
    let limits = config.connectors.limits;
    LinkLimits {
        max_links: limits.max_links,
        links_per_connector: limits.links_per_connector,
        streams_per_link: limits.streams_per_link,
        handshake: limits.handshake,
        open: limits.open,
        keepalive: limits.keepalive,
        sighting: limits.sighting,
    }
}

/// The protocols an internal listener offers.
const INTERNAL_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// How the internal listener `listen` protects its connections: mutual TLS
/// with its certificates, TLS asking no client certificate, or plain HTTP
/// outside production.
///
/// # Errors
///
/// [`GatewayError`] when its certificates cannot be read or used.
fn internal_transport(
    listen: &InternalListen,
    provider: &Arc<CryptoProvider>,
    config: &Config,
) -> Result<Transport, GatewayError> {
    let tls = match &listen.transport {
        InternalTransport::Mutual {
            authority,
            certificate,
        } => {
            let pem = ListenerPem::read(authority, certificate)
                .map_err(PlatformError::of("an internal listener's certificates"))?;
            mutual_server_config(provider, &pem, &INTERNAL_PROTOCOLS)
        }
        InternalTransport::Tls { certificate } => {
            let pem = ServedPem::read(certificate)
                .map_err(PlatformError::of("an internal listener's certificate"))?;
            server_only_config(provider, &pem, &INTERNAL_PROTOCOLS)
        }
        InternalTransport::PlainInDevelopment => return Ok(Transport::Plain),
    }
    .map_err(PlatformError::of("an internal listener's TLS"))?;
    let handshake = config.listen.timeouts.handshake;
    Ok(Transport::Internal(Arc::new(InternalTls::new(
        tls, handshake,
    ))))
}

/// How a client reaches an internal listener protected as `transport`
/// says, as the address a key proof names.
fn internal_scheme(transport: &InternalTransport) -> Scheme {
    match transport {
        InternalTransport::Mutual { .. } | InternalTransport::Tls { .. } => Scheme::Https,
        InternalTransport::PlainInDevelopment => Scheme::Http,
    }
}

/// Opens the connector listener when `GATEWAY_CONNECTOR_LISTEN` names one,
/// taking links until the stop, and answers where it listens.
async fn open_connectors(
    config: &Config,
    side: ConnectorSide<'_>,
    shutdown: &Shutdown,
) -> Result<Option<SocketAddr>, GatewayError> {
    let Some(listen) = &config.connectors.listen else {
        return Ok(None);
    };
    let pem = ListenerPem::read(&listen.authority, &listen.certificate)
        .map_err(PlatformError::of("the connector listener's certificates"))?;
    let tls = server_config(side.provider, &pem)
        .map_err(PlatformError::of("the connector listener's TLS"))?;
    let refused = |cause| GatewayError::Listen {
        listener: "connector",
        address: listen.address,
        cause,
    };
    let socket = TcpListener::bind(listen.address).await.map_err(refused)?;
    let bound = socket.local_addr().map_err(refused)?;
    let listener = ConnectorListener::new(ConnectorListenerParts {
        socket,
        tls,
        links: Arc::clone(side.links),
        sightings: Arc::clone(&side.stores.connector_sightings),
        limits: link_limits(config),
    });
    shutdown.spawn("connector", listener.run(stopped_at(shutdown)));
    Ok(Some(bound))
}

/// What the handshakes are made with.
struct Tls {
    provider: Arc<CryptoProvider>,
    certificates: Arc<CertificateTable>,
    client_auth: Arc<ClientAuthTable>,
    names: Arc<dyn ServedNames>,
}

/// The process's metrics registry and what counts into it.
struct Metrics {
    exporter: Arc<dyn MetricsExporter>,
    requests: Arc<LocalRequestObserver>,
    dropped: Arc<LocalDroppedRecords>,
}

impl Metrics {
    /// The registry, every counter registered on it.
    fn register() -> Result<Self, PlatformError> {
        let registry = Registry::new();
        let requests = LocalRequestObserver::register(&registry)
            .map_err(PlatformError::of("the request metrics"))?;
        let dropped = LocalDroppedRecords::register(&registry)
            .map_err(PlatformError::of("the dropped records metric"))?;
        Ok(Self {
            exporter: Arc::new(LocalMetricsExporter::new(registry)),
            requests: Arc::new(requests),
            dropped: Arc::new(dropped),
        })
    }
}

/// Keeps every tenant's own database route current, as the server does:
/// a tenant moved apart is reached where it lives.
fn follow_tenant_databases(foundation: &Foundation, config: &Config, shutdown: &Shutdown) {
    let routes = TenantDatabaseFollower::new(
        Arc::clone(&foundation.databases),
        Arc::clone(&foundation.bus),
        config.reload.everything,
    );
    let stopping = shutdown.stopping();
    shutdown.spawn("the tenant database follower", async move {
        tokio::select! {
            () = stopping => {}
            followed = routes.follow() => {
                if let Err(error) = followed {
                    tracing::error!(%error, "the tenants' database routes are no longer followed");
                }
            }
        }
    });
}

/// The one observer every request reports to, its destinations started.
fn reporting(startup: &Startup<'_>, metrics: &Metrics) -> Arc<dyn RequestObserver> {
    let config = startup.config;
    let records = config.observability.request_records;
    let traces = config.observability.traces.as_ref().and_then(|traces| {
        let endpoint = traces.endpoint.as_str().parse().ok()?;
        Some(TraceCollector {
            endpoint,
            service: traces.service_name.clone(),
        })
    });
    let reporting = Reporting {
        records: Arc::clone(&startup.stores.access_log),
        record_batching: BatchLimits::new(records.buffer, records.batch, records.flush),
        metrics: Arc::clone(&metrics.requests),
        dropped: metrics.dropped.clone(),
        dashboard: Arc::new(BusNotificationPublisher::new(
            Arc::clone(&startup.foundation.bus),
            startup.foundation.keys.broadcast_seal.clone(),
        )),
        shipping: Some(Arc::clone(&startup.use_cases.shipping)),
        traces,
        sink: log_sink(config),
    };
    Arc::new(reporting.observers(startup.shutdown))
}

/// The deployment's own log collector, when `LOG_SINK_URL` names one.
fn log_sink(config: &Config) -> Option<LogSink> {
    let shipping = config.observability.log_shipping.as_ref()?;
    let endpoint = shipping.endpoint.as_str().parse().ok()?;
    Some(LogSink {
        endpoint,
        header: shipping
            .header
            .as_ref()
            .map(|header| (header.name.clone(), header.value.clone())),
    })
}

/// The served certificates, with the platform's own for the base domain
/// and every name one label under it.
fn certificate_table(
    provider: &Arc<CryptoProvider>,
    config: &Config,
) -> Result<CertificateTable, PlatformError> {
    let platform = platform_certificate(config)?;
    CertificateTable::new(Arc::clone(provider), &platform)
        .map_err(PlatformError::of("the platform's certificate"))
}

/// The platform's certificate `GATEWAY_TLS_CERT` and `GATEWAY_TLS_KEY` name,
/// served for `<base>` and `*.<base>`, or none.
fn platform_certificate(config: &Config) -> Result<Vec<PlatformCertificate>, PlatformError> {
    let MainTransport::Tls {
        platform: Some(files),
    } = &config.listen.transport
    else {
        return Ok(Vec::new());
    };
    let base = &config.deployment.base_domain;
    let names = vec![
        base.clone(),
        DomainName::new(format!("*.{base}")).map_err(PlatformError::of("the platform's names"))?,
    ];
    let chain = CertificatePem::new(read(&files.certificate)?)
        .map_err(PlatformError::of("the platform's certificate"))?;
    Ok(vec![PlatformCertificate {
        names,
        chain,
        key: Secret::new(read(&files.key)?),
    }])
}

/// The text of the file at `path`.
fn read(path: &Path) -> Result<String, PlatformError> {
    std::fs::read_to_string(path).map_err(PlatformError::of("the platform's certificate files"))
}

/// One pool of backends per service, with the health probes and the name
/// lookups that keep them current, all stopped at the stop.
fn service_pools(
    foundation: &Foundation,
    config: &Config,
    links: &Arc<ConnectorLinks>,
    shutdown: &Shutdown,
) -> Result<Arc<ServicePools>, PlatformError> {
    let root = stopped_at(shutdown);
    let clients = Clients::new(&forward_settings(config), Arc::clone(links))
        .map_err(PlatformError::of("the upstream clients"))?;
    let health = HealthChecks::new(
        root.clone(),
        ProbeSettings {
            max_in_flight: OUTBOUND_CHECKS,
        },
        Arc::new(CacheBackendHealthReports::new(Arc::clone(
            &foundation.shared_state,
        ))),
    );
    let forward = &config.forward;
    let discovery = Arc::new(DiscoveryWatch::new(
        Arc::new(DnsBackendDiscovery::new(forward.dns_lookup_timeout)),
        DiscoverySettings {
            tick: forward.discovery_refresh,
            lookup_timeout: forward.dns_lookup_timeout,
            max_in_flight: OUTBOUND_CHECKS,
        },
    ));
    shutdown.spawn_until_stopped(Arc::clone(&discovery).run(root));
    Ok(Arc::new(ServicePools::new(clients, health, discovery)))
}

/// A cancellation that fires at the stop, for the parts that take one.
fn stopped_at(shutdown: &Shutdown) -> CancellationToken {
    let root = CancellationToken::new();
    let cancel = root.clone();
    let stopping = shutdown.stopping();
    shutdown.spawn_until_stopped(async move {
        stopping.await;
        cancel.cancel();
    });
    root
}

/// What forwarding is held to.
fn forward_settings(config: &Config) -> ForwardSettings {
    let connections = config.forward.connections;
    ForwardSettings {
        networks: config.forward.upstream_networks.clone(),
        connect_timeout: connections.connect_timeout,
        response_deadline: connections.response_deadline,
        long_lived_idle: connections.long_lived_idle,
        pool_idle_timeout: connections.pool_idle,
        pool_max_idle_per_backend: connections.pool_max_idle_per_backend,
        tunnels: TunnelLimits {
            max_open: NonZeroUsize::new(connections.max_tunnels).unwrap_or(NonZeroUsize::MIN),
            lifetime: config.limits.tunnels.lifetime,
            idle: config.limits.tunnels.idle,
            recheck_every: config.agents.recheck,
            recheck_timeout: config.agents.recheck_timeout,
        },
    }
}

/// This instance's copy of the fleet's blocks and flags, and where the ones
/// raised here go, the instance joined to the fleet's broadcasts.
fn fleet(
    foundation: &Foundation,
    config: &Config,
    shutdown: &Shutdown,
) -> (Arc<HeldVerdicts>, FleetPublisher) {
    let held = Arc::new(HeldVerdicts::new(HELD_VERDICTS));
    let seal: Arc<dyn VerdictSeal> = foundation.keys.fleet_seal.clone();
    let sink: Arc<dyn VerdictSink> = held.clone();
    let bus = Arc::clone(&foundation.bus);
    let (publisher, member) = FleetMember::join(bus, seal, sink, &config.deployment.fleet);
    shutdown.spawn_until_stopped(member.run());
    (held, publisher)
}

/// The sandbox `Custom` stages run in, its clock kept until the stop.
fn wasm(stores: &Stores, shutdown: &Shutdown) -> Result<Arc<WasmRuntime>, PlatformError> {
    let engine = WasmEngine::new().map_err(PlatformError::of("the WASM engine"))?;
    engine.keep_time(shutdown);
    let runtime = WasmRuntime::new(
        &engine,
        Arc::clone(&stores.wasm_modules),
        WasmBounds::default(),
    )
    .map_err(PlatformError::of("the WASM runtime"))?;
    Ok(Arc::new(runtime))
}

/// What the stream listeners decide and record with. Ports that end TLS
/// end it only where the main listener does; otherwise they stay unbound.
fn stream_sources(startup: &Startup<'_>, tls: &Tls, metrics: &Metrics) -> StreamSources {
    let config = startup.config;
    let ends_tls = matches!(config.listen.transport, MainTransport::Tls { .. });
    let stream_tls = ends_tls.then(|| {
        Arc::new(StreamTls::new(
            Arc::clone(&tls.provider),
            StreamTlsSources {
                certificates: Arc::clone(&tls.certificates),
                client_auth: Arc::clone(&tls.client_auth),
                names: Arc::clone(&tls.names),
            },
            config.listen.timeouts.handshake,
        ))
    });
    StreamSources {
        directory: Arc::clone(&startup.stores.stream_directory),
        admission: Arc::clone(&startup.use_cases.admit_stream),
        identify: Arc::clone(&startup.use_cases.identify_stream),
        tls: stream_tls,
        records: Some(Arc::new(StreamLog::start(
            Arc::clone(&startup.stores.stream_records),
            metrics.dropped.clone(),
            startup.shutdown,
        ))),
    }
}

/// Asks the stream listeners to match their ports to the routes every
/// `GATEWAY_STREAM_RECONCILE_SECONDS`, beside the follower's asks, so a
/// port a missed change left open or closed is put right.
fn reconcile_streams_on_timer(reload: &StreamReload, config: &Config, shutdown: &Shutdown) {
    let reload = reload.clone();
    let every = config.reload.stream_ports;
    shutdown.spawn_until_stopped(async move {
        let mut ticks = tokio::time::interval(every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            reload.request();
        }
    });
}

/// Where the stream listeners bind and what they carry.
fn stream_settings(config: &Config) -> StreamSettings {
    StreamSettings {
        listen_on: config.listen.main.ip(),
        networks: config.forward.upstream_networks.clone(),
        connections_per_route: config.limits.permits.per_stream_route,
        tunnel_checks: TunnelChecks {
            every: config.agents.recheck,
            timeout: config.agents.recheck_timeout,
        },
        ..StreamSettings::default()
    }
}

/// Starts the config follower filling `served`, and answers
/// whether its first full reload finished, for the readiness check.
///
/// The control plane's seal on events is made from a root the gateway is
/// never given, so the follower takes events as hints to read again and
/// withdraws nothing on their word.
fn follow(startup: &Startup<'_>, served: &Served<'_>) -> Result<TablesLoaded, PlatformError> {
    let source = snapshot_source(startup);
    let settings = FollowSettings::every(startup.config.reload.everything)
        .map_err(PlatformError::of("the config follower"))?;
    let follower = ConfigFollower::new(
        FollowPorts {
            bus: Arc::clone(&startup.foundation.bus),
            seals: Seals::default(),
            source: Arc::new(source),
            tables: Arc::new(ServedTables::new(
                Arc::clone(served.tables),
                Arc::clone(served.pools),
                Arc::clone(served.links),
            )),
        },
        settings,
    );
    let loaded = follower.loaded();
    startup.shutdown.spawn_until_stopped(follower.run());
    Ok(loaded)
}

/// The snapshot reader opens client keys and shares the stores used by requests.
fn snapshot_source(startup: &Startup<'_>) -> StoreSnapshotSource {
    let Startup {
        foundation,
        stores,
        use_cases,
        ..
    } = startup;
    StoreSnapshotSource::new(SnapshotStores {
        hosts: Arc::clone(&stores.hosts),
        tenants: Arc::clone(&stores.tenants),
        routes: Arc::clone(&stores.routes),
        services: Arc::clone(&stores.services),
        pipelines: Arc::clone(&stores.pipelines),
        stream_routes: Arc::clone(&stores.stream_routes),
        certificates: Arc::clone(&stores.served_certificates),
        issuers: use_cases.issuers.clone(),
        branding: Arc::clone(&stores.branding),
        client_keys: Arc::new(OpenClientKeyUseCase::new(OpenClientKeyPorts {
            encryptor: Arc::clone(&foundation.encryptor),
        })),
        connector_tunnels: Arc::clone(&stores.connector_tunnels),
    })
}

/// What the status listener answers with.
fn runtime_ports(foundation: &Foundation, metrics: &Metrics, tables: TablesLoaded) -> RuntimePorts {
    RuntimePorts {
        readiness: CheckReadinessPorts {
            database: Arc::new(PgReadinessProbe::new(Arc::clone(&foundation.databases))),
            message_bus: Arc::new(BusReadinessProbe::new(Arc::clone(&foundation.bus))),
            cache: Arc::new(CacheReadinessProbe::new(Arc::clone(
                &foundation.shared_state,
            ))),
        },
        exporter: Arc::clone(&metrics.exporter),
        tables,
    }
}

/// The counters every gateway shares.
fn fleet_counters(foundation: &Foundation) -> Arc<dyn FleetCounters> {
    Arc::new(CacheFleetCounters::new(Arc::clone(
        &foundation.shared_state,
    )))
}

/// The one renderer of every error page.
fn pages() -> Result<Arc<dyn PageRenderer>, PlatformError> {
    let renderer = TemplatePageRenderer::new().map_err(PlatformError::of("the page templates"))?;
    Ok(Arc::new(renderer))
}

/// How long the parts of one request may take, and how much of it is read.
fn bounds(config: &Config) -> RequestBounds {
    let limits = &config.limits;
    RequestBounds {
        bodies: limits.request_bodies,
        response_stages: limits.response_reads.response_stages,
        canary_scan: limits.response_reads.canary_scan,
        body_read: config.listen.timeouts.header,
        pipeline: limits.pipeline_timeout,
        call: limits.pipeline_timeout,
    }
}

/// How the main listener protects its connections.
fn main_transport(config: &Config, tls: &Tls) -> Transport {
    match config.listen.transport {
        MainTransport::PlainInDevelopment => Transport::Plain,
        MainTransport::Tls { .. } => Transport::Tls(Arc::new(TlsTerminator::new(
            Arc::clone(&tls.provider),
            TlsSources {
                certificates: Arc::clone(&tls.certificates),
                client_auth: Arc::clone(&tls.client_auth),
                names: Arc::clone(&tls.names),
            },
            config.listen.timeouts.handshake,
        ))),
    }
}

/// Whose PROXY header the main listener reads.
fn proxy_protocol(config: &Config) -> ProxyProtocol {
    match &config.listen.proxy_protocol {
        Peers::Off => ProxyProtocol::Off,
        Peers::From(peers) => ProxyProtocol::FromIngress(peers.clone()),
    }
}

/// One listener's binding and connection protection.
struct ListenerSetup {
    name: &'static str,
    address: SocketAddr,
    transport: Transport,
    proxy_protocol: ProxyProtocol,
}

/// Opens the public handler with the deployment's TLS and ingress settings.
async fn open_public(
    startup: &Startup<'_>,
    tls: &Tls,
    gateway: &Gateway,
) -> Result<SocketAddr, GatewayError> {
    open(
        ListenerSetup {
            name: "public",
            address: startup.config.listen.main,
            transport: main_transport(startup.config, tls),
            proxy_protocol: proxy_protocol(startup.config),
        },
        startup.config,
        gateway.clone(),
        startup.shutdown,
    )
    .await
}

/// Opens the plain ACME challenge listener when the deployment names one.
async fn open_acme(startup: &Startup<'_>) -> Result<Option<SocketAddr>, GatewayError> {
    let Some(address) = startup.config.listen.acme else {
        return Ok(None);
    };
    let bound = open(
        ListenerSetup {
            name: "acme",
            address,
            transport: Transport::Plain,
            proxy_protocol: ProxyProtocol::Off,
        },
        startup.config,
        AcmeResponder::new(
            Arc::clone(&startup.stores.acme_challenges),
            CHALLENGE_LOOKUP,
        ),
        startup.shutdown,
    )
    .await?;
    Ok(Some(bound))
}

/// Opens the runner listener with its own transport and request origin.
async fn open_runners(
    startup: &Startup<'_>,
    tls: &Tls,
    gateway: &Gateway,
) -> Result<Option<SocketAddr>, GatewayError> {
    let Some(listen) = &startup.config.listen.runners else {
        return Ok(None);
    };
    let transport = internal_transport(listen, &tls.provider, startup.config)?;
    let bound = open(
        ListenerSetup {
            name: "runner",
            address: listen.address,
            transport,
            proxy_protocol: ProxyProtocol::Off,
        },
        startup.config,
        gateway.reached_by(internal_scheme(&listen.transport)),
        startup.shutdown,
    )
    .await?;
    Ok(Some(bound))
}

/// Opens the workflow listener with access to the running stream supervisor.
async fn open_workflows(
    startup: &Startup<'_>,
    tls: &Tls,
    gateway: &Gateway,
    data: Arc<DataEntry>,
) -> Result<Option<SocketAddr>, GatewayError> {
    let Some(listen) = &startup.config.listen.workflows else {
        return Ok(None);
    };
    let transport = internal_transport(listen, &tls.provider, startup.config)?;
    let bound = open(
        ListenerSetup {
            name: "workflow",
            address: listen.address,
            transport,
            proxy_protocol: ProxyProtocol::Off,
        },
        startup.config,
        gateway.for_workflows(internal_scheme(&listen.transport), data),
        startup.shutdown,
    )
    .await?;
    Ok(Some(bound))
}

/// Binds one listener and registers its task with the shared shutdown.
async fn open<H: Handler>(
    setup: ListenerSetup,
    config: &Config,
    handler: H,
    shutdown: &Shutdown,
) -> Result<SocketAddr, GatewayError> {
    let ListenerSetup {
        name,
        address,
        transport,
        proxy_protocol,
    } = setup;
    let refused = |cause| GatewayError::Listen {
        listener: name,
        address,
        cause,
    };
    let socket = TcpListener::bind(address).await.map_err(refused)?;
    let bound = socket.local_addr().map_err(refused)?;
    let listener = Listener {
        socket,
        transport,
        proxy_protocol,
        permits: ConnectionPermits::new(
            NonZeroUsize::new(config.limits.permits.connections).unwrap_or(NonZeroUsize::MIN),
        ),
        limits: listen_limits(config),
        handler,
    };
    shutdown.spawn(name, listener.run(shutdown.clone()));
    Ok(bound)
}

/// Bounds HTTP parsing and idleness consistently across every HTTP listener.
fn listen_limits(config: &Config) -> ListenLimits {
    let timeouts = config.listen.timeouts;
    ListenLimits {
        opening: timeouts.header,
        http: HttpLimits {
            idle: timeouts.idle,
            header_read: timeouts.header,
            max_headers: config.limits.max_headers,
            max_streams: STREAMS_PER_CONNECTION,
        },
    }
}
