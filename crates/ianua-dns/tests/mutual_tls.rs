//! A nameserver on a host of its own following the control plane's zone
//! stream, both ends authenticating each other for real: a gRPC listener
//! on a loopback port, the nameserver started as the binary starts it,
//! and real queries asked of it.

#![cfg(test)]

mod support;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use ianua_app::ports::domain::DnsZoneReader;
use ianua_boot::env::Env;
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{
    HeldZone, RecordName, RecordSet, RecordValue, Serial, Ttl, Zone, ZoneStanding,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, IpAddress, TenantId};
use ianua_grpc::{DnsZonesService, GrpcConfig, GrpcListener, GrpcTls};
use ianua_infra::crypto::{KeyedCertificate, LinkPki, LinkValidity, issue_link_pki};
use ianua_proto::dns::v1::WatchRequest;
use ianua_proto::dns::v1::dns_zones_client::DnsZonesClient;
use tokio::sync::Notify;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

use crate::support::{addresses, answered_within, over_tcp};

/// The name the control plane's certificate carries, dialled by address.
const SERVER_NAME: &str = "localhost";

/// The name asked for, in the one zone the control plane holds.
const ASKED: &str = "api.auth.acme.test";

/// How long a catalog that should arrive may take.
const PATIENCE: Duration = Duration::from_secs(10);

/// How long to watch before concluding no catalog is coming.
const BRIEFLY: Duration = Duration::from_secs(2);

/// A reader holding Acme's one proven zone.
struct AcmeZone;

#[async_trait::async_trait]
impl DnsZoneReader for AcmeZone {
    async fn load_all_zones(&self) -> Result<Vec<HeldZone>, DomainError> {
        let set = RecordSet::new(
            RecordName::new(ASKED).unwrap(),
            Ttl::standard(),
            vec![RecordValue::Address(
                IpAddress::new("198.51.100.1").unwrap(),
            )],
        )
        .unwrap();
        let zone = Zone::new(
            DomainName::new("auth.acme.test").unwrap(),
            Serial::at(time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()),
            vec![set],
            vec![DomainName::new("abc123.ns1.ianua.test").unwrap()],
        )
        .unwrap();
        Ok(vec![HeldZone {
            zone,
            owner: TenantId::new(),
            standing: ZoneStanding::Proven,
        }])
    }
}

fn install_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

fn pki() -> LinkPki {
    issue_link_pki(SERVER_NAME, &["ns1".to_owned()], LinkValidity::default()).unwrap()
}

/// The control plane's listener, serving Acme's zone with `pki`'s server
/// certificate and trusting its authority, until `stop` is notified.
async fn control_plane(pki: &LinkPki, stop: &Arc<Notify>) -> SocketAddr {
    let config = GrpcConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        tls: GrpcTls {
            certificate_pem: pki.server.certificate_pem.clone(),
            private_key_pem: pki.server.private_key_pem.clone(),
            client_ca_pem: pki.authority.certificate_pem.clone(),
        },
    };
    let listener = GrpcListener::open(config, DnsZonesService::new(Arc::new(AcmeZone)))
        .await
        .unwrap();
    let address = listener.address();
    let stopping = Arc::clone(stop);
    tokio::spawn(listener.serve(async move { stopping.notified().await }));
    address
}

/// The client identity and server authority used for a nameserver's link.
struct LinkCredentials<'a> {
    client: &'a KeyedCertificate,
    authority_pem: &'a str,
}

/// A nameserver following the control plane at `control`, using `credentials`
/// for mutual TLS and writing their files to `folder`.
async fn nameserver(
    folder: &Path,
    control: SocketAddr,
    credentials: &LinkCredentials<'_>,
    shutdown: &Shutdown,
) -> SocketAddr {
    let write = |name: &str, contents: &str| {
        let path = folder.join(name);
        std::fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    };
    let certificate = write("ns1-cert.pem", &credentials.client.certificate_pem);
    let key = write("ns1-key.pem", credentials.client.private_key_pem.expose());
    let authority = write("ca-cert.pem", credentials.authority_pem);
    let endpoint = format!("https://{control}");
    let vars = Env::of([
        ("APP_ENV", "development"),
        ("CONTROL_PLANE_ENDPOINT", endpoint.as_str()),
        ("CONTROL_PLANE_SERVER_NAME", SERVER_NAME),
        ("CONTROL_PLANE_CLIENT_CERT", certificate.as_str()),
        ("CONTROL_PLANE_CLIENT_KEY", key.as_str()),
        ("CONTROL_PLANE_CA_CERT", authority.as_str()),
        ("DNS_BIND", "127.0.0.1:0"),
        ("DNS_HOSTMASTER", "hostmaster.ianua.test"),
    ]);
    ianua_dns::serving(&vars, shutdown).await.unwrap().address
}

async fn stopped(shutdown: Shutdown, control: &Arc<Notify>) {
    control.notify_one();
    shutdown.stop();
    shutdown.join().await.unwrap();
}

/// A nameserver holding a certificate the deployment's authority issued
/// receives the zones, and answers for them over UDP and TCP.
#[tokio::test]
async fn a_nameserver_with_our_certificate_answers_from_the_stream() {
    install_crypto_provider();
    let pki = pki();
    let stop = Arc::new(Notify::new());
    let control = control_plane(&pki, &stop).await;
    let folder = tempfile::tempdir().unwrap();
    let shutdown = Shutdown::new(Duration::from_secs(2));
    let dns = nameserver(
        folder.path(),
        control,
        &LinkCredentials {
            client: &pki.clients[0].keyed,
            authority_pem: &pki.authority.certificate_pem,
        },
        &shutdown,
    )
    .await;

    let udp = answered_within(dns, ASKED, PATIENCE).await;
    let tcp = over_tcp(dns, ASKED).await;

    let udp = udp.expect("the zones arrived over the stream");
    assert!(udp.metadata.authoritative);
    assert_eq!(addresses(&udp), ["198.51.100.1"]);
    assert_eq!(addresses(&tcp), ["198.51.100.1"]);
    stopped(shutdown, &stop).await;
}

/// A nameserver with a client certificate from another authority cannot
/// obtain a catalog that answers Acme's query.
#[tokio::test]
async fn a_certificate_from_another_authority_is_refused() {
    install_crypto_provider();
    let ours = pki();
    let theirs = pki();
    let stop = Arc::new(Notify::new());
    let control = control_plane(&ours, &stop).await;
    let folder = tempfile::tempdir().unwrap();
    let shutdown = Shutdown::new(Duration::from_secs(2));
    let dns = nameserver(
        folder.path(),
        control,
        &LinkCredentials {
            client: &theirs.clients[0].keyed,
            authority_pem: &ours.authority.certificate_pem,
        },
        &shutdown,
    )
    .await;

    let answered = answered_within(dns, ASKED, BRIEFLY).await;

    assert!(
        answered.is_none(),
        "a stranger's certificate must not read the zones"
    );
    stopped(shutdown, &stop).await;
}

/// A caller trusting the server but presenting no client certificate
/// cannot open the zone stream.
#[tokio::test]
async fn a_caller_without_a_certificate_is_refused() {
    install_crypto_provider();
    let pki = pki();
    let stop = Arc::new(Notify::new());
    let control = control_plane(&pki, &stop).await;
    let tls = ClientTlsConfig::new()
        .domain_name(SERVER_NAME)
        .ca_certificate(Certificate::from_pem(&pki.authority.certificate_pem));

    let watched = async {
        let channel = Endpoint::from_shared(format!("https://{control}"))?
            .tls_config(tls)?
            .connect()
            .await?;
        let opened = DnsZonesClient::new(channel)
            .watch(WatchRequest {})
            .await
            .map(|_| ());
        Ok::<_, Box<dyn std::error::Error>>(opened.is_ok())
    }
    .await;

    assert!(
        !matches!(watched, Ok(true)),
        "a caller without a certificate must not open the stream"
    );
    stop.notify_one();
}

/// A nameserver trusting the wrong control-plane authority obtains no
/// catalog that answers Acme's query.
#[tokio::test]
async fn a_control_plane_it_cannot_check_is_refused() {
    install_crypto_provider();
    let ours = pki();
    let theirs = pki();
    let stop = Arc::new(Notify::new());
    let control = control_plane(&ours, &stop).await;
    let folder = tempfile::tempdir().unwrap();
    let shutdown = Shutdown::new(Duration::from_secs(2));
    let dns = nameserver(
        folder.path(),
        control,
        &LinkCredentials {
            client: &ours.clients[0].keyed,
            authority_pem: &theirs.authority.certificate_pem,
        },
        &shutdown,
    )
    .await;

    let answered = answered_within(dns, ASKED, BRIEFLY).await;

    assert!(
        answered.is_none(),
        "an unchecked control plane must not be believed"
    );
    stopped(shutdown, &stop).await;
}

/// After the control-plane listener stops, the nameserver still answers
/// Acme's query with the address received before the stream ended.
#[tokio::test]
async fn a_dropped_stream_keeps_the_last_zones() {
    install_crypto_provider();
    let pki = pki();
    let stop = Arc::new(Notify::new());
    let control = control_plane(&pki, &stop).await;
    let folder = tempfile::tempdir().unwrap();
    let shutdown = Shutdown::new(Duration::from_secs(2));
    let dns = nameserver(
        folder.path(),
        control,
        &LinkCredentials {
            client: &pki.clients[0].keyed,
            authority_pem: &pki.authority.certificate_pem,
        },
        &shutdown,
    )
    .await;
    answered_within(dns, ASKED, PATIENCE)
        .await
        .expect("the zones arrived over the stream");

    stop.notify_one();
    tokio::time::sleep(BRIEFLY).await;
    let after = support::over_udp(dns, ASKED).await;

    assert_ne!(after.metadata.response_code, ResponseCode::Refused);
    assert_eq!(addresses(&after), ["198.51.100.1"]);
    shutdown.stop();
    shutdown.join().await.unwrap();
}
