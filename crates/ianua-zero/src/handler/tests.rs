//! The handler's refusals before and around the pipeline, each the deny
//! by default a request that cannot be decided gets. A client certificate
//! whose authority the tenant removed is refused at the next handshake,
//! which the listener's own tests cover.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::Request;
use http::request::Parts;
use ianua_app::error::AppError;
use ianua_app::ports::authentication::{PassReach, RunPassToken, TokenFault, TokenReading};
use ianua_app::ports::pages::{ErrorBranding, ErrorPageKind};
use ianua_app::ports::proxy::HostedTenant;
use ianua_app::test_support::proxy::test_pipeline_in;
use ianua_app::test_support::routing::{RouteShape, pinned_upstream, route_of, service_named};
use ianua_domain::domains::proxy::observation::GatewayCheck;
use ianua_domain::domains::proxy::pipeline_status::PipelineStatus;
use ianua_domain::domains::proxy::request::forwarded::ClientScheme;
use ianua_domain::domains::tenant::access::network_security::MtlsConfig;
use ianua_domain::domains::tenant::hosts::{PlatformAddressing, PlatformLabel, ReadableAddress};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ActionCallId, CorrelationId, DenialStatus, DisplayName, DomainName, Fact, Issuer,
    OrganizationId, RouteId, TenantId, TenantSlug, UserId,
};
use ianua_infra::cache::{CacheFleetCounters, MemoryState};
use ianua_infra::pages::TemplatePageRenderer;
use tokio_rustls::rustls::crypto::ring;

use super::refuse::Refused;
use super::{resolution, run, upstream};
use crate::follow::{Tables as _, TenantSnapshot};
use crate::listen::{
    CertificateTable, ClientAuthTable, ClientCertificate, ConnectionFacts, ConnectionParts,
};
use crate::request;
use crate::resolve::{Tables, TablesParts};

/// The shop's host.
const SHOP: &str = "shop.acme.com";

/// A TLS connection whose handshake asked for `name`.
fn tls_for(name: &str) -> ConnectionFacts {
    let client: SocketAddr = "203.0.113.7:50000".parse().unwrap();
    ConnectionFacts::new(ConnectionParts {
        client,
        peer: client,
        scheme: ClientScheme::Https,
        server_name: Fact::Known(DomainName::new(name).unwrap()),
        client_certificate: ClientCertificate::NotAsked,
        ja4: Fact::Unknown,
    })
}

/// `GET path` on `host`.
fn get(host: &str, path: &str) -> Parts {
    let (parts, ()) = Request::get(path)
        .header("host", host)
        .body(())
        .unwrap()
        .into_parts();
    parts
}

/// Tables serving the shop, on `shop.acme.com`, with one public route on
/// `/app`.
fn serving_the_shop() -> Tables {
    let tables = empty_tables();
    let pipeline = test_pipeline_in(PipelineStatus::Active);
    let service = service_named("app", pinned_upstream("https://backend.example.com", "app"));
    let route = route_of(RouteShape::public("app", "/app"), &service, &pipeline);
    tables.install(TenantSnapshot {
        hosted: HostedTenant {
            platform_label: PlatformLabel::new("k7f3q9").unwrap(),
            readable_address: ReadableAddress::Off,
            tenant_id: TenantId::new(),
            organization_slug: TenantSlug::try_from("acme-org".to_owned()).unwrap(),
            slug: TenantSlug::try_from("shop".to_owned()).unwrap(),
            domains: vec![DomainName::new(SHOP).unwrap()],
        },
        organization: OrganizationId::new(),
        issuer: Issuer::new("https://app.example.com/t/acme-org/shop").unwrap(),
        branding: ErrorBranding {
            name: DisplayName::try_from("Shop".to_owned()).unwrap(),
            logo_url: None,
            primary_color: None,
            background_color: None,
        },
        mtls: MtlsConfig::disabled(),
        routes: vec![route],
        services: vec![service],
        pipelines: vec![pipeline],
        client_keys: Vec::new(),
        connectors: Vec::new(),
    });
    tables
}

/// Empty host and certificate tables using the gateway's nested addressing.
fn empty_tables() -> Tables {
    let provider = Arc::new(ring::default_provider());
    Tables::new(TablesParts {
        addressing: PlatformAddressing::Nested,
        base_domain: DomainName::new("apps.example.com").unwrap(),
        client_auth: Arc::new(ClientAuthTable::new(Arc::clone(&provider))),
        certificates: Arc::new(CertificateTable::new(provider, &[]).unwrap()),
    })
}

/// A request for the shop over a connection opened for Eve's host is refused with 421.
#[test]
fn hosts_outside_the_handshake_are_misdirected() {
    let mut parts = get(SHOP, "/app");

    let refused = resolution::admitted(&mut parts, &tls_for("eve.example.com")).unwrap_err();

    assert_eq!(refused.status(), DenialStatus::MISDIRECTED_REQUEST);
}

/// A request whose path has two readings is refused before anything reads
/// it.
#[test]
fn ambiguous_paths_are_bad_requests() {
    let mut parts = get(SHOP, "/a/%2e%2e/admin");

    let refused = resolution::admitted(&mut parts, &tls_for(SHOP)).unwrap_err();

    assert_eq!(refused.status(), DenialStatus::BAD_REQUEST);
}

/// An unknown host returns 404 even when the shop is present in the routing table.
#[test]
fn an_unknown_host_is_not_found() {
    let tables = serving_the_shop();
    let mut parts = get("nobody.example.com", "/app");
    let admitted = resolution::admitted(&mut parts, &tls_for("nobody.example.com")).unwrap();

    let refused = resolution::tenant(&tables.current(), &admitted)
        .err()
        .unwrap();

    assert_eq!(refused.status(), DenialStatus::NOT_FOUND);
}

/// An unmatched path on the shop's known host returns 404.
#[test]
fn answers_not_found_for_unmatched_paths() {
    let tables = serving_the_shop();
    let mut parts = get(SHOP, "/admin");
    let admitted = resolution::admitted(&mut parts, &tls_for(SHOP)).unwrap();
    let routing = tables.current();
    let resolved = resolution::tenant(&routing, &admitted).ok().unwrap();

    let refused = resolution::route(&resolved.table, &admitted, &parts).unwrap_err();

    assert_eq!(refused.status(), DenialStatus::NOT_FOUND);
}

/// The shop's route takes a request to its path.
#[test]
fn matching_paths_resolve_their_route() {
    let tables = serving_the_shop();
    let mut parts = get(SHOP, "/app");
    let admitted = resolution::admitted(&mut parts, &tls_for(SHOP)).unwrap();
    let routing = tables.current();
    let resolved = resolution::tenant(&routing, &admitted).ok().unwrap();

    let matched = resolution::route(&resolved.table, &admitted, &parts);

    assert!(matched.is_ok());
}

/// Admission strips client-supplied identity, assertion and group headers,
/// including underscore spelling, while retaining the request ID.
#[test]
fn admission_strips_client_identity_headers() {
    let (mut parts, ()) = Request::get("/app")
        .header("host", SHOP)
        .header("x-forwarded-user", "ann")
        .header("x-ianua-assertion", "eyJhbGciOiJub25lIn0.e30.")
        .header("x_forwarded_groups", "admins")
        .header("x-request-id", "kept")
        .body(())
        .unwrap()
        .into_parts();

    let admitted = request::admit(&mut parts);

    assert!(admitted.is_ok());
    assert!(parts.headers.get("x-forwarded-user").is_none());
    assert!(parts.headers.get("x-ianua-assertion").is_none());
    assert!(parts.headers.get("x_forwarded_groups").is_none());
    assert_eq!(parts.headers["x-request-id"], "kept");
}

/// A pipeline error is converted to a 503 refusal.
#[test]
fn a_pipeline_that_fails_is_unavailable() {
    let refused = run::decided::<&str>(Ok(Err("the policy store is unreachable")))
        .err()
        .unwrap();

    assert_eq!(refused.status(), DenialStatus::SERVICE_UNAVAILABLE);
}

/// A pipeline timeout is converted to a 503 refusal.
#[tokio::test]
async fn pipeline_timeouts_answer_unavailable() {
    let elapsed = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
        .await
        .unwrap_err();

    let refused = run::decided::<&str>(Err(elapsed)).err().unwrap();

    assert_eq!(refused.status(), DenialStatus::SERVICE_UNAVAILABLE);
}

/// A missing assertion signing key is converted to a 503 refusal.
#[test]
fn missing_assertion_keys_answer_unavailable() {
    let unsigned = upstream::assertion_header(Ok(Err(AppError::NotFound(
        "assertion signing key".to_owned().into(),
    ))))
    .err()
    .unwrap();

    assert_eq!(unsigned.status(), DenialStatus::SERVICE_UNAVAILABLE);
}

/// Resolving application sign-in without an API relay returns a 503 refusal.
#[test]
fn missing_login_relay_answers_unavailable() {
    let counters = CacheFleetCounters::new(Arc::new(MemoryState::new(10)));

    let refused = resolution::gate(None, &counters).err().unwrap();

    assert_eq!(refused.status(), DenialStatus::SERVICE_UNAVAILABLE);
}

/// Ann's browser, signed out, loading a page of the shop is sent to sign
/// in; the shop's script asking the same is told `401`, never redirected.
#[test]
fn browsers_redirect_while_scripts_receive_unauthorized() {
    let pages = TemplatePageRenderer::new().unwrap();
    let missing = || {
        Refused::at_gateway(
            ErrorPageKind::NotSignedIn,
            GatewayCheck::PipelineOff,
            "credential_missing",
        )
        .answered_with(DenialStatus::UNAUTHORIZED)
    };
    let browser = missing().signing_in_at(Some(format!("https://{SHOP}/.ianua/login")));
    let mut accepts_json = http::HeaderMap::new();
    accepts_json.insert("accept", http::HeaderValue::from_static("application/json"));

    let sent = browser.answer(&accepts_json, CorrelationId::new(), &pages);
    let told = missing().answer(&accepts_json, CorrelationId::new(), &pages);

    assert_eq!(sent.status(), http::StatusCode::SEE_OTHER);
    assert_eq!(
        sent.headers()["location"],
        format!("https://{SHOP}/.ianua/login").as_str()
    );
    assert_eq!(told.status(), http::StatusCode::UNAUTHORIZED);
    assert!(told.headers().get("location").is_none());
}

/// A pass the gateway read and found good, for Pat's run on the shop.
fn pats_pass() -> RunPassToken {
    RunPassToken {
        call_id: ActionCallId::new(),
        user_id: UserId::new(),
        reaches: PassReach::Route(RouteId::new()),
        expires_at: ianua_domain::shared::clock::now() + time::Duration::MINUTE,
    }
}

/// Pat's run's pass reads back good: the run is let through to its route.
#[test]
fn a_good_pass_is_let_through() {
    let checked = resolution::pass_checked(Ok(Ok(TokenReading::Read(pats_pass()))));

    assert!(checked.is_ok());
}

/// An expired run-pass result is converted to a 401 refusal.
#[test]
fn answers_unauthorized_for_refused_passes() {
    let refused = resolution::pass_checked(Ok(Ok(TokenReading::Refused(TokenFault::Expired))))
        .err()
        .unwrap();

    assert_eq!(refused.status(), DenialStatus::UNAUTHORIZED);
}

/// A run-pass verification timeout is converted to 503 rather than an invalid-token response.
#[tokio::test]
async fn pass_check_timeouts_answer_unavailable() {
    let elapsed = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
        .await
        .unwrap_err();

    let refused = resolution::pass_checked(Err(elapsed)).err().unwrap();

    assert_eq!(refused.status(), DenialStatus::SERVICE_UNAVAILABLE);
}

/// A run-pass key-store error is converted to a 503 refusal.
#[test]
fn unreadable_pass_keys_answer_unavailable() {
    let unread = DomainError::infra_msg("the key store did not answer");

    let refused = resolution::pass_checked(Ok(Err(unread))).err().unwrap();

    assert_eq!(refused.status(), DenialStatus::SERVICE_UNAVAILABLE);
}
