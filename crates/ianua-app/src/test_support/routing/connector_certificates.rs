//! The fake connector authority, the gateway's connector reads, and the
//! enrolled connectors a test starts from.
//!
//! The fake authority reads a signing request whose body is `key<n>` as
//! naming the key whose pin is `n` repeated, and anything else as a
//! request whose signature does not hold.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::routing::connector::PrivateConnector;
use ianua_domain::domains::routing::connector::tunnel::{ConnectorTunnel, ConnectorTunnelRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificateRequestPem, ConnectorId, PublicKeyPin, TenantId};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::routing::{
    ConnectorAuthority, ConnectorIssue, ConnectorSightings, ConnectorTunnelStore,
    IssuedConnectorCertificate,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::routing::{awaiting_connector, connector_code_hash};

/// The authority certificate the fake hands out.
pub const FAKE_CONNECTOR_AUTHORITY_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nfake-connector-authority\n-----END CERTIFICATE-----\n";

/// A signing request the fake authority reads as naming the key `key`.
///
/// # Panics
///
/// Never: the text is a well-formed PEM block.
#[must_use]
pub fn connector_signing_request(key: u8) -> CertificateRequestPem {
    CertificateRequestPem::new(format!(
        "-----BEGIN CERTIFICATE REQUEST-----\nkey{key}\n-----END CERTIFICATE REQUEST-----\n"
    ))
    .expect("the fake request is a PEM block")
}

/// The pin of the key the fake authority reads `key<key>` as.
#[must_use]
pub fn connector_key(key: u8) -> PublicKeyPin {
    PublicKeyPin::from_digest([key; 32])
}

/// A connector named `name`, created and enrolled with the key `key` just
/// now, allowed to dial `name.corp.internal`.
///
/// # Panics
///
/// Panics if the domain refuses the enrollment, which it never does here.
#[must_use]
pub fn enrolled_connector(name: &str, key: u8) -> PrivateConnector<ResolvedTenant> {
    let code = format!("{name}-code");
    let domain = format!("{name}.corp.internal");
    let mut connector = awaiting_connector(name, &code, &[domain.as_str()]);
    connector
        .enroll(&connector_code_hash(&code), connector_key(key))
        .expect("a fresh code enrolls");
    connector
}

/// Connector authority for tests. It counts what it signs.
#[derive(Default)]
pub struct FakeConnectorAuthority {
    signed: AtomicUsize,
}

impl FakeConnectorAuthority {
    /// How many certificates it signed.
    #[must_use]
    pub fn signed(&self) -> usize {
        self.signed.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ConnectorAuthority for FakeConnectorAuthority {
    fn key_of(&self, request: &CertificateRequestPem) -> Result<PublicKeyPin, DomainError> {
        request
            .as_str()
            .lines()
            .find_map(|line| line.strip_prefix("key"))
            .and_then(|key| key.trim().parse::<u8>().ok())
            .map(connector_key)
            .ok_or_else(|| DomainError::invalid("the signing request's signature does not hold"))
    }

    async fn issue(
        &self,
        issue: ConnectorIssue<'_>,
    ) -> Result<IssuedConnectorCertificate, DomainError> {
        if self.key_of(issue.request)? != *issue.certificate.key() {
            return Err(DomainError::invalid(
                "the signing request names another key",
            ));
        }
        self.signed.fetch_add(1, Ordering::SeqCst);
        Ok(IssuedConnectorCertificate {
            certificate_pem: format!(
                "-----BEGIN CERTIFICATE-----\nconnector-{}\n-----END CERTIFICATE-----\n",
                issue.connector
            ),
            authority_pem: FAKE_CONNECTOR_AUTHORITY_PEM.to_owned(),
        })
    }
}

/// The gateway's read of enrolled connectors, over what a test puts in,
/// each under the tenant it belongs to.
#[derive(Default)]
pub struct FakeConnectorTunnelStore {
    tunnels: Mutex<Vec<(TenantId, ConnectorTunnel)>>,
}

impl TenantScoped for FakeConnectorTunnelStore {}

impl FakeConnectorTunnelStore {
    /// A store holding what `connector` shows the gateway, in `tenant`.
    ///
    /// # Panics
    ///
    /// Panics if `connector` is not enrolled.
    #[must_use]
    pub fn holding(tenant: TenantId, connector: &PrivateConnector<ResolvedTenant>) -> Self {
        let store = Self::default();
        store.put(tenant, connector);
        store
    }

    /// Puts what `connector` shows the gateway in `tenant`, in place of
    /// what was there for it.
    ///
    /// # Panics
    ///
    /// Panics if `connector` is not enrolled.
    pub fn put(&self, tenant: TenantId, connector: &PrivateConnector<ResolvedTenant>) {
        let certificate = connector
            .certificate()
            .expect("only an enrolled connector is shown to the gateway");
        let tunnel = ConnectorTunnel::reconstitute(ConnectorTunnelRow {
            id: *connector.id(),
            scope: connector.scope().clone(),
            key: *certificate.key(),
            status: connector.status(),
        })
        .expect("a connector's own parts make a tunnel");
        let mut tunnels = self.tunnels.lock().unwrap();
        tunnels.retain(|(owner, held)| !(*owner == tenant && held.id() == connector.id()));
        tunnels.push((tenant, tunnel));
    }
}

#[async_trait]
impl ConnectorTunnelStore for FakeConnectorTunnelStore {
    async fn enrolled(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ConnectorTunnel>, DomainError> {
        Ok(self
            .tunnels
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, _)| owner == &**tenant_id)
            .map(|(_, tunnel)| tunnel.clone())
            .collect())
    }
}

/// The gateway's sightings, noted in order.
#[derive(Default)]
pub struct FakeConnectorSightings {
    seen: Mutex<Vec<(TenantId, ConnectorId, OffsetDateTime)>>,
}

impl TenantScoped for FakeConnectorSightings {}

impl FakeConnectorSightings {
    /// Every sighting noted, in order.
    #[must_use]
    pub fn noted(&self) -> Vec<(TenantId, ConnectorId, OffsetDateTime)> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl ConnectorSightings for FakeConnectorSightings {
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        connector: &ConnectorId,
        at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.seen
            .lock()
            .unwrap()
            .push((**tenant_id, *connector, at));
        Ok(())
    }
}

impl Fake for Arc<dyn ConnectorAuthority> {
    fn fake() -> Self {
        Arc::new(FakeConnectorAuthority::default())
    }
}

impl Fake for Arc<dyn ConnectorTunnelStore> {
    fn fake() -> Self {
        Arc::new(FakeConnectorTunnelStore::default())
    }
}

impl Fake for Arc<dyn ConnectorSightings> {
    fn fake() -> Self {
        Arc::new(FakeConnectorSightings::default())
    }
}
