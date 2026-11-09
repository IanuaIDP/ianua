//! Handing a connector's agent the certificate the domain allowed: signed
//! by the platform's connector authority, then the connector saved and
//! what it raised recorded. Enrollment and renewal both end this way.

use std::sync::Arc;

use ianua_domain::domains::routing::connector::PrivateConnector;
use ianua_domain::domains::routing::connector::certificate::ConnectorCertificate;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{CertificateRequestPem, ConnectorId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::{ConnectorAuthority, ConnectorIssue, ConnectorStore};
use crate::tenancy::ScopedTenant;

/// A certificate signed for a connector's agent, with what it needs to
/// hold its link and to know when to ask again.
pub struct IssuedConnector {
    /// The enrolled identity authenticated by the issued certificate.
    pub connector_id: ConnectorId,
    /// The connector's certificate, PEM.
    pub certificate_pem: String,
    /// The authority's certificate, PEM, which the gateway's listener is
    /// checked against.
    pub authority_pem: String,
    /// When the certificate stops being good.
    pub expires_at: OffsetDateTime,
    /// From when the agent asks for the next one.
    pub renew_after: OffsetDateTime,
}

/// What the signing goes through.
pub(crate) struct CertificateDesk<'a> {
    /// Signs the certificate.
    pub(crate) authority: &'a dyn ConnectorAuthority,
    /// Keeps the connector.
    pub(crate) store: &'a dyn ConnectorStore,
}

/// One certificate to sign: for which connector, against which request,
/// as the domain allowed it.
pub(crate) struct Signing<'a> {
    /// The connector, changed by the domain and not saved yet.
    pub(crate) connector: &'a mut PrivateConnector<ResolvedTenant>,
    /// The request the agent sent.
    pub(crate) request: &'a CertificateRequestPem,
    /// What the domain allowed.
    pub(crate) certificate: ConnectorCertificate,
}

impl<'a> CertificateDesk<'a> {
    /// The desk signing through `authority` and saving to `store`.
    pub(crate) fn over(
        authority: &'a Arc<dyn ConnectorAuthority>,
        store: &'a Arc<dyn ConnectorStore>,
    ) -> Self {
        Self {
            authority: authority.as_ref(),
            store: store.as_ref(),
        }
    }

    /// Signs `signing`'s certificate, then saves its connector in `tenant`
    /// and records what it raised through `auditor`.
    ///
    /// Signed first: a connector saved enrolled whose certificate could
    /// not be signed would hold a spent code and no certificate. A
    /// certificate signed for a connector that then fails to save opens
    /// nothing, since the gateway admits only the key saved.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the request names another key.
    /// - `AppError::Internal` on signing, storage or audit failure.
    pub(crate) async fn issue(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        signing: Signing<'_>,
    ) -> Result<IssuedConnector, AppError> {
        let issued = self
            .authority
            .issue(ConnectorIssue {
                tenant: **tenant,
                connector: *signing.connector.id(),
                request: signing.request,
                certificate: &signing.certificate,
            })
            .await
            .map_err(AppError::from_domain)?;
        self.store
            .save(tenant, signing.connector)
            .await
            .or_internal()?;
        auditor
            .dispatch(&signing.connector.take_events(tenant))
            .await
            .or_internal()?;
        Ok(IssuedConnector {
            connector_id: *signing.connector.id(),
            certificate_pem: issued.certificate_pem,
            authority_pem: issued.authority_pem,
            expires_at: signing.certificate.expires_at(),
            renew_after: signing.certificate.renew_after(),
        })
    }
}
