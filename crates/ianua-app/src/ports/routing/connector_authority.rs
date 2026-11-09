//! The platform's connector authority: what reads a connector's signing
//! request and signs the certificate its link to the gateway is held with.

use std::fmt;

use async_trait::async_trait;
use ianua_domain::domains::routing::connector::certificate::ConnectorCertificate;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificateRequestPem, ConnectorId, PublicKeyPin, TenantId};

/// What one certificate is signed for: which tenant's connector, the
/// request its agent sent, and the certificate the domain allowed.
pub struct ConnectorIssue<'a> {
    /// The tenant the connector belongs to.
    pub tenant: TenantId,
    /// The connector identity the certificate will authenticate.
    pub connector: ConnectorId,
    /// The signing request the agent sent, naming its key.
    pub request: &'a CertificateRequestPem,
    /// The key and the end date the domain allowed.
    pub certificate: &'a ConnectorCertificate,
}

/// A certificate the authority signed, with the authority's own
/// certificate, which the agent checks the gateway's listener against.
#[derive(Clone)]
pub struct IssuedConnectorCertificate {
    /// The connector's certificate, PEM.
    pub certificate_pem: String,
    /// The authority's certificate, PEM.
    pub authority_pem: String,
}

impl fmt::Debug for IssuedConnectorCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedConnectorCertificate")
            .finish_non_exhaustive()
    }
}

/// Dyn-safe port signing connectors' certificates.
///
/// One authority for the platform. Each certificate names its tenant and
/// connector, is good for client authentication alone, and carries only
/// the key of the request it answers: nothing else the request asks for
/// is copied into it.
#[async_trait]
pub trait ConnectorAuthority: Send + Sync {
    /// The pin of the key `request` names, once its signature shows the
    /// sender holds that key.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when the request does not parse, asks
    ///   for an extension, or its signature does not hold.
    /// - `DomainError::Infrastructure` when no authority is set up.
    fn key_of(&self, request: &CertificateRequestPem) -> Result<PublicKeyPin, DomainError>;

    /// Signs the certificate `issue` describes.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when the request names another key than
    ///   the certificate allowed.
    /// - `DomainError::Infrastructure` when no authority is set up or the
    ///   signing fails.
    async fn issue(
        &self,
        issue: ConnectorIssue<'_>,
    ) -> Result<IssuedConnectorCertificate, DomainError>;
}
