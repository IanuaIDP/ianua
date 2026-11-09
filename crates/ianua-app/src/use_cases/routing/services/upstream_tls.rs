//! How a service's upstream TLS arrives, and how its client key is sealed
//! before the service is stored.
//!
//! The client certificate's private key comes in raw. It is sealed through
//! the crypto port here, so only its sealed form reaches the service, the
//! store and any event. An upstream handed over with TLS already set would
//! carry a key that never passed through here, so it is refused: TLS is
//! given beside the upstream, never inside it.

use ianua_domain::domains::routing::backend::tls::{
    UpstreamClientCertificate, UpstreamTls, UpstreamTlsParams, UpstreamTrust,
};
use ianua_domain::domains::routing::backend::upstream::Upstream;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, DomainName, ServiceId, Setting};

use crate::error::AppError;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor, SecretEncryptor};
use crate::services::sealing::sealed_text;
use crate::tenancy::ScopedTenant;

/// How the gateway is to open TLS to a service's upstream, as an admin
/// gives it.
pub struct UpstreamTlsRequest {
    /// Which CAs the upstream's certificate must chain to.
    pub trust: UpstreamTrust,
    /// The certificate presented when the upstream asks for one.
    pub client_certificate: Setting<ClientCertificateRequest>,
    /// The name sent as SNI and checked against the upstream's certificate,
    /// when it is not the host in the upstream's address.
    pub server_name: Setting<DomainName>,
}

/// A client certificate with its private key, as an admin gives it. It has
/// no `Debug`, so the key never prints.
pub struct ClientCertificateRequest {
    /// The certificate chain presented.
    pub certificate: CertificatePem,
    /// The private key PEM, raw. Sealed before it is stored.
    pub private_key: Secret,
}

/// Refuses an upstream that already carries TLS settings.
///
/// # Errors
///
/// `AppError::Domain` when `upstream` has TLS set.
pub(crate) fn ensure_no_tls_given(upstream: &Upstream) -> Result<(), AppError> {
    if upstream.tls().is_some() {
        return Err(AppError::from_domain(DomainError::invalid(message!(
            "routing-upstream-tls-is-given-on-its",
            "upstream TLS is given on its own, so its client key is sealed before it is stored"
        ))));
    }
    Ok(())
}

/// Where `tenant`'s service `service` keeps the client key it presents
/// to its upstream.
pub(crate) fn client_key_place(tenant: &ScopedTenant, service: &ServiceId) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::UpstreamClientKey,
        service,
    )
}

/// The TLS settings `request` describes, its client key sealed for
/// `place`.
///
/// # Errors
///
/// - `AppError::Domain` when the server name is a wildcard.
/// - `AppError::Internal` when the key cannot be sealed.
pub(crate) async fn sealed_tls(
    encryptor: &dyn SecretEncryptor,
    request: UpstreamTlsRequest,
    place: &SealedFor,
) -> Result<UpstreamTls, AppError> {
    let client_certificate = match request.client_certificate {
        Setting::Unset => Setting::Unset,
        Setting::Set(given) => Setting::Set(sealed_certificate(encryptor, given, place).await?),
    };
    UpstreamTls::new(UpstreamTlsParams {
        trust: request.trust,
        client_certificate,
        server_name: request.server_name,
    })
    .map_err(|refused| AppError::from_domain(DomainError::from(refused)))
}

/// `given` with its private key sealed for `place`.
///
/// # Errors
///
/// `AppError::Internal` when the key cannot be sealed.
async fn sealed_certificate(
    encryptor: &dyn SecretEncryptor,
    given: ClientCertificateRequest,
    place: &SealedFor,
) -> Result<UpstreamClientCertificate, AppError> {
    let private_key = sealed_text(encryptor, given.private_key.expose(), place).await?;
    Ok(UpstreamClientCertificate::new(
        given.certificate,
        private_key,
    ))
}

/// `upstream` with `tls` set on it, or as it is when `tls` is `None`.
pub(crate) fn with_tls(upstream: Upstream, tls: Option<&UpstreamTls>) -> Upstream {
    match tls {
        Some(tls) => upstream.with_tls(tls.clone()),
        None => upstream,
    }
}
