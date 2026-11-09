//! Encrypted assertion bodies: the key a SAML connection's provider seals
//! its assertions to, made here or brought by the tenant.

use ianua_app::use_cases::federation::connections::{
    RequireEncryptedAssertionsRequest, SpKeySource,
};
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, ConnectionId, SamlEntityId};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Where the key comes from: an empty body `{}` has this platform make a
/// new pair; `certificate` and `private_key` together bring the tenant's
/// own. Holds a private key, so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct EncryptionKeyBody {
    /// The certificate the provider encrypts to, PEM, when bringing a pair.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Its private key, PEM, when bringing a pair. Sealed before it is
    /// stored; never shown again.
    #[serde(default)]
    pub private_key: Option<String>,
}

impl EncryptionKeyBody {
    /// The request making `connection_id` take only assertions sealed to
    /// this key, with `service_provider` as the subject of a key made here.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when only one of the pair is given, or the
    ///   certificate is not PEM.
    pub(crate) fn for_connection(
        self,
        connection_id: ConnectionId,
        service_provider: SamlEntityId,
    ) -> Result<RequireEncryptedAssertionsRequest, ApiError> {
        let key = match (self.certificate, self.private_key) {
            (None, None) => SpKeySource::Generated,
            (Some(certificate), Some(private_key)) => SpKeySource::Uploaded {
                certificate: CertificatePem::new(certificate).map_err(ApiError::validation)?,
                private_key: Secret::new(private_key),
            },
            (Some(_), None) | (None, Some(_)) => {
                return Err(ApiError::validation(message!(
                    "api-bring-the-certificate-and-its-private",
                    "bring the certificate and its private key together, or neither"
                )));
            }
        };
        Ok(RequireEncryptedAssertionsRequest {
            connection_id,
            service_provider,
            key,
        })
    }
}

/// The certificate a provider encrypts its assertions to.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct EncryptionCertificateResponse {
    /// The certificate, PEM, to give the provider. The private key stays
    /// here, sealed.
    pub certificate: String,
}

impl From<CertificatePem> for EncryptionCertificateResponse {
    fn from(certificate: CertificatePem) -> Self {
        Self {
            certificate: certificate.as_str().to_owned(),
        }
    }
}
