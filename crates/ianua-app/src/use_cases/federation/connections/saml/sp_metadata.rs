//! SP metadata: the document a tenant's admin imports into their identity
//! provider so it sends people back here, for one SAML connection.
//!
//! It names this platform, where answers and logouts go, the certificate
//! of the key that signs its requests when the connection signs them, and
//! the certificate assertions are sealed to when it takes only sealed ones.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::{AuthnRequestSigning, ConnectionConfig};
use ianua_domain::message;
use ianua_domain::types::{ConnectionId, HttpsUrl};

use crate::error::{AppError, OrInternal};
use crate::ports::crypto::SigningKeyStore;
use crate::ports::federation::{
    ConnectionStore, RequestSigningCertificate, SamlServiceProviderMessages, ServiceProvider,
    SigningCertificateIssuer, SpMetadataTerms,
};
use crate::services::lookup::existing_key_set;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::federation::lookup::{
    active_signing_key, existing_connection, xml_signing_key,
};

/// Which connection's metadata, and where this platform answers for it.
pub struct SpMetadataRequest {
    /// The SAML connection.
    pub connection_id: ConnectionId,
    /// This platform as the connection's service provider.
    pub service_provider: ServiceProvider,
    /// Where the provider sends logout requests and answers.
    pub slo_url: HttpsUrl,
}

/// The ports [`SpMetadataUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SpMetadataPorts {
    /// The tenant's connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// The tenant's signing keys, for a connection that signs its requests.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Issues the certificate the metadata carries for the signing key.
    pub certificates: Arc<dyn SigningCertificateIssuer>,
    /// Writes the SAML messages this platform sends as a service provider.
    pub messages: Arc<dyn SamlServiceProviderMessages>,
}

/// Builds this platform's SAML service provider metadata for a connection.
pub struct SpMetadataUseCase {
    ports: SpMetadataPorts,
}

impl SpMetadataUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SpMetadataPorts) -> Self {
        Self { ports }
    }

    /// The certificate the metadata names for signed requests, issued for
    /// the key the tenant signs with now, or that requests go unsigned.
    async fn request_signing(
        &self,
        tenant: &ScopedTenant,
        signing: AuthnRequestSigning,
        service_provider: &ServiceProvider,
    ) -> Result<RequestSigningCertificate, AppError> {
        if signing == AuthnRequestSigning::Unsigned {
            return Ok(RequestSigningCertificate::Unsigned);
        }
        let key_set = existing_key_set(self.ports.key_store.as_ref(), tenant).await?;
        let key = active_signing_key(&key_set)?;
        self.ports
            .certificates
            .certificate_for(&xml_signing_key(key), &service_provider.entity_id)
            .await
            .map(RequestSigningCertificate::SignedBy)
            .or_internal()
    }
}

impl Query for SpMetadataUseCase {
    type Caller = ScopedTenant;
    type Input = SpMetadataRequest;
    type Output = Result<String, AppError>;

    /// The metadata naming `request`'s service provider for the connection.
    ///
    /// Public: the document carries nothing a stranger may not see, since an
    /// identity provider must be able to fetch it before any trust exists.
    /// It asks for the connection's `NameID` format, which for a sign-in
    /// connection is always the persistent one.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant has no such connection, or no
    ///   signing key set when the connection signs its requests.
    /// - `AppError::Conflict` if it is not a SAML connection.
    /// - `AppError::Internal` if the key set holds no active key, the
    ///   certificate cannot be issued, or on storage failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: SpMetadataRequest,
    ) -> Result<String, AppError> {
        let conn = existing_connection(
            self.ports.connection_store.as_ref(),
            tenant,
            &request.connection_id,
        )
        .await?;
        let ConnectionConfig::Saml(saml) = conn.config() else {
            return Err(AppError::Conflict(message!(
                "federation-only-a-saml-connection-has-service",
                "only a SAML connection has service provider metadata"
            )));
        };
        let request_signing = self
            .request_signing(tenant, saml.request_signing, &request.service_provider)
            .await?;
        let terms = SpMetadataTerms {
            name_id_format: &saml.name_id_format,
            request_signing,
            decryption: &saml.assertion_decryption,
            slo_url: &request.slo_url,
        };
        Ok(self
            .ports
            .messages
            .metadata(&request.service_provider, &terms))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::crypto::signing_key::{
        NewSigningKey, SigningAlgorithm, SigningKey, SigningKeySet,
    };
    use ianua_domain::domains::federation::connection::{
        AssertionDecryption, FederatedIdpConnection, GroupMapping, SamlConfig, SpEncryptionKey,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{
        CertificatePem, Expiry, KeyId, PublicKeyPem, SamlEntityId, SealedSecret,
    };

    use super::*;
    use crate::test_support::crypto::FakeSigningKeyStore;
    use crate::test_support::domain::TEST_CERTIFICATE_PEM;
    use crate::test_support::federation::{
        FakeConnectionStore, test_connection, test_saml_connection, test_saml_settings,
    };
    use crate::test_support::{block_on, test_ctx};

    fn acme() -> ServiceProvider {
        ServiceProvider {
            entity_id: SamlEntityId::new("https://acme.ianua.test/saml").unwrap(),
            acs_url: HttpsUrl::new("https://acme.ianua.test/saml/acs").unwrap(),
        }
    }

    fn key_store() -> Arc<FakeSigningKeyStore> {
        let key = SigningKey::create(NewSigningKey {
            kid: KeyId::new("key-1").unwrap(),
            algorithm: SigningAlgorithm::Rs256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            private_key: Secret::new("private-key"),
            expires_at: Expiry::Never,
        });
        Arc::new(FakeSigningKeyStore::holding(SigningKeySet::new(key)))
    }

    fn metadata_of(saml: SamlConfig) -> Result<String, AppError> {
        let id = ConnectionId::new();
        let conn = test_saml_connection(id, saml, GroupMapping::Off);
        metadata_for(conn, id)
    }

    fn metadata_for(
        conn: FederatedIdpConnection<ResolvedTenant>,
        id: ConnectionId,
    ) -> Result<String, AppError> {
        let use_case = SpMetadataUseCase::new(SpMetadataPorts {
            connection_store: Arc::new(FakeConnectionStore::holding(&test_ctx().tenant(), [conn])),
            key_store: key_store(),
            ..SpMetadataPorts::fakes()
        });
        let request = SpMetadataRequest {
            connection_id: id,
            service_provider: acme(),
            slo_url: HttpsUrl::new("https://acme.ianua.test/saml/slo").unwrap(),
        };
        block_on(use_case.execute(&test_ctx().tenant(), request))
    }

    /// Acme's admin downloads the metadata to import into Okta. It names
    /// Acme's tenant as the service provider, unsigned and readable.
    #[test]
    fn the_metadata_names_the_service_provider() {
        let metadata = metadata_of(test_saml_settings()).unwrap();

        assert_eq!(metadata, "https://acme.ianua.test/saml");
    }

    /// Okta answers only signed requests and Acme seals its assertions. The
    /// metadata says both, so Okta checks the requests and encrypts to
    /// Acme's key.
    #[test]
    fn the_metadata_names_signing_and_sealing() {
        let key = SpEncryptionKey::new(
            CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap(),
            SealedSecret::new("sealed-key").unwrap(),
        );
        let saml = SamlConfig {
            request_signing: AuthnRequestSigning::Signed,
            assertion_decryption: AssertionDecryption::Required(key),
            ..test_saml_settings()
        };

        let metadata = metadata_of(saml).unwrap();

        assert_eq!(metadata, "https://acme.ianua.test/saml signed sealed");
    }

    /// Someone asks for the metadata of a connection Acme does not have. It
    /// is not found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let conn = test_connection(ConnectionId::new(), ConnectionStatus::Active);

        let result = metadata_for(conn, ConnectionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
