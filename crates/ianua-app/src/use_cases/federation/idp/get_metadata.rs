//! Get IdP metadata: the SAML metadata document a service provider imports
//! to trust this tenant as its identity provider.
//!
//! It names the tenant's sign-in endpoints and carries the certificate of
//! the key that signs its assertions now. The document is public: a service
//! provider fetches it before anyone signs in.

use std::sync::Arc;

use ianua_domain::domains::federation::saml::idp_metadata_builder::{
    IdpMetadataParams, build_idp_metadata,
};
use ianua_domain::types::{HttpsUrl, SamlEntityId};

use crate::error::{AppError, OrInternal};
use crate::ports::crypto::SigningKeyStore;
use crate::ports::federation::SigningCertificateIssuer;
use crate::services::lookup::existing_key_set;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::federation::lookup::{active_signing_key, xml_signing_key};

/// Where the tenant's identity provider answers, as the metadata names it.
pub struct GetMetadataRequest {
    /// The identity provider's entity id, which its assertions name as
    /// their issuer.
    pub entity_id: SamlEntityId,
    /// Where a service provider sends its sign-in requests.
    pub sso_url: HttpsUrl,
    /// Where it sends logouts, or `None` to offer none.
    pub slo_url: Option<HttpsUrl>,
}

/// The ports [`GetMetadataUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetMetadataPorts {
    /// The tenant's signing keys.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Issues the certificate the metadata carries for the signing key.
    pub certificates: Arc<dyn SigningCertificateIssuer>,
}

/// Builds the tenant's SAML identity provider metadata.
pub struct GetMetadataUseCase {
    ports: GetMetadataPorts,
}

impl GetMetadataUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: GetMetadataPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetMetadataUseCase {
    type Caller = ScopedTenant;
    type Input = GetMetadataRequest;
    type Output = Result<String, AppError>;

    /// The metadata XML of `tenant`'s identity provider, carrying the
    /// certificate of the key it signs with now.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant has no signing key set.
    /// - `AppError::Internal` if the key set holds no active key, the
    ///   certificate cannot be issued, or on storage failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: GetMetadataRequest,
    ) -> Result<String, AppError> {
        let key_set = existing_key_set(self.ports.key_store.as_ref(), tenant).await?;
        let key = active_signing_key(&key_set)?;
        let signing_certificate = self
            .ports
            .certificates
            .certificate_for(&xml_signing_key(key), &request.entity_id)
            .await
            .or_internal()?;

        let metadata = build_idp_metadata(&IdpMetadataParams {
            entity_id: request.entity_id,
            sso_url: request.sso_url,
            slo_url: request.slo_url,
            signing_certificate,
        });
        Ok(metadata.xml)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::crypto::signing_key::{
        NewSigningKey, SigningAlgorithm, SigningKey, SigningKeySet,
    };
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{CertificatePem, Expiry, KeyId, PublicKeyPem};

    use super::*;
    use crate::ports::crypto::XmlSigningKey;
    use crate::test_support::crypto::FakeSigningKeyStore;
    use crate::test_support::federation::FakeSigningCertificateIssuer;
    use crate::test_support::{block_on, test_ctx};

    struct FailingIssuer;

    #[async_trait]
    impl SigningCertificateIssuer for FailingIssuer {
        async fn certificate_for(
            &self,
            _key: &XmlSigningKey<'_>,
            _issuer: &SamlEntityId,
        ) -> Result<CertificatePem, DomainError> {
            Err(DomainError::infra_msg("the key service is down"))
        }
    }

    fn url(value: &str) -> HttpsUrl {
        HttpsUrl::new(value).unwrap()
    }

    /// Acme's key set, signing with `key-1`.
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

    fn request() -> GetMetadataRequest {
        GetMetadataRequest {
            entity_id: SamlEntityId::new("https://auth.acme.com").unwrap(),
            sso_url: url("https://auth.acme.com/saml/sso"),
            slo_url: None,
        }
    }

    fn metadata(ports: GetMetadataPorts) -> Result<String, AppError> {
        block_on(GetMetadataUseCase::new(ports).execute(&test_ctx().tenant(), request()))
    }

    /// Acme's admin downloads the metadata for an app. It names the sign-in
    /// endpoint and carries the signing certificate's body.
    #[test]
    fn the_metadata_names_the_endpoint_and_carries_the_certificate() {
        let xml = metadata(GetMetadataPorts {
            key_store: key_store(),
            ..GetMetadataPorts::fakes()
        })
        .unwrap();

        assert!(xml.contains("IDPSSODescriptor"));
        assert!(xml.contains("https://auth.acme.com/saml/sso"));
        assert!(xml.contains("TUlJQnRlc3RjZXJ0"));
    }

    /// The certificate is issued for the key Acme signs assertions with
    /// now, so the app checks them against that key.
    #[test]
    fn the_certificate_is_for_the_active_signing_key() {
        let issuer = Arc::new(FakeSigningCertificateIssuer::default());

        metadata(GetMetadataPorts {
            key_store: key_store(),
            certificates: issuer.clone(),
        })
        .unwrap();

        assert_eq!(
            issuer.certified.lock().unwrap().as_slice(),
            [KeyId::new("key-1").unwrap()]
        );
    }

    /// Acme has no signing key yet. There is no certificate to publish, so
    /// the metadata is not found.
    #[test]
    fn a_tenant_without_signing_keys_is_not_found() {
        let result = metadata(GetMetadataPorts::fakes());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The certificate cannot be issued. No metadata goes out without one.
    #[test]
    fn a_certificate_that_cannot_be_issued_is_internal() {
        let result = metadata(GetMetadataPorts {
            key_store: key_store(),
            certificates: Arc::new(FailingIssuer),
        });

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
