//! Fakes that sign, decode and validate: JWT and XML signers, key decoders, certificate checks and token generators

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use ianua_domain::domains::crypto::jwk::JwkComponents;
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, KeyId, PublicKeyPem, RevocationListPem};

use crate::ports::crypto::{
    CertPemValidator, JwtSigner, JwtSigningKey, PublicKeyDecoder, SecureTokenGenerator, XmlSigner,
    XmlSigningKey,
};
use crate::test_support::Fake;

/// Signs nothing: returns `header.{claims}.sig_{kid}` and records each claim
/// set.
#[derive(Default)]
pub struct FakeJwtSigner {
    /// The claim sets it was asked to sign, in order.
    pub signed: Mutex<Vec<String>>,
}

#[async_trait]
impl JwtSigner for FakeJwtSigner {
    async fn sign_typed(
        &self,
        claims_json: &str,
        _typ: JwtType,
        key: JwtSigningKey<'_>,
    ) -> Result<String, DomainError> {
        self.signed.lock().unwrap().push(claims_json.to_owned());
        Ok(format!("header.{claims_json}.sig_{}", key.kid))
    }
}

/// Signs nothing but answers in the shape of a compact JWS: the kind, the
/// claims in base64url and the key id, so a value that checks that shape
/// takes it. Records each kind and claim set.
#[derive(Default)]
pub struct CompactJwtSigner {
    /// The kinds and claim sets it was asked to sign, in order.
    pub signed: Mutex<Vec<(JwtType, String)>>,
}

#[async_trait]
impl JwtSigner for CompactJwtSigner {
    async fn sign_typed(
        &self,
        claims_json: &str,
        typ: JwtType,
        key: JwtSigningKey<'_>,
    ) -> Result<String, DomainError> {
        self.signed
            .lock()
            .unwrap()
            .push((typ, claims_json.to_owned()));
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_json);
        Ok(format!("eyJhbGciOiJub25lIn0.{encoded}.{}", key.kid))
    }
}

/// A signer whose every call fails.
pub struct FailingJwtSigner;

#[async_trait]
impl JwtSigner for FailingJwtSigner {
    async fn sign_typed(
        &self,
        _claims_json: &str,
        _typ: JwtType,
        _key: JwtSigningKey<'_>,
    ) -> Result<String, DomainError> {
        Err(DomainError::infra_msg("sign failed"))
    }
}

/// Decodes any PEM into placeholder JWK components of the shape its
/// algorithm calls for.
pub struct FakeKeyComponentsDecoder;

impl PublicKeyDecoder for FakeKeyComponentsDecoder {
    fn decode(
        &self,
        _pem: &PublicKeyPem,
        kid: &KeyId,
        algorithm: SigningAlgorithm,
    ) -> Result<JwkComponents, DomainError> {
        let kid = kid.as_str().to_owned();
        Ok(match algorithm {
            SigningAlgorithm::Rs256 => JwkComponents::Rsa {
                kid,
                n: "test-n".to_owned(),
                e: "test-e".to_owned(),
            },
            SigningAlgorithm::Es256 => JwkComponents::Ec {
                kid,
                crv: "P-256".to_owned(),
                x: "test-x".to_owned(),
                y: "test-y".to_owned(),
            },
            SigningAlgorithm::EdDsa => JwkComponents::Okp {
                kid,
                crv: "Ed25519".to_owned(),
                x: "test-x".to_owned(),
            },
        })
    }
}

/// Certificate validator that accepts every PEM.
pub struct AcceptingCertValidator;

impl CertPemValidator for AcceptingCertValidator {
    fn validate_cert_pem(&self, _pem: &CertificatePem) -> Result<(), DomainError> {
        Ok(())
    }

    fn validate_revocation_list_pem(&self, _pem: &RevocationListPem) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Token generator that returns `x` repeated to the asked length.
pub struct FakeSecureTokenGenerator;

impl SecureTokenGenerator for FakeSecureTokenGenerator {
    fn generate(&self, byte_len: usize) -> Secret {
        Secret::new("x".repeat(byte_len))
    }
}

/// XML signer that marks documents as signed without real keys.
pub struct FakeXmlSigner;

#[async_trait]
impl XmlSigner for FakeXmlSigner {
    async fn sign_xml(&self, xml: &str, _key: &XmlSigningKey<'_>) -> Result<String, DomainError> {
        Ok(format!("<Signed>{xml}</Signed>"))
    }
}

impl Fake for Arc<dyn JwtSigner> {
    fn fake() -> Self {
        Arc::new(FakeJwtSigner::default())
    }
}

impl Fake for Arc<dyn PublicKeyDecoder> {
    fn fake() -> Self {
        Arc::new(FakeKeyComponentsDecoder)
    }
}

impl Fake for Arc<dyn CertPemValidator> {
    fn fake() -> Self {
        Arc::new(AcceptingCertValidator)
    }
}

impl Fake for Arc<dyn SecureTokenGenerator> {
    fn fake() -> Self {
        Arc::new(FakeSecureTokenGenerator)
    }
}

impl Fake for Arc<dyn XmlSigner> {
    fn fake() -> Self {
        Arc::new(FakeXmlSigner)
    }
}
