//! Fakes for SAML as a service provider: the requests this platform sends
//! and keeps until they are answered, the answers it checks, the assertions
//! it has spent, the metadata it reads, the keys assertions are sealed to,
//! and the messages peers send it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::federation::connection::{
    AssertionDecryption, IdpMetadataFacts, SamlConfig,
};
use ianua_domain::domains::federation::provider_values::ProviderValues;
use ianua_domain::domains::federation::saml::assertion::{
    AssertionDelivery, AssertionFacts, SamlAssertion,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificatePem, Email, Fact, FederatedSubject, HttpsUrl, PublicHttpsUrl, SamlAssertionId,
    SamlEntityId, SamlRequestId, SessionIndex, Setting, TenantId,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::federation::{
    GeneratedSpKey, RequestSigningCertificate, RequestSigningKey, SamlAnswer, SamlAssertionLedger,
    SamlConnection, SamlEncryptionKeys, SamlLoginRequest, SamlMetadataReader, SamlRedirect,
    SamlRequestStore, SamlServiceProviderMessages, SamlValidator, ServiceProvider, SpMetadataTerms,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::domain::TEST_CERTIFICATE_PEM;
use crate::test_support::federation::TEST_IDP_CERTIFICATE;

/// In-memory store of SAML requests in flight, each kept by its ID under its
/// tenant and handed out once.
#[derive(Default)]
pub struct FakeSamlRequests {
    requests: Mutex<HashMap<(TenantId, SamlRequestId), SamlLoginRequest>>,
}

impl TenantScoped for FakeSamlRequests {}

impl FakeSamlRequests {
    /// A store holding no request.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many requests wait for their answer, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

#[async_trait]
impl SamlRequestStore for FakeSamlRequests {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request_id: &SamlRequestId,
        request: &SamlLoginRequest,
    ) -> Result<(), DomainError> {
        self.requests
            .lock()
            .unwrap()
            .insert((**tenant_id, request_id.clone()), request.clone());
        Ok(())
    }

    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        request_id: &SamlRequestId,
    ) -> Result<Option<SamlLoginRequest>, DomainError> {
        Ok(self
            .requests
            .lock()
            .unwrap()
            .remove(&(**tenant_id, request_id.clone())))
    }
}

impl Fake for Arc<dyn SamlRequestStore> {
    fn fake() -> Self {
        Arc::new(FakeSamlRequests::empty())
    }
}

/// Builds every sign-in request with the ID [`FixedSamlMessages::REQUEST_ID`].
/// A signed request's address carries `Signature=sig_<kid>`, naming the key
/// it was signed with. The metadata is the entity id, followed by
/// `signed` when requests are signed and `sealed` when assertions must come
/// encrypted.
pub struct FixedSamlMessages;

impl FixedSamlMessages {
    /// The ID every request carries.
    pub const REQUEST_ID: &'static str = "_request-1";
}

impl SamlServiceProviderMessages for FixedSamlMessages {
    fn sign_in_request(
        &self,
        config: &SamlConfig,
        _service_provider: &ServiceProvider,
        key: RequestSigningKey<'_>,
    ) -> Result<SamlRedirect, DomainError> {
        let signature = match key {
            RequestSigningKey::Unsigned => String::new(),
            RequestSigningKey::SignedWith(key) => format!("&Signature=sig_{}", key.kid),
        };
        Ok(SamlRedirect {
            url: HttpsUrl::new(format!(
                "{}?RelayState={}{signature}",
                config.sso_url.as_str(),
                Self::REQUEST_ID
            ))?,
            request_id: SamlRequestId::new(Self::REQUEST_ID)?,
        })
    }

    fn metadata(&self, service_provider: &ServiceProvider, terms: &SpMetadataTerms<'_>) -> String {
        let mut metadata = service_provider.entity_id.as_str().to_owned();
        if let RequestSigningCertificate::SignedBy(_) = terms.request_signing {
            metadata.push_str(" signed");
        }
        if let AssertionDecryption::Required(_) = terms.decryption {
            metadata.push_str(" sealed");
        }
        metadata
    }
}

impl Fake for Arc<dyn SamlServiceProviderMessages> {
    fn fake() -> Self {
        Arc::new(FixedSamlMessages)
    }
}

/// Remembers spent assertion ids per tenant, like the real ledger, and how
/// long each was to be remembered for.
#[derive(Default)]
pub struct FakeSamlAssertionLedger {
    spent: Mutex<HashSet<(TenantId, SamlAssertionId)>>,
    remembered_until: Mutex<Vec<OffsetDateTime>>,
}

impl TenantScoped for FakeSamlAssertionLedger {}

impl FakeSamlAssertionLedger {
    /// A ledger with nothing spent.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Until when each spend asked for its assertion to be remembered, in
    /// order.
    #[must_use]
    pub fn remembered_until(&self) -> Vec<OffsetDateTime> {
        self.remembered_until.lock().unwrap().clone()
    }
}

#[async_trait]
impl SamlAssertionLedger for FakeSamlAssertionLedger {
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        assertion_id: &SamlAssertionId,
        expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        self.remembered_until.lock().unwrap().push(expires_at);
        Ok(self
            .spent
            .lock()
            .unwrap()
            .insert((**tenant_id, assertion_id.clone())))
    }
}

impl Fake for Arc<dyn SamlAssertionLedger> {
    fn fake() -> Self {
        Arc::new(FakeSamlAssertionLedger::empty())
    }
}

/// What a [`FakeSamlValidator`] makes of every response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Accepts,
    Refuses,
}

/// SAML validator that accepts or refuses every response, and remembers
/// which request each answered.
pub struct FakeSamlValidator {
    verdict: Verdict,
    assertion_id: SamlAssertionId,
    delivery: AssertionDelivery,
    attributes: HashMap<String, Vec<String>>,
    answered: Mutex<Vec<SamlRequestId>>,
}

impl FakeSamlValidator {
    /// The session index every accepted assertion carries.
    pub const SESSION_INDEX: &'static str = "_idp-session-1";

    /// A validator that accepts every response as Alice's, readable, under
    /// assertion id `_assertion-1` and session index
    /// [`SESSION_INDEX`](Self::SESSION_INDEX).
    #[must_use]
    pub fn succeeding() -> Self {
        Self {
            verdict: Verdict::Accepts,
            assertion_id: SamlAssertionId::new("_assertion-1").expect("a valid assertion id"),
            delivery: AssertionDelivery::Readable,
            attributes: HashMap::new(),
            answered: Mutex::new(Vec::new()),
        }
    }

    /// A validator that refuses every response, as for a bad signature.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            verdict: Verdict::Refuses,
            ..Self::succeeding()
        }
    }

    /// The same validator, reading every assertion as having come
    /// `delivery`.
    #[must_use]
    pub fn delivered(self, delivery: AssertionDelivery) -> Self {
        Self { delivery, ..self }
    }

    /// The same validator, reading `values` under the attribute `name` in
    /// every assertion, each as its own `AttributeValue`.
    #[must_use]
    pub fn with_attribute(mut self, name: &str, values: &[&str]) -> Self {
        let values = values.iter().map(|value| (*value).to_owned()).collect();
        self.attributes.insert(name.to_owned(), values);
        self
    }

    /// The assertion id every accepted response carries.
    #[must_use]
    pub fn assertion_id(&self) -> &SamlAssertionId {
        &self.assertion_id
    }

    /// The request ids responses answered, in order.
    #[must_use]
    pub fn answered(&self) -> Vec<SamlRequestId> {
        self.answered.lock().unwrap().clone()
    }
}

#[async_trait]
impl SamlValidator for FakeSamlValidator {
    async fn validate(
        &self,
        answer: &SamlAnswer<'_>,
        _config: &SamlConfig,
        connection: &SamlConnection,
        _service_provider: &ServiceProvider,
    ) -> Result<SamlAssertion, DomainError> {
        self.answered
            .lock()
            .unwrap()
            .push(answer.in_response_to.clone());
        if self.verdict == Verdict::Refuses {
            return Err(DomainError::invalid("SAML signature verification failed"));
        }
        Ok(SamlAssertion::new(AssertionFacts {
            connection_id: connection.id,
            assertion_id: self.assertion_id.clone(),
            email: Email::new("alice@acme.com")?,
            name_id: FederatedSubject::new("alice@acme.com")?,
            session_index: Setting::Set(SessionIndex::new(Self::SESSION_INDEX)?),
            delivery: self.delivery,
            authn_context: Fact::Unknown,
            attributes: ProviderValues::new(self.attributes.clone()),
        }))
    }
}

impl Fake for Arc<dyn SamlValidator> {
    fn fake() -> Self {
        Arc::new(FakeSamlValidator::succeeding())
    }
}

/// Metadata reader that serves one document for every address and reads
/// every document as Acme's Okta, listing the certificates it was given.
pub struct FakeSamlMetadataReader {
    certificates: Vec<CertificatePem>,
    fetched: Mutex<Vec<String>>,
}

impl FakeSamlMetadataReader {
    /// The document every address serves.
    pub const DOCUMENT: &'static str = "<md:EntityDescriptor entityID=\"https://idp.acme.com\"/>";

    /// A reader whose documents list `certificates`, current first.
    ///
    /// # Panics
    ///
    /// If a certificate is not PEM. Tests pass literals that are.
    #[must_use]
    pub fn listing(certificates: &[&str]) -> Self {
        Self {
            certificates: certificates
                .iter()
                .map(|pem| CertificatePem::new(*pem).expect("a valid certificate"))
                .collect(),
            fetched: Mutex::new(Vec::new()),
        }
    }

    /// The addresses fetched, in order.
    #[must_use]
    pub fn fetched(&self) -> Vec<String> {
        self.fetched.lock().unwrap().clone()
    }
}

#[async_trait]
impl SamlMetadataReader for FakeSamlMetadataReader {
    async fn fetch(&self, url: &PublicHttpsUrl) -> Result<String, DomainError> {
        self.fetched.lock().unwrap().push(url.as_str().to_owned());
        Ok(Self::DOCUMENT.to_owned())
    }

    fn read(&self, document: &str) -> Result<IdpMetadataFacts, DomainError> {
        if document != Self::DOCUMENT {
            return Err(DomainError::invalid(
                "this is not identity provider metadata",
            ));
        }
        Ok(IdpMetadataFacts {
            entity_id: HttpsUrl::new("https://idp.acme.com")?,
            sso_url: HttpsUrl::new("https://idp.acme.com/sso/new")?,
            slo_url: Setting::Set(HttpsUrl::new("https://idp.acme.com/slo")?),
            signing_certificates: self.certificates.clone(),
        })
    }
}

impl Fake for Arc<dyn SamlMetadataReader> {
    fn fake() -> Self {
        Arc::new(FakeSamlMetadataReader::listing(&[TEST_IDP_CERTIFICATE]))
    }
}

/// Encryption keys that make [`TEST_CERTIFICATE_PEM`] with the private key
/// `sp-private-key`, and take only that key as the pair of any
/// certificate.
pub struct FakeSamlEncryptionKeys;

impl FakeSamlEncryptionKeys {
    /// The private key every pair holds.
    pub const PRIVATE_KEY: &'static str = "sp-private-key";
}

#[async_trait]
impl SamlEncryptionKeys for FakeSamlEncryptionKeys {
    async fn generate(&self, _subject: &SamlEntityId) -> Result<GeneratedSpKey, DomainError> {
        Ok(GeneratedSpKey {
            certificate: CertificatePem::new(TEST_CERTIFICATE_PEM)?,
            private_key: Secret::new(Self::PRIVATE_KEY),
        })
    }

    fn ensure_pair(
        &self,
        _certificate: &CertificatePem,
        private_key: &Secret,
    ) -> Result<(), DomainError> {
        if private_key.expose() == Self::PRIVATE_KEY {
            return Ok(());
        }
        Err(DomainError::invalid(
            "the private key does not match the certificate",
        ))
    }
}

impl Fake for Arc<dyn SamlEncryptionKeys> {
    fn fake() -> Self {
        Arc::new(FakeSamlEncryptionKeys)
    }
}
