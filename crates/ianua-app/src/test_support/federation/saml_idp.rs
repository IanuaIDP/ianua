//! Fakes for SAML as an identity provider: the tenant's SAML apps, the
//! names people are given to them, the assertions sealed for them, the
//! certificate the metadata publishes, the apps each session signed in to,
//! and the sign-in requests held until they are answered.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::crypto::signing_key::{
    NewSigningKey, SigningAlgorithm, SigningKey, SigningKeySet,
};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::federation::saml::name_id::{NameIdFormat, SamlNameIdValue};
use ianua_domain::domains::federation::service_provider::{
    AcsUrls, AssertionEncryption, AttributeStatements, RequestSigningRule, SamlServiceProvider,
    SamlServiceProviderRow, SamlServiceProviderSettings, SignedParts,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificatePem, Expiry, HttpsUrl, KeyId, Label, PublicKeyPem, SamlArrivalId, SamlEntityId,
    SamlServiceProviderId, Setting, TenantId, UserId,
};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::crypto::XmlSigningKey;
use crate::ports::federation::{
    AssertionEncrypter, HeldSamlSignIn, HeldSamlSignInStore, SamlAppSortField, SamlNameIds,
    SamlServiceProviderStore, SigningCertificateIssuer,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::crypto::{FakeSigningKeyStore, FakeXmlSigner};
use crate::test_support::domain::TEST_CERTIFICATE_PEM;
use crate::test_support::listing::page;
use crate::use_cases::federation::logout::messages::{LogoutSigner, SessionEnding};

/// Acme's Salesforce app's entity id.
pub const TEST_APP_ENTITY_ID: &str = "https://app.acme.com";

/// Where Salesforce takes its assertions by default.
pub const TEST_APP_ACS_URL: &str = "https://app.acme.com/saml/acs";

/// Where Salesforce takes logout requests and answers.
pub const TEST_APP_SLO_URL: &str = "https://app.acme.com/saml/slo";

/// How Acme's Salesforce app is answered: at its one address, by a
/// pairwise `NameID`, sent the address and display name, its assertions
/// signed and readable, its requests taken unsigned, and single logout on.
///
/// # Panics
///
/// Never: every value is a literal that is valid.
#[must_use]
pub fn test_app_settings() -> SamlServiceProviderSettings {
    SamlServiceProviderSettings {
        acs_urls: AcsUrls::new(
            HttpsUrl::new(TEST_APP_ACS_URL).expect("a valid url"),
            Vec::new(),
        )
        .expect("one address"),
        logout_url: Setting::Set(HttpsUrl::new(TEST_APP_SLO_URL).expect("a valid url")),
        name_id_format: NameIdFormat::Persistent,
        attributes: AttributeStatements::standard().expect("the standard statements"),
        signing: SignedParts::Assertion,
        encryption: AssertionEncryption::Plain,
        request_signing: RequestSigningRule::NotRequired,
    }
}

/// Acme's Salesforce app under `id`, in `status`, answered by `settings`.
///
/// # Panics
///
/// Never: an app that changed when it was added is a consistent row.
#[must_use]
pub fn test_service_provider_with(
    id: SamlServiceProviderId,
    status: ConnectionStatus,
    settings: SamlServiceProviderSettings,
) -> SamlServiceProvider<ResolvedTenant> {
    let now = clock::now();
    SamlServiceProvider::reconstitute(SamlServiceProviderRow {
        id,
        name: Label::new("name", "Salesforce").expect("a valid name"),
        entity_id: SamlEntityId::new(TEST_APP_ENTITY_ID).expect("a valid entity id"),
        status,
        settings,
        created_at: now,
        updated_at: now,
    })
    .expect("an app that changed when it was added is a consistent row")
}

/// Acme's Salesforce app under `id`, in `status`, answered by
/// [`test_app_settings`].
#[must_use]
pub fn test_service_provider(
    id: SamlServiceProviderId,
    status: ConnectionStatus,
) -> SamlServiceProvider<ResolvedTenant> {
    test_service_provider_with(id, status, test_app_settings())
}

/// A key store holding a tenant key set that signs with `key-1` now, for
/// the SAML messages this platform signs.
///
/// # Panics
///
/// Never: every value is a literal that is valid.
#[must_use]
pub fn test_xml_signing_keys() -> Arc<FakeSigningKeyStore> {
    let key = SigningKey::create(NewSigningKey {
        kid: KeyId::new("key-1").expect("a valid key id"),
        algorithm: SigningAlgorithm::Rs256,
        public_key: PublicKeyPem::new(
            "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
        )
        .expect("a valid public key"),
        private_key: Secret::new("private-key"),
        expires_at: Expiry::Never,
    });
    Arc::new(FakeSigningKeyStore::holding(SigningKeySet::new(key)))
}

/// In-memory store of SAML apps, each kept under its tenant.
#[derive(Default)]
pub struct FakeSamlServiceProviderStore {
    providers: Mutex<Vec<(TenantId, SamlServiceProvider<ResolvedTenant>)>>,
}

impl TenantScoped for FakeSamlServiceProviderStore {}

impl FakeSamlServiceProviderStore {
    /// A store holding no app.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `providers` in `tenant`.
    #[must_use]
    pub fn holding(
        tenant: &ScopedTenant,
        providers: impl IntoIterator<Item = SamlServiceProvider<ResolvedTenant>>,
    ) -> Self {
        let kept = providers
            .into_iter()
            .map(|provider| (**tenant, provider))
            .collect();
        Self {
            providers: Mutex::new(kept),
        }
    }

    /// How many apps are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.providers.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: &ScopedTenant,
        keeps: impl Fn(&SamlServiceProvider<ResolvedTenant>) -> bool,
    ) -> Result<Vec<SamlServiceProvider<ResolvedTenant>>, DomainError> {
        self.providers
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, provider)| tenant == &**tenant_id && keeps(provider))
            .map(|(_, provider)| copy_provider(provider))
            .collect()
    }
}

#[async_trait]
impl SamlServiceProviderStore for FakeSamlServiceProviderStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlServiceProviderId,
    ) -> Result<Option<SamlServiceProvider<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |provider| provider.id() == id)?;
        Ok(found.into_iter().next())
    }

    async fn find_by_entity_id(
        &self,
        tenant_id: &ScopedTenant,
        entity_id: &SamlEntityId,
    ) -> Result<Option<SamlServiceProvider<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |provider| provider.entity_id() == entity_id)?;
        Ok(found.into_iter().next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        request: &PageRequest,
    ) -> Result<Page<SamlServiceProvider<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |_| true)?;
        page(found, &SortOrder::<SamlAppSortField>::default(), request)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        provider: &SamlServiceProvider<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_provider(provider)?;
        let mut providers = self.providers.lock().unwrap();
        let taken = providers.iter().any(|(tenant, kept)| {
            tenant == &**tenant_id
                && kept.entity_id() == provider.entity_id()
                && kept.id() != provider.id()
        });
        if taken {
            return Err(DomainError::conflict("another app has this entity id"));
        }
        providers.retain(|(tenant, kept)| !(tenant == &**tenant_id && kept.id() == provider.id()));
        providers.push((**tenant_id, copy));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlServiceProviderId,
    ) -> Result<(), DomainError> {
        self.providers
            .lock()
            .unwrap()
            .retain(|(tenant, provider)| !(tenant == &**tenant_id && provider.id() == id));
        Ok(())
    }
}

impl Fake for Arc<dyn SamlServiceProviderStore> {
    fn fake() -> Self {
        Arc::new(FakeSamlServiceProviderStore::empty())
    }
}

/// In-memory store of the sign-in requests held until they are answered,
/// each kept under its tenant.
#[derive(Default)]
pub struct FakeHeldSamlSignIns {
    held: Mutex<Vec<(TenantId, HeldSamlSignIn)>>,
}

impl TenantScoped for FakeHeldSamlSignIns {}

impl FakeHeldSamlSignIns {
    /// A store holding no request.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `request` in `tenant`.
    #[must_use]
    pub fn holding(tenant: TenantId, request: HeldSamlSignIn) -> Self {
        Self {
            held: Mutex::new(vec![(tenant, request)]),
        }
    }

    /// Every request held, in every tenant.
    #[must_use]
    pub fn all(&self) -> Vec<HeldSamlSignIn> {
        self.held
            .lock()
            .unwrap()
            .iter()
            .map(|(_, request)| request.clone())
            .collect()
    }
}

#[async_trait]
impl HeldSamlSignInStore for FakeHeldSamlSignIns {
    async fn hold(
        &self,
        tenant_id: &ScopedTenant,
        request: &HeldSamlSignIn,
    ) -> Result<(), DomainError> {
        self.held
            .lock()
            .unwrap()
            .push((**tenant_id, request.clone()));
        Ok(())
    }

    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlArrivalId,
    ) -> Result<Option<HeldSamlSignIn>, DomainError> {
        Ok(self
            .held
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, request)| tenant == &**tenant_id && &request.id == id)
            .map(|(_, request)| request.clone()))
    }

    async fn release(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlArrivalId,
    ) -> Result<(), DomainError> {
        self.held
            .lock()
            .unwrap()
            .retain(|(tenant, request)| !(tenant == &**tenant_id && &request.id == id));
        Ok(())
    }
}

impl Fake for Arc<dyn HeldSamlSignInStore> {
    fn fake() -> Self {
        Arc::new(FakeHeldSamlSignIns::empty())
    }
}

/// `provider` written out and read back, as storage would return it.
fn copy_provider(
    provider: &SamlServiceProvider<ResolvedTenant>,
) -> Result<SamlServiceProvider<ResolvedTenant>, DomainError> {
    SamlServiceProvider::reconstitute(SamlServiceProviderRow {
        id: *provider.id(),
        name: provider.name().clone(),
        entity_id: provider.entity_id().clone(),
        status: provider.status(),
        settings: provider.settings().clone(),
        created_at: provider.created_at(),
        updated_at: provider.updated_at(),
    })
}

/// `NameID` values that name the app and the account in the pairwise id,
/// `pairwise:<app>:<account>`, and count the transient ones,
/// `transient-1`, `transient-2` and so on.
#[derive(Default)]
pub struct FixedNameIds {
    transients: Mutex<u32>,
}

impl SamlNameIds for FixedNameIds {
    fn pairwise(
        &self,
        provider: &SamlServiceProviderId,
        account: &UserId,
    ) -> Result<SamlNameIdValue, DomainError> {
        Ok(SamlNameIdValue::new(format!(
            "pairwise:{provider}:{account}"
        ))?)
    }

    fn transient(&self) -> Result<SamlNameIdValue, DomainError> {
        let mut made = self.transients.lock().unwrap();
        *made = made.saturating_add(1);
        Ok(SamlNameIdValue::new(format!("transient-{made}"))?)
    }
}

impl Fake for Arc<dyn SamlNameIds> {
    fn fake() -> Self {
        Arc::new(FixedNameIds::default())
    }
}

/// Encrypter that wraps the assertion in `<Sealed>` and remembers the
/// certificates it sealed to.
#[derive(Default)]
pub struct FakeAssertionEncrypter {
    /// The certificates assertions were sealed to, in order.
    pub sealed_to: Mutex<Vec<CertificatePem>>,
}

#[async_trait]
impl AssertionEncrypter for FakeAssertionEncrypter {
    async fn encrypt(
        &self,
        signed_assertion: &str,
        recipient: &CertificatePem,
    ) -> Result<String, DomainError> {
        self.sealed_to.lock().unwrap().push(recipient.clone());
        Ok(format!("<Sealed>{signed_assertion}</Sealed>"))
    }
}

impl Fake for Arc<dyn AssertionEncrypter> {
    fn fake() -> Self {
        Arc::new(FakeAssertionEncrypter::default())
    }
}

/// Certificate issuer that issues [`TEST_CERTIFICATE_PEM`] for any key, and
/// remembers which keys it was asked to certify.
#[derive(Default)]
pub struct FakeSigningCertificateIssuer {
    /// The id of each key a certificate was issued for, in order.
    pub certified: Mutex<Vec<KeyId>>,
}

#[async_trait]
impl SigningCertificateIssuer for FakeSigningCertificateIssuer {
    async fn certificate_for(
        &self,
        key: &XmlSigningKey<'_>,
        _issuer: &SamlEntityId,
    ) -> Result<CertificatePem, DomainError> {
        self.certified.lock().unwrap().push(key.kid.clone());
        Ok(CertificatePem::new(TEST_CERTIFICATE_PEM)?)
    }
}

impl Fake for Arc<dyn SigningCertificateIssuer> {
    fn fake() -> Self {
        Arc::new(FakeSigningCertificateIssuer::default())
    }
}

/// Signs logout messages with [`test_xml_signing_keys`], as XML is signed
/// in tests.
#[must_use]
pub fn test_logout_signer() -> LogoutSigner {
    LogoutSigner {
        key_store: test_xml_signing_keys(),
        xml_signer: Arc::new(FakeXmlSigner),
    }
}

impl Fake for LogoutSigner {
    fn fake() -> Self {
        LogoutSigner {
            key_store: Fake::fake(),
            xml_signer: Fake::fake(),
        }
    }
}

impl Fake for SessionEnding {
    fn fake() -> Self {
        SessionEnding {
            sessions: Fake::fake(),
        }
    }
}
