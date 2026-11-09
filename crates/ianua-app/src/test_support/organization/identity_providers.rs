//! Fakes for the organization's identity provider: the provider as stored,
//! the dashboard sign-ins waiting on it, and the SAML assertions it spent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::federation::connection::{
    AssuranceTrust, ConnectionConfig, EmailTrust, OidcConfig,
};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::organization::access::identity_provider::{
    OrgIdentityProvider, OrgIdentityProviderRow,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, HttpsUrl, Label, OrganizationId, SamlAssertionId};
use time::OffsetDateTime;

use crate::ports::authentication::{SealOwner, SealedField, SealedFor};
use crate::ports::organization::{
    OrgIdentityProviderStore, OrgSamlAssertionLedger, OrgSsoKey, OrgSsoRequest, OrgSsoRequestStore,
};
use crate::test_support::Fake;
use crate::test_support::authentication::FakeEncryptor;
use crate::test_support::federation::test_saml_config;

/// The client secret every test OIDC provider was given, before sealing.
pub const ORG_OIDC_CLIENT_SECRET: &str = "acme-okta-client-secret";

/// How a test's organization identity provider stands.
#[derive(Clone)]
pub struct OrgProviderShape {
    /// How it is reached.
    pub config: ConnectionConfig,
    /// Whether its addresses are taken on its word.
    pub email_trust: EmailTrust,
    /// Whether its report of factors is taken on its word.
    pub assurance_trust: AssuranceTrust,
    /// Whether members sign in through it.
    pub status: ConnectionStatus,
}

impl OrgProviderShape {
    /// Acme's Okta over SAML, switched on, its addresses taken as proven.
    #[must_use]
    pub fn saml() -> Self {
        Self {
            config: test_saml_config(),
            email_trust: EmailTrust::Authoritative,
            assurance_trust: AssuranceTrust::Untrusted,
            status: ConnectionStatus::Active,
        }
    }

    /// Acme's Okta over OIDC, switched on, trusting nothing it says.
    #[must_use]
    pub fn oidc() -> Self {
        Self {
            config: test_org_oidc_config(),
            email_trust: EmailTrust::Unverified,
            assurance_trust: AssuranceTrust::Untrusted,
            status: ConnectionStatus::Active,
        }
    }

    /// The same, in `status`.
    #[must_use]
    pub fn in_status(self, status: ConnectionStatus) -> Self {
        Self { status, ..self }
    }

    /// The same, its addresses taken as `email_trust` says.
    #[must_use]
    pub fn trusting_email(self, email_trust: EmailTrust) -> Self {
        Self {
            email_trust,
            ..self
        }
    }
}

/// An OIDC configuration for Acme's Okta, its client secret
/// [`ORG_OIDC_CLIENT_SECRET`] sealed the way [`FakeEncryptor`] seals, for
/// no provider yet: [`stored_org_provider`] seals it again for the provider
/// it makes.
///
/// # Panics
///
/// Never: every value is a literal that is valid.
#[must_use]
pub fn test_org_oidc_config() -> ConnectionConfig {
    let unbound = SealedFor::new(
        SealOwner::Platform,
        SealedField::OrgProviderClientSecret,
        "unbound",
    );
    ConnectionConfig::Oidc(OidcConfig {
        issuer: HttpsUrl::new("https://acme.okta.com").expect("a valid url"),
        client_id: Label::new("client_id", "ianua-dashboard").expect("a valid client id"),
        encrypted_client_secret: FakeEncryptor::sealed_for(ORG_OIDC_CLIENT_SECRET, &unbound),
        scopes: Vec::new(),
    })
}

/// Where `organization_id`'s provider `id` keeps its OIDC client secret.
#[must_use]
pub fn org_provider_secret_place(organization_id: OrganizationId, id: &ConnectionId) -> SealedFor {
    SealedFor::new(
        SealOwner::Organization(organization_id),
        SealedField::OrgProviderClientSecret,
        id,
    )
}

/// `config` with an OIDC client secret sealed again for `place`.
fn sealed_again(config: ConnectionConfig, place: &SealedFor) -> ConnectionConfig {
    match config {
        ConnectionConfig::Oidc(oidc) => ConnectionConfig::Oidc(OidcConfig {
            encrypted_client_secret: FakeEncryptor::sealed_for(ORG_OIDC_CLIENT_SECRET, place),
            ..oidc
        }),
        ConnectionConfig::Saml(saml) => ConnectionConfig::Saml(saml),
    }
}

/// The identity provider of `organization_id` as stored, standing as
/// `shape` says.
///
/// # Panics
///
/// Never: the row is consistent by construction.
#[must_use]
pub fn stored_org_provider(
    organization_id: OrganizationId,
    shape: OrgProviderShape,
) -> OrgIdentityProvider {
    let id = ConnectionId::new();
    let place = org_provider_secret_place(organization_id, &id);
    OrgIdentityProvider::reconstitute(OrgIdentityProviderRow {
        id,
        organization_id,
        name: Label::new("name", "Acme Okta").expect("a valid name"),
        config: sealed_again(shape.config, &place),
        email_trust: shape.email_trust,
        assurance_trust: shape.assurance_trust,
        status: shape.status,
        created_at: clock::now(),
    })
    .expect("a provider added now is a consistent row")
}

/// `provider` copied as storage would hand it back.
fn copy_as_stored(provider: &OrgIdentityProvider) -> Result<OrgIdentityProvider, DomainError> {
    OrgIdentityProvider::reconstitute(OrgIdentityProviderRow {
        id: *provider.id(),
        organization_id: *provider.organization_id(),
        name: provider.name().clone(),
        config: provider.config().clone(),
        email_trust: provider.email_trust(),
        assurance_trust: provider.assurance_trust(),
        status: provider.status(),
        created_at: provider.created_at(),
    })
}

/// In-memory store of organizations' identity providers, one per
/// organization, as the real one keeps them.
#[derive(Default)]
pub struct FakeOrgIdentityProviderStore {
    providers: Mutex<Vec<OrgIdentityProvider>>,
}

impl FakeOrgIdentityProviderStore {
    /// A store holding no provider.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `provider`.
    #[must_use]
    pub fn holding(provider: OrgIdentityProvider) -> Self {
        Self {
            providers: Mutex::new(vec![provider]),
        }
    }

    /// The provider kept for `organization_id`, as stored.
    #[must_use]
    pub fn stored(&self, organization_id: &OrganizationId) -> Option<OrgIdentityProvider> {
        self.providers
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.organization_id() == organization_id)
            .map(|held| copy_as_stored(held).expect("a kept provider copies"))
    }

    /// How many providers are kept, in every organization.
    #[must_use]
    pub fn count(&self) -> usize {
        self.providers.lock().unwrap().len()
    }
}

#[async_trait]
impl OrgIdentityProviderStore for FakeOrgIdentityProviderStore {
    async fn find_for_organization(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OrgIdentityProvider>, DomainError> {
        self.providers
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.organization_id() == organization_id)
            .map(copy_as_stored)
            .transpose()
    }

    async fn save(&self, provider: &OrgIdentityProvider) -> Result<(), DomainError> {
        let copy = copy_as_stored(provider)?;
        let mut providers = self.providers.lock().unwrap();
        let same_org = providers
            .iter()
            .position(|held| held.organization_id() == provider.organization_id());
        let Some(at) = same_org else {
            providers.push(copy);
            return Ok(());
        };
        if providers[at].id() != provider.id() {
            return Err(DomainError::conflict(
                "the organization has an identity provider already",
            ));
        }
        providers[at] = copy;
        Ok(())
    }

    async fn delete(
        &self,
        organization_id: &OrganizationId,
        id: &ConnectionId,
    ) -> Result<(), DomainError> {
        self.providers
            .lock()
            .unwrap()
            .retain(|held| !(held.organization_id() == organization_id && held.id() == id));
        Ok(())
    }
}

impl Fake for Arc<dyn OrgIdentityProviderStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgIdentityProviderStore::empty())
    }
}

/// The text a key is kept under, the kinds kept apart.
fn key_text(key: OrgSsoKey<'_>) -> String {
    match key {
        OrgSsoKey::OidcState(state) => format!("oidc:{}", state.expose()),
        OrgSsoKey::SamlRequest(request_id) => format!("saml:{}", request_id.as_str()),
    }
}

/// In-memory store of dashboard sign-ins in flight, each handed out once.
#[derive(Default)]
pub struct FakeOrgSsoRequests {
    requests: Mutex<HashMap<String, OrgSsoRequest>>,
}

impl FakeOrgSsoRequests {
    /// A store holding no request.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many sign-ins wait for their answer.
    #[must_use]
    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

#[async_trait]
impl OrgSsoRequestStore for FakeOrgSsoRequests {
    async fn save(&self, key: OrgSsoKey<'_>, request: &OrgSsoRequest) -> Result<(), DomainError> {
        self.requests
            .lock()
            .unwrap()
            .insert(key_text(key), request.clone());
        Ok(())
    }

    async fn take(&self, key: OrgSsoKey<'_>) -> Result<Option<OrgSsoRequest>, DomainError> {
        Ok(self.requests.lock().unwrap().remove(&key_text(key)))
    }
}

impl Fake for Arc<dyn OrgSsoRequestStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgSsoRequests::empty())
    }
}

/// Remembers the assertions the organizations' providers spent, like the
/// real ledger.
#[derive(Default)]
pub struct FakeOrgSamlAssertionLedger {
    spent: Mutex<Vec<String>>,
}

impl FakeOrgSamlAssertionLedger {
    /// A ledger that has seen no assertion.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

#[async_trait]
impl OrgSamlAssertionLedger for FakeOrgSamlAssertionLedger {
    async fn spend(
        &self,
        assertion_id: &SamlAssertionId,
        _expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut spent = self.spent.lock().unwrap();
        let id = assertion_id.as_str().to_owned();
        if spent.contains(&id) {
            return Ok(false);
        }
        spent.push(id);
        Ok(true)
    }
}

impl Fake for Arc<dyn OrgSamlAssertionLedger> {
    fn fake() -> Self {
        Arc::new(FakeOrgSamlAssertionLedger::empty())
    }
}
