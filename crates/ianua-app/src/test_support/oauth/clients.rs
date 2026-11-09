//! Fakes for OAuth clients, their secrets, and the consents people give them.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient, OAuthClientRow};
use ianua_domain::domains::oauth::clients::consent::{OAuthConsent, OAuthConsentRow};
use ianua_domain::domains::oauth::clients::credential::ClientCredential;
use ianua_domain::domains::oauth::clients::registration::ClientManagement;
use ianua_domain::domains::oauth::clients::settings::ClientSettings;
use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ClientId, Label, OAuthClientId, RedirectUri, Scope, TenantId, TokenHash, UserId,
};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::oauth::{
    ClientSecretGenerator, ClientSecretVerifier, GeneratedClientCredentials, GeneratedSecret,
    OAuthClientSortField, OAuthClientStore, OAuthConsentStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::listing::page;
use crate::test_support::oauth::codes::hash_of;

/// In-memory OAuth client store, each client kept under its tenant.
#[derive(Default)]
pub struct FakeOAuthClientStore {
    clients: Mutex<Vec<(TenantId, OAuthClient<ResolvedTenant>)>>,
    id_reads: Mutex<Vec<Vec<OAuthClientId>>>,
}

impl TenantScoped for FakeOAuthClientStore {}

impl FakeOAuthClientStore {
    /// The client ids requested in each lookup, preserving batch boundaries.
    #[must_use]
    pub fn id_reads(&self) -> Vec<Vec<OAuthClientId>> {
        self.id_reads.lock().unwrap().clone()
    }

    /// A store holding no client.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `client` in `tenant`.
    #[must_use]
    pub fn holding(tenant: &ScopedTenant, client: OAuthClient<ResolvedTenant>) -> Self {
        Self {
            clients: Mutex::new(vec![(**tenant, client)]),
            ..Self::default()
        }
    }

    /// How many clients are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.clients.lock().unwrap().len()
    }
}

#[async_trait]
impl OAuthClientStore for FakeOAuthClientStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &OAuthClientId,
    ) -> Result<Option<OAuthClient<ResolvedTenant>>, DomainError> {
        self.id_reads.lock().unwrap().push(vec![*id]);
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, client)| tenant == &**tenant_id && client.id() == id)
            .map(|(_, client)| client.clone()))
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[OAuthClientId],
    ) -> Result<Vec<OAuthClient<ResolvedTenant>>, DomainError> {
        self.id_reads.lock().unwrap().push(ids.to_vec());
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, client)| tenant == &**tenant_id && ids.contains(client.id()))
            .map(|(_, client)| client.clone())
            .collect())
    }

    async fn find_by_client_id_value(
        &self,
        tenant_id: &ScopedTenant,
        client_id: &ClientId,
    ) -> Result<Option<OAuthClient<ResolvedTenant>>, DomainError> {
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, client)| {
                tenant == &**tenant_id && client.client_id_value() == client_id
            })
            .map(|(_, client)| client.clone()))
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<OAuthClientStatus>,
        sort: &SortOrder<OAuthClientSortField>,
        request: &PageRequest,
    ) -> Result<Page<OAuthClient<ResolvedTenant>>, DomainError> {
        let found: Vec<_> = self
            .clients
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, _)| tenant == &**tenant_id)
            .filter(|(_, client)| status.is_none_or(|status| client.status() == status))
            .map(|(_, client)| client.clone())
            .collect();
        page(found, sort, request)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        client: &OAuthClient<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut clients = self.clients.lock().unwrap();
        clients.retain(|(tenant, kept)| !(tenant == &**tenant_id && kept.id() == client.id()));
        clients.push((**tenant_id, client.clone()));
        Ok(())
    }
}

impl Fake for Arc<dyn OAuthClientStore> {
    fn fake() -> Self {
        Arc::new(FakeOAuthClientStore::empty())
    }
}

/// Where every client a test seeds sends its codes.
pub const TEST_REDIRECT: &str = "https://app.example.com/callback";

/// Where every client a test seeds may send a person after signing out.
pub const TEST_AFTER_LOGOUT: &str = "https://app.example.com/signed-out";

/// The secret every client a test seeds signs in with.
pub const TEST_CLIENT_SECRET: &str = "client_secret";

/// An active client named `name` that may use `grants`, sends codes to
/// [`TEST_REDIRECT`], sends people back to [`TEST_AFTER_LOGOUT`] after
/// signing out, may ask for `openid`, `read` and `write`, signs in with
/// [`TEST_CLIENT_SECRET`] in the `Authorization` header, and keeps the
/// platform's settings, as storage keeps it.
#[must_use]
pub fn client_row(name: &str, grants: &[GrantType]) -> OAuthClientRow {
    let id = OAuthClientId::new();
    OAuthClientRow {
        id,
        client_id_value: ClientId::new(format!("client_{}", id.as_uuid().simple()))
            .expect("a valid client id"),
        credential: ClientCredential::secret(hash_of(TEST_CLIENT_SECRET)),
        name: Label::new("name", name).expect("a valid name"),
        redirect_uris: vec![RedirectUri::new(TEST_REDIRECT).expect("a valid redirect")],
        post_logout_redirect_uris: vec![
            RedirectUri::new(TEST_AFTER_LOGOUT).expect("a valid sign-out address"),
        ],
        grant_types: grants.to_vec(),
        scopes: ["openid", "read", "write"]
            .into_iter()
            .map(|scope| Scope::new(scope).expect("a valid scope"))
            .collect(),
        settings: ClientSettings::platform_defaults(),
        management: ClientManagement::ByAdmins,
        status: OAuthClientStatus::Active,
        created_at: ianua_domain::shared::clock::now(),
    }
}

/// A public client named `name`, as [`client_row`] describes it but
/// holding no secret.
#[must_use]
pub fn public_client(name: &str, grants: &[GrantType]) -> OAuthClient<ResolvedTenant> {
    let mut row = client_row(name, grants);
    row.credential = ClientCredential::Public;
    OAuthClient::reconstitute(row).expect("a consistent public client row")
}

/// The client [`client_row`] describes, changed by `edit` first.
#[must_use]
pub fn client_with(
    name: &str,
    grants: &[GrantType],
    edit: impl FnOnce(&mut OAuthClientRow),
) -> OAuthClient<ResolvedTenant> {
    let mut row = client_row(name, grants);
    edit(&mut row);
    OAuthClient::reconstitute(row).expect("a consistent client row")
}

/// The client [`client_row`] describes.
#[must_use]
pub fn stored_client(name: &str, grants: &[GrantType]) -> OAuthClient<ResolvedTenant> {
    OAuthClient::reconstitute(client_row(name, grants)).expect("a consistent client row")
}

/// Client credential generator that counts what it makes: `client_1` with
/// secret `secret_1`, hashed with [`hash_of`].
#[derive(Default)]
pub struct FakeClientSecretGenerator {
    made: Mutex<u32>,
}

impl FakeClientSecretGenerator {
    /// A generator that has made nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ClientSecretGenerator for FakeClientSecretGenerator {
    async fn generate(&self) -> Result<GeneratedClientCredentials, DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        let raw_secret = format!("secret_{made}");
        Ok(GeneratedClientCredentials {
            client_id_value: ClientId::new(format!("client_{made}"))?,
            secret_hash: hash_of(&raw_secret),
            raw_secret: Secret::new(raw_secret),
        })
    }

    async fn generate_client_id(&self) -> Result<ClientId, DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        Ok(ClientId::new(format!("client_{made}"))?)
    }

    async fn generate_secret(&self) -> Result<GeneratedSecret, DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        let raw_secret = format!("secret_{made}");
        Ok(GeneratedSecret {
            secret_hash: hash_of(&raw_secret),
            raw_secret: Secret::new(raw_secret),
        })
    }
}

impl Fake for Arc<dyn ClientSecretGenerator> {
    fn fake() -> Self {
        Arc::new(FakeClientSecretGenerator::new())
    }
}

/// Client secret verifier that accepts a secret exactly when the hash is
/// its [`hash_of`].
pub struct FakeSecretVerifier;

#[async_trait]
impl ClientSecretVerifier for FakeSecretVerifier {
    async fn verify(&self, presented: &Secret, hash: &TokenHash) -> Result<bool, DomainError> {
        Ok(hash_of(presented.expose()) == *hash)
    }
}

/// Client secret verifier that refuses every secret, as for a wrong one.
pub struct RejectingSecretVerifier;

#[async_trait]
impl ClientSecretVerifier for RejectingSecretVerifier {
    async fn verify(&self, _presented: &Secret, _hash: &TokenHash) -> Result<bool, DomainError> {
        Ok(false)
    }
}

impl Fake for Arc<dyn ClientSecretVerifier> {
    fn fake() -> Self {
        Arc::new(FakeSecretVerifier)
    }
}

/// In-memory consent store, one consent per person and client in each
/// tenant.
#[derive(Default)]
pub struct FakeOAuthConsentStore {
    consents: Mutex<Vec<(TenantId, OAuthConsent<ResolvedTenant>)>>,
}

impl TenantScoped for FakeOAuthConsentStore {}

impl FakeOAuthConsentStore {
    /// A store holding no consent.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many consents are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.consents.lock().unwrap().len()
    }
}

#[async_trait]
impl OAuthConsentStore for FakeOAuthConsentStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        client_id: &OAuthClientId,
    ) -> Result<Option<OAuthConsent<ResolvedTenant>>, DomainError> {
        self.consents
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, consent)| {
                tenant == &**tenant_id
                    && consent.user_id() == user_id
                    && consent.client_id() == client_id
            })
            .map(|(_, consent)| copy_consent(consent))
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        consent: &OAuthConsent<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_consent(consent)?;
        let mut consents = self.consents.lock().unwrap();
        consents.retain(|(tenant, kept)| {
            !(tenant == &**tenant_id
                && kept.user_id() == consent.user_id()
                && kept.client_id() == consent.client_id())
        });
        consents.push((**tenant_id, copy));
        Ok(())
    }

    async fn list_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<OAuthConsent<ResolvedTenant>>, DomainError> {
        self.consents
            .lock()
            .unwrap()
            .iter()
            .rev()
            .filter(|(tenant, consent)| tenant == &**tenant_id && consent.user_id() == user_id)
            .map(|(_, consent)| copy_consent(consent))
            .collect()
    }
}

impl Fake for Arc<dyn OAuthConsentStore> {
    fn fake() -> Self {
        Arc::new(FakeOAuthConsentStore::empty())
    }
}

/// `consent` written out and read back, as storage would return it.
fn copy_consent(
    consent: &OAuthConsent<ResolvedTenant>,
) -> Result<OAuthConsent<ResolvedTenant>, DomainError> {
    OAuthConsent::reconstitute(OAuthConsentRow {
        user_id: *consent.user_id(),
        client_id: *consent.client_id(),
        scopes: consent.scopes().to_vec(),
        granted_at: consent.granted_at(),
    })
}
