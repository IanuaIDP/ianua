//! Fakes for OIDC sign-in: the provider's answers and the login flows kept
//! between the redirect and the callback.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::federation::oidc::identity::{OidcIdentityClaims, OidcIdentityParams};
use ianua_domain::domains::federation::provider_values::ProviderValues;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConnectionId, Email, FederatedSubject, HttpsUrl, Nonce, TenantId};

use crate::ports::TenantScoped;
use crate::ports::federation::{
    OidcAuthRedirect, OidcClientConfig, OidcCodeExchange, OidcFlowStore, OidcLoginFlow,
    OidcValidator,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// The `state` every redirect from [`FakeOidcValidator`] carries.
pub const OIDC_STATE: &str = "state-from-the-fake-provider";

/// The nonce every redirect from [`FakeOidcValidator`] carries.
pub const OIDC_NONCE: &str = "nonce-from-the-fake-provider";

/// In-memory OIDC flow store, each flow kept by its `state` under its
/// tenant and handed out once.
#[derive(Default)]
pub struct FakeOidcFlowStore {
    flows: Mutex<HashMap<(TenantId, String), OidcLoginFlow>>,
}

impl TenantScoped for FakeOidcFlowStore {}

impl FakeOidcFlowStore {
    /// A store holding no flow.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many flows wait for their callback, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.flows.lock().unwrap().len()
    }
}

#[async_trait]
impl OidcFlowStore for FakeOidcFlowStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        state: &Secret,
        flow: &OidcLoginFlow,
    ) -> Result<(), DomainError> {
        self.flows
            .lock()
            .unwrap()
            .insert((**tenant_id, state.expose().to_owned()), flow.clone());
        Ok(())
    }

    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        state: &Secret,
    ) -> Result<Option<OidcLoginFlow>, DomainError> {
        Ok(self
            .flows
            .lock()
            .unwrap()
            .remove(&(**tenant_id, state.expose().to_owned())))
    }
}

impl Fake for Arc<dyn OidcFlowStore> {
    fn fake() -> Self {
        Arc::new(FakeOidcFlowStore::new())
    }
}

/// OIDC validator that signs every code exchange in as one person, records
/// the opened client secret each exchange was made with and each issuer it
/// was asked to confirm, and hands out a fixed authorization redirect
/// carrying [`OIDC_STATE`] and [`OIDC_NONCE`].
pub struct FakeOidcValidator {
    email: Email,
    email_verified: Option<bool>,
    amr: Vec<String>,
    claims: HashMap<String, Vec<String>>,
    secrets_seen: Mutex<Vec<Secret>>,
    issuers_fetched: Mutex<Vec<HttpsUrl>>,
}

impl FakeOidcValidator {
    /// Signs every exchange in as subject `ada` with `email`, verified,
    /// after a password alone.
    ///
    /// # Panics
    ///
    /// Panics if `email` is not an address.
    #[must_use]
    pub fn signing_in(email: &str) -> Self {
        Self {
            email: Email::new(email).expect("the test names an address"),
            email_verified: Some(true),
            amr: vec!["pwd".to_owned()],
            claims: HashMap::new(),
            secrets_seen: Mutex::new(Vec::new()),
            issuers_fetched: Mutex::new(Vec::new()),
        }
    }

    /// The same, with every token carrying `values` under the claim `name`,
    /// as a `groups` claim lists groups.
    #[must_use]
    pub fn with_claim(mut self, name: &str, values: &[&str]) -> Self {
        let values = values.iter().map(|value| (*value).to_owned()).collect();
        self.claims.insert(name.to_owned(), values);
        self
    }

    /// The same, after a multi-factor sign-in at the provider.
    #[must_use]
    pub fn after_mfa(self) -> Self {
        Self {
            amr: vec!["pwd".to_owned(), "mfa".to_owned()],
            ..self
        }
    }

    /// The same, with the provider calling the address unverified.
    #[must_use]
    pub fn with_unverified_email(self) -> Self {
        Self {
            email_verified: Some(false),
            ..self
        }
    }

    /// The opened client secrets exchanges were made with, in order.
    #[must_use]
    pub fn secrets_seen(&self) -> Vec<Secret> {
        self.secrets_seen.lock().unwrap().clone()
    }

    /// The issuers whose configuration was fetched, in order.
    #[must_use]
    pub fn issuers_fetched(&self) -> Vec<HttpsUrl> {
        self.issuers_fetched.lock().unwrap().clone()
    }
}

#[async_trait]
impl OidcValidator for FakeOidcValidator {
    async fn exchange_code(
        &self,
        config: &OidcClientConfig,
        _exchange: &OidcCodeExchange<'_>,
        connection_id: &ConnectionId,
    ) -> Result<OidcIdentityClaims, DomainError> {
        self.secrets_seen
            .lock()
            .unwrap()
            .push(config.client_secret.clone());
        Ok(OidcIdentityClaims::new(OidcIdentityParams {
            connection_id: *connection_id,
            sub: FederatedSubject::new("ada")?,
            email: self.email.clone(),
            email_verified: self.email_verified,
            amr: self.amr.clone(),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            claims: ProviderValues::new(self.claims.clone()),
        }))
    }

    async fn build_authorization_url(
        &self,
        _config: &OidcClientConfig,
        _redirect_uri: &HttpsUrl,
    ) -> Result<OidcAuthRedirect, DomainError> {
        Ok(OidcAuthRedirect {
            url: HttpsUrl::new(format!(
                "https://idp.example.test/authorize?state={OIDC_STATE}"
            ))?,
            state: Secret::new(OIDC_STATE),
            nonce: Nonce::new(OIDC_NONCE)?,
            pkce_verifier: Secret::new("verifier-from-the-fake-provider"),
        })
    }

    async fn confirm_issuer(&self, issuer: &HttpsUrl) -> Result<(), DomainError> {
        self.issuers_fetched.lock().unwrap().push(issuer.clone());
        Ok(())
    }
}

impl Fake for Arc<dyn OidcValidator> {
    fn fake() -> Self {
        Arc::new(FakeOidcValidator::signing_in("ada@acme.com"))
    }
}

/// OIDC validator for an issuer that publishes no discovery document, as a
/// mistyped issuer address does. Nothing can sign in through it.
pub struct UnpublishedIssuer;

#[async_trait]
impl OidcValidator for UnpublishedIssuer {
    async fn exchange_code(
        &self,
        _config: &OidcClientConfig,
        _exchange: &OidcCodeExchange<'_>,
        _connection_id: &ConnectionId,
    ) -> Result<OidcIdentityClaims, DomainError> {
        Err(DomainError::infra_msg(
            "the issuer publishes no configuration",
        ))
    }

    async fn build_authorization_url(
        &self,
        _config: &OidcClientConfig,
        _redirect_uri: &HttpsUrl,
    ) -> Result<OidcAuthRedirect, DomainError> {
        Err(DomainError::infra_msg(
            "the issuer publishes no configuration",
        ))
    }

    async fn confirm_issuer(&self, _issuer: &HttpsUrl) -> Result<(), DomainError> {
        Err(DomainError::invalid(
            "the issuer publishes no OpenID Connect configuration",
        ))
    }
}
