//! OIDC: the redirect to a provider, the code it sends back, and the login
//! flow kept between the two.

use async_trait::async_trait;
use ianua_domain::domains::federation::oidc::identity::OidcIdentityClaims;
use ianua_domain::domains::federation::scope_token::ScopeToken;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConnectionId, HttpsUrl, Label, Nonce, TokenHash};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// A provider's client settings with its credential opened for one call.
/// Storage keeps an `OidcConfig` with a sealed secret instead. This type
/// has no serialization or `Debug`, so the opened value stays at the port.
pub struct OidcClientConfig {
    /// The issuer whose discovery document supplies the endpoints.
    pub issuer: HttpsUrl,
    /// The client registered with that issuer.
    pub client_id: Label,
    /// The opened credential, preserved exactly as the provider issued it.
    pub client_secret: Secret,
    /// The scopes requested at sign-in.
    pub scopes: Vec<ScopeToken>,
}

/// An OIDC authorization redirect plus the secrets the caller must bind
/// to the pre-login session and replay on the callback.
pub struct OidcAuthRedirect {
    /// The URL to redirect the user's browser to.
    pub url: HttpsUrl,
    /// CSRF `state` token. Persist it and check it matches on the callback.
    pub state: Secret,
    /// Nonce. Persist it and pass it back to `exchange_code`.
    pub nonce: Nonce,
    /// PKCE verifier. Persist it and pass it back to `exchange_code`.
    pub pkce_verifier: Secret,
}

/// The authorization code a provider sent back, with what the login it
/// answers was started with. Holds the code and the PKCE verifier, so it has
/// no `Debug`.
#[derive(Clone, Copy)]
pub struct OidcCodeExchange<'a> {
    /// The authorization code.
    pub code: &'a Secret,
    /// The nonce the login was started with.
    pub nonce: &'a Nonce,
    /// The PKCE verifier issued with the authorization URL.
    pub pkce_verifier: &'a Secret,
    /// The redirect URI the code was sent to.
    pub redirect_uri: &'a HttpsUrl,
}

/// Dyn-safe port for exchanging an OIDC authorization code for identity claims.
///
/// The infrastructure layer handles discovery, token exchange, JWT signature
/// verification, and claim extraction. This port returns domain-level
/// `OidcIdentityClaims` or an error.
#[async_trait]
pub trait OidcValidator: Send + Sync {
    /// Exchanges an authorization code for validated identity claims.
    ///
    /// `exchange.pkce_verifier` must be the verifier issued alongside the
    /// authorization URL for this login.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the code exchange fails,
    /// the ID token is invalid, or the nonce doesn't match.
    async fn exchange_code(
        &self,
        config: &OidcClientConfig,
        exchange: &OidcCodeExchange<'_>,
        connection_id: &ConnectionId,
    ) -> Result<OidcIdentityClaims, DomainError>;

    /// Builds the authorization redirect for the given OIDC connection.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if discovery or URL building fails.
    async fn build_authorization_url(
        &self,
        config: &OidcClientConfig,
        redirect_uri: &HttpsUrl,
    ) -> Result<OidcAuthRedirect, DomainError>;

    /// Confirms `issuer` publishes an OpenID Connect discovery document that
    /// names it as the issuer, which is where every sign-in reads the
    /// provider's endpoints from.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation`, with a message fit to show the
    /// administrator, if the document cannot be fetched or does not hold.
    async fn confirm_issuer(&self, issuer: &HttpsUrl) -> Result<(), DomainError>;
}

/// A pending OIDC login flow, persisted server-side between the
/// authorization redirect and the callback.
#[derive(Debug, Clone)]
pub struct OidcLoginFlow {
    /// The federation connection this login targets.
    pub connection_id: ConnectionId,
    /// The nonce to verify in the returned ID token.
    pub nonce: Nonce,
    /// The PKCE verifier to send during code exchange.
    pub pkce_verifier: Secret,
    /// The redirect URI registered for this flow.
    pub redirect_uri: HttpsUrl,
    /// Hash of the secret held by the browser that started the sign-in.
    pub binding_hash: TokenHash,
    /// Hash of the value the dashboard that started the sign-in keeps, which
    /// the one-time code is bound to.
    pub dashboard_hash: TokenHash,
}

/// Dyn-safe port for persisting in-flight OIDC login flows.
///
/// The flow is keyed by the CSRF `state` value. Looking it up on the
/// callback *is* the CSRF check (an attacker cannot guess a stored state),
/// and consuming it makes the state single-use.
#[async_trait]
pub trait OidcFlowStore: Send + Sync + TenantScoped {
    /// Persists a pending flow keyed by its `state`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        state: &Secret,
        flow: &OidcLoginFlow,
    ) -> Result<(), DomainError>;

    /// Atomically fetches and removes the flow for `state`. Returns `None`
    /// if no unexpired flow exists: an invalid, replayed, or stale state.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        state: &Secret,
    ) -> Result<Option<OidcLoginFlow>, DomainError>;
}
