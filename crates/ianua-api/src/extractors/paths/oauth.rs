//! The OAuth client, API key or tenant an OAuth request names.

use ianua_domain::shared::config::SlugLimits;
use ianua_domain::types::{
    ApiKeyId, ClientId, HttpsUrl, InitialAccessTokenId, Issuer, OAuthClientId, TenantSlug,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

/// `.../oauth/clients/{id}/...`
#[derive(Deserialize)]
pub(crate) struct ClientPath {
    id: Uuid,
}

impl ClientPath {
    /// The client named.
    #[must_use]
    pub(crate) fn client(&self) -> OAuthClientId {
        OAuthClientId::from_uuid(self.id)
    }
}

/// `.../oauth/api-keys/{id}/...`
#[derive(Deserialize)]
pub(crate) struct ApiKeyPath {
    id: Uuid,
}

impl ApiKeyPath {
    /// The key named.
    #[must_use]
    pub(crate) fn api_key(&self) -> ApiKeyId {
        ApiKeyId::from_uuid(self.id)
    }
}

/// `.../oauth/initial-access-tokens/{id}/...`
#[derive(Deserialize)]
pub(crate) struct InitialAccessTokenPath {
    id: Uuid,
}

impl InitialAccessTokenPath {
    /// The initial access token named.
    #[must_use]
    pub(crate) fn token(&self) -> InitialAccessTokenId {
        InitialAccessTokenId::from_uuid(self.id)
    }
}

/// `.../oauth/register/{client_id}`: a registered client by the
/// `client_id` it was issued.
#[derive(Deserialize)]
pub(crate) struct RegisteredClientPath {
    client_id: String,
}

impl RegisteredClientPath {
    /// The client named.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the path does not hold a valid
    ///   `client_id`.
    pub(crate) fn client_id(&self) -> Result<ClientId, ApiError> {
        ClientId::new(self.client_id.as_str()).map_err(ApiError::validation)
    }
}

/// `.../organizations/{org_slug}/tenants/{tenant_slug}/...`: the tenant
/// whose issuer signs what the request is handed.
#[derive(Deserialize)]
pub(crate) struct IssuerPath {
    org_slug: String,
    tenant_slug: String,
}

impl IssuerPath {
    /// The tenant's issuer under `app_base_url`.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the path does not hold valid slugs.
    pub(crate) fn issuer(&self, app_base_url: &HttpsUrl) -> Result<Issuer, ApiError> {
        let limits = SlugLimits::default();
        let org = TenantSlug::new(&self.org_slug, &limits).map_err(ApiError::validation)?;
        let tenant = TenantSlug::new(&self.tenant_slug, &limits).map_err(ApiError::validation)?;
        Ok(Issuer::of_tenant(app_base_url, &org, &tenant))
    }
}

/// `.../tenants/{tenant_slug}/oauth/...`: the tenant's slug, which a new
/// API key's prefix is made from.
#[derive(Deserialize)]
pub(crate) struct OAuthTenantPath {
    tenant_slug: String,
}

impl OAuthTenantPath {
    /// The tenant's slug.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the path does not hold a valid slug.
    pub(crate) fn tenant_slug(&self) -> Result<TenantSlug, ApiError> {
        TenantSlug::new(&self.tenant_slug, &SlugLimits::default()).map_err(ApiError::validation)
    }
}
