//! The organization's own identity provider, and the dashboard sign-ins
//! waiting on its answer.

use async_trait::async_trait;
use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ConnectionId, HttpsUrl, Nonce, OrganizationId, SamlAssertionId, SamlRequestId, TenantSlug,
    TokenHash,
};
use time::OffsetDateTime;

/// Dyn-safe port for the organization's identity provider.
///
/// An organization has at most one. The adapter keeps it unique per
/// organization, so a second save under another id is refused as a
/// conflict rather than kept beside the first.
#[async_trait]
pub trait OrgIdentityProviderStore: Send + Sync {
    /// The identity provider of `organization_id`, if it has one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure or when the
    /// stored row is corrupt.
    async fn find_for_organization(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OrgIdentityProvider>, DomainError>;

    /// Saves a new or changed provider.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the organization already has
    /// another provider, and `DomainError::Infrastructure` on persistence
    /// failure.
    async fn save(&self, provider: &OrgIdentityProvider) -> Result<(), DomainError>;

    /// Deletes the provider `id` of `organization_id`. Deleting one that is
    /// gone already is not an error.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        organization_id: &OrganizationId,
        id: &ConnectionId,
    ) -> Result<(), DomainError>;
}

/// What a dashboard sign-in sent to the provider waits on, by protocol.
#[derive(Debug, Clone)]
pub enum OrgSsoAwaiting {
    /// An OIDC authorization code, to swap with these.
    Oidc {
        /// The nonce the ID token must carry.
        nonce: Nonce,
        /// The PKCE verifier sent with the code.
        pkce_verifier: Secret,
        /// The redirect URI the code is sent to.
        redirect_uri: HttpsUrl,
    },
    /// A SAML response answering the request it is kept under.
    Saml,
}

/// A dashboard sign-in through the organization's provider, kept between
/// the redirect and the provider's answer.
#[derive(Debug, Clone)]
pub struct OrgSsoRequest {
    /// The organization signing in.
    pub organization_id: OrganizationId,
    /// The provider the browser was sent to.
    pub connection_id: ConnectionId,
    /// Hash of the secret held by the browser that started the sign-in.
    pub binding_hash: TokenHash,
    /// The tenant the member asked to land in, if any.
    pub tenant_slug: Option<TenantSlug>,
    /// What the answer is checked with.
    pub awaiting: OrgSsoAwaiting,
}

/// What a dashboard sign-in in flight is kept under: the OIDC `state`, or
/// the SAML request's ID the answer names in `RelayState`.
#[derive(Debug, Clone, Copy)]
pub enum OrgSsoKey<'a> {
    /// An OIDC sign-in's `state`.
    OidcState(&'a Secret),
    /// A SAML sign-in request's ID.
    SamlRequest(&'a SamlRequestId),
}

/// Dyn-safe port for the dashboard sign-ins waiting on the organization's
/// provider.
///
/// Looking a request up by its key is the CSRF check: nobody can guess a
/// stored `state` or request ID. Taking it removes it, so an answer is used
/// once. The adapter keeps the two kinds of key apart and lets a request
/// lapse after a few minutes.
#[async_trait]
pub trait OrgSsoRequestStore: Send + Sync {
    /// Keeps `request` under `key`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, key: OrgSsoKey<'_>, request: &OrgSsoRequest) -> Result<(), DomainError>;

    /// Atomically fetches and removes the request kept under `key`. `None`
    /// when nothing waits there: a key never issued, already answered, or
    /// lapsed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn take(&self, key: OrgSsoKey<'_>) -> Result<Option<OrgSsoRequest>, DomainError>;
}

/// Dyn-safe port recording which SAML assertions the organizations'
/// providers sent have been spent.
///
/// A SAML assertion is a bearer credential for its whole window, so a
/// replay is refused only by remembering it.
#[async_trait]
pub trait OrgSamlAssertionLedger: Send + Sync {
    /// Records `assertion_id` as spent until `expires_at`, returning whether
    /// this call was the one that spent it. Atomic: two nodes racing the
    /// same replay cannot both see `true`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, which
    /// the caller treats as a refusal.
    async fn spend(
        &self,
        assertion_id: &SamlAssertionId,
        expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError>;
}
