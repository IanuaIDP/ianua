//! Connecting an account by signing in at the integration's service: the
//! address the browser is sent to, the code it brings back swapped for a
//! credential, the random values that tie the two together, and the
//! connections kept in between.

use async_trait::async_trait;
use ianua_domain::domains::workflows::account::connection::{PendingConnection, ServicePlace};
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{PendingConnectionId, TenantId, TokenHash};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// The address a browser is sent to, at the service, to sign in and allow
/// the platform's app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInAddress(String);

impl SignInAddress {
    /// The address `written`, as the sign-in adapter built it.
    #[must_use]
    pub fn new(written: String) -> Self {
        Self(written)
    }

    /// The address as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the browser carries to the service: the `state` it brings back,
/// and the verifier whose challenge the service holds the code to. Holds
/// both in the clear, so it has no `Debug`.
#[derive(Clone, Copy)]
pub struct SignInRequest<'a> {
    /// The random `state`, sent to the service and checked when it comes
    /// back.
    pub state: &'a Secret,
    /// The PKCE verifier; the service is sent its `S256` challenge.
    pub verifier: &'a Secret,
}

/// What a service's code is swapped with. Holds the code and verifier in
/// the clear, so it has no `Debug`.
#[derive(Clone, Copy)]
pub struct Exchanging<'a> {
    /// The integration whose service issued the code.
    pub integration: &'a IntegrationKey,
    /// The service's code.
    pub code: &'a Secret,
    /// The PKCE verifier the code was asked for with.
    pub verifier: &'a Secret,
    /// The space at the service the person named, when asked for.
    pub place: Option<&'a ServicePlace>,
}

/// What a sign-in asks the person for besides the account's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceAsked {
    /// Nothing more.
    Nothing,
    /// The space at the service the account works in, by the service's own
    /// word for it, such as `organization` for Azure DevOps.
    Named(&'static str),
}

/// Why a service's code was not swapped for a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInFailure {
    /// The service refused the code: spent, expired or not for this app.
    Refused,
    /// The service could not be reached, or did not answer in time.
    Unreachable,
}

/// Dyn-safe port for signing in at an integration's service to connect an
/// account, through the app the deployment registered with that service.
///
/// The adapter knows each service's authorize and token addresses, the
/// scopes the integration needs, and the deployment's client id and secret.
/// It never follows a redirect with a credential and bounds every call with
/// a timeout.
#[async_trait]
pub trait ServiceSignIn: Send + Sync {
    /// Whether `integration` may be connected by signing in: its service
    /// offers it, and the deployment registered an app with the service.
    fn offers(&self, integration: &IntegrationKey) -> bool;

    /// What signing in at `integration`'s service asks for besides the
    /// account's name; nothing for one that offers no sign-in.
    fn asks_for(&self, integration: &IntegrationKey) -> PlaceAsked;

    /// Where to send the browser to sign in at `integration`'s service.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when `integration` offers no
    /// sign-in here.
    fn authorize_address(
        &self,
        integration: &IntegrationKey,
        request: SignInRequest<'_>,
    ) -> Result<SignInAddress, DomainError>;

    /// The credential `integration`'s service issues for `code`, made with
    /// `verifier`, written the way the integration's accounts hold it, for
    /// the `place` the person named when the sign-in asks for one.
    async fn exchange(&self, exchanging: Exchanging<'_>) -> Result<Secret, SignInFailure>;
}

/// Dyn-safe port making the random values a connection is tied together
/// with, and their digests.
pub trait ConnectionSecrets: Send + Sync {
    /// A fresh random value and its digest, for a `state`, a verifier or a
    /// one-time code. The value is URL-safe and long enough for a PKCE
    /// verifier.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when no randomness is to be
    /// had.
    fn generate(&self) -> Result<(Secret, TokenHash), DomainError>;

    /// The digest of `presented`, as [`Self::generate`] made it.
    fn digest(&self, presented: &Secret) -> TokenHash;
}

/// Dyn-safe port keeping the connections people began.
#[async_trait]
pub trait PendingConnectionStore: Send + Sync + TenantScoped {
    /// The tenant's connection `id`, if it is still kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &PendingConnectionId,
    ) -> Result<Option<PendingConnection<ResolvedTenant>>, DomainError>;

    /// Keeps `connection`, new or changed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when its state digest is already
    /// kept for another connection, and `DomainError::Infrastructure` when
    /// it cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        connection: &PendingConnection<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Where a connection whose `state` came back was begun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionAt {
    /// The tenant it was begun in.
    pub tenant_id: TenantId,
    /// The pending authorization exchange matched by the returned state.
    pub connection_id: PendingConnectionId,
}

/// Dyn-safe port reading, across every tenant, the connection a service's
/// answer names by its `state`, for the one callback address every app
/// registers, and sweeping the connections that ran out.
#[async_trait]
pub trait ConnectionStates: Send + Sync {
    /// Where the connection whose state digest is `state` was begun, if one
    /// is kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read.
    async fn find(&self, state: &TokenHash) -> Result<Option<ConnectionAt>, DomainError>;

    /// Removes up to `limit` connections that stopped being finishable
    /// before `now`, and how many it removed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be removed.
    async fn remove_expired(&self, now: OffsetDateTime, limit: u32) -> Result<u64, DomainError>;
}
