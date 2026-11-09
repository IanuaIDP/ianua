//! OAuth clients and their secrets.

use async_trait::async_trait;
use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, OAuthClientId, TokenHash};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field an OAuth client listing can be ordered by.
    pub enum OAuthClientSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by display name.
        Name => "name",
        /// Order by lifecycle status.
        Status => "status",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<OAuthClientSortField> for OAuthClient<ResolvedTenant> {
    fn sort_key(&self, field: OAuthClientSortField) -> SortKey {
        match field {
            OAuthClientSortField::CreatedAt => self.created_at().into(),
            OAuthClientSortField::Name => self.name().as_str().into(),
            OAuthClientSortField::Status => self.status().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for persisting and retrieving OAuth clients.
#[async_trait]
pub trait OAuthClientStore: Send + Sync + TenantScoped {
    /// Finds a client by its internal ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &OAuthClientId,
    ) -> Result<Option<OAuthClient<ResolvedTenant>>, DomainError>;

    /// Finds the named clients in one read, omitting missing ids and those
    /// outside the tenant. The result has no guaranteed order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[OAuthClientId],
    ) -> Result<Vec<OAuthClient<ResolvedTenant>>, DomainError>;

    /// Finds the tenant's client whose public client id is `client_id`,
    /// whatever its status.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_client_id_value(
        &self,
        tenant_id: &ScopedTenant,
        client_id: &ClientId,
    ) -> Result<Option<OAuthClient<ResolvedTenant>>, DomainError>;

    /// Lists clients for the tenant with optional status filter, ordering, and
    /// pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<OAuthClientStatus>,
        sort: &SortOrder<OAuthClientSortField>,
        page: &PageRequest,
    ) -> Result<Page<OAuthClient<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated client.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        client: &OAuthClient<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for verifying an OAuth client secret against its hash.
#[async_trait]
pub trait ClientSecretVerifier: Send + Sync {
    /// Whether `presented` is the secret `hash` was made from.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the hash cannot be checked.
    async fn verify(&self, presented: &Secret, hash: &TokenHash) -> Result<bool, DomainError>;
}

/// Dyn-safe port for generating OAuth client credentials.
#[async_trait]
pub trait ClientSecretGenerator: Send + Sync {
    /// Generates a new client ID value and secret, with the secret's hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate(&self) -> Result<GeneratedClientCredentials, DomainError>;

    /// Generates a new client ID value alone, for a client that proves
    /// itself without a secret: a public client, or one using its keys or
    /// certificate.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate_client_id(&self) -> Result<ClientId, DomainError>;

    /// Generates a new secret for a client that already has its id, as a
    /// rotation needs, with the secret's hash.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source fails.
    async fn generate_secret(&self) -> Result<GeneratedSecret, DomainError>;
}

/// A newly generated client secret. Holds the raw secret, so it has no
/// `Debug`.
pub struct GeneratedSecret {
    /// The raw client secret, shown once.
    pub raw_secret: Secret,
    /// The hashed client secret, stored.
    pub secret_hash: TokenHash,
}

/// Newly generated OAuth client credentials. Holds the raw secret, so it has
/// no `Debug`.
pub struct GeneratedClientCredentials {
    /// The public client ID (e.g. `"client_abc123"`).
    pub client_id_value: ClientId,
    /// The raw client secret, shown once.
    pub raw_secret: Secret,
    /// The hashed client secret, stored.
    pub secret_hash: TokenHash,
}
