//! Federation connections, the local accounts linked through them, and
//! what their group mappings gave each person.

use async_trait::async_trait;
use ianua_domain::domains::federation::connection::{FederatedIdpConnection, MappedHoldings};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::federation::link::FederatedLink;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, FederatedSubject, GroupId, RoleId, TenantId, UserId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a federation connection listing can be ordered by.
    pub enum ConnectionSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by provider name.
        ProviderName => "provider_name",
        /// Order by connection status.
        Status => "status",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<ConnectionSortField> for FederatedIdpConnection<ResolvedTenant> {
    fn sort_key(&self, field: ConnectionSortField) -> SortKey {
        match field {
            ConnectionSortField::CreatedAt => self.created_at().into(),
            ConnectionSortField::ProviderName => self.provider_name().as_str().into(),
            ConnectionSortField::Status => connection_status_word(self.status()).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word a connection's status sorts by, as it is stored.
fn connection_status_word(status: ConnectionStatus) -> &'static str {
    match status {
        ConnectionStatus::Active => "active",
        ConnectionStatus::Disabled => "disabled",
    }
}

/// Dyn-safe port for persisting and retrieving federation connections.
#[async_trait]
pub trait ConnectionStore: Send + Sync + TenantScoped {
    /// Finds a connection by its ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ConnectionId,
    ) -> Result<Option<FederatedIdpConnection<ResolvedTenant>>, DomainError>;

    /// Lists connections for the tenant with optional status filter, ordering,
    /// and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<ConnectionStatus>,
        sort: &SortOrder<ConnectionSortField>,
        page: &PageRequest,
    ) -> Result<Page<FederatedIdpConnection<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated connection.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        connection: &FederatedIdpConnection<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a connection by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &ConnectionId) -> Result<(), DomainError>;

    /// How many of the tenant's connections hand out `role_id`, as the role
    /// new accounts are given or through a group-mapping rule: each would
    /// go on handing out a role that is gone, so the role cannot be deleted
    /// under them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn count_naming_role(
        &self,
        tenant_id: &ScopedTenant,
        role_id: &RoleId,
    ) -> Result<u64, DomainError>;

    /// How many of the tenant's connections put people in `group_id`
    /// through a group-mapping rule, so the group cannot be deleted under
    /// them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn count_naming_group(
        &self,
        tenant_id: &ScopedTenant,
        group_id: &GroupId,
    ) -> Result<u64, DomainError>;
}

/// A SAML connection that follows the address its provider publishes its
/// metadata at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataFollower {
    /// The owner of the connection whose metadata needs refreshing.
    pub tenant_id: TenantId,
    /// The SAML configuration to refresh from its provider.
    pub connection_id: ConnectionId,
}

define_sort_field! {
    /// The one order metadata followers are read in: by tenant, then by
    /// connection.
    pub enum MetadataFollowerSortField {
        /// Order by tenant.
        Tenant => "tenant_id",
    }
    default = Tenant;
}

impl SortKeys<MetadataFollowerSortField> for MetadataFollower {
    fn sort_key(&self, field: MetadataFollowerSortField) -> SortKey {
        match field {
            MetadataFollowerSortField::Tenant => self.tenant_id.as_uuid().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.connection_id.as_uuid().into()
    }
}

/// Dyn-safe port finding, across every tenant, the SAML connections that
/// follow a metadata address, for the refresh that reads each again.
#[async_trait]
pub trait MetadataFollowers: Send + Sync {
    /// A page of them, in [`MetadataFollowerSortField`]'s order, which holds
    /// from one page to the next.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read, or
    /// the read does not answer within ten seconds.
    async fn list_following(
        &self,
        page: &PageRequest,
    ) -> Result<Page<MetadataFollower>, DomainError>;
}

/// Dyn-safe port for the links between local accounts and who their owners
/// are at a connection's identity provider.
///
/// At most one link per subject and one per account on each connection: an
/// account is one person at a provider, and a subject is one account here.
#[async_trait]
pub trait FederatedLinkStore: Send + Sync + TenantScoped {
    /// The link `subject` at `connection_id`'s provider signs in by, if any.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_subject(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        subject: &FederatedSubject,
    ) -> Result<Option<FederatedLink<ResolvedTenant>>, DomainError>;

    /// The link `user_id` holds at `connection_id`'s provider, if any.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<Option<FederatedLink<ResolvedTenant>>, DomainError>;

    /// Every link `user_id` holds, one per connection, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<FederatedLink<ResolvedTenant>>, DomainError>;

    /// Saves a new link.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` if the subject or the account is
    /// already linked on this connection.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        link: &FederatedLink<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Saves a change to a link already kept, found by its connection and
    /// account: its holder confirmed it again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, or when
    /// no such link is kept.
    async fn update(
        &self,
        tenant_id: &ScopedTenant,
        link: &FederatedLink<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes the link `user_id` holds at `connection_id`'s provider. The
    /// provider no longer signs the account in.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for what each connection's group mapping gave each person,
/// one record per connection and person, so a later sign-in takes back
/// what the provider no longer vouches for.
#[async_trait]
pub trait MappedHoldingsStore: Send + Sync + TenantScoped {
    /// What `connection_id`'s mapping gave `user_id`, if it ever gave them
    /// anything.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, or for
    /// a stored record that names a role or group twice.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        connection_id: &ConnectionId,
        user_id: &UserId,
    ) -> Result<Option<MappedHoldings<ResolvedTenant>>, DomainError>;

    /// Saves the record, replacing the one kept for its connection and
    /// person.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        holdings: &MappedHoldings<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}
