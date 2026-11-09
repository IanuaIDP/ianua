//! Channels between agents.

use async_trait::async_trait;
use ianua_domain::domains::agents::channels::channel::AgentChannel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentChannelId, AgentId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// The one order a tenant's agent channels are listed in: newest first.
    pub enum AgentChannelSortField {
        /// Order by when the channel was opened.
        OpenedAt => "opened_at",
    }
    default = OpenedAt;
    default direction = Desc;
}

impl SortKeys<AgentChannelSortField> for AgentChannel<ResolvedTenant> {
    fn sort_key(&self, field: AgentChannelSortField) -> SortKey {
        match field {
            AgentChannelSortField::OpenedAt => self.opened_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for channels people open between agents.
#[async_trait]
pub trait AgentChannelStore: Send + Sync + TenantScoped {
    /// Inserts or updates a channel.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        channel: &AgentChannel<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Finds a channel by id.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentChannelId,
    ) -> Result<Option<AgentChannel<ResolvedTenant>>, DomainError>;

    /// The tenant's channels, newest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<AgentChannel<ResolvedTenant>>, DomainError>;

    /// The channels from `sender` to `receiver` that no person has closed.
    /// Expiry is the caller's to check, against its own clock.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn unclosed_between(
        &self,
        tenant_id: &ScopedTenant,
        sender: &AgentId,
        receiver: &AgentId,
    ) -> Result<Vec<AgentChannel<ResolvedTenant>>, DomainError>;

    /// The channels into `receiver` from any agent that no person has closed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn unclosed_into(
        &self,
        tenant_id: &ScopedTenant,
        receiver: &AgentId,
    ) -> Result<Vec<AgentChannel<ResolvedTenant>>, DomainError>;
}
