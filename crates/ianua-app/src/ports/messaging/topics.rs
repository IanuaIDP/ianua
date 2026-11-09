//! Message topics.

use async_trait::async_trait;
use ianua_domain::domains::messaging::topic::{Topic, TopicStatus};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::TopicId;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a topic listing can be ordered by.
    pub enum TopicSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by display name.
        Name => "name",
        /// Order by machine-readable topic name.
        TopicName => "topic_name",
        /// Order by lifecycle status.
        Status => "status",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<TopicSortField> for Topic<ResolvedTenant> {
    fn sort_key(&self, field: TopicSortField) -> SortKey {
        match field {
            TopicSortField::CreatedAt => Aggregate::created_at(self).into(),
            TopicSortField::UpdatedAt => Aggregate::updated_at(self).into(),
            TopicSortField::Name => self.name().as_str().into(),
            TopicSortField::TopicName => self.topic_name().as_str().into(),
            TopicSortField::Status => topic_status_word(self.status()).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word a topic's status sorts by, as it is stored.
fn topic_status_word(status: TopicStatus) -> &'static str {
    match status {
        TopicStatus::Active => "active",
        TopicStatus::Paused => "paused",
        TopicStatus::Archived => "archived",
    }
}

/// Dyn-safe port for persisting and retrieving messaging topics.
#[async_trait]
pub trait TopicStore: Send + Sync + TenantScoped {
    /// Finds a topic by its unique ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &TopicId,
    ) -> Result<Option<Topic<ResolvedTenant>>, DomainError>;

    /// Finds a topic by its machine name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &TopicName,
    ) -> Result<Option<Topic<ResolvedTenant>>, DomainError>;

    /// Lists a page of topics for a tenant in the requested order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<TopicSortField>,
        page: &PageRequest,
    ) -> Result<Page<Topic<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated topic.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when another topic of the tenant has its
    ///   machine name, so a publish never has to pick between two.
    /// - `DomainError` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        topic: &Topic<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a topic by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &TopicId) -> Result<(), DomainError>;
}
