//! Subscriptions to topics.

use async_trait::async_trait;
use ianua_domain::domains::messaging::subscription::{
    ConsumerGroup, Subscription, SubscriptionStatus,
};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{ConsumerId, MessageSubscriptionId};

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a subscription listing can be ordered by.
    pub enum SubscriptionSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by subscribed topic name.
        TopicName => "topic_name",
        /// Order by lifecycle status.
        Status => "status",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<SubscriptionSortField> for Subscription<ResolvedTenant> {
    fn sort_key(&self, field: SubscriptionSortField) -> SortKey {
        match field {
            SubscriptionSortField::CreatedAt => Aggregate::created_at(self).into(),
            SubscriptionSortField::TopicName => self.topic_name().as_str().into(),
            SubscriptionSortField::Status => subscription_status_word(self.status()).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word a subscription's status sorts by, as it is stored.
fn subscription_status_word(status: SubscriptionStatus) -> &'static str {
    match status {
        SubscriptionStatus::Active => "active",
        SubscriptionStatus::Paused => "paused",
    }
}

/// Dyn-safe port for persisting and retrieving subscriptions.
#[async_trait]
pub trait SubscriptionStore: Send + Sync + TenantScoped {
    /// Finds a subscription by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &MessageSubscriptionId,
    ) -> Result<Option<Subscription<ResolvedTenant>>, DomainError>;

    /// Lists a page of subscriptions for a topic in the requested order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list_by_topic(
        &self,
        tenant_id: &ScopedTenant,
        topic_name: &TopicName,
        sort: &SortOrder<SubscriptionSortField>,
        page: &PageRequest,
    ) -> Result<Page<Subscription<ResolvedTenant>>, DomainError>;

    /// Lists a page of subscriptions for a service in the requested order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list_by_service(
        &self,
        tenant_id: &ScopedTenant,
        service_id: &ConsumerId,
        sort: &SortOrder<SubscriptionSortField>,
        page: &PageRequest,
    ) -> Result<Page<Subscription<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated subscription.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &Subscription<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// A subscription of consumer group `group` on `topic_name` other than
    /// `except`, if the group has one. The group's subscriptions read
    /// through one bus consumer, so it stays while any of them is left.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn other_in_group(
        &self,
        tenant_id: &ScopedTenant,
        topic_name: &TopicName,
        group: &ConsumerGroup,
        except: &MessageSubscriptionId,
    ) -> Result<Option<Subscription<ResolvedTenant>>, DomainError>;

    /// Deletes a subscription by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &MessageSubscriptionId,
    ) -> Result<(), DomainError>;
}
