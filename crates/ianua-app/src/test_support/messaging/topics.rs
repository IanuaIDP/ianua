//! Fakes for messaging topics and for who may use them, and the topics
//! their tests share.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::messaging::control::{MessagingControl, MessagingCreator};
use ianua_domain::domains::messaging::topic::{
    CreateTopicParams, RetentionPolicy, Topic, TopicRow,
};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::test_support::authority::anyone_holding;
use ianua_domain::types::{Label, Setting, TenantId, TopicId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::broker::TopicAuthorizer;
use crate::ports::messaging::{TopicSortField, TopicStore};
use crate::services::messaging::topic_authorizer::DelegationTopicAuthorizer;
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::{Fake, block_on, test_ctx};

/// Someone who manages messaging, for a test that makes or changes topics
/// and is not about who does it.
#[must_use]
pub fn messaging_admin() -> MessagingControl<'static> {
    MessagingControl::new(anyone_holding(&[SystemPermission::Messaging(
        MessagingAction::Manage,
    )]))
}

/// An active topic named `name`, with no schema, carrying internal data.
#[must_use]
pub fn topic_named(name: &str) -> Topic<ResolvedTenant> {
    topic_classed(name, DataClassLevel::Internal)
}

/// An active topic named `name`, with no schema, carrying data up to
/// `class`.
#[must_use]
pub fn topic_classed(name: &str, class: DataClassLevel) -> Topic<ResolvedTenant> {
    let admin = messaging_admin();
    Topic::create(
        CreateTopicParams {
            name: Label::new("name", name).unwrap(),
            topic_name: TopicName::new(name).unwrap(),
            description: None,
            schema: Setting::Unset,
            retention: RetentionPolicy::Unlimited,
            data_class: class,
        },
        MessagingCreator::Person(&admin),
    )
    .unwrap()
}

/// [`topic_named`], paused.
#[must_use]
pub fn paused_topic(name: &str) -> Topic<ResolvedTenant> {
    let mut topic = topic_named(name);
    topic.pause(&messaging_admin()).unwrap();
    topic
}

/// The topic `store` keeps under `id` in the tenant every test caller acts
/// in, as storage returns it.
#[must_use]
pub fn stored_topic(store: &FakeTopicStore, id: &TopicId) -> Topic<ResolvedTenant> {
    block_on(store.find_by_id(&test_ctx().tenant(), id))
        .unwrap()
        .unwrap()
}

/// [`topic_named`], archived.
#[must_use]
pub fn archived_topic(name: &str) -> Topic<ResolvedTenant> {
    let mut topic = topic_named(name);
    topic.archive(&messaging_admin()).unwrap();
    topic
}

/// A store holding `topic` in the tenant every test caller acts in.
#[must_use]
pub fn topics_of_test_tenant(topic: Topic<ResolvedTenant>) -> Arc<FakeTopicStore> {
    Arc::new(FakeTopicStore::holding(&test_ctx().tenant(), topic))
}

/// In-memory topic store, each topic kept under its tenant.
#[derive(Default)]
pub struct FakeTopicStore {
    topics: Mutex<Vec<(TenantId, Topic<ResolvedTenant>)>>,
}

impl TenantScoped for FakeTopicStore {}

impl FakeTopicStore {
    /// A store holding no topic.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `topic` in `tenant`.
    #[must_use]
    pub fn holding(tenant: &ScopedTenant, topic: Topic<ResolvedTenant>) -> Self {
        Self {
            topics: Mutex::new(vec![(**tenant, topic)]),
        }
    }

    /// How many topics are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.topics.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: &ScopedTenant,
        keeps: impl Fn(&Topic<ResolvedTenant>) -> bool,
    ) -> Result<Vec<Topic<ResolvedTenant>>, DomainError> {
        self.topics
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, topic)| tenant == &**tenant_id && keeps(topic))
            .map(|(_, topic)| copy_topic(topic))
            .collect()
    }
}

#[async_trait]
impl TopicStore for FakeTopicStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &TopicId,
    ) -> Result<Option<Topic<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |topic| topic.id() == id)?;
        Ok(found.into_iter().next())
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &TopicName,
    ) -> Result<Option<Topic<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |topic| topic.topic_name() == name)?;
        Ok(found.into_iter().next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<TopicSortField>,
        request: &PageRequest,
    ) -> Result<Page<Topic<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |_| true)?;
        page(found, sort, request)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        topic: &Topic<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_topic(topic)?;
        let mut topics = self.topics.lock().unwrap();
        let taken = topics.iter().any(|(tenant, kept)| {
            tenant == &**tenant_id
                && kept.id() != topic.id()
                && kept.topic_name() == topic.topic_name()
        });
        if taken {
            return Err(DomainError::conflict(
                "another topic of the tenant has this name",
            ));
        }
        topics.retain(|(tenant, kept)| !(tenant == &**tenant_id && kept.id() == topic.id()));
        topics.push((**tenant_id, copy));
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &TopicId) -> Result<(), DomainError> {
        self.topics
            .lock()
            .unwrap()
            .retain(|(tenant, topic)| !(tenant == &**tenant_id && topic.id() == id));
        Ok(())
    }
}

impl Fake for Arc<dyn TopicStore> {
    fn fake() -> Self {
        Arc::new(FakeTopicStore::empty())
    }
}

impl Fake for Arc<dyn TopicAuthorizer> {
    fn fake() -> Self {
        Arc::new(DelegationTopicAuthorizer::new())
    }
}

/// `topic` written out and read back, as storage would return it.
fn copy_topic(topic: &Topic<ResolvedTenant>) -> Result<Topic<ResolvedTenant>, DomainError> {
    Topic::reconstitute(TopicRow {
        id: *topic.id(),
        name: topic.name().clone(),
        topic_name: topic.topic_name().clone(),
        description: topic.description().cloned(),
        schema: Setting::from_stored(topic.schema().cloned()),
        retention: topic.retention(),
        status: topic.status(),
        created_by: topic.created_by().clone(),
        data_class: topic.data_class(),
        created_at: Aggregate::created_at(topic),
        updated_at: Aggregate::updated_at(topic),
    })
}
