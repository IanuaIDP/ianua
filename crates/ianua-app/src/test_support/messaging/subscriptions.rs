//! Fake for subscriptions to messaging topics, and the subscriptions their
//! tests share.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::messaging::delivery::{AckPolicy, PushEndpoint, SubscriptionDelivery};
use ianua_domain::domains::messaging::subscription::{
    ConsumerGroup, CreateSubscriptionParams, Subscriber, Subscription, SubscriptionRow,
};
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{ConsumerId, MessageSubscriptionId, PublicHttpsUrl, Setting, TenantId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor};
use crate::ports::messaging::{SubscriptionSortField, SubscriptionStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::FakeEncryptor;
use crate::test_support::consumers::billing_sync;
use crate::test_support::listing::page;
use crate::test_support::messaging::messaging_admin;
use crate::test_support::{Fake, block_on, test_ctx};

/// Where every [`push_subscription_of`] posts its messages.
pub const TEST_PUSH_URL: &str = "https://hooks.acme.com/orders";

/// The secret every [`push_subscription_of`] signs with, before it is
/// sealed.
pub const TEST_PUSH_SECRET: &str = "old-push-secret";

/// A pull subscription of a fresh "billing-sync" to `topic`, made by
/// someone who manages messaging.
#[must_use]
pub fn enrolled_subscription(topic: &Topic<ResolvedTenant>) -> Subscription<ResolvedTenant> {
    subscription_of(&billing_sync(), topic)
}

/// A pull subscription of `consumer` to `topic`, made by someone who
/// manages messaging.
#[must_use]
pub fn subscription_of(
    consumer: &Consumer<ResolvedTenant>,
    topic: &Topic<ResolvedTenant>,
) -> Subscription<ResolvedTenant> {
    delivered_by(consumer, topic, SubscriptionDelivery::Pull)
}

/// A subscription of `consumer` to `topic` pushed to [`TEST_PUSH_URL`],
/// signed with [`TEST_PUSH_SECRET`] sealed as [`FakeEncryptor`] seals it.
///
/// # Panics
///
/// Never in practice: the address is a public HTTPS URL.
#[must_use]
pub fn push_subscription_of(
    consumer: &Consumer<ResolvedTenant>,
    topic: &Topic<ResolvedTenant>,
) -> Subscription<ResolvedTenant> {
    let id = MessageSubscriptionId::new();
    let endpoint = PushEndpoint::new(
        PublicHttpsUrl::new(TEST_PUSH_URL).unwrap(),
        FakeEncryptor::sealed_for(TEST_PUSH_SECRET, &push_secret_place(&id)),
    );
    made_as(
        id,
        Made {
            consumer,
            topic,
            delivery: SubscriptionDelivery::Push(endpoint),
            consumer_group: Setting::Unset,
        },
    )
}

/// Where the test tenant's subscription `id` keeps its push secrets.
#[must_use]
pub fn push_secret_place(id: &MessageSubscriptionId) -> SealedFor {
    SealedFor::new(
        SealOwner::Tenant(test_ctx().tenant_id()),
        SealedField::PushSecret,
        id,
    )
}

/// A pull subscription of `consumer` to `topic` in the consumer group
/// `group`, made by someone who manages messaging.
///
/// # Panics
///
/// When `group` is not a well-formed group name.
#[must_use]
pub fn grouped_subscription_of(
    consumer: &Consumer<ResolvedTenant>,
    topic: &Topic<ResolvedTenant>,
    group: &str,
) -> Subscription<ResolvedTenant> {
    made_with(
        consumer,
        topic,
        SubscriptionDelivery::Pull,
        Setting::Set(ConsumerGroup::new(group).unwrap()),
    )
}

/// A subscription of `consumer` to `topic` delivered by `delivery` with the
/// standard acknowledgement policy, made by someone who manages messaging.
fn delivered_by(
    consumer: &Consumer<ResolvedTenant>,
    topic: &Topic<ResolvedTenant>,
    delivery: SubscriptionDelivery,
) -> Subscription<ResolvedTenant> {
    made_with(consumer, topic, delivery, Setting::Unset)
}

/// A subscription of `consumer` to `topic` delivered by `delivery` in
/// `consumer_group`, made by someone who manages messaging.
fn made_with(
    consumer: &Consumer<ResolvedTenant>,
    topic: &Topic<ResolvedTenant>,
    delivery: SubscriptionDelivery,
    consumer_group: Setting<ConsumerGroup>,
) -> Subscription<ResolvedTenant> {
    made_as(
        MessageSubscriptionId::new(),
        Made {
            consumer,
            topic,
            delivery,
            consumer_group,
        },
    )
}

/// What a test subscription is made of, beside its id.
struct Made<'a> {
    consumer: &'a Consumer<ResolvedTenant>,
    topic: &'a Topic<ResolvedTenant>,
    delivery: SubscriptionDelivery,
    consumer_group: Setting<ConsumerGroup>,
}

/// The subscription `id` that `made` describes, made by someone who
/// manages messaging.
fn made_as(id: MessageSubscriptionId, made: Made<'_>) -> Subscription<ResolvedTenant> {
    let admin = messaging_admin();
    Subscription::create(
        made.topic,
        CreateSubscriptionParams {
            id,
            consumer_group: made.consumer_group,
            delivery: made.delivery,
            ack_policy: AckPolicy::standard(),
            filter: Setting::Unset,
        },
        Subscriber::Enrolled {
            by: &admin,
            consumer: made.consumer,
        },
    )
    .unwrap()
}

/// Builds a consumer subscription that retains its topic binding but cannot receive messages.
#[must_use]
pub fn paused_subscription_of(
    consumer: &Consumer<ResolvedTenant>,
    topic: &Topic<ResolvedTenant>,
) -> Subscription<ResolvedTenant> {
    let mut subscription = subscription_of(consumer, topic);
    subscription.pause(&messaging_admin()).unwrap();
    subscription
}

/// The subscription `store` keeps under `id` in the tenant every test
/// caller acts in, as storage returns it.
#[must_use]
pub fn stored_subscription(
    store: &FakeSubscriptionStore,
    id: &MessageSubscriptionId,
) -> Subscription<ResolvedTenant> {
    block_on(store.find_by_id(&test_ctx().tenant(), id))
        .unwrap()
        .unwrap()
}

/// In-memory subscription store, each subscription kept under its tenant.
#[derive(Default)]
pub struct FakeSubscriptionStore {
    subscriptions: Mutex<Vec<(TenantId, Subscription<ResolvedTenant>)>>,
}

impl TenantScoped for FakeSubscriptionStore {}

impl FakeSubscriptionStore {
    /// A store holding no subscription.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `subscriptions` in the tenant every test caller acts
    /// in.
    #[must_use]
    pub fn of_test_tenant(
        subscriptions: impl IntoIterator<Item = Subscription<ResolvedTenant>>,
    ) -> Arc<Self> {
        let tenant = test_ctx().tenant_id();
        let store = Self::default();
        store
            .subscriptions
            .lock()
            .unwrap()
            .extend(subscriptions.into_iter().map(|held| (tenant, held)));
        Arc::new(store)
    }

    /// How many subscriptions are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.subscriptions.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: &ScopedTenant,
        keeps: impl Fn(&Subscription<ResolvedTenant>) -> bool,
    ) -> Result<Vec<Subscription<ResolvedTenant>>, DomainError> {
        self.subscriptions
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, subscription)| tenant == &**tenant_id && keeps(subscription))
            .map(|(_, subscription)| copy_subscription(subscription))
            .collect()
    }

    fn listed(
        &self,
        tenant_id: &ScopedTenant,
        keeps: impl Fn(&Subscription<ResolvedTenant>) -> bool,
        sort: &SortOrder<SubscriptionSortField>,
        request: &PageRequest,
    ) -> Result<Page<Subscription<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, keeps)?;
        page(found, sort, request)
    }
}

#[async_trait]
impl SubscriptionStore for FakeSubscriptionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &MessageSubscriptionId,
    ) -> Result<Option<Subscription<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |subscription| subscription.id() == id)?;
        Ok(found.into_iter().next())
    }

    async fn list_by_topic(
        &self,
        tenant_id: &ScopedTenant,
        topic_name: &TopicName,
        sort: &SortOrder<SubscriptionSortField>,
        request: &PageRequest,
    ) -> Result<Page<Subscription<ResolvedTenant>>, DomainError> {
        self.listed(
            tenant_id,
            |subscription| subscription.topic_name() == topic_name,
            sort,
            request,
        )
    }

    async fn list_by_service(
        &self,
        tenant_id: &ScopedTenant,
        service_id: &ConsumerId,
        sort: &SortOrder<SubscriptionSortField>,
        request: &PageRequest,
    ) -> Result<Page<Subscription<ResolvedTenant>>, DomainError> {
        self.listed(
            tenant_id,
            |subscription| subscription.consumer_id() == service_id,
            sort,
            request,
        )
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &Subscription<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_subscription(subscription)?;
        let mut subscriptions = self.subscriptions.lock().unwrap();
        subscriptions
            .retain(|(tenant, kept)| !(tenant == &**tenant_id && kept.id() == subscription.id()));
        subscriptions.push((**tenant_id, copy));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &MessageSubscriptionId,
    ) -> Result<(), DomainError> {
        self.subscriptions
            .lock()
            .unwrap()
            .retain(|(tenant, subscription)| !(tenant == &**tenant_id && subscription.id() == id));
        Ok(())
    }

    async fn other_in_group(
        &self,
        tenant_id: &ScopedTenant,
        topic_name: &TopicName,
        group: &ConsumerGroup,
        except: &MessageSubscriptionId,
    ) -> Result<Option<Subscription<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |subscription| {
            subscription.topic_name() == topic_name
                && subscription.consumer_group() == Some(group)
                && subscription.id() != except
        })?;
        Ok(found.into_iter().next())
    }
}

impl Fake for Arc<dyn SubscriptionStore> {
    fn fake() -> Self {
        Arc::new(FakeSubscriptionStore::empty())
    }
}

/// `subscription` written out and read back, as storage would return it.
fn copy_subscription(
    subscription: &Subscription<ResolvedTenant>,
) -> Result<Subscription<ResolvedTenant>, DomainError> {
    Subscription::reconstitute(SubscriptionRow {
        id: *subscription.id(),
        topic_name: subscription.topic_name().clone(),
        consumer_id: *subscription.consumer_id(),
        consumer_group: Setting::from_stored(subscription.consumer_group().cloned()),
        delivery: subscription.delivery().clone(),
        ack_policy: *subscription.ack_policy(),
        filter: Setting::from_stored(subscription.filter().cloned()),
        status: subscription.status(),
        created_at: Aggregate::created_at(subscription),
        updated_at: Aggregate::updated_at(subscription),
    })
}
