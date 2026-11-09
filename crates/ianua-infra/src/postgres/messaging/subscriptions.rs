//! The subscriptions of a tenant's services to its topics, each row under
//! row-level security.
//!
//! A subscription names its topic and its service, and goes with either.
//! A push subscription's secrets are kept as the sealer handed them over,
//! never in clear. A list first reads the ids of its page, by topic or by
//! service, then reads those rows by id, as every read of a subscription
//! does.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Keyset, Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::messaging::{SubscriptionSortField, SubscriptionStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::messaging::subscription::{ConsumerGroup, Subscription};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConsumerId, MessageSubscriptionId, TenantId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{SubscriptionColumns, SubscriptionRecord};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres subscription store.
pub struct PgSubscriptionStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSubscriptionStore {}

impl PgSubscriptionStore {
    /// A store keeping subscriptions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// One page of the subscriptions of `tenant` that `listed` keeps, in
    /// the requested keyset order.
    async fn page_of(
        &self,
        tenant: &ScopedTenant,
        listed: PageQuery<'_>,
        keyset: Keyset<'_, SortOrder<SubscriptionSortField>>,
    ) -> Result<Page<Subscription<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, tenant, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        let subscriptions = records
            .into_iter()
            .map(SubscriptionRecord::into_subscription)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(subscriptions))
    }
}

/// The records of the subscriptions of `tenant` that `ids` names, in no
/// order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<SubscriptionRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        SubscriptionRecord,
        "queries/topic_subscriptions/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

impl SortColumns for SubscriptionSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::TopicName => "topic_name",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl SubscriptionStore for PgSubscriptionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &MessageSubscriptionId,
    ) -> Result<Option<Subscription<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        records
            .into_iter()
            .next()
            .map(SubscriptionRecord::into_subscription)
            .transpose()
    }

    async fn list_by_topic(
        &self,
        tenant_id: &ScopedTenant,
        topic_name: &TopicName,
        sort: &SortOrder<SubscriptionSortField>,
        page: &PageRequest,
    ) -> Result<Page<Subscription<ResolvedTenant>>, DomainError> {
        let listed = PageQuery::ids("id", "topic_subscriptions")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .filter("topic_name = ?", topic_name.as_str().to_owned());
        self.page_of(tenant_id, listed, page.keyset(sort)?).await
    }

    async fn list_by_service(
        &self,
        tenant_id: &ScopedTenant,
        service_id: &ConsumerId,
        sort: &SortOrder<SubscriptionSortField>,
        page: &PageRequest,
    ) -> Result<Page<Subscription<ResolvedTenant>>, DomainError> {
        let listed = PageQuery::ids("id", "topic_subscriptions")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .filter("consumer_id = ?", *service_id.as_uuid());
        self.page_of(tenant_id, listed, page.keyset(sort)?).await
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &Subscription<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = SubscriptionColumns::of(subscription);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/topic_subscriptions/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.topic_name,
                    columns.consumer_id,
                    columns.consumer_group,
                    columns.delivery_mode,
                    columns.push_url,
                    columns.push_secret_sealed,
                    columns.previous_secret_sealed,
                    columns.previous_secret_until,
                    columns.ack_deadline_seconds,
                    columns.max_deliveries,
                    columns.filter,
                    columns.status,
                    columns.created_at,
                    columns.updated_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn other_in_group(
        &self,
        tenant_id: &ScopedTenant,
        topic_name: &TopicName,
        group: &ConsumerGroup,
        except: &MessageSubscriptionId,
    ) -> Result<Option<Subscription<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let member = sqlx::query_file_scalar!(
                    "queries/topic_subscriptions/other_in_group.sql",
                    tenant_id.as_uuid(),
                    topic_name.as_str(),
                    group.as_str(),
                    except.as_uuid()
                )
                .fetch_optional(&mut *connection)
                .await?;
                let ids: Vec<Uuid> = member.into_iter().collect();
                records_of(connection, tenant_id, &ids).await
            },
        )
        .await?;
        records
            .into_iter()
            .next()
            .map(SubscriptionRecord::into_subscription)
            .transpose()
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &MessageSubscriptionId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/topic_subscriptions/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::messaging::TopicStore;
    use ianua_domain::domains::messaging::delivery::{
        AckPolicy, PushEndpoint, SubscriptionDelivery,
    };
    use ianua_domain::domains::messaging::message_type::MessageFilter;
    use ianua_domain::domains::messaging::subscription::{
        ConsumerGroup, DeliveryMode, SubscriptionRow, SubscriptionStatus,
    };
    use ianua_domain::domains::messaging::topic::Topic;
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{PreviousSigningSecret, PublicHttpsUrl, Seconds, Setting};

    use super::*;
    use crate::postgres::messaging::PgTopicStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::branding::sealed;
    use crate::test_support::rows::messaging::{
        a_consumer, pushed_to_acme, subscription_row, topic_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgSubscriptionStore,
        tenant: ScopedTenant,
        billing: ConsumerId,
    }

    /// A fresh database, the store on it, a tenant with the topics
    /// `orders.created` and `payments.settled`, and the service "billing".
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        a_topic(&db, &tenant, "orders.created").await;
        a_topic(&db, &tenant, "payments.settled").await;
        let billing = a_consumer(&db, &tenant, "billing").await;
        Fixture {
            store: PgSubscriptionStore::new(Arc::clone(&db.databases)),
            tenant,
            billing,
            db,
        }
    }

    /// Saves the topic `topic_name` in `tenant` through its store.
    async fn a_topic(db: &TestDb, tenant: &ScopedTenant, topic_name: &str) {
        let topic: Topic<ResolvedTenant> = Topic::reconstitute(topic_row(topic_name)).unwrap();
        PgTopicStore::new(Arc::clone(&db.databases))
            .save(tenant, &topic)
            .await
            .unwrap();
    }

    fn subscription(row: SubscriptionRow) -> Subscription<ResolvedTenant> {
        Subscription::reconstitute(row).unwrap()
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn topics(page: &Page<Subscription<ResolvedTenant>>) -> Vec<&str> {
        page.items
            .iter()
            .map(|subscription| subscription.topic_name().as_str())
            .collect()
    }

    impl Fixture {
        fn of(&self, topic_name: &str) -> Subscription<ResolvedTenant> {
            subscription(self.row_of(topic_name))
        }

        fn row_of(&self, topic_name: &str) -> SubscriptionRow {
            subscription_row(topic_name, self.billing)
        }

        async fn save_all(&self, subscriptions: &[&Subscription<ResolvedTenant>]) {
            for subscription in subscriptions {
                self.store.save(&self.tenant, subscription).await.unwrap();
            }
        }

        async fn found(&self, id: &MessageSubscriptionId) -> Option<Subscription<ResolvedTenant>> {
            self.store.find_by_id(&self.tenant, id).await.unwrap()
        }

        /// Finds a peer subscription while excluding the current member from its group.
        async fn group_peer(
            &self,
            topic: &TopicName,
            group: &ConsumerGroup,
            except: &MessageSubscriptionId,
        ) -> Option<Subscription<ResolvedTenant>> {
            self.store
                .other_in_group(&self.tenant, topic, group, except)
                .await
                .unwrap()
        }
    }

    /// A pushed subscription in a consumer group with a filter, its secret
    /// rotated with the old one signing for a while, is found by its id as
    /// it was saved, every secret still sealed.
    #[tokio::test]
    async fn a_saved_push_subscription_is_found_by_its_id() {
        let fx = fixture().await;
        let rotated = PushEndpoint::restored(
            PublicHttpsUrl::new("https://hooks.acme.com/orders").unwrap(),
            sealed("new-secret"),
            PreviousSigningSecret::SignsUntil {
                secret: sealed("old-secret"),
                until: at(600),
            },
        );
        let pushed = subscription(SubscriptionRow {
            consumer_group: Setting::Set(ConsumerGroup::new("billing-workers").unwrap()),
            delivery: SubscriptionDelivery::Push(rotated),
            ack_policy: AckPolicy::new(Seconds::new(60), 10).unwrap(),
            filter: Setting::Set(MessageFilter::new("orders").unwrap()),
            updated_at: at(5),
            ..fx.row_of("orders.created")
        });
        fx.save_all(&[&pushed]).await;

        let found = fx.found(pushed.id()).await.unwrap();

        assert_eq!(found.topic_name(), pushed.topic_name());
        assert_eq!(found.consumer_id(), pushed.consumer_id());
        assert_eq!(found.consumer_group(), pushed.consumer_group());
        assert_eq!(found.delivery(), pushed.delivery());
        assert_eq!(found.ack_policy(), pushed.ack_policy());
        assert_eq!(found.filter(), pushed.filter());
        assert_eq!(found.delivery_mode(), DeliveryMode::Push);
        assert_eq!(found.created_at(), pushed.created_at());
        assert_eq!(found.updated_at(), at(5));
    }

    fn in_group(row: SubscriptionRow, group: &str) -> Subscription<ResolvedTenant> {
        subscription(SubscriptionRow {
            consumer_group: Setting::Set(ConsumerGroup::new(group).unwrap()),
            ..row
        })
    }

    /// Billing and payroll read `orders.created` as the group "workers". Each
    /// finds the other in the group; neither finds a subscription of
    /// another group or another topic.
    #[tokio::test]
    async fn a_group_member_finds_the_others_of_its_group() {
        let fx = fixture().await;
        let payroll = a_consumer(&fx.db, &fx.tenant, "payroll").await;
        let billing = in_group(fx.row_of("orders.created"), "workers");
        let payroll = in_group(subscription_row("orders.created", payroll), "workers");
        let elsewhere = in_group(fx.row_of("payments.settled"), "workers");
        fx.save_all(&[&billing, &payroll, &elsewhere]).await;
        let group = ConsumerGroup::new("workers").unwrap();
        let orders = TopicName::new("orders.created").unwrap();

        let other = fx.group_peer(&orders, &group, billing.id()).await;
        let alone = fx
            .group_peer(
                &TopicName::new("payments.settled").unwrap(),
                &group,
                elsewhere.id(),
            )
            .await;
        let other_group = fx
            .group_peer(
                &orders,
                &ConsumerGroup::new("auditors").unwrap(),
                billing.id(),
            )
            .await;

        assert_eq!(other.as_ref().map(Subscription::id), Some(payroll.id()));
        assert!(alone.is_none());
        assert!(other_group.is_none());
    }

    /// A pulled subscription reads back pulled, with nothing to sign.
    #[tokio::test]
    async fn a_saved_pull_subscription_reads_back_pulled() {
        let fx = fixture().await;
        let pulled = fx.of("orders.created");
        fx.save_all(&[&pulled]).await;

        let found = fx.found(pulled.id()).await.unwrap();

        assert_eq!(found.delivery(), &SubscriptionDelivery::Pull);
    }

    /// An id nobody has finds nothing, and another tenant does not find
    /// this tenant's subscription.
    #[tokio::test]
    async fn a_subscription_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let pulled = fx.of("orders.created");
        fx.save_all(&[&pulled]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let unknown = fx.found(&MessageSubscriptionId::new()).await;
        let elsewhere = fx.store.find_by_id(&other, pulled.id()).await.unwrap();

        assert!(unknown.is_none());
        assert!(elsewhere.is_none());
    }

    /// The subscription is paused and its secret rotated: saving it again
    /// keeps the new values and the time it was made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let pulled = fx.of("orders.created");
        fx.save_all(&[&pulled]).await;
        let changed = subscription(SubscriptionRow {
            id: *pulled.id(),
            delivery: pushed_to_acme("pushed"),
            status: SubscriptionStatus::Paused,
            updated_at: at(9),
            ..fx.row_of("orders.created")
        });

        fx.save_all(&[&changed]).await;

        let found = fx.found(pulled.id()).await.unwrap();
        assert_eq!(found.status(), SubscriptionStatus::Paused);
        assert_eq!(found.delivery_mode(), DeliveryMode::Push);
        assert_eq!(found.created_at(), pulled.created_at());
    }

    /// A topic's subscriptions list page by page, each page after the
    /// last, and none to another topic is on them.
    #[tokio::test]
    async fn a_topics_subscriptions_are_listed_page_by_page() {
        let fx = fixture().await;
        let audit = a_consumer(&fx.db, &fx.tenant, "audit").await;
        let ledger = a_consumer(&fx.db, &fx.tenant, "ledger").await;
        fx.save_all(&[
            &fx.of("orders.created"),
            &subscription(subscription_row("orders.created", audit)),
            &subscription(subscription_row("orders.created", ledger)),
            &fx.of("payments.settled"),
        ])
        .await;
        let order = SortOrder::single(Sort::ascending(SubscriptionSortField::CreatedAt));
        let topic = TopicName::new("orders.created").unwrap();

        let page_one = fx
            .store
            .list_by_topic(&fx.tenant, &topic, &order, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx
            .store
            .list_by_topic(&fx.tenant, &topic, &order, &after)
            .await
            .unwrap();

        assert_eq!(page_one.items.len(), 2);
        assert_eq!(topics(&page_two), ["orders.created"]);
        assert!(!page_two.has_next());
    }

    /// A service's subscriptions list by topic, and another service's are
    /// not among them.
    #[tokio::test]
    async fn a_services_subscriptions_are_listed_by_topic() {
        let fx = fixture().await;
        let audit = a_consumer(&fx.db, &fx.tenant, "audit").await;
        fx.save_all(&[
            &fx.of("payments.settled"),
            &fx.of("orders.created"),
            &subscription(subscription_row("orders.created", audit)),
        ])
        .await;
        let by_topic = SortOrder::single(Sort::ascending(SubscriptionSortField::TopicName));
        let by_status = SortOrder::single(Sort::ascending(SubscriptionSortField::Status));

        let listed = fx
            .store
            .list_by_service(&fx.tenant, &fx.billing, &by_topic, &first(10))
            .await
            .unwrap();
        let statuses = fx
            .store
            .list_by_service(&fx.tenant, &fx.billing, &by_status, &first(10))
            .await
            .unwrap();

        assert_eq!(topics(&listed), ["orders.created", "payments.settled"]);
        assert_eq!(statuses.items.len(), 2);
    }

    /// Deleting the saved orders reader makes the tenant lookup return no row.
    #[tokio::test]
    async fn a_deleted_subscription_is_gone() {
        let fx = fixture().await;
        let pulled = fx.of("orders.created");
        fx.save_all(&[&pulled]).await;

        fx.store.delete(&fx.tenant, pulled.id()).await.unwrap();

        assert!(fx.found(pulled.id()).await.is_none());
    }

    /// Saving a subscription with an unknown topic or consumer returns an
    /// infrastructure error; the subscription to the unknown topic is
    /// absent from lookup.
    #[tokio::test]
    async fn a_subscription_to_nothing_is_refused() {
        let fx = fixture().await;
        let to_no_topic = fx.of("orders.lost");
        let for_no_service = subscription(subscription_row("orders.created", ConsumerId::new()));

        let no_topic = fx.store.save(&fx.tenant, &to_no_topic).await;
        let no_service = fx.store.save(&fx.tenant, &for_no_service).await;

        assert!(matches!(no_topic, Err(DomainError::Infrastructure(_))));
        assert!(matches!(no_service, Err(DomainError::Infrastructure(_))));
        assert!(fx.found(to_no_topic.id()).await.is_none());
    }

    /// A tenant with a database of its own keeps its subscriptions there,
    /// beside its topics and services.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_subscriptions_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        a_topic(&fx.db, &apart, "orders.created").await;
        let service = a_consumer(&fx.db, &apart, "billing").await;
        let pulled = subscription(subscription_row("orders.created", service));

        fx.store.save(&apart, &pulled).await.unwrap();

        let there = PgSubscriptionStore::new(Arc::clone(&own.databases));
        assert!(
            there
                .find_by_id(&apart, pulled.id())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A subscription whose stored consumer group contains spaces fails
    /// to load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_subscription_is_refused() {
        let fx = fixture().await;
        let pulled = fx.of("orders.created");
        fx.save_all(&[&pulled]).await;
        fx.db
            .tamper("UPDATE topic_subscriptions SET consumer_group = 'two words'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, pulled.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
