//! A tenant's topics, each row under row-level security.
//!
//! One name is one topic of the tenant, so a service publishing to a name
//! never has to pick between two. A list first reads the ids of its page,
//! then reads those rows by id, as every read of a topic does.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::messaging::{TopicSortField, TopicStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TenantId, TopicId};
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use uuid::Uuid;

use self::record::{TopicColumns, TopicRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a topic name to one topic of a tenant.
const NAME_KEY: &str = "topics_name_key";

/// The Postgres topic store.
pub struct PgTopicStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgTopicStore {}

impl PgTopicStore {
    /// A store keeping topics in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Writes `topic` for `tenant`, or finds its name taken by another
    /// topic of the tenant.
    async fn write(
        &self,
        tenant: &ScopedTenant,
        topic: &Topic<ResolvedTenant>,
    ) -> Result<Uniqueness, DomainError> {
        let columns = TopicColumns::of(topic)?;
        scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let attempt = write_columns(connection, tenant, &columns).await;
                unique_on(attempt, NAME_KEY)
            },
        )
        .await
    }
}

/// Writes the topic and its creator identity through the tenant-scoped connection.
async fn write_columns(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    columns: &TopicColumns<'_>,
) -> Result<PgQueryResult, sqlx::Error> {
    let maker = &columns.created_by;
    sqlx::query_file!(
        "queries/topics/save.sql",
        columns.id,
        tenant.as_uuid(),
        columns.name,
        columns.topic_name,
        columns.description,
        columns.schema_definition,
        columns.retention_kind,
        columns.retention_amount,
        columns.status,
        maker.kind,
        maker.id,
        maker.person,
        columns.data_class,
        columns.created_at,
        columns.updated_at,
    )
    .execute(connection)
    .await
}

/// The records of the topics of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<TopicRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        TopicRecord,
        "queries/topics/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt(record: Option<TopicRecord>) -> Result<Option<Topic<ResolvedTenant>>, DomainError> {
    record.map(TopicRecord::into_topic).transpose()
}

impl SortColumns for TopicSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
            Self::TopicName => "topic_name",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl TopicStore for PgTopicStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &TopicId,
    ) -> Result<Option<Topic<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        rebuilt(records.into_iter().next())
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &TopicName,
    ) -> Result<Option<Topic<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TopicRecord,
                    "queries/topics/by_name.sql",
                    tenant_id.as_uuid(),
                    name.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<TopicSortField>,
        page: &PageRequest,
    ) -> Result<Page<Topic<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed = PageQuery::ids("id", "topics").filter("tenant_id = ?", *tenant_id.as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, tenant_id, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        let topics = records
            .into_iter()
            .map(TopicRecord::into_topic)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(topics))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        topic: &Topic<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        match self.write(tenant_id, topic).await? {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-topic-of-the-tenant-has",
                "another topic of the tenant has this name"
            ))),
        }
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &TopicId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/topics/delete.sql",
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
    use std::num::{NonZeroU32, NonZeroU64};

    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::messaging::SubscriptionStore;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::messaging::control::CreatedBy;
    use ianua_domain::domains::messaging::schema::SchemaDefinition;
    use ianua_domain::domains::messaging::subscription::Subscription;
    use ianua_domain::domains::messaging::topic::{RetentionPolicy, TopicRow, TopicStatus};
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{ConsumerId, Label, Setting};

    use super::*;
    use crate::postgres::messaging::PgSubscriptionStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::messaging::{
        ORDER_SCHEMA, a_consumer, subscription_row, topic_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgTopicStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep topics
    /// for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgTopicStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn topic(row: TopicRow) -> Topic<ResolvedTenant> {
        Topic::reconstitute(row).unwrap()
    }

    fn named(topic_name: &str) -> Topic<ResolvedTenant> {
        topic(topic_row(topic_name))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn names(page: &Page<Topic<ResolvedTenant>>) -> Vec<&str> {
        page.items
            .iter()
            .map(|topic| topic.topic_name().as_str())
            .collect()
    }

    impl Fixture {
        async fn save_all(&self, topics: &[&Topic<ResolvedTenant>]) {
            for topic in topics {
                self.store.save(&self.tenant, topic).await.unwrap();
            }
        }

        async fn found(&self, id: &TopicId) -> Option<Topic<ResolvedTenant>> {
            self.store.find_by_id(&self.tenant, id).await.unwrap()
        }

        /// Reads a page for the fixture tenant using the requested ordering and cursor.
        async fn page(
            &self,
            order: &SortOrder<TopicSortField>,
            request: &PageRequest,
        ) -> Page<Topic<ResolvedTenant>> {
            self.store
                .list_all(&self.tenant, order, request)
                .await
                .unwrap()
        }
    }

    /// A topic with a schema, a description, a retention of a day and a
    /// consumer as its maker is found by its id as it was saved.
    #[tokio::test]
    async fn a_saved_topic_is_found_by_its_id() {
        let fx = fixture().await;
        let orders = topic(TopicRow {
            description: Some(Label::new("description", "Every order placed").unwrap()),
            schema: Setting::Set(SchemaDefinition::new(ORDER_SCHEMA).unwrap()),
            retention: RetentionPolicy::Duration(NonZeroU32::new(86_400).unwrap()),
            created_by: CreatedBy::Consumer(ConsumerId::new()),
            data_class: DataClassLevel::Confidential,
            ..topic_row("orders.created")
        });
        fx.save_all(&[&orders]).await;

        let found = fx.found(orders.id()).await.unwrap();

        assert_eq!(found.name(), orders.name());
        assert_eq!(found.topic_name(), orders.topic_name());
        assert_eq!(found.description(), orders.description());
        assert_eq!(found.schema(), orders.schema());
        assert_eq!(found.retention(), orders.retention());
        assert_eq!(found.status(), orders.status());
        assert_eq!(found.created_by(), orders.created_by());
        assert_eq!(found.data_class(), orders.data_class());
        assert_eq!(found.created_at(), orders.created_at());
    }

    /// A person's topic keeping its last thousand messages reads back with
    /// the person behind the account and the count.
    #[tokio::test]
    async fn a_topic_made_by_a_person_keeps_who_they_are() {
        let fx = fixture().await;
        let counted = topic(TopicRow {
            retention: RetentionPolicy::MessageCount(NonZeroU64::new(1000).unwrap()),
            ..topic_row("payments.settled")
        });
        fx.save_all(&[&counted]).await;

        let found = fx.found(counted.id()).await.unwrap();

        assert_eq!(found.created_by(), counted.created_by());
        assert_eq!(found.retention(), counted.retention());
    }

    /// A topic is found by the name services publish to; a name nobody
    /// uses finds nothing.
    #[tokio::test]
    async fn a_topic_is_found_by_its_name() {
        let fx = fixture().await;
        let orders = named("orders.created");
        fx.save_all(&[&orders]).await;

        let by_name = fx
            .store
            .find_by_name(&fx.tenant, &TopicName::new("orders.created").unwrap())
            .await
            .unwrap()
            .unwrap();
        let unknown = fx
            .store
            .find_by_name(&fx.tenant, &TopicName::new("orders.lost").unwrap())
            .await
            .unwrap();

        assert_eq!(by_name.id(), orders.id());
        assert!(unknown.is_none());
    }

    /// An id nobody has finds nothing, and another tenant finds neither by
    /// id nor by name this tenant's topic.
    #[tokio::test]
    async fn a_topic_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let orders = named("orders.created");
        fx.save_all(&[&orders]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let unknown = fx.found(&TopicId::new()).await;
        let by_id = fx.store.find_by_id(&other, orders.id()).await.unwrap();
        let by_name = fx
            .store
            .find_by_name(&other, orders.topic_name())
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(by_id.is_none());
        assert!(by_name.is_none());
    }

    /// Saving another `orders.created` topic in the same tenant returns a
    /// conflict, while another tenant can save that name.
    #[tokio::test]
    async fn a_name_another_topic_has_is_refused() {
        let fx = fixture().await;
        fx.save_all(&[&named("orders.created")]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let second = fx.store.save(&fx.tenant, &named("orders.created")).await;
        let elsewhere = fx.store.save(&other, &named("orders.created")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
        assert!(elsewhere.is_ok());
    }

    /// The topic is paused and renamed: saving it again keeps the new
    /// values and the time it was made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let orders = named("orders.created");
        fx.save_all(&[&orders]).await;
        let changed = topic(TopicRow {
            id: *orders.id(),
            name: Label::new("name", "Orders").unwrap(),
            status: TopicStatus::Paused,
            updated_at: at(5),
            ..topic_row("orders.created")
        });

        fx.save_all(&[&changed]).await;

        let found = fx.found(orders.id()).await.unwrap();
        assert_eq!(found.name().as_str(), "Orders");
        assert_eq!(found.status(), TopicStatus::Paused);
        assert_eq!(found.updated_at(), at(5));
        assert_eq!(found.created_at(), orders.created_at());
    }

    /// The tenant's topics list by name page by page, each page after the
    /// last, and by status with the active ones first; another tenant's
    /// topic is on no page.
    #[tokio::test]
    async fn topics_are_listed_page_by_page() {
        let fx = fixture().await;
        let archived = topic(TopicRow {
            status: TopicStatus::Archived,
            ..topic_row("a.old")
        });
        fx.save_all(&[&named("c.new"), &archived, &named("b.new")])
            .await;
        fx.store
            .save(
                &ScopedTenant::for_background(TenantId::new()),
                &named("a.theirs"),
            )
            .await
            .unwrap();
        let by_name = SortOrder::single(Sort::ascending(TopicSortField::TopicName));
        let by_status = SortOrder::single(Sort::ascending(TopicSortField::Status));

        let page_one = fx.page(&by_name, &first(2)).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.page(&by_name, &after).await;
        let statuses = fx.page(&by_status, &first(10)).await;

        assert_eq!(names(&page_one), ["a.old", "b.new"]);
        assert_eq!(names(&page_two), ["c.new"]);
        assert!(!page_two.has_next());
        assert_eq!(names(&statuses).last(), Some(&"a.old"));
    }

    /// A deleted topic is gone, with every subscription to it, and its
    /// name is free for another.
    #[tokio::test]
    async fn a_deleted_topic_takes_its_subscriptions() {
        let fx = fixture().await;
        let orders = named("orders.created");
        fx.save_all(&[&orders]).await;
        let billing = a_consumer(&fx.db, &fx.tenant, "billing").await;
        let subscriptions = PgSubscriptionStore::new(Arc::clone(&fx.db.databases));
        let subscription =
            Subscription::reconstitute(subscription_row("orders.created", billing)).unwrap();
        subscriptions.save(&fx.tenant, &subscription).await.unwrap();

        fx.store.delete(&fx.tenant, orders.id()).await.unwrap();

        assert!(fx.found(orders.id()).await.is_none());
        assert!(
            subscriptions
                .find_by_id(&fx.tenant, subscription.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fx.store
                .save(&fx.tenant, &named("orders.created"))
                .await
                .is_ok()
        );
    }

    /// A tenant with a database of its own keeps its topics there, and the
    /// platform database does not hold them.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_topics_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let orders = named("orders.created");

        fx.store.save(&apart, &orders).await.unwrap();

        let there = PgTopicStore::new(Arc::clone(&own.databases));
        assert!(
            there
                .find_by_id(&apart, orders.id())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            fx.store
                .find_by_id(&apart, orders.id())
                .await
                .unwrap()
                .is_some()
        );
        fx.db.databases.deregister(&apart);
        assert!(
            fx.store
                .find_by_id(&apart, orders.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A topic with the invalid stored name `Orders..Created` fails to
    /// load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_topic_is_refused() {
        let fx = fixture().await;
        let orders = named("orders.created");
        fx.save_all(&[&orders]).await;
        fx.db
            .tamper("UPDATE topics SET topic_name = 'Orders..Created'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, orders.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
