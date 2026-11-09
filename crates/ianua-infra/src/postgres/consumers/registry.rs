//! A tenant's consumers, each table row under row-level security.
//!
//! A consumer signs in with one credential, and for a short while after a
//! rotation with the one it replaced. Each is kept in the columns of its
//! kind, and the database derives from them what a gateway finds the
//! consumer by. One credential in use names one consumer of the tenant, so
//! a sign-in never has to pick between two; a replaced one is found only
//! when no consumer uses it now. A list first reads the ids of its page,
//! then reads those rows by id, as every read of a consumer does.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::consumers::{ConsumerSortField, ConsumerStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CertificateFingerprint, ConsumerId, FederatedSubject, Issuer, KeyPrefix, TenantId,
};
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use uuid::Uuid;

use self::record::{ConsumerColumns, ConsumerRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a credential in use to one consumer of a
/// tenant.
const CREDENTIAL_KEY: &str = "consumers_credential_key";

/// The Postgres consumer store.
pub struct PgConsumerStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgConsumerStore {}

impl PgConsumerStore {
    /// A store keeping consumers in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Writes `consumer` for `tenant`, or finds its credential in use by
    /// another consumer.
    async fn write(
        &self,
        tenant: &ScopedTenant,
        consumer: &Consumer<ResolvedTenant>,
    ) -> Result<Uniqueness, DomainError> {
        let columns = ConsumerColumns::of(consumer)?;
        scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let attempt = write_columns(connection, tenant, &columns).await;
                unique_on(attempt, CREDENTIAL_KEY)
            },
        )
        .await
    }
}

/// Writes both credential generations and the consumer's metadata in one checked statement.
/// The checked query's explicit bind list alone exceeds the function-length limit.
#[allow(clippy::too_many_lines)]
async fn write_columns(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    columns: &ConsumerColumns<'_>,
) -> Result<PgQueryResult, sqlx::Error> {
    let (current, previous) = (&columns.current, &columns.previous);
    sqlx::query_file!(
        "queries/consumers/save.sql",
        columns.id,
        tenant.as_uuid(),
        columns.name,
        columns.description,
        current.kind,
        current.key_prefix,
        current.key_hash,
        current.cert_fingerprint.as_deref(),
        current.jwt_issuer,
        current.jwt_subject,
        current.jwks_uri,
        current.expires_at,
        previous.kind,
        previous.key_prefix,
        previous.key_hash,
        previous.cert_fingerprint.as_deref(),
        previous.jwt_issuer,
        previous.jwt_subject,
        previous.jwks_uri,
        previous.expires_at,
        columns.previous_until,
        columns.quota_requests,
        columns.quota_period,
        columns.status,
        columns.clearance,
        columns.created_by,
        columns.created_at,
        columns.updated_at,
    )
    .execute(connection)
    .await
}

/// The records of the consumers of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<ConsumerRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        ConsumerRecord,
        "queries/consumers/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt(
    record: Option<ConsumerRecord>,
) -> Result<Option<Consumer<ResolvedTenant>>, DomainError> {
    record.map(ConsumerRecord::into_consumer).transpose()
}

impl SortColumns for ConsumerSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl ConsumerStore for PgConsumerStore {
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[ConsumerId],
    ) -> Result<Vec<Consumer<ResolvedTenant>>, DomainError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        records
            .into_iter()
            .map(ConsumerRecord::into_consumer)
            .collect()
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ConsumerId,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        rebuilt(records.into_iter().next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<ConsumerSortField>,
        page: &PageRequest,
    ) -> Result<Page<Consumer<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed =
            PageQuery::ids("id", "consumers").filter("tenant_id = ?", *tenant_id.as_uuid());
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
        let consumers = records
            .into_iter()
            .map(ConsumerRecord::into_consumer)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(consumers))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        consumer: &Consumer<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        match self.write(tenant_id, consumer).await? {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-consumer-of-the-tenant-signs",
                "another consumer of the tenant signs in with this credential"
            ))),
        }
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &ConsumerId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/consumers/delete.sql",
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

    async fn find_by_key_prefix(
        &self,
        tenant_id: &ScopedTenant,
        key_prefix: &KeyPrefix,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ConsumerRecord,
                    "queries/consumers/by_key_prefix.sql",
                    tenant_id.as_uuid(),
                    key_prefix.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn find_by_cert_fingerprint(
        &self,
        tenant_id: &ScopedTenant,
        fingerprint: &CertificateFingerprint,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError> {
        let written = fingerprint.to_string();
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ConsumerRecord,
                    "queries/consumers/by_fingerprint.sql",
                    tenant_id.as_uuid(),
                    written
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }

    async fn find_by_jwt_issuer_subject(
        &self,
        tenant_id: &ScopedTenant,
        issuer: &Issuer,
        subject: &FederatedSubject,
    ) -> Result<Option<Consumer<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ConsumerRecord,
                    "queries/consumers/by_subject.sql",
                    tenant_id.as_uuid(),
                    issuer.as_str(),
                    subject.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt(record)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_domain::domains::consumers::consumer::{ConsumerRow, ConsumerStatus};
    use ianua_domain::domains::consumers::credentials::{HeldCredential, PreviousCredential};
    use ianua_domain::domains::consumers::quota::{ConsumerQuota, QuotaPeriod, RequestAllowance};
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{ActorRef, Expiry, Label};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::consumers::{
        api_key, client_cert, consumer_row, jwt_bearer, rotated_consumer_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgConsumerStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep consumers
    /// for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgConsumerStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn consumer(row: ConsumerRow) -> Consumer<ResolvedTenant> {
        Consumer::reconstitute(row).unwrap()
    }

    fn named(name: &str) -> Consumer<ResolvedTenant> {
        consumer(consumer_row(name))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn names(page: &Page<Consumer<ResolvedTenant>>) -> Vec<&str> {
        page.items
            .iter()
            .map(|consumer| consumer.name().as_str())
            .collect()
    }

    fn prefix(text: &str) -> KeyPrefix {
        KeyPrefix::new(text).unwrap()
    }

    impl Fixture {
        async fn save_all(&self, consumers: &[&Consumer<ResolvedTenant>]) {
            for consumer in consumers {
                self.store.save(&self.tenant, consumer).await.unwrap();
            }
        }

        async fn by_key(&self, text: &str) -> Option<Consumer<ResolvedTenant>> {
            self.store
                .find_by_key_prefix(&self.tenant, &prefix(text))
                .await
                .unwrap()
        }

        /// Looks up this tenant's consumer using a token issuer and subject.
        async fn by_subject(
            &self,
            issuer: &Issuer,
            subject: &str,
        ) -> Option<Consumer<ResolvedTenant>> {
            self.store
                .find_by_jwt_issuer_subject(
                    &self.tenant,
                    issuer,
                    &FederatedSubject::new(subject).unwrap(),
                )
                .await
                .unwrap()
        }

        /// Requires a batch lookup to expose no consumers to the named tenant.
        async fn assert_no_consumers(&self, tenant: &ScopedTenant, ids: &[ConsumerId]) {
            assert!(
                self.store
                    .find_by_ids(tenant, ids)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }

    /// A partner rotated onto a client certificate, with a description and
    /// a daily quota, is found by its id as it was saved, its old key kept
    /// working for its overlap.
    #[tokio::test]
    async fn a_saved_consumer_is_found_by_its_id() {
        let fx = fixture().await;
        let partner = consumer(ConsumerRow {
            description: Some(Label::new("description", "Nightly billing sync").unwrap()),
            quota: ConsumerQuota::Limited(RequestAllowance::new(10_000, QuotaPeriod::Day).unwrap()),
            ..rotated_consumer_row("partner", client_cert(7))
        });
        fx.save_all(&[&partner]).await;

        let found = fx
            .store
            .find_by_id(&fx.tenant, partner.id())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found.name(), partner.name());
        assert_eq!(found.description(), partner.description());
        assert_eq!(found.credentials(), partner.credentials());
        assert_eq!(found.quota(), partner.quota());
        assert_eq!(found.clearance(), partner.clearance());
        assert!(
            matches!((found.created_by(), partner.created_by()), (ActorRef::User(kept), ActorRef::User(saved)) if kept == saved)
        );
        assert_eq!(found.updated_at(), at(10));
        assert!(matches!(
            found.credentials().previous(),
            PreviousCredential::Overlapping { .. }
        ));
    }

    /// An id nobody has finds nothing, and another tenant does not find
    /// this tenant's consumer by id or by its key.
    #[tokio::test]
    async fn a_consumer_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let billing = named("billing");
        fx.save_all(&[&billing]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let unknown = fx
            .store
            .find_by_id(&fx.tenant, &ConsumerId::new())
            .await
            .unwrap();
        let by_id = fx.store.find_by_id(&other, billing.id()).await.unwrap();
        let by_key = fx
            .store
            .find_by_key_prefix(&other, &prefix("billing_key"))
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(by_id.is_none());
        assert!(by_key.is_none());
    }

    /// A batch keeps only requested consumers belonging to its tenant,
    /// returning a repeated id once and omitting missing or foreign ids.
    #[tokio::test]
    async fn consumer_batches_keep_the_tenant_boundary() {
        let fx = fixture().await;
        let billing = named("billing");
        let omitted = named("omitted");
        fx.save_all(&[&billing, &omitted]).await;
        let other = ScopedTenant::for_background(TenantId::new());
        let foreign = named("foreign");
        fx.store.save(&other, &foreign).await.unwrap();

        let found = fx
            .store
            .find_by_ids(
                &fx.tenant,
                &[
                    *billing.id(),
                    *foreign.id(),
                    ConsumerId::new(),
                    *billing.id(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), billing.id());
        assert_eq!(found[0].credentials(), billing.credentials());
        fx.assert_no_consumers(&fx.tenant, &[]).await;
        fx.assert_no_consumers(&other, &[*billing.id()]).await;
    }

    /// A consumer is found by the key it uses now, and during its overlap by
    /// the key it replaced; a key nobody holds finds nothing.
    #[tokio::test]
    async fn a_consumer_is_found_by_its_key_and_by_the_key_it_replaced() {
        let fx = fixture().await;
        let rotated = consumer(rotated_consumer_row("partner", api_key("partner_new")));
        fx.save_all(&[&rotated]).await;

        let by_new = fx.by_key("partner_new").await.unwrap();
        let by_old = fx.by_key("partner_key").await.unwrap();

        assert_eq!(by_new.id(), rotated.id());
        assert_eq!(by_old.id(), rotated.id());
        assert!(fx.by_key("nobody_key").await.is_none());
    }

    /// A consumer is found by its certificate's fingerprint, and another by
    /// the issuer and subject of its tokens; another subject finds nothing.
    #[tokio::test]
    async fn a_consumer_is_found_by_its_certificate_and_by_its_tokens() {
        let fx = fixture().await;
        let mtls = consumer(ConsumerRow {
            credential: HeldCredential::new(client_cert(3), Expiry::Never),
            ..consumer_row("mtls")
        });
        let tokens = consumer(rotated_consumer_row("tokens", jwt_bearer("svc-42")));
        fx.save_all(&[&mtls, &tokens]).await;
        let issuer = Issuer::new("https://partner.example").unwrap();

        let by_cert = fx
            .store
            .find_by_cert_fingerprint(&fx.tenant, &CertificateFingerprint::from_digest([3; 32]))
            .await
            .unwrap()
            .unwrap();
        let by_token = fx.by_subject(&issuer, "svc-42").await.unwrap();
        let other_subject = fx.by_subject(&issuer, "svc-43").await;

        assert_eq!(by_cert.id(), mtls.id());
        assert_eq!(by_token.id(), tokens.id());
        assert!(other_subject.is_none());
    }

    /// A key one consumer still accepts from before its rotation, and
    /// another uses now, finds the one using it now.
    #[tokio::test]
    async fn the_consumer_using_a_key_now_is_found_before_one_that_replaced_it() {
        let fx = fixture().await;
        let moved = consumer(rotated_consumer_row("old", client_cert(9)));
        let taker = consumer(ConsumerRow {
            credential: HeldCredential::new(api_key("old_key"), Expiry::Never),
            ..consumer_row("taker")
        });
        fx.save_all(&[&moved, &taker]).await;

        let found = fx.by_key("old_key").await.unwrap();

        assert_eq!(found.id(), taker.id());
    }

    /// Saving another consumer with billing's current API key returns a
    /// conflict.
    #[tokio::test]
    async fn a_credential_another_consumer_uses_is_refused() {
        let fx = fixture().await;
        fx.save_all(&[&named("billing")]).await;
        let copy = consumer(ConsumerRow {
            name: Label::new("name", "copy").unwrap(),
            ..consumer_row("billing")
        });

        let second = fx.store.save(&fx.tenant, &copy).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// The tenant's consumers list by name page by page, each page after the
    /// last, and by status with the active ones first.
    #[tokio::test]
    async fn consumers_are_listed_page_by_page() {
        let fx = fixture().await;
        let off = consumer(ConsumerRow {
            status: ConsumerStatus::Disabled,
            ..consumer_row("a-off")
        });
        fx.save_all(&[&named("c-sync"), &off, &named("b-sync")])
            .await;
        let by_name = SortOrder::single(Sort::ascending(ConsumerSortField::Name));
        let by_status = SortOrder::single(Sort::ascending(ConsumerSortField::Status));

        let page_one = fx
            .store
            .list_all(&fx.tenant, &by_name, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx
            .store
            .list_all(&fx.tenant, &by_name, &after)
            .await
            .unwrap();
        let statuses = fx
            .store
            .list_all(&fx.tenant, &by_status, &first(10))
            .await
            .unwrap();

        assert_eq!(names(&page_one), ["a-off", "b-sync"]);
        assert_eq!(names(&page_two), ["c-sync"]);
        assert!(!page_two.has_next());
        assert_eq!(names(&statuses)[2], "a-off");
    }

    /// The consumer is renamed and disabled: saving it again keeps the new
    /// values and the time it was made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let billing = named("billing");
        fx.save_all(&[&billing]).await;
        let changed = consumer(ConsumerRow {
            id: *billing.id(),
            name: Label::new("name", "invoices").unwrap(),
            status: ConsumerStatus::Disabled,
            updated_at: at(5),
            ..consumer_row("billing")
        });

        fx.save_all(&[&changed]).await;

        let found = fx
            .store
            .find_by_id(&fx.tenant, billing.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name().as_str(), "invoices");
        assert_eq!(found.status(), ConsumerStatus::Disabled);
        assert_eq!(found.created_at(), billing.created_at());
        assert!(
            matches!((found.created_by(), billing.created_by()), (ActorRef::User(kept), ActorRef::User(saved)) if kept == saved)
        );
    }

    /// A deleted consumer is gone, and its key is free for another.
    #[tokio::test]
    async fn a_deleted_consumer_is_gone() {
        let fx = fixture().await;
        let billing = named("billing");
        fx.save_all(&[&billing]).await;

        fx.store.delete(&fx.tenant, billing.id()).await.unwrap();

        assert!(
            fx.store
                .find_by_id(&fx.tenant, billing.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(fx.store.save(&fx.tenant, &named("billing")).await.is_ok());
    }

    /// A consumer with an empty stored name fails to load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_consumer_is_refused() {
        let fx = fixture().await;
        let billing = named("billing");
        fx.save_all(&[&billing]).await;
        fx.db.tamper("UPDATE consumers SET name = ''").await;

        let read = fx.store.find_by_id(&fx.tenant, billing.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
