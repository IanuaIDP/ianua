//! A tenant's webhook subscriptions, with the body of every message sent
//! to each and every try at sending one, each table under row-level
//! security.
//!
//! The signing secrets are kept as the sealer handed them over, never in
//! clear. A try that counts on the failure streak is kept and counted in
//! one statement, from the row as it stands when locked, so two tries at
//! once both count and an edit made meanwhile is kept. A webhook's
//! messages and tries go with it. A list first reads the ids of its page,
//! then reads those rows by id.

mod history;
mod record;
mod streak;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::webhooks::{
    DeliveryAttemptSortField, RecordedDelivery, WebhookMessage, WebhookStore,
    WebhookSubscriptionSortField,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::webhooks::delivery::DeliveryAttempt;
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    EventType, FailureLimit, FailureOutcome, TenantId, WebhookDeliveryId, WebhookMessageId,
    WebhookSubscriptionId,
};
use sqlx::PgConnection;
use uuid::Uuid;

use self::history::{DeliveryColumns, DeliveryRecord, MessageRecord};
use self::record::{WebhookColumns, WebhookRecord};
use self::streak::{Counting, change_of, count};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The Postgres webhook store.
pub struct PgWebhookStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgWebhookStore {}

impl PgWebhookStore {
    /// A store keeping webhooks and their history in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Counts `attempt` on its webhook of `tenant` and keeps it, answering
    /// the webhook as it stands then and what the try did to its streak,
    /// or nothing when the webhook is gone.
    async fn counted(
        &self,
        tenant: &ScopedTenant,
        attempt: &DeliveryAttempt,
        disable_after: FailureLimit,
    ) -> Result<Option<(WebhookRecord, FailureOutcome)>, DomainError> {
        let counting = Counting {
            columns: DeliveryColumns::of(attempt),
            now: clock::now(),
            limit: i64::from(disable_after.get()),
        };
        scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let Some((id, outcome)) = count(&mut *connection, tenant, &counting).await? else {
                    return Ok(None);
                };
                let records = records_of(connection, tenant, &[id]).await?;
                Ok(records.into_iter().next().map(|record| (record, outcome)))
            },
        )
        .await
    }
}

/// The records of the webhooks of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<WebhookRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        WebhookRecord,
        "queries/webhook_subscriptions/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt_all(
    records: Vec<WebhookRecord>,
) -> Result<Vec<WebhookSubscription<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(WebhookRecord::into_webhook)
        .collect()
}

impl SortColumns for WebhookSubscriptionSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Status => "status",
            Self::Url => "url",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

impl SortColumns for DeliveryAttemptSortField {
    fn column(self) -> &'static str {
        match self {
            Self::AttemptedAt => "attempted_at",
            Self::Status => "status",
            Self::AttemptNumber => "attempt_number",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl WebhookStore for PgWebhookStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &WebhookSubscriptionId,
    ) -> Result<Option<WebhookSubscription<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<WebhookSubscriptionStatus>,
        sort: &SortOrder<WebhookSubscriptionSortField>,
        page: &PageRequest,
    ) -> Result<Page<WebhookSubscription<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let of_tenant = PageQuery::ids("id", "webhook_subscriptions")
            .filter("tenant_id = ?", *tenant_id.as_uuid());
        let listed = match status {
            Some(status) => of_tenant.filter("status = ?", status.word()),
            None => of_tenant,
        };
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
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn list_receiving(
        &self,
        tenant_id: &ScopedTenant,
        event_type: EventType,
    ) -> Result<Vec<WebhookSubscription<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    WebhookRecord,
                    "queries/webhook_subscriptions/receiving.sql",
                    tenant_id.as_uuid(),
                    event_type.as_str()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        subscription: &WebhookSubscription<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = WebhookColumns::of(subscription);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/webhook_subscriptions/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.url,
                    columns.signing_secret_sealed,
                    columns.previous_secret_sealed,
                    columns.previous_secret_until,
                    &columns.event_types,
                    columns.status,
                    columns.description,
                    columns.retry,
                    columns.created_by_kind,
                    columns.created_by_id,
                    columns.consecutive_failures,
                    columns.last_delivered_at,
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

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &WebhookSubscriptionId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/webhook_subscriptions/delete.sql",
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

    async fn list_delivery_attempts(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
        sort: &SortOrder<DeliveryAttemptSortField>,
        page: &PageRequest,
    ) -> Result<Page<DeliveryAttempt>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed = PageQuery::ids("id", "webhook_deliveries")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .filter("subscription_id = ?", *subscription_id.as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = sqlx::query_file_as!(
                    DeliveryRecord,
                    "queries/webhook_deliveries/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        let attempts = records
            .into_iter()
            .map(DeliveryRecord::into_attempt)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(attempts))
    }

    async fn record_delivery(
        &self,
        tenant_id: &ScopedTenant,
        attempt: &DeliveryAttempt,
        disable_after: FailureLimit,
    ) -> Result<Option<RecordedDelivery>, DomainError> {
        let Some((record, failure)) = self.counted(tenant_id, attempt, disable_after).await? else {
            return Ok(None);
        };
        Ok(Some(RecordedDelivery {
            subscription: record.into_webhook()?,
            change: change_of(attempt, failure),
        }))
    }

    async fn keep_uncounted_attempt(
        &self,
        tenant_id: &ScopedTenant,
        attempt: &DeliveryAttempt,
    ) -> Result<(), DomainError> {
        let columns = DeliveryColumns::of(attempt);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/webhook_deliveries/keep.sql",
                    tenant_id.as_uuid(),
                    columns.subscription_id,
                    columns.id,
                    columns.message_id,
                    columns.event_type,
                    columns.status,
                    columns.response_code,
                    columns.duration_ms,
                    columns.attempt_number,
                    columns.attempted_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn find_delivery_attempt(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
        id: &WebhookDeliveryId,
    ) -> Result<Option<DeliveryAttempt>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DeliveryRecord,
                    "queries/webhook_deliveries/find.sql",
                    tenant_id.as_uuid(),
                    subscription_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(DeliveryRecord::into_attempt).transpose()
    }

    async fn keep_message(
        &self,
        tenant_id: &ScopedTenant,
        message: &WebhookMessage,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/webhook_messages/keep.sql",
                    tenant_id.as_uuid(),
                    message.subscription_id.as_uuid(),
                    message.id.as_uuid(),
                    message.event_type.as_str(),
                    &message.payload
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn find_message(
        &self,
        tenant_id: &ScopedTenant,
        subscription_id: &WebhookSubscriptionId,
        id: &WebhookMessageId,
    ) -> Result<Option<WebhookMessage>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    MessageRecord,
                    "queries/webhook_messages/find.sql",
                    tenant_id.as_uuid(),
                    subscription_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(MessageRecord::into_message).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::webhooks::StreakChange;
    use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
    use ianua_domain::domains::webhooks::subscription::WebhookSubscriptionRow;
    use ianua_domain::types::event_type::IdentityEvent;
    use ianua_domain::types::{AgentId, PreviousSigningSecret, PrincipalRef, Text};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::branding::sealed;
    use crate::test_support::rows::webhooks::{attempt_of, message_to, webhook_row};

    struct Fixture {
        db: TestDb,
        store: PgWebhookStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep webhooks
    /// for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgWebhookStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn webhook(row: WebhookSubscriptionRow) -> WebhookSubscription<ResolvedTenant> {
        WebhookSubscription::reconstitute(row).unwrap()
    }

    fn at_url(url: &str) -> WebhookSubscription<ResolvedTenant> {
        webhook(webhook_row(url))
    }

    fn limit(count: u32) -> FailureLimit {
        FailureLimit::new(count).unwrap()
    }

    fn first(count: u32) -> PageRequest {
        PageRequest::first(Limit::new(count).unwrap())
    }

    fn urls(page: &Page<WebhookSubscription<ResolvedTenant>>) -> Vec<&str> {
        page.items
            .iter()
            .map(|webhook| webhook.url().as_str())
            .collect()
    }

    impl Fixture {
        async fn save_all(&self, webhooks: &[&WebhookSubscription<ResolvedTenant>]) {
            for webhook in webhooks {
                self.store.save(&self.tenant, webhook).await.unwrap();
            }
        }

        async fn found(
            &self,
            id: &WebhookSubscriptionId,
        ) -> Option<WebhookSubscription<ResolvedTenant>> {
            self.store.find_by_id(&self.tenant, id).await.unwrap()
        }

        /// A webhook saved at `url`, and a message kept for it.
        async fn with_message(
            &self,
            url: &str,
        ) -> (WebhookSubscription<ResolvedTenant>, WebhookMessage) {
            let saved = at_url(url);
            self.save_all(&[&saved]).await;
            let message = message_to(*saved.id());
            self.store
                .keep_message(&self.tenant, &message)
                .await
                .unwrap();
            (saved, message)
        }

        async fn record(
            &self,
            attempt: &DeliveryAttempt,
            disable_after: FailureLimit,
        ) -> Option<RecordedDelivery> {
            self.store
                .record_delivery(&self.tenant, attempt, disable_after)
                .await
                .unwrap()
        }

        async fn attempts(&self, id: &WebhookSubscriptionId) -> Vec<DeliveryAttempt> {
            let order = SortOrder::single(Sort::ascending(DeliveryAttemptSortField::AttemptNumber));
            self.store
                .list_delivery_attempts(&self.tenant, id, &order, &first(100))
                .await
                .unwrap()
                .items
        }

        /// Reads this tenant's webhook page with the requested status filter.
        async fn page(
            &self,
            status: Option<WebhookSubscriptionStatus>,
            order: &SortOrder<WebhookSubscriptionSortField>,
            page: &PageRequest,
        ) -> Page<WebhookSubscription<ResolvedTenant>> {
            self.store
                .list_all(&self.tenant, status, order, page)
                .await
                .unwrap()
        }
    }

    /// Checks the paused webhook's secrets, subscription settings and saved delivery state.
    fn assert_saved_webhook(
        found: &WebhookSubscription<ResolvedTenant>,
        saved: &WebhookSubscription<ResolvedTenant>,
    ) {
        assert_eq!(found.url(), saved.url());
        assert_eq!(found.signing_secret(), saved.signing_secret());
        assert_eq!(found.previous_secret(), saved.previous_secret());
        assert_eq!(found.event_types(), saved.event_types());
        assert_eq!(found.status(), WebhookSubscriptionStatus::Paused);
        assert_eq!(found.description(), saved.description());
        assert_eq!(found.retry(), RetryPreset::Patient);
        assert_eq!(found.created_by(), saved.created_by());
        assert_eq!(found.consecutive_failures(), 3);
        assert_eq!(found.last_delivered_at(), Some(at(4)));
        assert_eq!(found.created_at(), saved.created_at());
        assert_eq!(found.updated_at(), at(5));
    }

    /// A paused webhook an agent made, for two events, with a description,
    /// the patient retry policy and its old secret still signing, is found
    /// by its id as it was saved, every secret still sealed.
    #[tokio::test]
    async fn a_saved_webhook_is_found_by_its_id() {
        let fx = fixture().await;
        let saved = webhook(WebhookSubscriptionRow {
            previous_secret: PreviousSigningSecret::SignsUntil {
                secret: sealed("old-secret"),
                until: at(600),
            },
            event_types: vec![
                IdentityEvent::UserRegistered.into(),
                IdentityEvent::UserDeleted.into(),
            ],
            status: WebhookSubscriptionStatus::Paused,
            description: Some(Text::new("description", "Security alerting").unwrap()),
            retry: RetryPreset::Patient,
            created_by: PrincipalRef::Agent(AgentId::new()),
            consecutive_failures: 3,
            last_delivered_at: Some(at(4)),
            updated_at: at(5),
            ..webhook_row("https://hooks.acme.com/in")
        });
        fx.save_all(&[&saved]).await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_saved_webhook(&found, &saved);
    }

    /// An id nobody has finds nothing, and another tenant does not find
    /// this tenant's webhook.
    #[tokio::test]
    async fn a_webhook_is_found_only_by_its_tenant() {
        let fx = fixture().await;
        let saved = at_url("https://hooks.acme.com/in");
        fx.save_all(&[&saved]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(fx.found(&WebhookSubscriptionId::new()).await.is_none());
        assert!(
            fx.store
                .find_by_id(&other, saved.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The tenant's webhooks list by address page by page, each page after
    /// the last, and the paused ones alone when asked for.
    #[tokio::test]
    async fn webhooks_are_listed_page_by_page_and_by_status() {
        let fx = fixture().await;
        let paused = webhook(WebhookSubscriptionRow {
            status: WebhookSubscriptionStatus::Paused,
            ..webhook_row("https://b.acme.com/in")
        });
        fx.save_all(&[
            &at_url("https://c.acme.com/in"),
            &paused,
            &at_url("https://a.acme.com/in"),
        ])
        .await;
        let by_url = SortOrder::single(Sort::ascending(WebhookSubscriptionSortField::Url));
        let by_update = SortOrder::single(Sort::ascending(WebhookSubscriptionSortField::UpdatedAt));

        let page_one = fx.page(None, &by_url, &first(2)).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.page(None, &by_url, &after).await;
        let only_paused = fx
            .page(
                Some(WebhookSubscriptionStatus::Paused),
                &by_update,
                &first(10),
            )
            .await;

        assert_eq!(
            urls(&page_one),
            ["https://a.acme.com/in", "https://b.acme.com/in"]
        );
        assert_eq!(urls(&page_two), ["https://c.acme.com/in"]);
        assert!(!page_two.has_next());
        assert_eq!(urls(&only_paused), ["https://b.acme.com/in"]);
    }

    /// An event is sent to the active webhooks that list it, and to none
    /// paused or listing other events.
    #[tokio::test]
    async fn an_event_goes_to_the_active_webhooks_that_list_it() {
        let fx = fixture().await;
        let listening = at_url("https://a.acme.com/in");
        let paused = webhook(WebhookSubscriptionRow {
            status: WebhookSubscriptionStatus::Paused,
            ..webhook_row("https://b.acme.com/in")
        });
        let elsewhere = webhook(WebhookSubscriptionRow {
            event_types: vec![IdentityEvent::UserDeleted.into()],
            ..webhook_row("https://c.acme.com/in")
        });
        fx.save_all(&[&listening, &paused, &elsewhere]).await;

        let receiving = fx
            .store
            .list_receiving(&fx.tenant, IdentityEvent::UserRegistered.into())
            .await
            .unwrap();

        let ids: Vec<_> = receiving.iter().map(|webhook| *webhook.id()).collect();
        assert_eq!(ids, [*listening.id()]);
    }

    /// A success ends the streak and is the last delivery; the try is kept.
    #[tokio::test]
    async fn a_success_ends_the_streak() {
        let fx = fixture().await;
        let (_, message) = fx.with_message("https://hooks.acme.com/in").await;
        let _clock = clock::freeze(at(100));
        fx.record(&attempt_of(&message, 0, 50, 500), limit(10))
            .await;

        let recorded = fx
            .record(&attempt_of(&message, 1, 60, 200), limit(10))
            .await
            .unwrap();

        assert_eq!(recorded.change, StreakChange::Delivered);
        assert_eq!(recorded.subscription.consecutive_failures(), 0);
        assert_eq!(recorded.subscription.last_delivered_at(), Some(at(100)));
        assert_eq!(recorded.subscription.updated_at(), at(100));
        assert_eq!(fx.attempts(&message.subscription_id).await.len(), 2);
    }

    /// Failures count until the limit switches the webhook off, which is
    /// reported once; a failure after that is only counted.
    #[tokio::test]
    async fn the_failure_reaching_the_limit_switches_the_webhook_off_once() {
        let fx = fixture().await;
        let (_, message) = fx.with_message("https://hooks.acme.com/in").await;
        let _clock = clock::freeze(at(100));

        let first_try = fx.record(&attempt_of(&message, 0, 50, 500), limit(2)).await;
        let second_try = fx.record(&attempt_of(&message, 1, 60, 503), limit(2)).await;
        let third_try = fx.record(&attempt_of(&message, 2, 70, 503), limit(2)).await;

        let changes: Vec<_> = [first_try, second_try, third_try]
            .into_iter()
            .map(|recorded| recorded.map(|recorded| recorded.change))
            .collect();
        assert_eq!(
            changes,
            [
                Some(StreakChange::Failed(FailureOutcome::Counted)),
                Some(StreakChange::Failed(FailureOutcome::Disabled)),
                Some(StreakChange::Failed(FailureOutcome::Counted)),
            ]
        );
        let found = fx.found(&message.subscription_id).await.unwrap();
        assert_eq!(found.status(), WebhookSubscriptionStatus::Disabled);
        assert_eq!(found.consecutive_failures(), 3);
    }

    /// A paused webhook counts a failure past the limit and stays paused.
    #[tokio::test]
    async fn a_paused_webhook_is_never_switched_off() {
        let fx = fixture().await;
        let paused = webhook(WebhookSubscriptionRow {
            status: WebhookSubscriptionStatus::Paused,
            ..webhook_row("https://hooks.acme.com/in")
        });
        fx.save_all(&[&paused]).await;
        let message = message_to(*paused.id());
        fx.store.keep_message(&fx.tenant, &message).await.unwrap();
        let _clock = clock::freeze(at(100));

        let recorded = fx
            .record(&attempt_of(&message, 0, 50, 500), limit(1))
            .await
            .unwrap();

        assert_eq!(
            recorded.change,
            StreakChange::Failed(FailureOutcome::Counted)
        );
        assert_eq!(
            recorded.subscription.status(),
            WebhookSubscriptionStatus::Paused
        );
    }

    /// A try for a webhook that is gone counts nothing and answers nothing.
    #[tokio::test]
    async fn a_try_for_a_gone_webhook_answers_nothing() {
        let fx = fixture().await;
        let message = message_to(WebhookSubscriptionId::new());

        let recorded = fx
            .record(&attempt_of(&message, 0, 50, 200), limit(10))
            .await;

        assert!(recorded.is_none());
    }

    /// A test send is kept in the history and leaves the streak, the last
    /// delivery and the status as they were.
    #[tokio::test]
    async fn a_test_send_is_kept_without_counting() {
        let fx = fixture().await;
        let (saved, message) = fx.with_message("https://hooks.acme.com/in").await;
        let tried = attempt_of(&message, 0, 50, 500);

        fx.store
            .keep_uncounted_attempt(&fx.tenant, &tried)
            .await
            .unwrap();

        let found = fx.found(saved.id()).await.unwrap();
        assert_eq!(found.consecutive_failures(), 0);
        assert_eq!(found.updated_at(), saved.updated_at());
        let kept = fx
            .store
            .find_delivery_attempt(&fx.tenant, saved.id(), &tried.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.outcome, tried.outcome);
        assert_eq!(kept.message_id, message.id);
    }

    /// Saving a delivery attempt for an unsaved message returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_try_at_a_message_never_kept_is_refused() {
        let fx = fixture().await;
        let saved = at_url("https://hooks.acme.com/in");
        fx.save_all(&[&saved]).await;
        let unkept = message_to(*saved.id());

        let kept = fx
            .store
            .keep_uncounted_attempt(&fx.tenant, &attempt_of(&unkept, 0, 50, 200))
            .await;

        assert!(matches!(kept, Err(DomainError::Infrastructure(_))));
    }

    /// A try is found under its own webhook and under no other.
    #[tokio::test]
    async fn a_try_is_found_only_under_its_webhook() {
        let fx = fixture().await;
        let (saved, message) = fx.with_message("https://hooks.acme.com/in").await;
        let other = at_url("https://other.acme.com/in");
        fx.save_all(&[&other]).await;
        let tried = attempt_of(&message, 0, 50, 200);
        fx.store
            .keep_uncounted_attempt(&fx.tenant, &tried)
            .await
            .unwrap();

        let under_other = fx
            .store
            .find_delivery_attempt(&fx.tenant, other.id(), &tried.id)
            .await
            .unwrap();
        let unknown = fx
            .store
            .find_delivery_attempt(&fx.tenant, saved.id(), &WebhookDeliveryId::new())
            .await
            .unwrap();

        assert!(under_other.is_none());
        assert!(unknown.is_none());
    }

    /// A webhook's tries list by their number page by page, each page
    /// after the last.
    #[tokio::test]
    async fn a_webhooks_tries_are_listed_page_by_page() {
        let fx = fixture().await;
        let (saved, message) = fx.with_message("https://hooks.acme.com/in").await;
        for number in [2, 0, 1] {
            fx.store
                .keep_uncounted_attempt(&fx.tenant, &attempt_of(&message, number, 50, 500))
                .await
                .unwrap();
        }
        let order = SortOrder::single(Sort::ascending(DeliveryAttemptSortField::AttemptNumber));

        let page_one = fx
            .store
            .list_delivery_attempts(&fx.tenant, saved.id(), &order, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx
            .store
            .list_delivery_attempts(&fx.tenant, saved.id(), &order, &after)
            .await
            .unwrap();

        let numbers: Vec<_> = page_one
            .items
            .iter()
            .chain(&page_two.items)
            .map(|attempt| attempt.attempt_number)
            .collect();
        assert_eq!(numbers, [0, 1, 2]);
        assert!(!page_two.has_next());
    }

    /// A kept message is found under its webhook as it was sent; keeping it
    /// again changes nothing, and another tenant finds nothing.
    #[tokio::test]
    async fn a_kept_message_is_found_under_its_webhook() {
        let fx = fixture().await;
        let (saved, message) = fx.with_message("https://hooks.acme.com/in").await;
        let again = WebhookMessage {
            payload: b"changed".to_vec(),
            ..message.clone()
        };
        fx.store.keep_message(&fx.tenant, &again).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let found = fx
            .store
            .find_message(&fx.tenant, saved.id(), &message.id)
            .await
            .unwrap();
        let elsewhere = fx
            .store
            .find_message(&other, saved.id(), &message.id)
            .await
            .unwrap();

        assert_eq!(found, Some(message));
        assert!(elsewhere.is_none());
    }

    /// A deleted webhook is gone with its messages and tries.
    #[tokio::test]
    async fn a_deleted_webhook_takes_its_history() {
        let fx = fixture().await;
        let (saved, message) = fx.with_message("https://hooks.acme.com/in").await;
        fx.store
            .keep_uncounted_attempt(&fx.tenant, &attempt_of(&message, 0, 50, 200))
            .await
            .unwrap();

        fx.store.delete(&fx.tenant, saved.id()).await.unwrap();

        assert!(fx.found(saved.id()).await.is_none());
        assert!(fx.attempts(saved.id()).await.is_empty());
        assert!(
            fx.store
                .find_message(&fx.tenant, saved.id(), &message.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A tenant with a database of its own keeps its webhooks and their
    /// history there.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_webhooks_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let saved = at_url("https://hooks.acme.com/in");
        let message = message_to(*saved.id());

        fx.store.save(&apart, &saved).await.unwrap();
        fx.store.keep_message(&apart, &message).await.unwrap();

        let there = PgWebhookStore::new(Arc::clone(&own.databases));
        assert!(
            there
                .find_by_id(&apart, saved.id())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            there
                .find_message(&apart, saved.id(), &message.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A webhook subscription with an unknown stored event type fails to
    /// load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_webhook_is_refused() {
        let fx = fixture().await;
        let saved = at_url("https://hooks.acme.com/in");
        fx.save_all(&[&saved]).await;
        fx.db
            .tamper("UPDATE webhook_subscriptions SET event_types = '{nobody.raises_this}'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
