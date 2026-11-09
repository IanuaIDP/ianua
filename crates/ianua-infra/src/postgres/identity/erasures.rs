//! Requests to erase a person's data: each one row of `erasure_requests`,
//! under row-level security. A request outlives the account it erases, as
//! the record that the erasure was asked for and carried out, so it names
//! the user without a foreign key.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::identity::{ErasureBatch, ErasureRequestStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::privacy::erasure::ErasureRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ErasureRequestId, TokenHash, UserId};

use self::record::{ErasureColumns, ErasureRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a cancel link to one request.
const CANCEL_TOKEN_KEY: &str = "erasure_requests_cancel_token_key";

/// The Postgres store of erasure requests.
pub struct PgErasureRequestStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgErasureRequestStore {}

impl PgErasureRequestStore {
    /// A store keeping erasure requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// Refuses a cancellation link already assigned to another erasure request.
fn ensure_unique_link(written: Uniqueness) -> Result<(), DomainError> {
    match written {
        Uniqueness::Kept => Ok(()),
        Uniqueness::Taken => Err(DomainError::conflict(message!(
            "infra-another-erasure-request-already-has-this",
            "another erasure request already has this cancel link"
        ))),
    }
}

fn rebuilt_one(
    record: Option<ErasureRecord>,
) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError> {
    record.map(ErasureRecord::into_request).transpose()
}

#[async_trait]
impl ErasureRequestStore for PgErasureRequestStore {
    async fn find_active_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ErasureRecord,
                    "queries/erasure_requests/active_of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt_one(record)
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ErasureRequestId,
    ) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ErasureRecord,
                    "queries/erasure_requests/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt_one(record)
    }

    async fn find_by_cancel_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        cancel_token_hash: &TokenHash,
    ) -> Result<Option<ErasureRequest<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ErasureRecord,
                    "queries/erasure_requests/by_cancel_token.sql",
                    tenant_id.as_uuid(),
                    cancel_token_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        rebuilt_one(record)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &ErasureRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ErasureColumns::of(request);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/erasure_requests/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.user_id,
                    columns.reason,
                    columns.status,
                    columns.completed_at,
                    columns.requested_at,
                    columns.scheduled_at,
                    columns.cancel_token_hash,
                    columns.sent_to,
                )
                .execute(connection)
                .await;
                unique_on(attempt, CANCEL_TOKEN_KEY)
            },
        )
        .await?;
        ensure_unique_link(written)
    }

    async fn find_due(
        &self,
        tenant_id: &ScopedTenant,
        batch: ErasureBatch,
    ) -> Result<Vec<ErasureRequest<ResolvedTenant>>, DomainError> {
        let limit = i64::try_from(ErasureBatch::LIMIT).map_err(DomainError::infra)?;
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ErasureRecord,
                    "queries/erasure_requests/due.sql",
                    tenant_id.as_uuid(),
                    batch.now,
                    batch.after.map(|after| after.scheduled_at),
                    batch.after.map(|after| *after.id.as_uuid()),
                    limit
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(ErasureRecord::into_request)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::ErasurePosition;
    use ianua_domain::domains::identity::privacy::erasure::{ErasureRequestRow, ErasureState};
    use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
    use ianua_domain::types::TenantId;
    use time::Duration;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::identity::erasure_row;

    /// A fresh database, the store on it, and one tenant to keep requests
    /// in. No user row is needed: a request outlives its account.
    async fn fixture() -> (TestDb, PgErasureRequestStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgErasureRequestStore::new(Arc::clone(&db.databases));
        (db, store, ScopedTenant::for_background(TenantId::new()))
    }

    fn request(row: ErasureRequestRow) -> ErasureRequest<ResolvedTenant> {
        ErasureRequest::reconstitute(row).unwrap()
    }

    fn hash(text: &str) -> TokenHash {
        TokenHash::from_stored(text.to_owned())
    }

    /// Ann's request is found by its id, by its cancel link and as her
    /// active one; once it is completed, saving it again keeps when.
    #[tokio::test]
    async fn a_request_is_found_and_keeps_where_it_stands() {
        let (_db, store, tenant) = fixture().await;
        let ann = UserId::new();
        let asked = request(erasure_row(ann, "h-cancel"));
        store.save(&tenant, &asked).await.unwrap();

        assert_active_lookups(&store, &tenant, &asked).await;
        let done_at = asked.scheduled_at().saturating_add(Duration::hours(1));
        let completed = request(ErasureRequestRow {
            id: *asked.id(),
            state: ErasureState::Completed { at: done_at },
            ..erasure_row(ann, "h-cancel")
        });
        store.save(&tenant, &completed).await.unwrap();
        let found = store
            .find_by_id(&tenant, asked.id())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found.completed_at(), Some(done_at));
        assert!(
            store
                .find_active_by_user(&tenant, &ann)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Finds the pending request through its cancellation link and active account lookup.
    async fn assert_active_lookups(
        store: &PgErasureRequestStore,
        tenant: &ScopedTenant,
        asked: &ErasureRequest<ResolvedTenant>,
    ) {
        let by_link = store
            .find_by_cancel_token_hash(tenant, &hash("h-cancel"))
            .await
            .unwrap()
            .unwrap();
        let active = store
            .find_active_by_user(tenant, asked.user_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_link.id(), asked.id());
        assert_eq!(active.id(), asked.id());
    }

    /// A held request is not under way, though it waits; a cancelled one is
    /// over.
    #[tokio::test]
    async fn only_a_pending_or_processing_request_is_active() {
        let (_db, store, tenant) = fixture().await;
        let (ann, bob) = (UserId::new(), UserId::new());
        for (user, state, link) in [
            (ann, ErasureState::Held, "h-ann"),
            (bob, ErasureState::Cancelled, "h-bob"),
        ] {
            let row = ErasureRequestRow {
                state,
                ..erasure_row(user, link)
            };
            store.save(&tenant, &request(row)).await.unwrap();
        }

        assert!(
            store
                .find_active_by_user(&tenant, &ann)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .find_active_by_user(&tenant, &bob)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The sweep finds the pending and failed requests whose grace period
    /// is over, oldest first, and leaves the rest.
    #[tokio::test]
    async fn due_requests_are_found_oldest_first() {
        let (_db, store, tenant) = fixture().await;
        let due_later = request(erasure_row(UserId::new(), "h-1"));
        let failed = request(ErasureRequestRow {
            state: ErasureState::Failed,
            requested_at: at(-100),
            scheduled_at: at(-100).saturating_add(Duration::days(14)),
            ..erasure_row(UserId::new(), "h-2")
        });
        let held = request(ErasureRequestRow {
            state: ErasureState::Held,
            ..erasure_row(UserId::new(), "h-3")
        });
        let not_yet = request(ErasureRequestRow {
            requested_at: at(100),
            scheduled_at: at(100).saturating_add(Duration::days(14)),
            ..erasure_row(UserId::new(), "h-4")
        });
        for asked in [&due_later, &failed, &held, &not_yet] {
            store.save(&tenant, asked).await.unwrap();
        }

        let due = store
            .find_due(
                &tenant,
                ErasureBatch::first(at(50).saturating_add(Duration::days(14))),
            )
            .await
            .unwrap();

        let ids: Vec<ErasureRequestId> = due.iter().map(|asked| *asked.id()).collect();
        assert_eq!(ids, [*failed.id(), *due_later.id()]);
        assert_eq!(due[0].status(), ErasureStatus::Failed);
    }

    /// Equal due times span two pages without omissions or repeats. The first
    /// request remains failed, but the next page advances past it; foreign
    /// requests do not consume this tenant's batch.
    #[tokio::test]
    async fn due_erasure_batches_are_bounded_and_advance_over_timestamp_ties() {
        let (_db, store, tenant) = fixture().await;
        let expected = save_tied_requests(&store, &tenant).await;
        let mut batch = ErasureBatch::first(at(50).saturating_add(Duration::days(14)));
        let first = store.find_due(&tenant, batch).await.unwrap();
        assert_eq!(first.len(), ErasureBatch::LIMIT);
        let last = first.last().unwrap();
        batch.after = Some(position_of(last));

        let second = store.find_due(&tenant, batch).await.unwrap();

        assert_eq!(second.len(), 1);
        let found: Vec<_> = first
            .iter()
            .chain(&second)
            .map(|asked| *asked.id())
            .collect();
        assert_eq!(found, expected);
        assert_eq!(first[0].status(), ErasureStatus::Failed);
        let last = second.last().unwrap();
        batch.after = Some(position_of(last));
        assert!(store.find_due(&tenant, batch).await.unwrap().is_empty());
        assert_eq!(
            store
                .find_due(&tenant, ErasureBatch::first(batch.now))
                .await
                .unwrap()[0]
                .id(),
            &expected[0]
        );
    }

    /// Saves two pages of equally due requests, a failed first request and another tenant's.
    async fn save_tied_requests(
        store: &PgErasureRequestStore,
        tenant: &ScopedTenant,
    ) -> Vec<ErasureRequestId> {
        let mut expected = Vec::new();
        for index in 1..=501 {
            let id = ErasureRequestId::from_uuid(uuid::Uuid::from_u128(index));
            let asked = request(ErasureRequestRow {
                id,
                state: match index {
                    1 => ErasureState::Failed,
                    _ => ErasureState::Pending,
                },
                ..erasure_row(UserId::new(), &format!("cancel-{index}"))
            });
            store.save(tenant, &asked).await.unwrap();
            expected.push(id);
        }
        let foreign = ScopedTenant::for_background(TenantId::new());
        store
            .save(&foreign, &request(erasure_row(UserId::new(), "foreign")))
            .await
            .unwrap();
        expected
    }

    /// Advances the erasure cursor past this request's time and stable identifier.
    fn position_of(request: &ErasureRequest<ResolvedTenant>) -> ErasurePosition {
        ErasurePosition {
            scheduled_at: request.scheduled_at(),
            id: *request.id(),
        }
    }

    /// Saving a second erasure request with an existing cancellation link
    /// returns a conflict.
    #[tokio::test]
    async fn a_cancel_link_another_request_has_is_refused() {
        let (_db, store, tenant) = fixture().await;
        store
            .save(&tenant, &request(erasure_row(UserId::new(), "h-same")))
            .await
            .unwrap();

        let second = store
            .save(&tenant, &request(erasure_row(UserId::new(), "h-same")))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// An id nobody has finds nothing, and another tenant finds none of
    /// Acme's requests.
    #[tokio::test]
    async fn an_unknown_or_another_tenants_request_is_not_found() {
        let (_db, store, tenant) = fixture().await;
        let asked = request(erasure_row(UserId::new(), "h-cancel"));
        store.save(&tenant, &asked).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(
            store
                .find_by_id(&tenant, &ErasureRequestId::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .find_by_id(&other, asked.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .find_by_cancel_token_hash(&other, &hash("h-cancel"))
                .await
                .unwrap()
                .is_none()
        );
    }

    /// An erasure request stored with only one minute of grace fails to
    /// load as corrupt storage.
    #[tokio::test]
    async fn a_request_scheduled_outside_the_grace_period_is_refused() {
        let (db, store, tenant) = fixture().await;
        let asked = request(erasure_row(UserId::new(), "h-cancel"));
        store.save(&tenant, &asked).await.unwrap();
        db.tamper("UPDATE erasure_requests SET scheduled_at = requested_at + interval '1 minute'")
            .await;

        let read = store.find_by_id(&tenant, asked.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
