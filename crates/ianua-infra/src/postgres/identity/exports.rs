//! Requests for a copy of a person's data: each one row of `data_exports`,
//! under row-level security. A person has at most one asked for or ready
//! at a time, which a unique index keeps.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, Sort, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::identity::{DataExportStore, ExportSweepSortField};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::privacy::export::DataExportRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DataExportId, UserId};
use time::OffsetDateTime;

use self::record::{ExportColumns, ExportRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The index that keeps a person to one open request.
const ONE_OPEN: &str = "data_exports_one_open";

/// The Postgres store of data export requests.
pub struct PgDataExportStore {
    databases: Arc<Databases>,
}

/// The selected export sweep with its matching timestamp order.
struct SweepQuery<'a> {
    /// Orders records by the timestamp selected for this sweep.
    order: SortOrder<ExportSweepSortField>,
    /// Selects identifiers within the tenant and captured cutoff.
    listed: PageQuery<'a>,
}

impl TenantScoped for PgDataExportStore {}

impl SortColumns for ExportSweepSortField {
    /// Uses the indexed timestamp belonging to this sweep.
    fn column(self) -> &'static str {
        match self {
            Self::RequestedAt => "requested_at",
            Self::AvailableUntil => "available_until",
        }
    }

    /// Waiting rows always have a request time and ready rows have a window.
    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

impl PgDataExportStore {
    /// A store keeping export requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Reads one indexed page and hydrates only those requests in one query.
    async fn sweep_page(
        &self,
        tenant: &ScopedTenant,
        page: &PageRequest,
        query: SweepQuery<'_>,
    ) -> Result<Page<DataExportRequest<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(&query.order)?;
        let records = scoped(
            &self.databases,
            RowScope::from(tenant),
            async |connection| {
                let ids = query.listed.fetch(&keyset, &mut *connection).await?;
                let records = sqlx::query_file_as!(
                    ExportRecord,
                    "queries/data_exports/by_ids.sql",
                    tenant.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }
}

fn rebuilt(
    records: Vec<ExportRecord>,
) -> Result<Vec<DataExportRequest<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(ExportRecord::into_request)
        .collect()
}

#[async_trait]
impl DataExportStore for PgDataExportStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &DataExportRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ExportColumns::of(request);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/data_exports/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.user_id,
                    columns.scope,
                    columns.asked_by,
                    columns.status,
                    columns.ready_at,
                    columns.available_until,
                    columns.requested_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, ONE_OPEN)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-this-person-already-has-an-export",
                "this person already has an export asked for or ready"
            ))),
        }
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DataExportId,
    ) -> Result<Option<DataExportRequest<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ExportRecord,
                    "queries/data_exports/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ExportRecord::into_request).transpose()
    }

    async fn open_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<DataExportRequest<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ExportRecord,
                    "queries/data_exports/open_of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ExportRecord::into_request).transpose()
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<DataExportRequest<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ExportRecord,
                    "queries/data_exports/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn waiting(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<DataExportRequest<ResolvedTenant>>, DomainError> {
        let listed = PageQuery::ids("id", "data_exports")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .keep("status = 'requested'")
            .filter("requested_at <= ?", now);
        self.sweep_page(
            tenant_id,
            page,
            SweepQuery {
                order: SortOrder::default(),
                listed,
            },
        )
        .await
    }

    async fn lapsed(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<DataExportRequest<ResolvedTenant>>, DomainError> {
        let listed = PageQuery::ids("id", "data_exports")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .keep("status = 'ready'")
            .filter("available_until <= ?", now);
        let order = SortOrder::single(Sort::ascending(ExportSweepSortField::AvailableUntil));
        self.sweep_page(tenant_id, page, SweepQuery { order, listed })
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::privacy::export::{DOWNLOAD_WINDOW, DataExportRequestRow};
    use ianua_domain::domains::identity::privacy::export_state::{ExportState, ExportStatus};
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::identity::{export_row, user_row};

    struct Fixture {
        db: TestDb,
        store: PgDataExportStore,
        tenant: ScopedTenant,
        ann: UserId,
        bob: UserId,
    }

    impl Fixture {
        /// Persists one export in the fixture's tenant.
        async fn save(&self, request: &DataExportRequest<ResolvedTenant>) {
            self.store.save(&self.tenant, request).await.unwrap();
        }

        /// Reads a waiting page using the same cutoff throughout a sweep.
        async fn waiting(
            &self,
            now: OffsetDateTime,
            page: &PageRequest,
        ) -> Page<DataExportRequest<ResolvedTenant>> {
            self.store.waiting(&self.tenant, now, page).await.unwrap()
        }

        /// Reads a lapsed page using the same cutoff throughout a sweep.
        async fn lapsed(
            &self,
            now: OffsetDateTime,
            page: &PageRequest,
        ) -> Page<DataExportRequest<ResolvedTenant>> {
            self.store.lapsed(&self.tenant, now, page).await.unwrap()
        }

        /// Reads the persisted status so paging tests can prove a request stays unchanged.
        async fn status(&self, id: &DataExportId) -> ExportStatus {
            self.store
                .find_by_id(&self.tenant, id)
                .await
                .unwrap()
                .unwrap()
                .status()
        }
    }

    /// A fresh database holding Ann and Bob in one tenant, and the store on
    /// it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let ann: User<ResolvedTenant> = User::reconstitute(user_row("ann@acme.example")).unwrap();
        let bob: User<ResolvedTenant> = User::reconstitute(user_row("bob@acme.example")).unwrap();
        users.save(&tenant, &ann).await.unwrap();
        users.save(&tenant, &bob).await.unwrap();
        Fixture {
            store: PgDataExportStore::new(Arc::clone(&db.databases)),
            tenant,
            ann: *ann.id(),
            bob: *bob.id(),
            db,
        }
    }

    fn request(row: DataExportRequestRow) -> DataExportRequest<ResolvedTenant> {
        DataExportRequest::reconstitute(row).unwrap()
    }

    /// Ready at `seconds` past the fixed moment, for the whole window.
    fn ready_at(seconds: i64) -> ExportState {
        ExportState::Ready {
            at: at(seconds),
            available_until: at(seconds).saturating_add(DOWNLOAD_WINDOW),
        }
    }

    fn ids(found: &[DataExportRequest<ResolvedTenant>]) -> Vec<DataExportId> {
        found.iter().map(|request| *request.id()).collect()
    }

    /// Ann's request is found by its id and as her open one, and once it is
    /// ready, saving it again keeps its window.
    #[tokio::test]
    async fn a_request_is_found_and_keeps_where_it_stands() {
        let db = fixture().await;
        let asked = request(export_row(db.ann, 0));
        db.store.save(&db.tenant, &asked).await.unwrap();
        let ready = request(DataExportRequestRow {
            id: *asked.id(),
            state: ready_at(10),
            ..export_row(db.ann, 0)
        });

        db.store.save(&db.tenant, &ready).await.unwrap();

        let found = db
            .store
            .find_by_id(&db.tenant, asked.id())
            .await
            .unwrap()
            .unwrap();
        let open = db
            .store
            .open_for_user(&db.tenant, &db.ann)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.state(), ready_at(10));
        assert_eq!(open.id(), asked.id());
    }

    /// Saving a second open data export request for Ann returns a conflict.
    #[tokio::test]
    async fn a_second_open_request_is_refused() {
        let db = fixture().await;
        db.store
            .save(&db.tenant, &request(export_row(db.ann, 0)))
            .await
            .unwrap();

        let second = db
            .store
            .save(&db.tenant, &request(export_row(db.ann, 5)))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Ann's requests list newest first, the expired one too, and she has
    /// no open one once both are over.
    #[tokio::test]
    async fn a_persons_requests_are_listed_newest_first() {
        let db = fixture().await;
        let older = request(DataExportRequestRow {
            state: ExportState::Expired,
            ..export_row(db.ann, 0)
        });
        let newer = request(DataExportRequestRow {
            state: ExportState::Expired,
            ..export_row(db.ann, 10)
        });
        for asked in [&older, &newer] {
            db.store.save(&db.tenant, asked).await.unwrap();
        }

        let listed = db.store.list_by_user(&db.tenant, &db.ann).await.unwrap();
        let open = db.store.open_for_user(&db.tenant, &db.ann).await.unwrap();

        assert_eq!(ids(&listed), [*newer.id(), *older.id()]);
        assert!(open.is_none());
    }

    /// The worker finds the requests still waiting for their file, oldest
    /// first, and not one already over.
    #[tokio::test]
    async fn waiting_requests_are_found_oldest_first() {
        let db = fixture().await;
        let later = request(export_row(db.ann, 20));
        let sooner = request(export_row(db.bob, 10));
        db.store.save(&db.tenant, &later).await.unwrap();
        db.store.save(&db.tenant, &sooner).await.unwrap();
        db.save(&request(DataExportRequestRow {
            state: ExportState::Expired,
            ..export_row(db.ann, 0)
        }))
        .await;

        let waiting = db
            .store
            .waiting(
                &db.tenant,
                at(100),
                &PageRequest::first(Limit::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(ids(&waiting.items), [*sooner.id(), *later.id()]);
        assert!(
            waiting
                .items
                .iter()
                .all(|asked| asked.status() == ExportStatus::Requested)
        );
    }

    /// The sweep finds the ready requests whose window is over, and leaves
    /// one whose window is still open.
    #[tokio::test]
    async fn ready_requests_past_their_window_are_found() {
        let db = fixture().await;
        let over = request(DataExportRequestRow {
            state: ready_at(0),
            ..export_row(db.bob, 0)
        });
        let open = request(DataExportRequestRow {
            state: ready_at(30),
            ..export_row(db.ann, 0)
        });
        db.store.save(&db.tenant, &over).await.unwrap();
        db.store.save(&db.tenant, &open).await.unwrap();

        let lapsed = db
            .store
            .lapsed(
                &db.tenant,
                at(15).saturating_add(DOWNLOAD_WINDOW),
                &PageRequest::first(Limit::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(ids(&lapsed.items), [*over.id()]);
    }

    /// An id nobody has finds nothing, and another tenant finds none of
    /// Acme's requests.
    #[tokio::test]
    async fn an_unknown_or_another_tenants_request_is_not_found() {
        let db = fixture().await;
        let asked = request(export_row(db.ann, 0));
        db.store.save(&db.tenant, &asked).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(
            db.store
                .find_by_id(&db.tenant, &DataExportId::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.store
                .find_by_id(&other, asked.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.store
                .waiting(
                    &other,
                    at(100),
                    &PageRequest::first(Limit::new(10).unwrap())
                )
                .await
                .unwrap()
                .items
                .is_empty()
        );
    }

    /// Two waiting requests share a timestamp. Paging advances past the
    /// first without changing it, and excludes a later request and tenant.
    #[tokio::test]
    async fn waiting_export_pages_keep_the_cutoff_and_timestamp_ties() {
        let db = fixture().await;
        let expected = save_waiting_ties(&db).await;
        let limit = Limit::new(1).unwrap();

        let before = db.waiting(at(10), &PageRequest::first(limit)).await;
        let after = db
            .waiting(at(10), &PageRequest::new(before.next.clone(), limit))
            .await;
        let foreign = ScopedTenant::for_background(TenantId::new());
        let hidden = db
            .store
            .waiting(&foreign, at(10), &PageRequest::first(limit))
            .await
            .unwrap();

        assert_eq!(ids(&before.items), [expected[0]]);
        assert_eq!(ids(&after.items), [expected[1]]);
        assert!(after.next.is_none());
        assert!(hidden.items.is_empty());
        assert_eq!(db.status(&expected[0]).await, ExportStatus::Requested);
    }

    /// Saves two waiting exports at one timestamp and one beyond the sweep cutoff.
    async fn save_waiting_ties(db: &Fixture) -> [DataExportId; 2] {
        let first = request(export_row(db.ann, 0));
        let second = request(export_row(db.bob, 0));
        let future_user: User<ResolvedTenant> =
            User::reconstitute(user_row("cy@acme.example")).unwrap();
        let users = PgUserStore::new(Arc::clone(&db.db.databases), DomainLimits::default());
        users.save(&db.tenant, &future_user).await.unwrap();
        let future = request(export_row(*future_user.id(), 100));
        for export in [&first, &second, &future] {
            db.save(export).await;
        }
        let mut expected = [*first.id(), *second.id()];
        expected.sort_by_key(|id| *id.as_uuid());
        expected
    }

    /// Equal download deadlines page by id while the first export remains
    /// ready. A window after the cutoff and another tenant stay excluded.
    #[tokio::test]
    async fn lapsed_export_pages_advance_over_equal_deadlines() {
        let db = fixture().await;
        let expected = save_ready_ties(&db).await;
        let limit = Limit::new(1).unwrap();
        let now = at(0).saturating_add(DOWNLOAD_WINDOW);

        let before = db.lapsed(now, &PageRequest::first(limit)).await;
        let after = db
            .lapsed(now, &PageRequest::new(before.next.clone(), limit))
            .await;
        let foreign = ScopedTenant::for_background(TenantId::new());
        let hidden = db
            .store
            .lapsed(&foreign, now, &PageRequest::first(limit))
            .await
            .unwrap();
        let early = db.lapsed(at(0), &PageRequest::first(limit)).await;

        assert_eq!(ids(&before.items), [expected[0]]);
        assert_eq!(ids(&after.items), [expected[1]]);
        assert!(after.next.is_none());
        assert!(hidden.items.is_empty());
        assert!(early.items.is_empty());
        assert_eq!(db.status(&expected[0]).await, ExportStatus::Ready);
    }

    /// Saves two ready exports sharing a deadline in their stable identifier order.
    async fn save_ready_ties(db: &Fixture) -> [DataExportId; 2] {
        let first = request(DataExportRequestRow {
            state: ready_at(0),
            ..export_row(db.ann, 0)
        });
        let second = request(DataExportRequestRow {
            state: ready_at(0),
            ..export_row(db.bob, 0)
        });
        for export in [&first, &second] {
            db.save(export).await;
        }
        let mut expected = [*first.id(), *second.id()];
        expected.sort_by_key(|id| *id.as_uuid());
        expected
    }

    /// An export request with an unknown stored scope fails to load as
    /// corrupt storage.
    #[tokio::test]
    async fn a_request_of_an_unknown_scope_is_refused() {
        let db = fixture().await;
        let asked = request(export_row(db.ann, 0));
        db.store.save(&db.tenant, &asked).await.unwrap();
        db.db
            .tamper(
                "ALTER TABLE data_exports DROP CONSTRAINT data_exports_scope_known;
                 UPDATE data_exports SET scope = 'everything'",
            )
            .await;

        let read = db.store.find_by_id(&db.tenant, asked.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
