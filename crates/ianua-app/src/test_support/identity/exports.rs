//! Fakes for copies of a person's data: the request store, a builder, the
//! file store and a notifier that record what they were asked to do.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::privacy::export::{
    DOWNLOAD_WINDOW, DataExportRequest, DataExportRequestRow, ExportAskedBy, ExportScope,
};
use ianua_domain::domains::identity::privacy::export_state::ExportState;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DataExportId, HttpsUrl, Locale, Preference, UserId};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest, Sort, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::identity::{
    DataExportBuilder, DataExportFiles, DataExportNotifier, DataExportStore, ExportSweepSortField,
};
use crate::ports::shared::MailRecipient;
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authentication::Plane;

/// In-memory export requests, kept as rows in their tenant.
#[derive(Default)]
pub struct FakeDataExportStore {
    rows: Mutex<Vec<(Plane, DataExportRequestRow)>>,
    waiting_batches: Mutex<Vec<usize>>,
    lapsed_batches: Mutex<Vec<usize>>,
}

impl FakeDataExportStore {
    /// The number of waiting requests returned by each sweep read.
    #[must_use]
    pub fn waiting_batch_sizes(&self) -> Vec<usize> {
        self.waiting_batches.lock().unwrap().clone()
    }

    /// The number of expired-window requests returned by each sweep read.
    #[must_use]
    pub fn lapsed_batch_sizes(&self) -> Vec<usize> {
        self.lapsed_batches.lock().unwrap().clone()
    }

    /// No requests.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Holds `request` in the test tenant.
    #[must_use]
    pub fn holding(request: &DataExportRequest<ResolvedTenant>) -> Self {
        let store = Self::default();
        store.put(Plane::test_tenant(), request);
        store
    }

    /// The request with `id` in the test tenant, as last saved.
    #[must_use]
    pub fn stored(&self, id: &DataExportId) -> Option<DataExportRequest<ResolvedTenant>> {
        self.matching(Plane::test_tenant(), |row| row.id == *id)
            .into_iter()
            .next()
    }

    /// How many requests are held, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.rows.lock().unwrap().len()
    }

    fn put(&self, plane: Plane, request: &DataExportRequest<ResolvedTenant>) {
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|(held_on, row)| !(*held_on == plane && row.id == *request.id()));
        rows.push((plane, row_of(request)));
    }

    fn matching(
        &self,
        plane: Plane,
        keep: impl Fn(&DataExportRequestRow) -> bool,
    ) -> Vec<DataExportRequest<ResolvedTenant>> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(held_on, row)| *held_on == plane && keep(row))
            .map(|(_, row)| {
                DataExportRequest::reconstitute(copy_row(row)).expect("a kept row rebuilds")
            })
            .collect()
    }
}

/// `user_id`'s own request for everything kept about them, still being
/// gathered.
#[must_use]
pub fn asked_export_of(user_id: UserId) -> DataExportRequest<ResolvedTenant> {
    export_in(user_id, ExportState::Requested, clock::now())
}

/// `user_id`'s own request, ready since a moment ago for the full window.
#[must_use]
pub fn ready_export_of(user_id: UserId) -> DataExportRequest<ResolvedTenant> {
    let now = clock::now();
    let ready = ExportState::Ready {
        at: now,
        available_until: now + DOWNLOAD_WINDOW,
    };
    export_in(user_id, ready, now)
}

/// `user_id`'s own request, made ready eight days ago, so its window is
/// over.
#[must_use]
pub fn lapsed_export_of(user_id: UserId) -> DataExportRequest<ResolvedTenant> {
    let asked = clock::now() - time::Duration::days(8);
    let ready = ExportState::Ready {
        at: asked,
        available_until: asked + DOWNLOAD_WINDOW,
    };
    export_in(user_id, ready, asked)
}

/// `user_id`'s request in `state`, asked for at `requested_at`.
///
/// # Panics
///
/// Panics if the state contradicts the time, which no helper here passes.
fn export_in(
    user_id: UserId,
    state: ExportState,
    requested_at: OffsetDateTime,
) -> DataExportRequest<ResolvedTenant> {
    DataExportRequest::reconstitute(DataExportRequestRow {
        id: DataExportId::new(),
        user_id,
        scope: ExportScope::Access,
        asked_by: ExportAskedBy::Holder,
        state,
        requested_at,
    })
    .expect("a consistent export row")
}

/// The row storage would keep for `request`.
fn row_of(request: &DataExportRequest<ResolvedTenant>) -> DataExportRequestRow {
    DataExportRequestRow {
        id: *request.id(),
        user_id: *request.user_id(),
        scope: request.scope(),
        asked_by: request.asked_by(),
        state: request.state(),
        requested_at: request.requested_at(),
    }
}

/// A copy of `row`, which does not implement `Clone`.
fn copy_row(row: &DataExportRequestRow) -> DataExportRequestRow {
    DataExportRequestRow {
        id: row.id,
        user_id: row.user_id,
        scope: row.scope,
        asked_by: row.asked_by,
        state: row.state,
        requested_at: row.requested_at,
    }
}

impl TenantScoped for FakeDataExportStore {}

#[async_trait]
impl DataExportStore for FakeDataExportStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &DataExportRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.put(Plane::of(tenant_id), request);
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DataExportId,
    ) -> Result<Option<DataExportRequest<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(Plane::of(tenant_id), |row| row.id == *id)
            .into_iter()
            .next())
    }

    async fn open_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Option<DataExportRequest<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(Plane::of(tenant_id), |row| {
                row.user_id == *user_id && row.state != ExportState::Expired
            })
            .into_iter()
            .next())
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<DataExportRequest<ResolvedTenant>>, DomainError> {
        let mut found = self.matching(Plane::of(tenant_id), |row| row.user_id == *user_id);
        found.reverse();
        Ok(found)
    }

    async fn waiting(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<DataExportRequest<ResolvedTenant>>, DomainError> {
        let found = self.matching(Plane::of(tenant_id), |row| {
            row.state == ExportState::Requested && row.requested_at <= now
        });
        let order = SortOrder::<ExportSweepSortField>::default();
        let found = crate::test_support::listing::page(found, &order, page)?;
        self.waiting_batches.lock().unwrap().push(found.items.len());
        Ok(found)
    }

    async fn lapsed(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        page: &PageRequest,
    ) -> Result<Page<DataExportRequest<ResolvedTenant>>, DomainError> {
        let found = self.matching(Plane::of(tenant_id), |row| {
            row.state
                .available_until()
                .is_some_and(|until| until <= now)
        });
        let order = SortOrder::single(Sort::ascending(ExportSweepSortField::AvailableUntil));
        let found = crate::test_support::listing::page(found, &order, page)?;
        self.lapsed_batches.lock().unwrap().push(found.items.len());
        Ok(found)
    }
}

/// Whether a fake builder's sections can be read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Sections {
    /// Every section reads, so a file is built.
    #[default]
    Readable,
    /// No section reads in time.
    Unreadable,
}

/// A builder that keeps a file for every request, or fails every one.
#[derive(Default)]
pub struct FakeDataExportBuilder {
    built: Mutex<Vec<DataExportId>>,
    sections: Sections,
}

impl FakeDataExportBuilder {
    /// A builder whose sections can never be read.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            built: Mutex::default(),
            sections: Sections::Unreadable,
        }
    }

    /// The requests a file was built for.
    #[must_use]
    pub fn built(&self) -> Vec<DataExportId> {
        self.built.lock().unwrap().clone()
    }
}

#[async_trait]
impl DataExportBuilder for FakeDataExportBuilder {
    async fn build(
        &self,
        _tenant_id: &ScopedTenant,
        request: &DataExportRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        if self.sections == Sections::Unreadable {
            return Err(DomainError::infra_msg(
                "a section could not be read in time",
            ));
        }
        self.built.lock().unwrap().push(*request.id());
        Ok(())
    }
}

/// A file store that hands out links on `files.test` and records which
/// files were deleted.
#[derive(Default)]
pub struct FakeDataExportFiles {
    deleted: Mutex<Vec<DataExportId>>,
}

impl FakeDataExportFiles {
    /// The files deleted.
    #[must_use]
    pub fn deleted(&self) -> Vec<DataExportId> {
        self.deleted.lock().unwrap().clone()
    }
}

#[async_trait]
impl DataExportFiles for FakeDataExportFiles {
    async fn download_link(
        &self,
        _tenant_id: &ScopedTenant,
        id: &DataExportId,
        _available_until: OffsetDateTime,
    ) -> Result<HttpsUrl, DomainError> {
        HttpsUrl::new(format!("https://files.test/exports/{id}")).map_err(DomainError::from)
    }

    async fn delete(
        &self,
        _tenant_id: &ScopedTenant,
        id: &DataExportId,
    ) -> Result<(), DomainError> {
        self.deleted.lock().unwrap().push(*id);
        Ok(())
    }
}

/// Records who was told their export is ready.
#[derive(Default)]
pub struct RecordingExportNotifier {
    told: Mutex<Vec<(String, Preference<Locale>)>>,
}

impl RecordingExportNotifier {
    /// The addresses told, in order.
    #[must_use]
    pub fn told(&self) -> Vec<String> {
        self.told
            .lock()
            .unwrap()
            .iter()
            .map(|(to, _)| to.clone())
            .collect()
    }

    /// The languages each was told in, in order.
    #[must_use]
    pub fn locales(&self) -> Vec<Preference<Locale>> {
        self.told
            .lock()
            .unwrap()
            .iter()
            .map(|(_, locale)| locale.clone())
            .collect()
    }
}

#[async_trait]
impl DataExportNotifier for RecordingExportNotifier {
    async fn ready(
        &self,
        _tenant_id: &ScopedTenant,
        to: MailRecipient<'_>,
        _available_until: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.told
            .lock()
            .unwrap()
            .push((to.email.as_str().to_owned(), to.locale.clone()));
        Ok(())
    }
}

impl Fake for Arc<dyn DataExportStore> {
    fn fake() -> Self {
        Arc::new(FakeDataExportStore::empty())
    }
}

impl Fake for Arc<dyn DataExportBuilder> {
    fn fake() -> Self {
        Arc::new(FakeDataExportBuilder::default())
    }
}

impl Fake for Arc<dyn DataExportFiles> {
    fn fake() -> Self {
        Arc::new(FakeDataExportFiles::default())
    }
}

impl Fake for Arc<dyn DataExportNotifier> {
    fn fake() -> Self {
        Arc::new(RecordingExportNotifier::default())
    }
}
