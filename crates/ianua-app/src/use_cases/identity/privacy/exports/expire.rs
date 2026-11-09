//! Expire exports: once an export's download window is over, its file is
//! deleted and the export is closed, in every tenant.
//!
//! A file holding everything kept about a person must not outlive the week
//! it was made for: a copy left in storage is one more place to leak from.

use std::sync::Arc;

use ianua_domain::domains::identity::privacy::export::DataExportRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest};
use crate::ports::identity::{DataExportFiles, DataExportStore};
use crate::ports::tenant::TenantStore;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`ExpireExportsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExpireExportsPorts {
    /// Lists the tenants to look in.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The requests.
    pub export_store: Arc<dyn DataExportStore>,
    /// Deletes the files.
    pub files: Arc<dyn DataExportFiles>,
}

/// Closes every export whose download window is over.
pub struct ExpireExportsUseCase {
    ports: ExpireExportsPorts,
}

impl ExpireExportsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ExpireExportsPorts) -> Self {
        Self { ports }
    }

    /// Closes every lapsed export of `tenant` as of `now`, and answers how
    /// many.
    async fn expire_tenant(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<u64, AppError> {
        let mut closed: u64 = 0;
        let limit = Limit::internal(500);
        let mut page = PageRequest::first(limit);
        loop {
            let lapsed = self
                .ports
                .export_store
                .lapsed(tenant, now, &page)
                .await
                .or_internal()?;
            for export in lapsed.items {
                self.expire_one(tenant, auditor, export, now).await?;
                closed = closed.saturating_add(1);
            }
            let Some(next) = lapsed.next else {
                return Ok(closed);
            };
            page = PageRequest::new(Some(next), limit);
        }
    }

    /// Deletes one export's file first, then closes it, so a file is never
    /// left behind a closed export.
    async fn expire_one(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        mut export: DataExportRequest<ResolvedTenant>,
        now: OffsetDateTime,
    ) -> Result<(), AppError> {
        export.expire(now).map_err(AppError::from_domain)?;
        self.ports
            .files
            .delete(tenant, export.id())
            .await
            .or_internal()?;
        self.ports
            .export_store
            .save(tenant, &export)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ActorRef::System, export.take_events(tenant))
            .await
            .or_internal()
    }
}

impl Command for ExpireExportsUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<u64, AppError>;

    /// Closes every export in every tenant whose window is over at `now`,
    /// deleting its file, records `identity.data_export_expired` for each,
    /// and answers how many were closed.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` if a lapsed export refuses to close.
    /// - `AppError::Internal` when the tenants or their exports cannot be
    ///   read or written, a file cannot be deleted, or what was done cannot
    ///   be recorded.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<u64, AppError> {
        let mut closed: u64 = 0;
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                let tenant_auditor = auditor.with_tenant(*tenant.id());
                let scoped = ScopedTenant::for_background(*tenant.id());
                let here = self.expire_tenant(&scoped, &tenant_auditor, now).await?;
                closed = closed.saturating_add(here);
            }
        }
        Ok(closed)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::identity::privacy::export_state::ExportStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{DataExportId, HttpsUrl, UserId};

    use super::*;
    use crate::test_support::identity::{
        FakeDataExportFiles, FakeDataExportStore, lapsed_export_of, ready_export_of,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor,
    };

    /// Storage that refuses removal while keeping the download interface usable.
    struct RefusingRemoval;

    #[async_trait]
    impl DataExportFiles for RefusingRemoval {
        /// Delegates link creation so this fake fails only file removal.
        async fn download_link(
            &self,
            tenant: &ScopedTenant,
            id: &DataExportId,
            until: OffsetDateTime,
        ) -> Result<HttpsUrl, DomainError> {
            FakeDataExportFiles::default()
                .download_link(tenant, id, until)
                .await
        }

        /// Refuses removal before the request may be persisted as expired.
        async fn delete(&self, _: &ScopedTenant, _: &DataExportId) -> Result<(), DomainError> {
            Err(DomainError::infra_msg("file storage unavailable"))
        }
    }

    fn run(
        store: Arc<FakeDataExportStore>,
        files: Arc<FakeDataExportFiles>,
    ) -> (Result<u64, AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ExpireExportsUseCase::new(ExpireExportsPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            export_store: store,
            files,
        });
        let result = block_on(use_case.execute(&(), &test_auditor(audit.clone()), clock::now()));
        (result, audit)
    }

    /// Ann's export was ready a week and a day ago. Its file is deleted, it
    /// closes, and that is recorded.
    #[test]
    fn a_lapsed_export_is_closed_and_its_file_deleted() {
        let export = lapsed_export_of(UserId::new());
        let id = *export.id();
        let store = Arc::new(FakeDataExportStore::holding(&export));
        let files = Arc::new(FakeDataExportFiles::default());

        let (result, audit) = run(store.clone(), files.clone());

        assert_eq!(result.unwrap(), 1);
        assert_eq!(store.stored(&id).unwrap().status(), ExportStatus::Expired);
        assert_eq!(files.deleted(), [id]);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["identity.data_export_expired"]
        );
    }

    /// More than one batch of expired windows closes completely, deletes
    /// every file, and records each closure without an unbounded read.
    #[test]
    fn expired_exports_are_read_in_bounded_batches() {
        let store = Arc::new(FakeDataExportStore::empty());
        let tenant = ScopedTenant::for_background(*test_tenant_for_ctx().id());
        for _ in 0..501 {
            block_on(store.save(&tenant, &lapsed_export_of(UserId::new()))).unwrap();
        }
        let files = Arc::new(FakeDataExportFiles::default());

        let (result, audit) = run(store.clone(), files.clone());

        assert_eq!(result.unwrap(), 501);
        assert_eq!(files.deleted().len(), 501);
        assert_eq!(audit.records.lock().unwrap().len(), 501);
        assert_eq!(store.lapsed_batch_sizes(), [500, 1]);
    }

    /// A file-removal failure aborts expiry without recording an event.
    /// Both requests stay ready, and a later run with working storage
    /// successfully expires both.
    #[test]
    fn an_export_file_failure_aborts_and_keeps_requests_retryable() {
        let store = Arc::new(FakeDataExportStore::empty());
        let tenant = ScopedTenant::for_background(*test_tenant_for_ctx().id());
        let first = lapsed_export_of(UserId::new());
        let second = lapsed_export_of(UserId::new());
        for export in [&first, &second] {
            block_on(store.save(&tenant, export)).unwrap();
        }
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ExpireExportsUseCase::new(ExpireExportsPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            export_store: store.clone(),
            files: Arc::new(RefusingRemoval),
        });

        let failed = block_on(use_case.execute(&(), &test_auditor(audit.clone()), clock::now()));

        assert!(matches!(failed, Err(AppError::Internal(_))));
        assert!(audit.records.lock().unwrap().is_empty());
        assert_eq!(
            store.stored(first.id()).unwrap().status(),
            ExportStatus::Ready
        );
        assert_eq!(
            store.stored(second.id()).unwrap().status(),
            ExportStatus::Ready
        );
        let (retried, _) = run(store, Arc::new(FakeDataExportFiles::default()));
        assert_eq!(retried.unwrap(), 2);
    }

    /// Failure to audit an export's expiry aborts the sweep after deleting
    /// one file, leaving the second file untouched.
    #[test]
    fn an_export_expiry_audit_failure_aborts_the_sweep() {
        let store = Arc::new(FakeDataExportStore::empty());
        let tenant = ScopedTenant::for_background(*test_tenant_for_ctx().id());
        for _ in 0..2 {
            block_on(store.save(&tenant, &lapsed_export_of(UserId::new()))).unwrap();
        }
        let files = Arc::new(FakeDataExportFiles::default());
        let use_case = ExpireExportsUseCase::new(ExpireExportsPorts {
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            export_store: store,
            files: files.clone(),
        });

        let result = block_on(use_case.execute(
            &(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            clock::now(),
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(files.deleted().len(), 1);
    }

    /// Ann's export became ready today. It stays downloadable and its file
    /// stays.
    #[test]
    fn an_export_still_in_its_window_stays() {
        let export = ready_export_of(UserId::new());
        let id = *export.id();
        let store = Arc::new(FakeDataExportStore::holding(&export));
        let files = Arc::new(FakeDataExportFiles::default());

        let (result, _) = run(store.clone(), files.clone());

        assert_eq!(result.unwrap(), 0);
        assert_eq!(store.stored(&id).unwrap().status(), ExportStatus::Ready);
        assert!(files.deleted().is_empty());
    }
}
