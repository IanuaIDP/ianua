//! Exports of the audit logs, kept in the platform database whatever log
//! they export, so the sweep that ends them finds every one in one read.
//!
//! An export is found only under the log it exports: its id and its log
//! are asked for together. A tenant's export names its tenant and sits
//! under row-level security; the store reads them as platform work, its
//! every query naming the log it reads.

mod record;
mod words;

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::audit::AuditExportStore;
use ianua_domain::domains::audit::access::AuditLogOf;
use ianua_domain::domains::audit::export::{AuditLogExport, WRITE_DEADLINE};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AuditExportId;
use time::OffsetDateTime;

use self::record::{ExportColumns, ExportRecord, scope_of};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of audit log exports.
pub struct PgAuditExportStore {
    databases: Arc<Databases>,
}

impl PgAuditExportStore {
    /// A store keeping exports in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AuditExportStore for PgAuditExportStore {
    async fn save(&self, export: &AuditLogExport) -> Result<(), DomainError> {
        let columns = ExportColumns::of(export)?;
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/audit_exports/save.sql",
                columns.id,
                columns.log,
                columns.organization_id,
                columns.tenant_id,
                columns.requested_by,
                columns.record_filter,
                columns.format,
                columns.status,
                columns.state_at,
                columns.available_until,
                columns.row_count,
                columns.requested_at,
                columns.file_sha256,
                columns.seal,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    async fn find(
        &self,
        log: AuditLogOf,
        id: &AuditExportId,
    ) -> Result<Option<AuditLogExport>, DomainError> {
        let (organization, tenant) = scope_of(log);
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                ExportRecord,
                "queries/audit_exports/of_log.sql",
                id.as_uuid(),
                log.as_str(),
                organization,
                tenant
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(ExportRecord::into_export).transpose()
    }

    async fn pending_count(&self, log: AuditLogOf) -> Result<u64, DomainError> {
        let (organization, tenant) = scope_of(log);
        let count = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_scalar!(
                "queries/audit_exports/pending_of_log.sql",
                log.as_str(),
                organization,
                tenant
            )
            .fetch_one(connection)
            .await
        })
        .await?;
        Ok(u64::try_from(count).unwrap_or_default())
    }

    async fn due_to_end(
        &self,
        now: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<AuditLogExport>, DomainError> {
        let deadline_before = now.saturating_sub(WRITE_DEADLINE);
        let records = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                ExportRecord,
                "queries/audit_exports/due.sql",
                deadline_before,
                now,
                i64::from(limit.get())
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        records.into_iter().map(ExportRecord::into_export).collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::export::DOWNLOAD_WINDOW;
    use ianua_domain::domains::audit::export::seal::WrittenFile;
    use ianua_domain::domains::audit::export::state::AuditExportState;
    use ianua_domain::types::{OrganizationId, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        export_row, export_seal, file_digest, pending_export, saved_organization, saved_tenant_of,
        written_export,
    };

    struct Fixture {
        db: TestDb,
        organization: OrganizationId,
        tenant: TenantId,
        store: PgAuditExportStore,
    }

    /// A fresh database holding Acme and one of its tenants, and the store
    /// on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = *saved_tenant_of(&db.databases, organization).await;
        let store = PgAuditExportStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            organization,
            tenant,
            store,
        }
    }

    /// An export of each log is found under its own log, as it was saved.
    #[tokio::test]
    async fn an_export_is_found_under_its_own_log() {
        let db = fixture().await;
        for log in [
            AuditLogOf::Platform,
            AuditLogOf::Organization(db.organization),
            AuditLogOf::Tenant(db.tenant),
        ] {
            let export = written_export(log, 5);
            db.store.save(&export).await.unwrap();

            let found = db.store.find(log, export.id()).await.unwrap().unwrap();

            assert_eq!(found.state(), export.state());
            assert_eq!(found.format(), export.format());
            assert_eq!(found.requested_at(), export.requested_at());
        }
    }

    /// Looking up a tenant export under its organization's log finds nothing,
    /// as does looking up an unknown export in the correct tenant log.
    #[tokio::test]
    async fn an_export_is_not_found_under_another_log() {
        let db = fixture().await;
        let export = pending_export(AuditLogOf::Tenant(db.tenant), 0);
        db.store.save(&export).await.unwrap();

        let found = db
            .store
            .find(AuditLogOf::Organization(db.organization), export.id())
            .await
            .unwrap();

        assert!(found.is_none());
        assert!(
            db.store
                .find(AuditLogOf::Tenant(db.tenant), &AuditExportId::new())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The worker writes an export: saving it again keeps its window, its
    /// count, its file's digest and its seal.
    #[tokio::test]
    async fn saving_again_keeps_the_written_state() {
        let db = fixture().await;
        let log = AuditLogOf::Tenant(db.tenant);
        let mut export = pending_export(log, 0);
        db.store.save(&export).await.unwrap();
        let file = WrittenFile {
            rows: 1_200,
            digest: file_digest(),
            seal: Some(export_seal()),
        };
        export.mark_written(at(60), file).unwrap();

        db.store.save(&export).await.unwrap();

        let found = db.store.find(log, export.id()).await.unwrap().unwrap();
        assert_eq!(
            found.state(),
            AuditExportState::Ready {
                at: at(60),
                available_until: at(60).saturating_add(DOWNLOAD_WINDOW),
                rows: 1_200,
                digest: file_digest(),
            }
        );
        assert_eq!(found.seal(), Some(&export_seal()));
    }

    /// Taking the seal off a written tenant export breaks the table's own
    /// rule, so an unsealed file can never be read back as ready.
    #[tokio::test]
    #[should_panic(expected = "the tampering statement runs")]
    async fn the_table_refuses_a_ready_tenant_export_without_a_seal() {
        let db = fixture().await;
        let export = written_export(AuditLogOf::Tenant(db.tenant), 1);
        db.store.save(&export).await.unwrap();

        db.db
            .tamper(&format!(
                "UPDATE audit_exports SET seal = NULL WHERE id = '{}'",
                export.id().as_uuid()
            ))
            .await;
    }

    /// Only a log's own exports still being written count against it.
    #[tokio::test]
    async fn a_logs_pending_exports_are_counted() {
        let db = fixture().await;
        let log = AuditLogOf::Tenant(db.tenant);
        for export in [
            pending_export(log, 0),
            pending_export(log, 1),
            written_export(log, 2),
            pending_export(AuditLogOf::Organization(db.organization), 3),
        ] {
            db.store.save(&export).await.unwrap();
        }

        assert_eq!(db.store.pending_count(log).await.unwrap(), 2);
        assert_eq!(
            db.store.pending_count(AuditLogOf::Platform).await.unwrap(),
            0
        );
    }

    /// The exports due to end are those pending past their write deadline
    /// and those ready past their window, oldest first and at most so
    /// many, whatever their log.
    #[tokio::test]
    async fn the_exports_due_to_end_are_found_across_logs() {
        let db = fixture().await;
        let stuck = pending_export(AuditLogOf::Tenant(db.tenant), -10);
        let fresh = pending_export(AuditLogOf::Platform, 601_000);
        let lapsed = written_export(AuditLogOf::Organization(db.organization), 10);
        for export in [&stuck, &fresh, &lapsed] {
            db.store.save(export).await.unwrap();
        }
        let now = at(10)
            .saturating_add(DOWNLOAD_WINDOW)
            .saturating_add(time::Duration::seconds(1));

        let due = db
            .store
            .due_to_end(now, NonZeroU32::new(10).unwrap())
            .await
            .unwrap();
        let first = db
            .store
            .due_to_end(now, NonZeroU32::new(1).unwrap())
            .await
            .unwrap();

        let ids: Vec<_> = due.iter().map(|export| *export.id()).collect();
        assert_eq!(ids, [*stuck.id(), *lapsed.id()]);
        assert_eq!(first.len(), 1);
    }

    /// Reading an export whose stored availability was extended by a year
    /// returns a corruption error.
    #[tokio::test]
    async fn an_export_with_a_stretched_window_is_refused() {
        let db = fixture().await;
        let log = AuditLogOf::Platform;
        let export = written_export(log, 5);
        db.store.save(&export).await.unwrap();
        db.db
            .tamper(
                "UPDATE audit_exports SET available_until = available_until + interval '1 year'",
            )
            .await;

        let read = db.store.find(log, export.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Saving an export for an unknown tenant returns an infrastructure error.
    #[tokio::test]
    async fn an_export_of_an_unknown_tenant_is_refused() {
        let db = fixture().await;
        let export = AuditLogExport::reconstitute(export_row(
            AuditLogOf::Tenant(TenantId::new()),
            AuditExportState::Pending,
            0,
        ))
        .unwrap();

        let saved = db.store.save(&export).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }
}
