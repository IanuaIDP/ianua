//! Imports of accounts from another system, and how far the worker got.
//!
//! An import is one row of `user_imports`, and the records it was sent are
//! rows of `user_import_records`, password hashes included, read only
//! through this store. The records are written once, in one statement,
//! when the import is first kept; saving its progress after each chunk
//! writes the import's own row alone.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::identity::UserImportStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::account::import::run::UserImport;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UserImportId;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{RunColumns, RunRecord, SentColumns, SentRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// Whether a save added the import or took its progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Saved {
    /// The import is new, so its records still have to be written.
    New,
    /// The import was known; only its progress changed.
    Known,
    /// Another tenant holds an import under this id, so nothing was written.
    Elsewhere,
}

/// The Postgres store of user imports.
pub struct PgUserImportStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl TenantScoped for PgUserImportStore {}

impl PgUserImportStore {
    /// A store keeping imports in `databases`, checking each stored name
    /// against `limits` as it is read back.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }
}

/// Keeps the import's own row, and answers whether it was new.
async fn keep_run(
    connection: &mut PgConnection,
    tenant: &Uuid,
    run: &RunColumns<'_>,
) -> Result<Saved, sqlx::Error> {
    let inserted = sqlx::query_file_scalar!(
        "queries/user_imports/save.sql",
        run.id,
        tenant,
        run.started_by,
        run.status,
        run.ended_at,
        run.total,
        run.done,
        run.imported,
        &run.refused_lines,
        &run.refused_reasons,
        run.created_at,
    )
    .fetch_optional(connection)
    .await?;
    Ok(match inserted {
        Some(true) => Saved::New,
        Some(false) => Saved::Known,
        None => Saved::Elsewhere,
    })
}

/// Writes the records of a new import in one statement.
async fn add_records(
    connection: &mut PgConnection,
    (tenant, import): (&Uuid, &Uuid),
    sent: &SentColumns,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/user_import_records/add.sql",
        tenant,
        import,
        &sent.lines,
        &sent.emails,
        &sent.display_names,
        &sent.given_names as &[Option<String>],
        &sent.family_names as &[Option<String>],
        &sent.preferred_usernames as &[Option<String>],
        &sent.pictures as &[Option<String>],
        &sent.phone_numbers as &[Option<String>],
        &sent.external_ids as &[Option<String>],
        &sent.departments as &[Option<String>],
        &sent.manager_ids as &[Option<Uuid>],
        &sent.employee_numbers as &[Option<String>],
        &sent.password_hashes as &[Option<String>],
    )
    .execute(connection)
    .await
    .map(|_| ())
}

#[async_trait]
impl UserImportStore for PgUserImportStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        import: &UserImport<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let run = RunColumns::of(import)?;
        let kept = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let kept = keep_run(&mut *connection, tenant_id.as_uuid(), &run).await?;
                if kept == Saved::New {
                    let ids = (tenant_id.as_uuid(), run.id);
                    add_records(connection, ids, &SentColumns::of(import)).await?;
                }
                Ok(kept)
            },
        )
        .await?;
        if kept == Saved::Elsewhere {
            return Err(DomainError::conflict(message!(
                "infra-another-import-already-has-this-id",
                "another import already has this id"
            )));
        }
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &UserImportId,
    ) -> Result<Option<UserImport<ResolvedTenant>>, DomainError> {
        let found = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let run = sqlx::query_file_as!(
                    RunRecord,
                    "queries/user_imports/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(&mut *connection)
                .await?;
                let Some(run) = run else {
                    return Ok(None);
                };
                let sent = sqlx::query_file_as!(
                    SentRecord,
                    "queries/user_import_records/of_import.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_all(connection)
                .await?;
                Ok(Some((run, sent)))
            },
        )
        .await?;
        found
            .map(|(run, sent)| run.into_import(sent, &self.limits))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::import::password_hash::ImportedPasswordHash;
    use ianua_domain::domains::identity::account::import::refusal::{
        FailedRecord, RecordLine, RecordRefusal,
    };
    use ianua_domain::domains::identity::account::import::run::{ChunkOutcome, UserImportRow};
    use ianua_domain::domains::identity::account::import::state::ImportStatus;
    use ianua_domain::domains::identity::account::import::{ImportRecord, ImportedPassword};
    use ianua_domain::types::{TenantId, UserId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::identity::{import_record, import_row};

    /// A bcrypt hash another system kept.
    const BCRYPT: &str = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

    /// A fresh database, the store on it, and one tenant to keep imports in.
    async fn fixture() -> (TestDb, PgUserImportStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgUserImportStore::new(Arc::clone(&db.databases), DomainLimits::default());
        (db, store, ScopedTenant::for_background(TenantId::new()))
    }

    fn with_password(email: &str) -> ImportRecord {
        ImportRecord {
            password: ImportedPassword::Hash(ImportedPasswordHash::parse(BCRYPT).unwrap()),
            ..import_record(email)
        }
    }

    fn import(row: UserImportRow) -> UserImport<ResolvedTenant> {
        UserImport::reconstitute(row).unwrap()
    }

    /// An import of three records, one with its password hash, is found
    /// again as it was sent, its records in the order they came.
    #[tokio::test]
    async fn a_kept_import_is_found_with_its_records_in_order() {
        let (_db, store, tenant) = fixture().await;
        let sent = import(UserImportRow {
            records: vec![
                import_record("cid@acme.example"),
                with_password("ann@acme.example"),
                import_record("bob@acme.example"),
            ],
            ..import_row(UserId::new(), &[])
        });

        store.save(&tenant, &sent).await.unwrap();

        let found = store.find_by_id(&tenant, sent.id()).await.unwrap().unwrap();
        assert_eq!(found.records(), sent.records());
        assert_eq!(found.status(), ImportStatus::Pending);
        assert_eq!(found.counts(), sent.counts());
    }

    /// The worker takes an import up and records its only chunk, one record
    /// refused: saving it again keeps the progress and the records once.
    #[tokio::test]
    async fn saving_progress_keeps_it_and_the_records_once() {
        let (_db, store, tenant) = fixture().await;
        let mut sent = import(import_row(
            UserId::new(),
            &["ann@acme.example", "bob@acme.example"],
        ));
        store.save(&tenant, &sent).await.unwrap();
        sent.take_up().unwrap();
        let end = sent.next_chunk().unwrap().end();
        sent.record_chunk(
            ChunkOutcome {
                end,
                imported: 1,
                refused: vec![FailedRecord::new(
                    RecordLine::new(2).unwrap(),
                    RecordRefusal::AddressTaken,
                )],
            },
            at(60),
        )
        .unwrap();

        store.save(&tenant, &sent).await.unwrap();

        let found = store.find_by_id(&tenant, sent.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), ImportStatus::Finished);
        assert_eq!(found.state(), sent.state());
        assert_eq!(found.refused(), sent.refused());
        assert_eq!(found.records().len(), 2);
    }

    /// An id nobody kept finds nothing, and another tenant finds none of
    /// Acme's imports.
    #[tokio::test]
    async fn an_unknown_or_another_tenants_import_is_not_found() {
        let (_db, store, tenant) = fixture().await;
        let sent = import(import_row(UserId::new(), &["ann@acme.example"]));
        store.save(&tenant, &sent).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        assert!(
            store
                .find_by_id(&tenant, &UserImportId::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.find_by_id(&other, sent.id()).await.unwrap().is_none());
    }

    /// An import containing an invalid stored email address fails to load
    /// as corrupt storage.
    #[tokio::test]
    async fn an_import_with_a_broken_record_is_refused() {
        let (db, store, tenant) = fixture().await;
        let sent = import(import_row(UserId::new(), &["ann@acme.example"]));
        store.save(&tenant, &sent).await.unwrap();
        db.tamper("UPDATE user_import_records SET email = 'not an address'")
            .await;

        let read = store.find_by_id(&tenant, sent.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Deleting Bob's stored row from a two-person import makes the import
    /// fail to load as corrupt storage.
    #[tokio::test]
    async fn an_import_missing_a_record_is_refused() {
        let (db, store, tenant) = fixture().await;
        let sent = import(import_row(
            UserId::new(),
            &["cid@acme.example", "bob@acme.example"],
        ));
        store.save(&tenant, &sent).await.unwrap();
        db.tamper("DELETE FROM user_import_records WHERE email = 'bob@acme.example'")
            .await;

        let read = store.find_by_id(&tenant, sent.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
