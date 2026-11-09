//! A tenant's sandboxes, each table row under row-level security. A list
//! reads the ids of its page first, in its order, then reads those
//! sandboxes through the one query by ids.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{SandboxSortField, SandboxStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::sandbox::Sandbox;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SandboxId;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{SandboxColumns, SandboxRecord};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of sandboxes.
pub struct PgSandboxStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSandboxStore {}

impl PgSandboxStore {
    /// A store keeping sandboxes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl SortColumns for SandboxSortField {
    fn column(self) -> &'static str {
        match self {
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The records of the sandboxes of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<SandboxRecord>, sqlx::Error> {
    sqlx::query_file_as!(SandboxRecord, "queries/sandboxes/by_ids.sql", tenant, ids)
        .fetch_all(connection)
        .await
}

fn rebuilt_all(records: Vec<SandboxRecord>) -> Result<Vec<Sandbox<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(SandboxRecord::into_sandbox)
        .collect()
}

#[async_trait]
impl SandboxStore for PgSandboxStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SandboxId,
    ) -> Result<Option<Sandbox<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<SandboxSortField>,
        page: &PageRequest,
    ) -> Result<Page<Sandbox<ResolvedTenant>>, DomainError> {
        let keyset = page.keyset(sort)?;
        let listed =
            PageQuery::ids("id", "sandboxes").filter("tenant_id = ?", *tenant_id.as_uuid());
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, tenant_id.as_uuid(), &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        sandbox: &Sandbox<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = SandboxColumns::of(sandbox)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/sandboxes/save.sql",
                    c.id,
                    tenant_id.as_uuid(),
                    c.name,
                    c.kind,
                    c.language,
                    c.status,
                    c.latest_version,
                    c.created_by,
                    c.created_at,
                    c.updated_at,
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::control::WorkflowControl;
    use ianua_domain::domains::workflows::sandbox::runtime::Language;
    use ianua_domain::domains::workflows::sandbox::{
        CreateSandboxParams, SandboxKind, SandboxStatus,
    };
    use ianua_domain::test_support::authority::assumed_authority;
    use ianua_domain::types::{Label, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::workflows::ann;

    const MANAGES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Manage)];

    /// A store over a fresh database, and one tenant in it.
    struct Fixture {
        _db: TestDb,
        sandboxes: PgSandboxStore,
        tenant: ScopedTenant,
    }

    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            sandboxes: PgSandboxStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            _db: db,
        }
    }

    /// A JavaScript sandbox called `name`, made by Ann, who manages
    /// workflows in `tenant`.
    fn made(tenant: &ScopedTenant, name: &str) -> Sandbox<ResolvedTenant> {
        made_of(tenant, name, SandboxKind::Code(Language::JavaScript))
    }

    /// A sandbox of `kind` called `name`, made by Ann in `tenant`.
    fn made_of(tenant: &ScopedTenant, name: &str, kind: SandboxKind) -> Sandbox<ResolvedTenant> {
        let authority = assumed_authority(&ann(), **tenant, &MANAGES, &[]);
        Sandbox::create(
            CreateSandboxParams {
                name: Label::new("name", name).unwrap(),
                kind,
            },
            &WorkflowControl::new(authority),
        )
        .unwrap()
    }

    /// Ann makes a sandbox for her company's image. It reads back as an
    /// image sandbox with no language.
    #[tokio::test]
    async fn an_image_sandbox_reads_back_with_no_language() {
        let f = fixture().await;
        let sandbox = made_of(&f.tenant, "Code generator", SandboxKind::OwnImage);

        f.sandboxes.save(&f.tenant, &sandbox).await.unwrap();
        let found = f
            .sandboxes
            .find_by_id(&f.tenant, sandbox.id())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found.kind(), SandboxKind::OwnImage);
    }

    /// Ann makes a sandbox and archives it. It reads back as she left it,
    /// its name, language, status and maker kept, the save overwriting the
    /// first.
    #[tokio::test]
    async fn a_sandbox_reads_back_as_it_was_saved() {
        let f = fixture().await;
        let mut sandbox = made(&f.tenant, "Clean titles");
        f.sandboxes.save(&f.tenant, &sandbox).await.unwrap();
        let authority = assumed_authority(&ann(), *f.tenant, &MANAGES, &[]);
        sandbox.archive(&WorkflowControl::new(authority)).unwrap();

        f.sandboxes.save(&f.tenant, &sandbox).await.unwrap();
        let found = f
            .sandboxes
            .find_by_id(&f.tenant, sandbox.id())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found.name(), sandbox.name());
        assert_eq!(found.kind(), SandboxKind::Code(Language::JavaScript));
        assert_eq!(found.status(), SandboxStatus::Archived);
        assert_eq!(found.created_by(), sandbox.created_by());
    }

    /// Ann's tenant holds three sandboxes. Listed by name two at a time,
    /// the first page holds the first two, and the next the third.
    #[tokio::test]
    async fn sandboxes_are_listed_in_name_order_a_page_at_a_time() {
        let f = fixture().await;
        for name in ["Charlie", "Alpha", "Bravo"] {
            f.sandboxes
                .save(&f.tenant, &made(&f.tenant, name))
                .await
                .unwrap();
        }
        let by_name = SortOrder::<SandboxSortField>::parse(Some("name")).unwrap();

        let first = f
            .sandboxes
            .list(
                &f.tenant,
                &by_name,
                &PageRequest::first(Limit::new(2).unwrap()),
            )
            .await
            .unwrap();
        let names: Vec<&str> = first.items.iter().map(|one| one.name().as_str()).collect();

        assert_eq!(names, ["Alpha", "Bravo"]);
        assert!(first.next.is_some());
    }

    /// Another tenant's lookup cannot find Ann's sandbox, and its sandbox
    /// listing is empty.
    #[tokio::test]
    async fn another_tenant_sees_no_sandbox_of_ann() {
        let f = fixture().await;
        let sandbox = made(&f.tenant, "Clean titles");
        f.sandboxes.save(&f.tenant, &sandbox).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let found = f.sandboxes.find_by_id(&other, sandbox.id()).await.unwrap();
        let listed = f
            .sandboxes
            .list(
                &other,
                &SortOrder::default(),
                &PageRequest::first(Limit::new(10).unwrap()),
            )
            .await
            .unwrap();

        assert!(found.is_none());
        assert!(listed.items.is_empty());
    }
}
