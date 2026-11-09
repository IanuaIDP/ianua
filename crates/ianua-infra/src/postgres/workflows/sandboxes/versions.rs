//! The saved versions of a tenant's sandboxes, each table row under
//! row-level security. A sandbox's version number is kept once, so two
//! saves made at once cannot both become the same version. A build is
//! written only while the version is still being built.

mod held;
mod record;
mod source;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::{NewestFirstField, SandboxVersionStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::sandbox::version::SandboxVersion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{SandboxId, SandboxVersionId};
use sqlx::postgres::PgArguments;
use sqlx::query::Query;
use sqlx::{PgConnection, Postgres};
use uuid::Uuid;

use self::record::{BuildColumns, VersionColumns, VersionRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{PageQuery, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps one version of each number per sandbox.
const NUMBER_ONCE: &str = "sandbox_versions_number_once";

/// The Postgres store of sandbox versions.
pub struct PgSandboxVersionStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgSandboxVersionStore {}

impl PgSandboxVersionStore {
    /// A store keeping sandbox versions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The records of the versions of `tenant` that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<VersionRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        VersionRecord,
        "queries/sandbox_versions/by_ids.sql",
        tenant,
        ids
    )
    .fetch_all(connection)
    .await
}

fn rebuilt_all(
    records: Vec<VersionRecord>,
) -> Result<Vec<SandboxVersion<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(VersionRecord::into_version)
        .collect()
}

/// Binds every version column to the checked insert before execution in the tenant scope.
#[expect(
    clippy::too_many_lines,
    reason = "one checked insert binds each of the version's columns in order"
)]
fn insert_query(tenant: &Uuid, c: &VersionColumns<'_>) -> Query<'static, Postgres, PgArguments> {
    sqlx::query_file!(
        "queries/sandbox_versions/insert.sql",
        c.id,
        tenant,
        c.sandbox_id,
        c.number,
        c.program,
        c.runtime,
        c.image,
        c.code,
        c.packages,
        c.image_bytes,
        c.run_seconds,
        c.memory_mib,
        c.build.build,
        c.build.bundle_digest,
        c.build.bundle_bytes,
        c.build.unlisted.as_deref(),
        c.build.failure,
        c.build.failure_detail,
        c.build.scan.scan_high,
        c.build.scan.scan_medium,
        c.build.scan.scan_low,
        c.saved_by,
        c.created_at,
        c.updated_at,
        &c.allowed_hosts,
        c.source.integration,
        c.source.repository,
        c.source.path,
        c.source.commit,
        c.held_agent,
    )
}

/// Binds `version`'s build columns `b` to the checked update that writes
/// them only while it is still being built.
fn save_build_query<'a>(
    tenant: &'a Uuid,
    version: &'a SandboxVersion<ResolvedTenant>,
    b: &'a BuildColumns,
) -> Query<'a, Postgres, PgArguments> {
    sqlx::query_file!(
        "queries/sandbox_versions/save_build.sql",
        tenant,
        version.id().as_uuid(),
        b.build,
        b.bundle_digest.as_deref(),
        b.bundle_bytes,
        b.unlisted.as_deref(),
        b.failure,
        b.failure_detail.as_deref(),
        b.scan.scan_high,
        b.scan.scan_medium,
        b.scan.scan_low,
        version.updated_at(),
    )
}

#[async_trait]
impl SandboxVersionStore for PgSandboxVersionStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &SandboxVersionId,
    ) -> Result<Option<SandboxVersion<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id.as_uuid(), &ids).await,
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list_of(
        &self,
        tenant_id: &ScopedTenant,
        sandbox_id: &SandboxId,
        page: &PageRequest,
    ) -> Result<Page<SandboxVersion<ResolvedTenant>>, DomainError> {
        let order = SortOrder::<NewestFirstField>::default();
        let keyset = page.keyset(&order)?;
        let listed = PageQuery::ids("id", "sandbox_versions")
            .filter("tenant_id = ?", *tenant_id.as_uuid())
            .filter("sandbox_id = ?", *sandbox_id.as_uuid());
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

    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        version: &SandboxVersion<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let c = VersionColumns::of(version)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = insert_query(tenant_id.as_uuid(), &c)
                    .execute(connection)
                    .await;
                unique_on(attempt, NUMBER_ONCE)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-version-of-the-sandbox-was-saved",
                "another version of the sandbox was saved meanwhile; save again"
            ))),
        }
    }

    async fn save_build(
        &self,
        tenant_id: &ScopedTenant,
        version: &SandboxVersion<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let b = BuildColumns::of(version.build())?;
        let done = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                save_build_query(tenant_id.as_uuid(), version, &b)
                    .execute(connection)
                    .await
            },
        )
        .await?;
        if done.rows_affected() == 0 {
            return Err(DomainError::conflict(message!(
                "workflows-the-version-was-built-already",
                "the version's bundle was built or failed already"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::Limit;
    use ianua_app::ports::workflows::SandboxStore;
    use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
    use ianua_domain::domains::agents::execution::run::{CheckTries, GoalTemplate};
    use ianua_domain::domains::agents::execution::tool::ToolName;
    use ianua_domain::domains::agents::execution::usage::Spend;
    use ianua_domain::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use ianua_domain::domains::workflows::control::WorkflowControl;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::sandbox::agent::{HeldAgent, HeldAgentParams};
    use ianua_domain::domains::workflows::sandbox::build::{
        Build, BuildFailure, Bundle, BundleDigest,
    };
    use ianua_domain::domains::workflows::sandbox::image::{
        ImageFindings, LesserFindings, OwnImage, PinnedImage,
    };
    use ianua_domain::domains::workflows::sandbox::network::{AllowedHost, NetworkAccess};
    use ianua_domain::domains::workflows::sandbox::package::{
        PackageName, PackageVersion, Packages, PinnedPackage,
    };
    use ianua_domain::domains::workflows::sandbox::recipe::{
        CodeParams, CodeProgram, Program, RunBudget, SandboxCode,
    };
    use ianua_domain::domains::workflows::sandbox::runtime::{Language, Runtime, RuntimeImage};
    use ianua_domain::domains::workflows::sandbox::source::{
        CodeSource, CommitSha, RepositoryFile, RepositoryName, RepositoryPath,
    };
    use ianua_domain::domains::workflows::sandbox::{
        CreateSandboxParams, Sandbox, SandboxKind, VersionDraft,
    };
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::test_support::authority::assumed_authority;
    use ianua_domain::types::{ActionClass, AgentId, Label, ModelProviderId, TenantId};

    use super::*;
    use crate::postgres::workflows::PgSandboxStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::workflows::ann;

    const MANAGES: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::Manage)];

    struct Fixture {
        _db: TestDb,
        sandboxes: PgSandboxStore,
        versions: PgSandboxVersionStore,
        tenant: ScopedTenant,
        sandbox: Sandbox<ResolvedTenant>,
    }

    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let sandboxes = PgSandboxStore::new(Arc::clone(&db.databases));
        let ann = ann();
        let authority = assumed_authority(&ann, *tenant, &MANAGES, &[]);
        let sandbox = Sandbox::create(
            CreateSandboxParams {
                name: Label::new("name", "Clean issue text").unwrap(),
                kind: SandboxKind::Code(Language::Python),
            },
            &WorkflowControl::new(authority),
        )
        .unwrap();
        sandboxes.save(&tenant, &sandbox).await.unwrap();
        Fixture {
            versions: PgSandboxVersionStore::new(Arc::clone(&db.databases)),
            sandboxes,
            tenant,
            sandbox,
            _db: db,
        }
    }

    fn draft() -> VersionDraft {
        let pinned = |name: &str, version: &str| {
            PinnedPackage::new(
                PackageName::new(Language::Python, name).unwrap(),
                PackageVersion::new(Language::Python, version).unwrap(),
            )
        };
        let code = CodeProgram::new(CodeParams {
            runtime: Runtime::Python313,
            image: RuntimeImage::new(format!("python:3.13-slim@sha256:{}", "ae".repeat(32)))
                .unwrap(),
            code: SandboxCode::new("def main(item):\n\treturn item\n").unwrap(),
            packages: Packages::new(vec![pinned("requests", "2.31.0"), pinned("idna", "3.7")])
                .unwrap(),
        })
        .unwrap();
        VersionDraft {
            program: Program::Code(code),
            budget: RunBudget::new(30, 256).unwrap(),
            network: NetworkAccess::new(vec![
                AllowedHost::new("api.github.com").unwrap(),
                AllowedHost::new("pypi.org").unwrap(),
            ])
            .unwrap(),
            source: CodeSource::Imported(RepositoryFile {
                integration: IntegrationKey::new("github").unwrap(),
                repository: RepositoryName::new("acme/web").unwrap(),
                path: RepositoryPath::new("scripts/tidy.py").unwrap(),
                commit: CommitSha::new("c".repeat(40)).unwrap(),
            }),
        }
    }

    impl Fixture {
        fn saved(&mut self) -> SandboxVersion<ResolvedTenant> {
            let ann = ann();
            let authority = assumed_authority(&ann, *self.tenant, &MANAGES, &[]);
            self.sandbox
                .save_version(&WorkflowControl::new(authority), draft())
                .unwrap()
        }

        async fn found(&self, id: &SandboxVersionId) -> SandboxVersion<ResolvedTenant> {
            self.versions
                .find_by_id(&self.tenant, id)
                .await
                .unwrap()
                .unwrap()
        }
    }

    /// Ann saves version 1 of her sandbox, its code imported from a
    /// repository. It reads back with its code, the file and commit it came
    /// from, packages in their order, limits and the hosts it may reach,
    /// still building, and the sandbox's latest number reads back as 1.
    /// Another tenant finds neither.
    #[tokio::test]
    async fn a_saved_version_reads_back_as_it_was_saved() {
        let mut fx = fixture().await;
        let version = fx.saved();
        fx.versions.insert(&fx.tenant, &version).await.unwrap();
        fx.sandboxes.save(&fx.tenant, &fx.sandbox).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let found = fx.found(version.id()).await;
        let sandbox = fx
            .sandboxes
            .find_by_id(&fx.tenant, fx.sandbox.id())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found.recipe(), version.recipe());
        assert_eq!(found.source(), version.source());
        assert_eq!(found.build(), &Build::Building);
        assert_eq!(sandbox.latest_version(), 1);
        assert!(
            fx.versions
                .find_by_id(&other, version.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fx.sandboxes
                .find_by_id(&other, fx.sandbox.id())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Ann saves a version holding an agent that drafts replies, its code
    /// the check of every reply. It reads back holding the agent and the
    /// rules it works under; a plain version reads back holding code.
    #[tokio::test]
    async fn a_version_holding_an_agent_reads_back_with_its_rules() {
        let mut fx = fixture().await;
        let ann = ann();
        let authority = assumed_authority(&ann, *fx.tenant, &MANAGES, &[]);
        let rules = drafter();
        let held = fx
            .sandbox
            .save_agent_version(&WorkflowControl::new(authority), draft(), rules.clone())
            .unwrap();
        let plain = fx.saved();
        fx.versions.insert(&fx.tenant, &held).await.unwrap();
        fx.versions.insert(&fx.tenant, &plain).await.unwrap();

        let found = fx.found(held.id()).await;

        assert_eq!(found.held_agent(), Some(&rules));
        assert_eq!(fx.found(plain.id()).await.held_agent(), None);
    }

    /// The rules of an agent drafting replies with two tries.
    fn drafter() -> HeldAgent {
        HeldAgent::new(HeldAgentParams {
            agent_id: AgentId::new(),
            provider_id: ModelProviderId::new(),
            goal: GoalTemplate::new("Draft a reply to the customer").unwrap(),
            purpose: IntentEnvelope::new([ActionClass::Read]),
            tools: vec![ToolName::new("search_orders").unwrap()],
            approval_classes: vec![ActionClass::Communicate],
            max_steps: 12,
            spend_cap: Spend::from_micros(2_000_000),
            ask_past: Restriction::To(Spend::from_micros(1_000_000)),
            tries: CheckTries::new(2).unwrap(),
        })
        .unwrap()
    }

    /// Two drafts from the same sandbox state both have version number 2;
    /// inserting the second after the first returns a conflict.
    #[tokio::test]
    async fn a_number_is_taken_once_per_sandbox() {
        let mut fx = fixture().await;
        let first = fx.saved();
        fx.versions.insert(&fx.tenant, &first).await.unwrap();
        let read = fx.sandbox.clone();
        let second = fx.saved();
        fx.sandbox = read;
        let racing = fx.saved();
        fx.versions.insert(&fx.tenant, &second).await.unwrap();

        let refused = fx.versions.insert(&fx.tenant, &racing).await;

        assert_eq!((second.number(), racing.number()), (2, 2));
        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// The version's bundle comes ready and reads back so. A second try,
    /// which then fails the copy it read, is refused, and the ready bundle
    /// stands. A failure on another version reads back naming its package.
    #[tokio::test]
    async fn a_build_is_written_once() {
        let mut fx = fixture().await;
        let mut ready = fx.saved();
        let mut broken = fx.saved();
        fx.versions.insert(&fx.tenant, &ready).await.unwrap();
        fx.versions.insert(&fx.tenant, &broken).await.unwrap();
        let mut late = ready.clone();
        let idna = PackageName::new(Language::Python, "certifi").unwrap();
        let bundle =
            Bundle::new(BundleDigest::new("d".repeat(64)).unwrap(), 4096, vec![idna]).unwrap();
        let requests = PackageName::new(Language::Python, "requests").unwrap();
        ready.finish_build(bundle.clone()).unwrap();
        late.fail_build(BuildFailure::RegistryUnavailable).unwrap();
        broken
            .fail_build(BuildFailure::FingerprintMismatch(requests.clone()))
            .unwrap();

        fx.versions.save_build(&fx.tenant, &ready).await.unwrap();
        let second = fx.versions.save_build(&fx.tenant, &late).await;
        fx.versions.save_build(&fx.tenant, &broken).await.unwrap();

        assert!(matches!(second, Err(DomainError::Conflict(_))));
        assert_eq!(fx.found(ready.id()).await.build(), &Build::Ready(bundle));
        assert_eq!(
            fx.found(broken.id()).await.build(),
            &Build::Failed(BuildFailure::FingerprintMismatch(requests))
        );
    }

    /// A sandbox's versions list newest first, one page at a time.
    #[tokio::test]
    async fn versions_list_newest_first() {
        let mut fx = fixture().await;
        for _ in 0..3 {
            let version = fx.saved();
            fx.versions.insert(&fx.tenant, &version).await.unwrap();
        }

        let page = fx
            .versions
            .list_of(
                &fx.tenant,
                fx.sandbox.id(),
                &PageRequest::first(Limit::new(2).unwrap()),
            )
            .await
            .unwrap();

        let numbers: Vec<u32> = page.items.iter().map(SandboxVersion::number).collect();
        assert_eq!(numbers, [3, 2]);
        assert!(page.next.is_some());
    }

    /// A version of Ann's company's code generator image, pinned to its
    /// digest, 80 MiB in size, with no network.
    fn codegen_image() -> VersionDraft {
        let image = PinnedImage::parse(&format!(
            "registry.acme.example/tools/codegen@sha256:{}",
            "ef".repeat(32)
        ))
        .unwrap();
        VersionDraft {
            program: Program::Image(OwnImage::new(image, 80 * 1024 * 1024).unwrap()),
            budget: RunBudget::new(60, 512).unwrap(),
            network: NetworkAccess::closed(),
            source: CodeSource::Written,
        }
    }

    /// Ann saves a version of her company's code generator image in an
    /// image sandbox. It reads back pinned to its digest with its size,
    /// and once its scan cleared it, with what the scan found.
    #[tokio::test]
    async fn an_image_version_reads_back_with_its_scan() {
        let fx = fixture().await;
        let control = WorkflowControl::new(assumed_authority(&ann(), *fx.tenant, &MANAGES, &[]));
        let mut sandbox = Sandbox::create(
            CreateSandboxParams {
                name: Label::new("name", "Code generator").unwrap(),
                kind: SandboxKind::OwnImage,
            },
            &control,
        )
        .unwrap();
        fx.sandboxes.save(&fx.tenant, &sandbox).await.unwrap();
        let mut version = sandbox.save_version(&control, codegen_image()).unwrap();
        fx.versions.insert(&fx.tenant, &version).await.unwrap();
        let high = LesserFindings {
            high: 1,
            ..LesserFindings::default()
        };
        version
            .finish_scan(&ImageFindings::new(Vec::new(), high))
            .unwrap();

        fx.versions.save_build(&fx.tenant, &version).await.unwrap();

        let found = fx.found(version.id()).await;
        assert_eq!(found.recipe(), version.recipe());
        assert_eq!(found.build(), &Build::Cleared(high));
    }
}
