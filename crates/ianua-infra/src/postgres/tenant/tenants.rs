//! Tenants, kept in the platform database.
//!
//! Every read of a tenant goes through one checked query by ids, or by
//! slug, and one mapping into the aggregate. A list or a batch first reads
//! the ids it holds, then reads those rows the same way.

mod record;
mod words;

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Keyset, Page, PageRequest, SortOrder};
use ianua_app::ports::tenant::{TenantSortField, TenantStore};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::domains::tenant::status::{ARCHIVE_GRACE, TenantStatus};
use ianua_domain::message;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId, TenantId, TenantSlug};
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{TenantColumns, TenantRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a slug to one tenant of an organization.
const SLUG_KEY: &str = "tenants_organization_slug_key";

/// The Postgres tenant store.
pub struct PgTenantStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgTenantStore {
    /// A store keeping tenants in `databases`, checking each stored name
    /// against `limits` as it is read back.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }

    fn rebuilt(&self, record: TenantRecord) -> Result<Tenant, DomainError> {
        record.into_tenant(&self.limits)
    }

    fn rebuilt_all(&self, records: Vec<TenantRecord>) -> Result<Vec<Tenant>, DomainError> {
        records
            .into_iter()
            .map(|record| self.rebuilt(record))
            .collect()
    }

    /// The page `keyset` asks for of the tenants `listed` finds, read in
    /// `scope`.
    async fn page(
        &self,
        scope: RowScope,
        listed: PageQuery<'static>,
        keyset: Keyset<'_, SortOrder<TenantSortField>>,
    ) -> Result<Page<Tenant>, DomainError> {
        let records = scoped(&self.databases, scope, async |connection| {
            let ids = listed.fetch(&keyset, &mut *connection).await?;
            let records = records_of(connection, &ids).await?;
            Ok(in_page_order(&ids, records, |record| record.id))
        })
        .await?;
        Ok(keyset.seal(self.rebuilt_all(records)?))
    }
}

/// The records of the tenants `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<TenantRecord>, sqlx::Error> {
    sqlx::query_file_as!(TenantRecord, "queries/tenants/by_ids.sql", ids)
        .fetch_all(connection)
        .await
}

/// The records of the tenants `ids` names, in the order of `ids`.
async fn records_in_order(
    connection: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<TenantRecord>, sqlx::Error> {
    let records = records_of(connection, ids).await?;
    Ok(in_page_order(ids, records, |record| record.id))
}

/// Writes the mapped tenant columns in the platform database.
async fn write_columns(
    connection: &mut PgConnection,
    columns: &TenantColumns<'_>,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query_file!(
        "queries/tenants/save.sql",
        columns.id,
        columns.organization_id,
        columns.slug,
        columns.display_name,
        columns.primary_domain,
        columns.contact_email,
        columns.status,
        columns.held,
        columns.archived_at,
        columns.compliance,
        columns.auth_config,
        columns.mtls,
        columns.timezone,
        columns.locale,
        columns.residency,
        columns.customer_cloud,
        columns.environment,
        columns.created_at,
        columns.updated_at,
        columns.platform_label,
        columns.readable_address,
    )
    .execute(connection)
    .await
}

impl SortColumns for TenantSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::DisplayName => "display_name",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The ids of every tenant.
fn every_tenant() -> PageQuery<'static> {
    PageQuery::ids("id", "tenants")
}

/// `listed` narrowed to `status`, or to every tenant not deleted.
fn in_status(listed: PageQuery<'static>, status: Option<TenantStatus>) -> PageQuery<'static> {
    let Some(status) = status else {
        return listed.keep("status <> 'deleted'");
    };
    listed.filter("status = ?", status.word())
}

#[async_trait]
impl TenantStore for PgTenantStore {
    async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            records_of(connection, &ids).await
        })
        .await?;
        records
            .into_iter()
            .next()
            .map(|record| self.rebuilt(record))
            .transpose()
    }

    async fn find_by_slug_in_org(
        &self,
        slug: &TenantSlug,
        organization_id: &OrganizationId,
    ) -> Result<Option<Arc<Tenant>>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                TenantRecord,
                "queries/tenants/by_slug_in_organization.sql",
                slug.as_str(),
                organization_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record
            .map(|record| self.rebuilt(record).map(Arc::new))
            .transpose()
    }

    async fn slug_exists_in_org(
        &self,
        slug: &TenantSlug,
        organization_id: &OrganizationId,
    ) -> Result<bool, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/tenants/slug_taken.sql",
                slug.as_str(),
                organization_id.as_uuid()
            )
            .fetch_one(connection)
            .await
        })
        .await
    }

    async fn list_by_organization(
        &self,
        organization_id: &OrganizationId,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        page: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        let held = every_tenant().filter("organization_id = ?", *organization_id.as_uuid());
        self.page(
            RowScope::Unscoped,
            in_status(held, status),
            page.keyset(sort)?,
        )
        .await
    }

    async fn list_granted_to_org_user(
        &self,
        org_user_id: &OrgUserId,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        page: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        let granted = every_tenant().filter(
            "id IN (SELECT tenant_id FROM org_tenant_grants WHERE org_user_id = ?)",
            *org_user_id.as_uuid(),
        );
        self.page(
            RowScope::Platform,
            in_status(granted, status),
            page.keyset(sort)?,
        )
        .await
    }

    async fn list_all(
        &self,
        status: Option<TenantStatus>,
        sort: &SortOrder<TenantSortField>,
        page: &PageRequest,
    ) -> Result<Page<Tenant>, DomainError> {
        self.page(
            RowScope::Unscoped,
            in_status(every_tenant(), status),
            page.keyset(sort)?,
        )
        .await
    }

    async fn list_past_grace(
        &self,
        now: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<Tenant>, DomainError> {
        let archived_by = now.saturating_sub(ARCHIVE_GRACE);
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids = sqlx::query_file_scalar!(
                "queries/tenants/past_grace.sql",
                archived_by,
                i64::from(limit.get())
            )
            .fetch_all(&mut *connection)
            .await?;
            records_in_order(connection, &ids).await
        })
        .await?;
        self.rebuilt_all(records)
    }

    async fn batch_after(
        &self,
        after: Option<TenantId>,
        size: NonZeroU32,
    ) -> Result<Vec<Tenant>, DomainError> {
        let after = after.map_or(Uuid::nil(), |id| *id.as_uuid());
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids =
                sqlx::query_file_scalar!("queries/tenants/after.sql", after, i64::from(size.get()))
                    .fetch_all(&mut *connection)
                    .await?;
            records_in_order(connection, &ids).await
        })
        .await?;
        self.rebuilt_all(records)
    }

    async fn count_in_cloud(
        &self,
        organization_id: &OrganizationId,
        provider: CloudProvider,
    ) -> Result<u64, DomainError> {
        let count = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/tenants/in_customer_cloud.sql",
                organization_id.as_uuid(),
                provider.word()
            )
            .fetch_one(connection)
            .await
        })
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }

    async fn save(&self, tenant: &Tenant) -> Result<(), DomainError> {
        let columns = TenantColumns::of(tenant)?;
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let attempt = write_columns(connection, &columns).await;
            unique_on(attempt, SLUG_KEY)
        })
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-tenant-of-the-organization-already",
                "another tenant of the organization already has this slug"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::organization::{OrgTenantGrantStore, OrgUserStore, OrganizationStore};
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::organization::members::tenant_grant::{
        OrgTenantGrant, OrgTenantGrantRow,
    };
    use ianua_domain::domains::tenant::lifecycle::TenantRow;
    use ianua_domain::domains::tenant::provisioning::infrastructure::{
        DeploymentRegion, IsolationLevel, NetworkPlacement, Placement, TenantResidency,
    };
    use ianua_domain::domains::tenant::status::Archival;
    use ianua_domain::shared::config::SlugLimits;
    use ianua_domain::types::{ActedBy, DomainName, RoleId, Setting};
    use time::Duration;

    use super::*;
    use crate::postgres::organization::{
        PgOrgTenantGrantStore, PgOrgUserStore, PgOrganizationStore,
    };
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{org_user_row, organization_row};
    use crate::test_support::rows::tenant::{deleted_tenant_row, tenant_row};

    struct Fixture {
        database: TestDb,
        store: PgTenantStore,
        organization: OrganizationId,
    }

    impl Fixture {
        /// Lists this organization's tenants by display name with the requested status and page.
        async fn page(&self, status: Option<TenantStatus>, page: &PageRequest) -> Page<Tenant> {
            self.store
                .list_by_organization(&self.organization, status, &by_name(), page)
                .await
                .unwrap()
        }

        /// Saves Ann as an organization member with two roles in the selected tenant.
        async fn member_with_grants(&self, granted: &Tenant) -> OrgUserId {
            let held =
                OrgUser::reconstitute(org_user_row(self.organization, "ann@acme.example")).unwrap();
            PgOrgUserStore::new(
                Arc::clone(&self.database.databases),
                DomainLimits::default(),
            )
            .save(&held)
            .await
            .unwrap();
            let member = *held.id();
            let grants: Vec<OrgTenantGrant> = (0..2)
                .map(|_| {
                    OrgTenantGrant::reconstitute(OrgTenantGrantRow {
                        org_user_id: member,
                        tenant_id: *granted.id(),
                        role_id: RoleId::new(),
                        granted_by: ActedBy::Platform,
                        granted_at: at(0),
                    })
                    .unwrap()
                })
                .collect();
            PgOrgTenantGrantStore::new(Arc::clone(&self.database.databases))
                .replace_in_tenant(&member, granted.id(), &grants)
                .await
                .unwrap();
            member
        }
    }

    /// A fresh database holding one organization, and the store on it.
    async fn fixture() -> Fixture {
        let database = TestDb::fresh().await;
        let organization = an_organization(&database, "acme").await;
        let store = PgTenantStore::new(Arc::clone(&database.databases), DomainLimits::default());
        Fixture {
            database,
            store,
            organization,
        }
    }

    /// Saves an organization under `slug` through its store.
    async fn an_organization(database: &TestDb, slug: &str) -> OrganizationId {
        let organization = Organization::reconstitute(organization_row(slug, slug)).unwrap();
        PgOrganizationStore::new(Arc::clone(&database.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        *organization.id()
    }

    fn row(organization: OrganizationId, slug: &str) -> TenantRow {
        tenant_row(organization, slug)
    }

    fn tenant(row: TenantRow) -> Tenant {
        Tenant::reconstitute(row).unwrap()
    }

    fn active(organization: OrganizationId, slug: &str) -> Tenant {
        tenant(row(organization, slug))
    }

    fn archived(organization: OrganizationId, slug: &str, at_time: OffsetDateTime) -> Tenant {
        tenant(TenantRow {
            status: TenantStatus::Archived,
            archival: Archival::Since(at_time),
            created_at: at(-1),
            ..row(organization, slug)
        })
    }

    fn deleted(organization: OrganizationId, slug: &str) -> Tenant {
        tenant(deleted_tenant_row(organization, slug))
    }

    fn in_aws(organization: OrganizationId, slug: &str) -> Tenant {
        let placement = Placement::CustomerCloud {
            provider: CloudProvider::Aws,
            region: DeploymentRegion::EuCentral1,
            network: NetworkPlacement::Provision,
        };
        tenant(TenantRow {
            residency: TenantResidency::new(placement, IsolationLevel::DedicatedInstance).unwrap(),
            ..row(organization, slug)
        })
    }

    async fn save_all(store: &PgTenantStore, tenants: &[&Tenant]) {
        for tenant in tenants {
            store.save(tenant).await.unwrap();
        }
    }

    fn by_name() -> SortOrder<TenantSortField> {
        SortOrder::single(Sort::ascending(TenantSortField::DisplayName))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn slugs(tenants: &[Tenant]) -> Vec<&str> {
        tenants
            .iter()
            .map(|tenant| tenant.slug().as_str())
            .collect()
    }

    fn limit(size: u32) -> NonZeroU32 {
        NonZeroU32::new(size).unwrap()
    }

    /// Acme's tenant is found by its id and by its slug within Acme, and
    /// not by that slug within another organization.
    #[tokio::test]
    async fn a_saved_tenant_is_found_by_its_id_and_its_slug() {
        let db = fixture().await;
        let team = tenant(TenantRow {
            primary_domain: Setting::Set(DomainName::new("team.acme.example").unwrap()),
            ..row(db.organization, "team")
        });

        db.store.save(&team).await.unwrap();

        let by_id = db.store.find_by_id(team.id()).await.unwrap().unwrap();
        let by_slug = db
            .store
            .find_by_slug_in_org(team.slug(), &db.organization)
            .await
            .unwrap()
            .unwrap();
        for found in [&by_id, &*by_slug] {
            assert_eq!(found.id(), team.id());
            assert_eq!(found.primary_domain(), team.primary_domain());
            assert_eq!(found.compliance(), team.compliance());
            assert_eq!(found.auth_config(), team.auth_config());
            assert_eq!(found.residency(), team.residency());
        }
        let elsewhere = db
            .store
            .find_by_slug_in_org(team.slug(), &OrganizationId::new())
            .await
            .unwrap();
        assert!(elsewhere.is_none());
    }

    /// An id nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_tenant_is_not_found() {
        let db = fixture().await;

        assert!(
            db.store
                .find_by_id(&TenantId::new())
                .await
                .unwrap()
                .is_none()
        );
    }

    fn slug(value: &str) -> TenantSlug {
        TenantSlug::new(value, &SlugLimits::default()).unwrap()
    }

    /// Saving another tenant under Acme's existing slug returns a conflict.
    /// That slug remains taken in Acme and available in Globex, while another
    /// slug remains available in Acme.
    #[tokio::test]
    async fn a_slug_another_tenant_of_the_organization_has_is_refused() {
        let db = fixture().await;
        let globex = an_organization(&db.database, "globex").await;
        db.store
            .save(&active(db.organization, "team"))
            .await
            .unwrap();

        let second = db.store.save(&active(db.organization, "team")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
        let (team, other) = (slug("team"), slug("other"));
        let store = &db.store;
        assert!(
            store
                .slug_exists_in_org(&team, &db.organization)
                .await
                .unwrap()
        );
        assert!(
            !store
                .slug_exists_in_org(&other, &db.organization)
                .await
                .unwrap()
        );
        assert!(!store.slug_exists_in_org(&team, &globex).await.unwrap());
    }

    /// Acme and Globex each call a tenant `production`: slugs are unique
    /// only within an organization. Each is kept, and each organization's
    /// slug lookup finds its own.
    #[tokio::test]
    async fn two_organizations_each_keep_a_tenant_under_one_slug() {
        let db = fixture().await;
        let globex = an_organization(&db.database, "globex").await;
        let acmes = active(db.organization, "production");
        let globexs = active(globex, "production");

        save_all(&db.store, &[&acmes, &globexs]).await;

        let production = slug("production");
        for (organization, expected) in [(db.organization, &acmes), (globex, &globexs)] {
            let found = db
                .store
                .find_by_slug_in_org(&production, &organization)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.id(), expected.id());
            assert_eq!(found.organization_id(), &organization);
            assert!(
                db.store
                    .slug_exists_in_org(&production, &organization)
                    .await
                    .unwrap()
            );
        }
    }

    /// Acme lists its tenants page by page; a deleted one is left out
    /// unless deleted ones are asked for.
    #[tokio::test]
    async fn an_organization_lists_its_tenants_without_the_deleted_ones() {
        let db = fixture().await;
        let other = an_organization(&db.database, "globex").await;
        save_all(
            &db.store,
            &[
                &active(db.organization, "c-team"),
                &active(db.organization, "a-team"),
                &active(db.organization, "b-team"),
                &deleted(db.organization, "gone"),
                &active(other, "theirs"),
            ],
        )
        .await;

        let page_one = db.page(None, &first(2)).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = db.page(None, &after).await;
        let removed = db.page(Some(TenantStatus::Deleted), &first(10)).await;

        assert_eq!(slugs(&page_one.items), ["a-team", "b-team"]);
        assert_eq!(slugs(&page_two.items), ["c-team"]);
        assert!(!page_two.has_next());
        assert_eq!(slugs(&removed.items), ["gone"]);
    }

    /// A member sees the tenants they were let into, and no others.
    #[tokio::test]
    async fn a_member_lists_only_the_tenants_granted_to_them() {
        let db = fixture().await;
        let (granted, withheld) = (
            active(db.organization, "granted"),
            active(db.organization, "withheld"),
        );
        save_all(&db.store, &[&granted, &withheld]).await;
        let member = db.member_with_grants(&granted).await;

        let page = db
            .store
            .list_granted_to_org_user(&member, None, &by_name(), &first(10))
            .await
            .unwrap();

        assert_eq!(slugs(&page.items), ["granted"]);
    }

    /// Every tenant lists across organizations, in its order.
    #[tokio::test]
    async fn every_tenant_lists_across_organizations() {
        let db = fixture().await;
        let other = an_organization(&db.database, "globex").await;
        save_all(
            &db.store,
            &[&active(other, "b-team"), &active(db.organization, "a-team")],
        )
        .await;

        let page = db
            .store
            .list_all(None, &by_name(), &first(10))
            .await
            .unwrap();

        assert_eq!(slugs(&page.items), ["a-team", "b-team"]);
    }

    /// The sweep finds archived tenants whose grace has passed, the longest
    /// archived first, and leaves the rest.
    #[tokio::test]
    async fn the_tenants_past_their_grace_are_found_longest_archived_first() {
        let db = fixture().await;
        let now = at(0).saturating_add(Duration::days(100));
        save_all(
            &db.store,
            &[
                &archived(
                    db.organization,
                    "recent",
                    now.saturating_sub(Duration::days(10)),
                ),
                &archived(
                    db.organization,
                    "later",
                    now.saturating_sub(Duration::days(40)),
                ),
                &archived(
                    db.organization,
                    "oldest",
                    now.saturating_sub(Duration::days(60)),
                ),
                &active(db.organization, "open"),
            ],
        )
        .await;

        let due = db.store.list_past_grace(now, limit(10)).await.unwrap();
        let first_due = db.store.list_past_grace(now, limit(1)).await.unwrap();

        assert_eq!(slugs(&due), ["oldest", "later"]);
        assert_eq!(slugs(&first_due), ["oldest"]);
    }

    /// A sweep walks every tenant in batches by id, each batch after the
    /// last.
    #[tokio::test]
    async fn tenants_are_walked_in_batches_by_id() {
        let db = fixture().await;
        let tenants = [
            active(db.organization, "one"),
            active(db.organization, "two"),
            active(db.organization, "three"),
        ];
        save_all(&db.store, &tenants.iter().collect::<Vec<_>>()).await;
        let mut expected: Vec<TenantId> = tenants.iter().map(|tenant| *tenant.id()).collect();
        expected.sort_by_key(|id| *id.as_uuid());

        let first_batch = db.store.batch_after(None, limit(2)).await.unwrap();
        let last_seen = first_batch.last().map(|tenant| *tenant.id());
        let second_batch = db.store.batch_after(last_seen, limit(2)).await.unwrap();

        let walked: Vec<TenantId> = first_batch
            .iter()
            .chain(&second_batch)
            .map(|tenant| *tenant.id())
            .collect();
        assert_eq!(walked, expected);
    }

    /// Acme's tenants in its own AWS account are counted; one on the
    /// platform and a deleted one are not.
    #[tokio::test]
    async fn tenants_in_a_customer_cloud_are_counted() {
        let db = fixture().await;
        let gone = TenantRow {
            residency: in_aws(db.organization, "unused").residency().clone(),
            ..deleted_tenant_row(db.organization, "gone")
        };
        save_all(
            &db.store,
            &[
                &in_aws(db.organization, "aws-one"),
                &in_aws(db.organization, "aws-two"),
                &active(db.organization, "platform"),
                &tenant(gone),
            ],
        )
        .await;

        let aws = db
            .store
            .count_in_cloud(&db.organization, CloudProvider::Aws)
            .await
            .unwrap();
        let gcp = db
            .store
            .count_in_cloud(&db.organization, CloudProvider::Gcp)
            .await
            .unwrap();

        assert_eq!((aws, gcp), (2, 0));
    }

    /// Saving again keeps the new values: an archived tenant keeps when it
    /// was archived.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let db = fixture().await;
        let team = active(db.organization, "team");
        db.store.save(&team).await.unwrap();
        let archived_team = tenant(TenantRow {
            id: *team.id(),
            status: TenantStatus::Archived,
            archival: Archival::Since(at(5)),
            updated_at: at(5),
            ..row(db.organization, "team")
        });

        db.store.save(&archived_team).await.unwrap();

        let found = db.store.find_by_id(team.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), TenantStatus::Archived);
        assert_eq!(found.archival(), Archival::Since(at(5)));
    }

    /// The gateway, signed in as its own role, reads a tenant by its id,
    /// as it does for the trust each tenant places in client certificates:
    /// the read touches no table of setups or teardowns its role cannot
    /// read.
    #[tokio::test]
    async fn the_gateway_reads_a_tenant_by_its_id() {
        let db = fixture().await;
        let team = active(db.organization, "team");
        db.store.save(&team).await.unwrap();
        let gateway = PgTenantStore::new(Arc::clone(&db.database.gateway), DomainLimits::default());

        let found = gateway.find_by_id(team.id()).await.unwrap().unwrap();

        assert_eq!(found.slug().as_str(), "team");
        assert_eq!(found.organization_id(), &db.organization);
    }
}
