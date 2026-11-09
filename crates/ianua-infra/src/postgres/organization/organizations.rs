//! Organizations, kept in the platform database.
//!
//! Every read goes through one checked query by id, or by slug, and one
//! mapping into the aggregate. A list first reads the ids of its page, then
//! reads those rows the same way.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::organization::{OrganizationSortField, OrganizationStore};
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::status::OrganizationStatus;
use ianua_domain::message;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantSlug};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{OrganizationColumns, OrganizationRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a slug to one organization.
const SLUG_KEY: &str = "organizations_slug_key";

/// The Postgres organization store.
pub struct PgOrganizationStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgOrganizationStore {
    /// A store keeping organizations in `databases`, checking each stored
    /// name against `limits` as it is read back.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }

    fn rebuilt(&self, record: OrganizationRecord) -> Result<Organization, DomainError> {
        record.into_organization(&self.limits)
    }
}

/// The records of the organizations `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<OrganizationRecord>, sqlx::Error> {
    sqlx::query_file_as!(OrganizationRecord, "queries/organizations/by_ids.sql", ids)
        .fetch_all(connection)
        .await
}

impl SortColumns for OrganizationSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Name => "name",
            Self::Slug => "slug",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The ids of the organizations in `status`, or of every one.
fn listed(status: Option<OrganizationStatus>) -> PageQuery<'static> {
    let every = PageQuery::ids("id", "organizations");
    let Some(status) = status else {
        return every;
    };
    every.filter("status = ?", status.word())
}

#[async_trait]
impl OrganizationStore for PgOrganizationStore {
    async fn find_by_ids(&self, ids: &[OrganizationId]) -> Result<Vec<Organization>, DomainError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<_> = ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            records_of(connection, &ids).await
        })
        .await?;
        records
            .into_iter()
            .map(|record| self.rebuilt(record))
            .collect()
    }

    async fn find_by_id(&self, id: &OrganizationId) -> Result<Option<Organization>, DomainError> {
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

    async fn find_by_slug(
        &self,
        slug: &TenantSlug,
    ) -> Result<Option<Arc<Organization>>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                OrganizationRecord,
                "queries/organizations/by_slug.sql",
                slug.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record
            .map(|record| self.rebuilt(record).map(Arc::new))
            .transpose()
    }

    async fn slug_exists(&self, slug: &TenantSlug) -> Result<bool, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!("queries/organizations/slug_taken.sql", slug.as_str())
                .fetch_one(connection)
                .await
        })
        .await
    }

    async fn list_all(
        &self,
        status: Option<OrganizationStatus>,
        sort: &SortOrder<OrganizationSortField>,
        page: &PageRequest,
    ) -> Result<Page<Organization>, DomainError> {
        let keyset = page.keyset(sort)?;
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids = listed(status).fetch(&keyset, &mut *connection).await?;
            let records = records_of(connection, &ids).await?;
            Ok(in_page_order(&ids, records, |record| record.id))
        })
        .await?;
        let organizations = records
            .into_iter()
            .map(|record| self.rebuilt(record))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset.seal(organizations))
    }

    async fn save(&self, organization: &Organization) -> Result<(), DomainError> {
        let columns = OrganizationColumns::of(organization)?;
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let attempt = sqlx::query_file!(
                "queries/organizations/save.sql",
                columns.id,
                columns.slug,
                columns.name,
                columns.contact_email,
                columns.display_name,
                columns.plan,
                columns.negotiated_limits,
                columns.status,
                columns.suspended_by_member,
                columns.suspended_by_platform,
                columns.auth_config,
                columns.created_at,
                columns.updated_at,
            )
            .execute(connection)
            .await;
            unique_on(attempt, SLUG_KEY)
        })
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-organization-already-has-this-slug",
                "another organization already has this slug"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::organization::OrgUserStore;
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::organization::billing::negotiated::{NegotiatedLimits, PlanTerms};
    use ianua_domain::domains::organization::billing::plan::{OrganizationPlan, PlanLimits};
    use ianua_domain::domains::organization::lifecycle::OrganizationRow;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::organization::status::{OrgSuspensionReason, Suspension};
    use ianua_domain::domains::tenant::lifecycle::{Tenant, TenantRow};
    use ianua_domain::domains::tenant::status::{Archival, TenantStatus};
    use ianua_domain::shared::config::SlugLimits;
    use ianua_domain::types::{OrgUserId, TenantId};

    use super::*;
    use crate::postgres::organization::PgOrgUserStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{org_user_row, organization_row};
    use crate::test_support::rows::tenant::{deleted_tenant_row, tenant_row};

    /// A fresh database, and the store on it.
    async fn fixture() -> (TestDb, PgOrganizationStore) {
        let db = TestDb::fresh().await;
        let store = PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default());
        (db, store)
    }

    fn row(slug: &str, name: &str) -> OrganizationRow {
        organization_row(slug, name)
    }

    fn organization(row: OrganizationRow) -> Organization {
        Organization::reconstitute(row).unwrap()
    }

    fn named(slug: &str, name: &str) -> Organization {
        organization(row(slug, name))
    }

    /// Saves the tenant `row` describes through the tenant store.
    async fn hold_tenant(db: &TestDb, row: TenantRow) -> TenantId {
        let tenant = Tenant::reconstitute(row).unwrap();
        PgTenantStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant)
            .await
            .unwrap();
        *tenant.id()
    }

    /// Saves a member of `organization` through the member store.
    async fn hold_member(db: &TestDb, organization: OrganizationId) -> OrgUserId {
        let member = OrgUser::reconstitute(org_user_row(organization, "ann@acme.example")).unwrap();
        PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&member)
            .await
            .unwrap();
        *member.id()
    }

    fn by(field: OrganizationSortField) -> SortOrder<OrganizationSortField> {
        SortOrder::single(Sort::ascending(field))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn slugs(page: &Page<Organization>) -> Vec<&str> {
        page.items.iter().map(|org| org.slug().as_str()).collect()
    }

    /// Acme signs up: it is found again by its id and by its slug, as it
    /// was saved.
    #[tokio::test]
    async fn a_saved_organization_is_found_by_its_id_and_its_slug() {
        let (_db, store) = fixture().await;
        let acme = named("acme", "Acme");

        store.save(&acme).await.unwrap();

        let by_id = store.find_by_id(acme.id()).await.unwrap().unwrap();
        let by_slug = store.find_by_slug(acme.slug()).await.unwrap().unwrap();
        for found in [&by_id, &*by_slug] {
            assert_eq!(found.id(), acme.id());
            assert_eq!(found.name(), acme.name());
            assert_eq!(found.contact_email(), acme.contact_email());
            assert_eq!(found.plan(), acme.plan());
            assert_eq!(found.auth_config(), acme.auth_config());
            assert_eq!(found.created_at(), acme.created_at());
        }
    }

    /// A batch keeps only requested organizations, once each, including their
    /// own live tenants and sign-in rules. Missing ids and empty batches are safe.
    #[tokio::test]
    async fn organization_batches_keep_each_organizations_own_data() {
        let (db, store) = fixture().await;
        let acme = named("acme", "Acme");
        let globex = named("globex", "Globex");
        store.save(&acme).await.unwrap();
        store.save(&globex).await.unwrap();
        let active = hold_tenant(&db, tenant_row(*acme.id(), "active")).await;
        hold_tenant(&db, tenant_row(*globex.id(), "elsewhere")).await;
        hold_tenant(&db, deleted_tenant_row(*acme.id(), "deleted")).await;

        let found = store
            .find_by_ids(&[*acme.id(), OrganizationId::new(), *acme.id()])
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), acme.id());
        assert_eq!(found[0].tenant_ids(), &[active]);
        assert_eq!(found[0].auth_config(), acme.auth_config());
        assert!(store.find_by_ids(&[]).await.unwrap().is_empty());
    }

    /// An id or slug nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_organization_is_not_found() {
        let (_db, store) = fixture().await;

        let nobody = TenantSlug::new("nobody", &SlugLimits::default()).unwrap();

        assert!(
            store
                .find_by_id(&OrganizationId::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.find_by_slug(&nobody).await.unwrap().is_none());
    }

    /// Acme stops paying and the platform suspends it: saving it again
    /// keeps the suspension and who made it.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let (_db, store) = fixture().await;
        let acme = named("acme", "Acme");
        store.save(&acme).await.unwrap();
        let suspended = organization(OrganizationRow {
            id: *acme.id(),
            status: OrganizationStatus::Suspended,
            suspended_by: Suspension::ByPlatform(OrgSuspensionReason::NonPayment),
            updated_at: at(5),
            ..row("acme", "Acme")
        });

        store.save(&suspended).await.unwrap();

        let found = store.find_by_id(acme.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), OrganizationStatus::Suspended);
        assert_eq!(
            found.suspended_by(),
            Suspension::ByPlatform(OrgSuspensionReason::NonPayment)
        );
        assert_eq!(found.updated_at(), at(5));
    }

    /// An owner suspends Acme: the store keeps which member did it.
    #[tokio::test]
    async fn a_member_who_suspended_it_is_kept() {
        let (db, store) = fixture().await;
        let open = named("acme", "Acme");
        store.save(&open).await.unwrap();
        let member = hold_member(&db, *open.id()).await;
        let acme = organization(OrganizationRow {
            id: *open.id(),
            status: OrganizationStatus::Suspended,
            suspended_by: Suspension::ByMember(member),
            updated_at: at(1),
            ..row("acme", "Acme")
        });

        store.save(&acme).await.unwrap();

        let found = store.find_by_id(acme.id()).await.unwrap().unwrap();
        assert_eq!(found.suspended_by(), Suspension::ByMember(member));
    }

    /// A Custom organization's negotiated limits are the limits it reads
    /// back.
    #[tokio::test]
    async fn negotiated_limits_are_kept() {
        let (_db, store) = fixture().await;
        let agreed = PlanLimits {
            max_users: 250_000,
            ..PlanLimits::business()
        };
        let acme = organization(OrganizationRow {
            plan: OrganizationPlan::Custom,
            terms: PlanTerms::Negotiated(NegotiatedLimits::new(agreed.clone()).unwrap()),
            ..row("acme", "Acme")
        });

        store.save(&acme).await.unwrap();

        let found = store.find_by_id(acme.id()).await.unwrap().unwrap();
        assert_eq!(found.limits(), agreed);
    }

    /// Saving another organization with Acme's stored slug returns a conflict.
    #[tokio::test]
    async fn a_slug_another_organization_has_is_refused() {
        let (_db, store) = fixture().await;
        store.save(&named("acme", "Acme")).await.unwrap();

        let second = store.save(&named("acme", "Other Acme")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// A slug is taken once an organization has it, and free otherwise.
    #[tokio::test]
    async fn a_slug_is_taken_once_an_organization_has_it() {
        let (_db, store) = fixture().await;
        let acme = named("acme", "Acme");
        let free = TenantSlug::new("globex", &SlugLimits::default()).unwrap();

        store.save(&acme).await.unwrap();

        assert!(store.slug_exists(acme.slug()).await.unwrap());
        assert!(!store.slug_exists(&free).await.unwrap());
    }

    /// Reading Acme includes its active and archived tenants and excludes
    /// its deleted tenant.
    #[tokio::test]
    async fn an_organization_holds_its_tenants_but_not_the_deleted_ones() {
        let (db, store) = fixture().await;
        let acme = named("acme", "Acme");
        store.save(&acme).await.unwrap();
        let active = hold_tenant(&db, tenant_row(*acme.id(), "active")).await;
        let archived = hold_tenant(
            &db,
            TenantRow {
                status: TenantStatus::Archived,
                archival: Archival::Since(at(1)),
                updated_at: at(1),
                ..tenant_row(*acme.id(), "archived")
            },
        )
        .await;
        hold_tenant(&db, deleted_tenant_row(*acme.id(), "deleted")).await;

        let found = store.find_by_id(acme.id()).await.unwrap().unwrap();

        let mut expected = vec![active, archived];
        expected.sort_by_key(|id| *id.as_uuid());
        assert_eq!(found.tenant_ids(), expected);
    }

    /// An operator pages through organizations by name: each page follows
    /// the last, and the last says nothing follows.
    #[tokio::test]
    async fn a_list_is_read_page_by_page_in_its_order() {
        let (_db, store) = fixture().await;
        for (slug, name) in [("c-org", "Carol"), ("a-org", "Alice"), ("b-org", "Bob")] {
            store.save(&named(slug, name)).await.unwrap();
        }
        let order = by(OrganizationSortField::Name);

        let page_one = store.list_all(None, &order, &first(2)).await.unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = store.list_all(None, &order, &after).await.unwrap();

        assert_eq!(slugs(&page_one), ["a-org", "b-org"]);
        assert_eq!(slugs(&page_two), ["c-org"]);
        assert!(!page_two.has_next());
    }

    /// A list of closed organizations shows only closed ones.
    #[tokio::test]
    async fn a_list_narrowed_to_a_status_shows_only_that_status() {
        let (_db, store) = fixture().await;
        store.save(&named("acme", "Acme")).await.unwrap();
        let closed = organization(OrganizationRow {
            status: OrganizationStatus::Closed,
            ..row("globex", "Globex")
        });
        store.save(&closed).await.unwrap();

        let page = store
            .list_all(
                Some(OrganizationStatus::Closed),
                &by(OrganizationSortField::CreatedAt),
                &first(10),
            )
            .await
            .unwrap();

        assert_eq!(slugs(&page), ["globex"]);
    }

    /// Paging by stored status words returns the active, closed and suspended
    /// organizations in order, with each organization appearing once.
    #[tokio::test]
    async fn a_list_sorted_by_status_pages_by_the_stored_word() {
        let (_db, store) = fixture().await;
        let suspended = organization(OrganizationRow {
            status: OrganizationStatus::Suspended,
            suspended_by: Suspension::ByPlatform(OrgSuspensionReason::Operator),
            ..row("c-org", "Carol")
        });
        store.save(&suspended).await.unwrap();
        store.save(&named("a-org", "Alice")).await.unwrap();
        let closed = organization(OrganizationRow {
            status: OrganizationStatus::Closed,
            ..row("b-org", "Bob")
        });
        store.save(&closed).await.unwrap();
        let order = by(OrganizationSortField::Status);

        let page_one = store.list_all(None, &order, &first(1)).await.unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let rest = store.list_all(None, &order, &after).await.unwrap();

        assert_eq!(slugs(&page_one), ["a-org"]);
        assert_eq!(slugs(&rest), ["b-org", "c-org"]);
    }

    /// Reading an organization with an unsupported stored authentication
    /// configuration version returns an infrastructure error.
    #[tokio::test]
    async fn a_stored_value_in_a_shape_the_store_does_not_read_is_refused() {
        let (db, store) = fixture().await;
        let acme = named("acme", "Acme");
        store.save(&acme).await.unwrap();
        db.tamper("UPDATE organizations SET auth_config = jsonb_set(auth_config, '{v}', '2')")
            .await;

        let read = store.find_by_id(acme.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Reading an organization with an invalid stored contact email returns
    /// an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_organization_is_refused() {
        let (db, store) = fixture().await;
        let acme = named("acme", "Acme");
        store.save(&acme).await.unwrap();
        db.tamper("UPDATE organizations SET contact_email = 'not an address'")
            .await;

        let read = store.find_by_id(acme.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
