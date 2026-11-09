//! The groups a tenant's directory keeps that a SCIM filter picks, oldest
//! first, a stretch of them by position with how many it picks in all.
//! Groups a person keeps in the dashboard are never picked.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::SortDirection;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::{
    ScimGroupAttribute, ScimGroupQueries, ScimPage, ScimQuery, ScimWindow,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::group::Group;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use uuid::Uuid;

use self::record::picked_groups;
use crate::postgres::authorization::groups::tree::record::GroupRecord;
use crate::postgres::federation::scim::filters::group_picks;
use crate::postgres::foundation::paging::picks::Picks;
use crate::postgres::foundation::paging::window::WindowQuery;
use crate::postgres::foundation::paging::{Count, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The groups a directory keeps, never those kept in the dashboard.
const DIRECTORY_ONLY: &str = "groups.origin = 'directory'";

/// Oldest first, the id last.
const OLDEST_FIRST: [(&str, SortDirection); 2] = [
    ("groups.created_at", SortDirection::Asc),
    ("groups.id", SortDirection::Asc),
];

/// The Postgres finder of the groups a SCIM filter picks.
pub struct PgScimGroupQueries {
    databases: Arc<Databases>,
}

impl PgScimGroupQueries {
    /// A finder reading groups from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgScimGroupQueries {}

/// The query for the ids of a stretch of the directory's groups of
/// `tenant` that `picks` keeps, and the one counting all of them.
fn picked_by(tenant: Uuid, picks: &Picks) -> (WindowQuery<'static>, WindowQuery<'static, Count>) {
    let listed = WindowQuery::ids("groups.id", "groups")
        .filter("groups.tenant_id = ?", tenant)
        .keep(DIRECTORY_ONLY)
        .picking(picks);
    let counted = WindowQuery::<Count>::counted("groups")
        .filter("groups.tenant_id = ?", tenant)
        .keep(DIRECTORY_ONLY)
        .picking(picks);
    (listed, counted)
}

#[async_trait]
impl ScimGroupQueries for PgScimGroupQueries {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        query: &ScimQuery<ScimGroupAttribute>,
        window: ScimWindow,
    ) -> Result<ScimPage<Group<ResolvedTenant>>, DomainError> {
        let tenant = *tenant_id.as_uuid();
        let (listed, counted) = picked_by(tenant, &group_picks(query));
        let (records, total) = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed
                    .fetch(&OLDEST_FIRST, window, &mut *connection)
                    .await?;
                let total = counted.count(&mut *connection).await?;
                let records =
                    sqlx::query_file_as!(GroupRecord, "queries/groups/by_ids.sql", &tenant, &ids)
                        .fetch_all(connection)
                        .await?;
                Ok((in_page_order(&ids, records, |record| record.id), total))
            },
        )
        .await?;
        Ok(ScimPage {
            items: picked_groups(records)?,
            total: u64::try_from(total).map_err(DomainError::infra)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::authorization::GroupStore;
    use ianua_app::ports::federation::{ScimFilterValue, ScimOperator};
    use ianua_domain::domains::authorization::group::{GroupOrigin, GroupRow};

    use super::*;
    use crate::postgres::authorization::PgGroupStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{group_row, tenant};

    struct Fixture {
        db: TestDb,
        queries: PgScimGroupQueries,
        tenant: ScopedTenant,
    }

    /// A fresh database holding the directory's Engineering and Research,
    /// created in that order, and the dashboard's Admins, and the finder on
    /// it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let groups = PgGroupStore::new(Arc::clone(&db.databases));
        let directory = |name: &str, created: i64| GroupRow {
            origin: GroupOrigin::Directory,
            created_at: at(created),
            updated_at: at(created),
            ..group_row(name)
        };
        for row in [
            directory("Engineering", 0),
            directory("Research", 10),
            group_row("Admins"),
        ] {
            groups
                .save(&tenant, &Group::reconstitute(row).unwrap())
                .await
                .unwrap();
        }
        Fixture {
            queries: PgScimGroupQueries::new(Arc::clone(&db.databases)),
            tenant,
            db,
        }
    }

    fn named(operator: ScimOperator, value: &str) -> ScimQuery<ScimGroupAttribute> {
        ScimQuery::Compare {
            attribute: ScimGroupAttribute::DisplayName,
            operator,
            value: ScimFilterValue::new(value).unwrap(),
        }
    }

    impl Fixture {
        async fn names(
            &self,
            query: &ScimQuery<ScimGroupAttribute>,
            window: ScimWindow,
        ) -> (Vec<String>, u64) {
            let page = self
                .queries
                .find(&self.tenant, query, window)
                .await
                .unwrap();
            let names = page
                .items
                .iter()
                .map(|group| group.name().as_str().to_owned())
                .collect();
            (names, page.total)
        }
    }

    /// Okta pages through the directory's groups, oldest first, and never
    /// sees the dashboard's own.
    #[tokio::test]
    async fn only_the_directorys_groups_are_listed() {
        let fx = fixture().await;

        let (names, total) = fx.names(&ScimQuery::All, ScimWindow::new(1, 100)).await;

        assert_eq!(names, ["Engineering", "Research"]);
        assert_eq!(total, 2);
    }

    /// Okta looks Research up by its name in another case. It finds it.
    #[tokio::test]
    async fn a_group_is_looked_up_by_name_ignoring_case() {
        let fx = fixture().await;

        let (names, _) = fx
            .names(
                &named(ScimOperator::Equals, "RESEARCH"),
                ScimWindow::new(1, 100),
            )
            .await;

        assert_eq!(names, ["Research"]);
    }

    /// Looking up the dashboard's Admins group through SCIM returns no
    /// groups and a total of zero.
    #[tokio::test]
    async fn a_dashboard_group_is_never_picked() {
        let fx = fixture().await;

        let (names, total) = fx
            .names(
                &named(ScimOperator::Equals, "Admins"),
                ScimWindow::new(1, 100),
            )
            .await;

        assert!(names.is_empty());
        assert_eq!(total, 0);
    }

    /// Names starting with `eng` or containing `search` pick both groups;
    /// both at once pick neither.
    #[tokio::test]
    async fn filters_join_with_and_and_or() {
        let fx = fixture().await;
        let either = ScimQuery::Or(
            Box::new(named(ScimOperator::StartsWith, "eng")),
            Box::new(named(ScimOperator::Contains, "search")),
        );
        let both = ScimQuery::And(
            Box::new(named(ScimOperator::StartsWith, "eng")),
            Box::new(named(ScimOperator::Contains, "search")),
        );

        let (either, _) = fx.names(&either, ScimWindow::new(1, 100)).await;
        let (both, _) = fx.names(&both, ScimWindow::new(1, 100)).await;

        assert_eq!(either, ["Engineering", "Research"]);
        assert!(both.is_empty());
    }

    /// The second group on, one at a time, is Research, of two in all.
    #[tokio::test]
    async fn a_stretch_starts_at_its_index_and_reports_the_total() {
        let fx = fixture().await;

        let (names, total) = fx.names(&ScimQuery::All, ScimWindow::new(2, 1)).await;

        assert_eq!(names, ["Research"]);
        assert_eq!(total, 2);
    }

    /// A SCIM group listing from Globex contains none of Acme's groups.
    #[tokio::test]
    async fn another_tenants_groups_are_not_picked() {
        let fx = fixture().await;

        let page = fx
            .queries
            .find(&tenant(), &ScimQuery::All, ScimWindow::new(1, 100))
            .await
            .unwrap();

        assert!(page.items.is_empty());
    }

    /// A directory group with an empty stored name makes its SCIM listing
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_corrupt_group_is_refused() {
        let fx = fixture().await;
        fx.db
            .tamper("UPDATE groups SET name = '' WHERE name = 'Research'")
            .await;

        let page = fx
            .queries
            .find(&fx.tenant, &ScimQuery::All, ScimWindow::new(1, 100))
            .await;

        assert!(matches!(page, Err(DomainError::Infrastructure(_))));
    }
}
