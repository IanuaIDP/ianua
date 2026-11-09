//! The users of a tenant a SCIM directory's filter picks, a stretch of
//! them by position with how many it picks in all, as RFC 7644 has a
//! directory page.
//!
//! The ids of the stretch and the count are read with the filter the
//! directory sent, then the users with the identity context's own query
//! by ids, all in one transaction.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::{
    ScimPage, ScimQuery, ScimUserAttribute, ScimUserQueries, ScimUserSort, ScimWindow,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use uuid::Uuid;

use self::record::users_from;
use crate::postgres::federation::scim::filters::{user_order, user_picks};
use crate::postgres::foundation::paging::picks::Picks;
use crate::postgres::foundation::paging::window::WindowQuery;
use crate::postgres::foundation::paging::{Count, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::identity::users::record::UserRecord;

/// The Postgres finder of the users a SCIM filter picks.
pub struct PgScimUserQueries {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgScimUserQueries {
    /// A finder reading users from `databases`, checking each stored name
    /// against `limits` as it is read back.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }
}

impl TenantScoped for PgScimUserQueries {}

/// The query for the ids of a stretch of the users of `tenant` that
/// `picks` keeps, and the one counting all of them.
fn picked_by(tenant: Uuid, picks: &Picks) -> (WindowQuery<'static>, WindowQuery<'static, Count>) {
    let listed = WindowQuery::ids("users.id", "users")
        .filter("users.tenant_id = ?", tenant)
        .picking(picks);
    let counted = WindowQuery::<Count>::counted("users")
        .filter("users.tenant_id = ?", tenant)
        .picking(picks);
    (listed, counted)
}

#[async_trait]
impl ScimUserQueries for PgScimUserQueries {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        query: &ScimQuery<ScimUserAttribute>,
        sort: ScimUserSort,
        window: ScimWindow,
    ) -> Result<ScimPage<User<ResolvedTenant>>, DomainError> {
        let order = user_order(sort);
        let tenant = *tenant_id.as_uuid();
        let (listed, counted) = picked_by(tenant, &user_picks(query));
        let (records, total) = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&order, window, &mut *connection).await?;
                let total = counted.count(&mut *connection).await?;
                let records =
                    sqlx::query_file_as!(UserRecord, "queries/users/by_ids.sql", &tenant, &ids)
                        .fetch_all(connection)
                        .await?;
                Ok((in_page_order(&ids, records, |record| record.id), total))
            },
        )
        .await?;
        Ok(ScimPage {
            items: users_from(records, &self.limits)?,
            total: u64::try_from(total).map_err(DomainError::infra)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::SortDirection;
    use ianua_app::ports::federation::{ScimFilterValue, ScimOperator};
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::identity::account::profile_values::{Department, ExternalId};
    use ianua_domain::domains::identity::account::user::UserRow;
    use ianua_domain::domains::identity::account::user_profile::{DirectoryRecords, UserProfile};
    use ianua_domain::types::{Joining, Setting};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    struct Fixture {
        db: TestDb,
        queries: PgScimUserQueries,
        tenant: ScopedTenant,
    }

    /// Grace joined after Ada and has directory attributes that SCIM filters can select.
    fn grace_row() -> UserRow {
        UserRow {
            created_at: at(10),
            updated_at: at(10),
            joining: Joining::Joined { at: at(10) },
            profile: UserProfile {
                records: DirectoryRecords {
                    external_id: Setting::Set(ExternalId::new("00u42").unwrap()),
                    department: Setting::Set(Department::new("Research").unwrap()),
                    ..DirectoryRecords::default()
                },
                ..UserProfile::default()
            },
            ..user_row("grace@acme.example")
        }
    }

    /// A fresh database holding Ada, Grace and Alan in one tenant, created
    /// in that order, Grace with a directory id and a department, and the
    /// finder on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let users = PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let grace = grace_row();
        let alan = UserRow {
            created_at: at(20),
            updated_at: at(20),
            joining: Joining::Joined { at: at(20) },
            ..user_row("alan@acme.example")
        };
        for row in [user_row("ada@acme.example"), grace, alan] {
            users
                .save(&tenant, &User::reconstitute(row).unwrap())
                .await
                .unwrap();
        }
        Fixture {
            queries: PgScimUserQueries::new(Arc::clone(&db.databases), DomainLimits::default()),
            tenant,
            db,
        }
    }

    fn compare(
        attribute: ScimUserAttribute,
        operator: ScimOperator,
        value: &str,
    ) -> ScimQuery<ScimUserAttribute> {
        ScimQuery::Compare {
            attribute,
            operator,
            value: ScimFilterValue::new(value).unwrap(),
        }
    }

    impl Fixture {
        async fn emails(
            &self,
            query: &ScimQuery<ScimUserAttribute>,
            sort: ScimUserSort,
            window: ScimWindow,
        ) -> (Vec<String>, u64) {
            let page = self
                .queries
                .find(&self.tenant, query, sort, window)
                .await
                .unwrap();
            let emails = page
                .items
                .iter()
                .map(|user| user.email().as_str().to_owned())
                .collect();
            (emails, page.total)
        }

        async fn picked(&self, query: &ScimQuery<ScimUserAttribute>) -> Vec<String> {
            self.emails(query, ScimUserSort::Default, ScimWindow::new(1, 100))
                .await
                .0
        }
    }

    /// Okta pages through every user, oldest first.
    #[tokio::test]
    async fn every_user_is_listed_oldest_first() {
        let fx = fixture().await;

        let picked = fx.picked(&ScimQuery::All).await;

        assert_eq!(
            picked,
            [
                "ada@acme.example",
                "grace@acme.example",
                "alan@acme.example"
            ]
        );
    }

    /// Okta looks Grace up by her address in any case before it creates
    /// her. It finds her and only her.
    #[tokio::test]
    async fn a_user_is_looked_up_by_user_name_in_any_case() {
        let fx = fixture().await;

        let picked = fx
            .picked(&compare(
                ScimUserAttribute::UserName,
                ScimOperator::Equals,
                "Grace@Acme.example",
            ))
            .await;

        assert_eq!(picked, ["grace@acme.example"]);
    }

    /// Entra looks Grace up by her directory id, whose case counts.
    #[tokio::test]
    async fn an_external_id_is_compared_as_it_is() {
        let fx = fixture().await;

        let exact = fx
            .picked(&compare(
                ScimUserAttribute::ExternalId,
                ScimOperator::Equals,
                "00u42",
            ))
            .await;
        let other_case = fx
            .picked(&compare(
                ScimUserAttribute::ExternalId,
                ScimOperator::Equals,
                "00U42",
            ))
            .await;

        assert_eq!(exact, ["grace@acme.example"]);
        assert!(other_case.is_empty());
    }

    /// A directory looks for addresses starting with `ada` or containing
    /// `grace`, and for the research department: each filter picks whom it
    /// names, and `and` needs both.
    #[tokio::test]
    async fn filters_join_with_and_and_or() {
        let fx = fixture().await;
        let either = ScimQuery::Or(
            Box::new(compare(
                ScimUserAttribute::UserName,
                ScimOperator::StartsWith,
                "ada",
            )),
            Box::new(compare(
                ScimUserAttribute::UserName,
                ScimOperator::Contains,
                "GRACE",
            )),
        );
        let both = ScimQuery::And(
            Box::new(compare(
                ScimUserAttribute::UserName,
                ScimOperator::StartsWith,
                "ada",
            )),
            Box::new(compare(
                ScimUserAttribute::Department,
                ScimOperator::Equals,
                "research",
            )),
        );

        assert_eq!(
            fx.picked(&either).await,
            ["ada@acme.example", "grace@acme.example"]
        );
        assert!(fx.picked(&both).await.is_empty());
    }

    /// A SCIM filter containing a literal percent sign matches none of
    /// the fixture's user names.
    #[tokio::test]
    async fn a_wildcard_in_a_filter_matches_only_itself() {
        let fx = fixture().await;

        let picked = fx
            .picked(&compare(
                ScimUserAttribute::UserName,
                ScimOperator::Contains,
                "%",
            ))
            .await;

        assert!(picked.is_empty());
    }

    /// Sorted by department, Grace, the one with a department, comes
    /// first whichever way it runs.
    #[tokio::test]
    async fn users_without_the_sorted_value_come_last() {
        let fx = fixture().await;
        let by = |direction| ScimUserSort::By(ScimUserAttribute::Department, direction);

        let rising = fx
            .emails(
                &ScimQuery::All,
                by(SortDirection::Asc),
                ScimWindow::new(1, 100),
            )
            .await
            .0;
        let falling = fx
            .emails(
                &ScimQuery::All,
                by(SortDirection::Desc),
                ScimWindow::new(1, 100),
            )
            .await
            .0;

        assert_eq!(rising[0], "grace@acme.example");
        assert_eq!(falling[0], "grace@acme.example");
    }

    /// Okta asks for the second user on, one at a time: it gets Grace, and
    /// learns there are three in all.
    #[tokio::test]
    async fn a_stretch_starts_at_its_index_and_reports_the_total() {
        let fx = fixture().await;

        let (emails, total) = fx
            .emails(
                &ScimQuery::All,
                ScimUserSort::Default,
                ScimWindow::new(2, 1),
            )
            .await;

        assert_eq!(emails, ["grace@acme.example"]);
        assert_eq!(total, 3);
    }

    /// A page requested from index ten billion is empty while its total
    /// still reports all three users.
    #[tokio::test]
    async fn a_start_far_past_the_end_is_capped() {
        let fx = fixture().await;

        let (emails, total) = fx
            .emails(
                &ScimQuery::All,
                ScimUserSort::Default,
                ScimWindow::new(10_000_000_000, 100),
            )
            .await;

        assert!(emails.is_empty());
        assert_eq!(total, 3);
    }

    /// Listing users from Globex returns no Acme users and a total of zero.
    #[tokio::test]
    async fn another_tenants_users_are_not_picked() {
        let fx = fixture().await;

        let page = fx
            .queries
            .find(
                &tenant(),
                &ScimQuery::All,
                ScimUserSort::Default,
                ScimWindow::new(1, 100),
            )
            .await
            .unwrap();

        assert!(page.items.is_empty());
        assert_eq!(page.total, 0);
    }

    /// A user with an invalid stored email address makes the SCIM listing
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_corrupt_user_is_refused() {
        let fx = fixture().await;
        fx.db
            .tamper("UPDATE users SET email = 'not an address' WHERE email = 'ada@acme.example'")
            .await;

        let page = fx
            .queries
            .find(
                &fx.tenant,
                &ScimQuery::All,
                ScimUserSort::Default,
                ScimWindow::new(1, 100),
            )
            .await;

        assert!(matches!(page, Err(DomainError::Infrastructure(_))));
    }
}
