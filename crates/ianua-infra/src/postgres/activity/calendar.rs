//! The counts behind the activity calendar: how many audit records fell on
//! each UTC day, by category, for a tenant or for an organization and its
//! tenants.
//!
//! Each place the records are kept is counted once, by day and event type:
//! a tenant in the database it lives in, the tenants of an organization
//! its reader reaches in the platform database at once, each with a
//! database of its own there, and the organization's own records. The
//! counts are then summed into the
//! categories the domain files each event under, so no category is stored
//! beside a record to fall out of step with it.

mod record;

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::future::try_join_all;
use ianua_app::ports::activity::ActivityStore;
use ianua_domain::domains::activity::{ActivityScope, CalendarRange, DailyCategoryCount};
use ianua_domain::domains::audit::access::OrgLogView;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrganizationId, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use self::record::{DayCountRecord, into_counts};
use crate::postgres::audit::logs::sources::reached_history_tenants;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres read of the activity calendar's counts.
pub struct PgActivityStore {
    databases: Arc<Databases>,
}

impl PgActivityStore {
    /// A read of the audit records kept in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The day counts of `tenants`' records within `window`, read where
    /// `scope` says they are kept.
    async fn of_tenants(
        &self,
        scope: RowScope,
        tenants: Vec<Uuid>,
        window: (OffsetDateTime, OffsetDateTime),
    ) -> Result<Vec<DayCountRecord>, DomainError> {
        scoped(&self.databases, scope, async |connection| {
            sqlx::query_file_as!(
                DayCountRecord,
                "queries/audit_records/daily_counts.sql",
                &tenants,
                window.0,
                window.1
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// The day counts of `organization`'s own records within `window`.
    async fn of_organization(
        &self,
        organization: &OrganizationId,
        window: (OffsetDateTime, OffsetDateTime),
    ) -> Result<Vec<DayCountRecord>, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                DayCountRecord,
                "queries/platform_audit_records/daily_counts_of_organization.sql",
                organization.as_uuid(),
                window.0,
                window.1
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// The day counts of `view`'s organization and the tenants it reaches,
    /// each place they are kept read at once.
    async fn of_organization_and_tenants(
        &self,
        view: &OrgLogView,
        window: (OffsetDateTime, OffsetDateTime),
    ) -> Result<Vec<DayCountRecord>, DomainError> {
        let organization = view.organization();
        let tenants = reached_history_tenants(&self.databases, organization, view.reach()).await?;
        let apart = self.dedicated_tenants(&tenants);
        let shared: Vec<Uuid> = tenants
            .into_iter()
            .filter(|tenant| !apart.contains(tenant))
            .collect();
        let own_databases = try_join_all(apart.into_iter().map(|tenant| {
            self.of_tenants(
                RowScope::Tenant(TenantId::from_uuid(tenant)),
                vec![tenant],
                window,
            )
        }));
        let (own, platform, apart) = futures_util::try_join!(
            self.of_organization(organization, window),
            self.of_tenants(RowScope::Platform, shared, window),
            own_databases,
        )?;
        Ok(own
            .into_iter()
            .chain(platform)
            .chain(apart.into_iter().flatten())
            .collect())
    }

    /// Selects retained-history tenants whose records live outside the shared database.
    fn dedicated_tenants(&self, tenants: &[Uuid]) -> BTreeSet<Uuid> {
        self.databases
            .with_own_database()
            .iter()
            .map(|tenant| *tenant.as_uuid())
            .filter(|tenant| tenants.contains(tenant))
            .collect()
    }
}

#[async_trait]
impl ActivityStore for PgActivityStore {
    async fn daily_category_counts(
        &self,
        scope: &ActivityScope,
        range: &CalendarRange,
    ) -> Result<Vec<DailyCategoryCount>, DomainError> {
        let window = range.utc_window();
        let records = match scope {
            ActivityScope::Tenant(tenant) => {
                self.of_tenants(RowScope::Tenant(*tenant), vec![*tenant.as_uuid()], window)
                    .await?
            }
            ActivityScope::Organization(view) => {
                self.of_organization_and_tenants(view, window).await?
            }
        };
        into_counts(records)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::tenant::TenantStore;
    use ianua_domain::domains::activity::ActivityCategory;
    use ianua_domain::domains::audit::access::LogReach;
    use ianua_domain::test_support::events::sample_organization_event;
    use ianua_domain::types::ActedBy;
    use time::Date;

    use super::*;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::{
        failed_sign_in, recorded, saved_organization, saved_tenant_of,
    };

    struct Fixture {
        db: TestDb,
        organization: OrganizationId,
        tenant: TenantId,
        store: PgActivityStore,
    }

    impl Fixture {
        /// Reads the organization's calendar around the fixtures' fixed event dates.
        async fn organization_counts(&self) -> Vec<DailyCategoryCount> {
            self.store
                .daily_category_counts(
                    &ActivityScope::Organization(OrgLogView::new(
                        self.organization,
                        LogReach::Every,
                    )),
                    &around_the_fixed_moment(),
                )
                .await
                .unwrap()
        }
    }

    /// A fresh database holding Acme and one of its tenants, and the read
    /// on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        let tenant = *saved_tenant_of(&db.databases, organization).await;
        Fixture {
            store: PgActivityStore::new(Arc::clone(&db.databases)),
            organization,
            tenant,
            db,
        }
    }

    /// The days around the fixed moment every test row is dated from.
    fn around_the_fixed_moment() -> CalendarRange {
        let day = at(0).date();
        CalendarRange::new(day.previous_day().unwrap(), day.next_day().unwrap()).unwrap()
    }

    fn cells(counts: &[DailyCategoryCount]) -> Vec<(Date, ActivityCategory, u64)> {
        counts
            .iter()
            .map(|cell| (cell.date, cell.category, cell.count))
            .collect()
    }

    /// Three failed sign-ins of the tenant, one a day later, are counted
    /// on their days under authentication.
    #[tokio::test]
    async fn a_tenants_records_are_counted_by_day_and_category() {
        let fx = fixture().await;
        let events = vec![
            failed_sign_in(fx.tenant, 1),
            failed_sign_in(fx.tenant, 2),
            failed_sign_in(fx.tenant, 86_400),
        ];
        recorded(&fx.db.databases, events).await;
        let day = at(0).date();

        let counts = fx
            .store
            .daily_category_counts(
                &ActivityScope::Tenant(fx.tenant),
                &around_the_fixed_moment(),
            )
            .await
            .unwrap();

        assert_eq!(
            cells(&counts),
            [
                (day, ActivityCategory::Authentication, 2),
                (day.next_day().unwrap(), ActivityCategory::Authentication, 1),
            ]
        );
    }

    /// Records outside the range are left out.
    #[tokio::test]
    async fn records_outside_the_range_are_left_out() {
        let fx = fixture().await;
        recorded(
            &fx.db.databases,
            vec![failed_sign_in(fx.tenant, 10 * 86_400)],
        )
        .await;

        let counts = fx
            .store
            .daily_category_counts(
                &ActivityScope::Tenant(fx.tenant),
                &around_the_fixed_moment(),
            )
            .await
            .unwrap();

        assert!(counts.is_empty());
    }

    /// Vic reaches no tenant, so his calendar counts the organization's
    /// own record alone; Max reaches one, so his counts that tenant's too.
    #[tokio::test]
    async fn an_organizations_calendar_counts_only_the_tenants_its_reader_reaches() {
        let fx = fixture().await;
        let other = *saved_tenant_of(&fx.db.databases, fx.organization).await;
        recorded(
            &fx.db.databases,
            vec![
                failed_sign_in(fx.tenant, 1),
                failed_sign_in(other, 2),
                sample_organization_event(fx.organization, at(3)),
            ],
        )
        .await;
        let counted = async |reach| {
            let view = OrgLogView::new(fx.organization, reach);
            let counts = fx
                .store
                .daily_category_counts(
                    &ActivityScope::Organization(view),
                    &around_the_fixed_moment(),
                )
                .await
                .unwrap();
            counts.iter().map(|cell| cell.count).sum::<u64>()
        };

        assert_eq!(counted(LogReach::Tenants(Vec::new())).await, 1);
        assert_eq!(counted(LogReach::Tenants(vec![fx.tenant])).await, 2);
    }

    /// An organization's calendar counts its own records and those of each
    /// tenant, one kept in a database of its own among them; another
    /// organization's tenant is left out.
    #[tokio::test]
    async fn an_organizations_calendar_counts_its_own_and_its_tenants() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = *saved_tenant_of(&fx.db.databases, fx.organization).await;
        fx.db.databases.register(apart, own.as_dedicated());
        let elsewhere = saved_organization(&fx.db.databases).await;
        let theirs = *saved_tenant_of(&fx.db.databases, elsewhere).await;
        recorded(
            &fx.db.databases,
            vec![
                failed_sign_in(fx.tenant, 1),
                failed_sign_in(apart, 2),
                failed_sign_in(theirs, 3),
                sample_organization_event(fx.organization, at(4)),
            ],
        )
        .await;

        let counts = fx.organization_counts().await;

        let day = at(0).date();
        assert_eq!(
            cells(&counts),
            [
                (day, ActivityCategory::Authentication, 2),
                (day, ActivityCategory::Provisioning, 1),
            ]
        );
    }

    /// An organization's calendar still counts its deleted tenant's retained
    /// sign-in record, while excluding another organization's record.
    #[tokio::test]
    async fn an_organizations_calendar_keeps_its_deleted_tenants_retained_activity() {
        let fx = fixture().await;
        let elsewhere = saved_organization(&fx.db.databases).await;
        let theirs = *saved_tenant_of(&fx.db.databases, elsewhere).await;
        recorded(
            &fx.db.databases,
            vec![failed_sign_in(fx.tenant, 1), failed_sign_in(theirs, 2)],
        )
        .await;
        let tenants = PgTenantStore::new(
            Arc::clone(&fx.db.databases),
            ianua_domain::shared::config::DomainLimits::default(),
        );
        let mut tenant = tenants.find_by_id(&fx.tenant).await.unwrap().unwrap();
        let _archived =
            ianua_domain::shared::clock::freeze(tenant.created_at() + time::Duration::days(1));
        tenant.archive(ActedBy::Platform).unwrap();
        let _later =
            ianua_domain::shared::clock::freeze(tenant.updated_at() + time::Duration::days(31));
        tenant.delete(ActedBy::Platform).unwrap();
        tenants.save(&tenant).await.unwrap();
        let counts = fx.organization_counts().await;
        assert_eq!(
            cells(&counts),
            [(at(0).date(), ActivityCategory::Authentication, 1)]
        );
    }

    /// A tenant's calendar is empty when the only recorded activity belongs
    /// to another tenant in the same organization.
    #[tokio::test]
    async fn a_tenants_calendar_counts_its_own_records_alone() {
        let fx = fixture().await;
        let other = *saved_tenant_of(&fx.db.databases, fx.organization).await;
        recorded(&fx.db.databases, vec![failed_sign_in(other, 1)]).await;

        let counts = fx
            .store
            .daily_category_counts(
                &ActivityScope::Tenant(fx.tenant),
                &around_the_fixed_moment(),
            )
            .await
            .unwrap();

        assert!(counts.is_empty());
    }
}
