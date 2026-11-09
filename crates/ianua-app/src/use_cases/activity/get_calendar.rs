//! The contribution calendar of an organization or a tenant.

use std::sync::Arc;

use ianua_domain::domains::activity::{ActivityCalendar, ActivityScope, CalendarRange};
use ianua_domain::domains::authorization::permission::{AuditLogAction, SystemPermission};

use crate::acting::{OrgActors, TenantAuthorities};
use crate::context::{CallerContext, OrgCaller};
use crate::error::AppError;
use crate::ports::activity::ActivityStore;
use crate::ports::organization::OrgTenantGrantStore;
use crate::services::lookup::granted_tenants;
use crate::use_case::Query;

/// Who asks for a calendar, and so whose activity it counts.
pub enum ActivityViewer {
    /// A member, for their organization and the tenants they reach.
    Organization(OrgCaller),
    /// Someone acting in a tenant, for that tenant.
    Tenant(CallerContext),
}

/// The ports [`GetCalendarUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetCalendarPorts {
    /// Audit event counts per day and category.
    pub activity: Arc<dyn ActivityStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The tenants a member was let into, which decide what they count.
    pub tenant_grants: Arc<dyn OrgTenantGrantStore>,
}

/// Builds the activity calendar: audit event counts per day and category,
/// zero-filled and graded into intensity levels.
pub struct GetCalendarUseCase {
    ports: GetCalendarPorts,
}

impl GetCalendarUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetCalendarPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetCalendarUseCase {
    type Caller = ActivityViewer;
    type Input = CalendarRange;
    type Output = Result<ActivityCalendar, AppError>;

    /// The calendar of what `viewer` may watch, over `range`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the viewer's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the viewer may not read the audit log of
    ///   their organization or tenant.
    /// - `AppError::Internal` when the store fails or reports counts that do
    ///   not form a calendar.
    async fn execute(
        &self,
        viewer: &ActivityViewer,
        range: CalendarRange,
    ) -> Result<ActivityCalendar, AppError> {
        let scope = watched_scope(&self.ports, viewer).await?;
        let counts = self
            .ports
            .activity
            .daily_category_counts(&scope, &range)
            .await
            .map_err(AppError::from_domain)?;
        ActivityCalendar::from_daily_category_counts(range, &counts).map_err(AppError::from_domain)
    }
}

/// The organization or tenant whose activity `viewer` may watch: their
/// own, once they hold the right to read its audit log, as far into an
/// organization's tenants as they reach.
async fn watched_scope(
    ports: &GetCalendarPorts,
    viewer: &ActivityViewer,
) -> Result<ActivityScope, AppError> {
    match viewer {
        ActivityViewer::Tenant(caller) => {
            let authority = ports.tenant_authorities.authority(caller).await?;
            authority
                .ensure_holds(SystemPermission::AuditLog(AuditLogAction::View))
                .map_err(AppError::from_domain)?;
            Ok(ActivityScope::Tenant(*authority.tenant()))
        }
        ActivityViewer::Organization(caller) => {
            let (organization, actor) = ports.org_actors.actor(caller).await?;
            let granted = granted_tenants(ports.tenant_grants.as_ref(), actor.member()).await?;
            let view = actor
                .control()?
                .audit_log_view(organization.id(), &granted)
                .map_err(AppError::from_domain)?;
            Ok(ActivityScope::Organization(view))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::activity::{ActivityCategory, ActivityLevel, DailyCategoryCount};
    use ianua_domain::domains::audit::access::{LogReach, OrgLogView};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::TenantId;
    use time::{Date, Month};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, FakeTenantAuthorities, Refusal};
    use crate::test_support::organization::{FakeOrgTenantGrantStore, platform_grant_to};
    use crate::test_support::{block_on, test_ctx, test_org_caller};

    /// Hands back fixed counts and remembers whose activity was asked for.
    struct FixedActivityStore {
        counts: Vec<DailyCategoryCount>,
        asked: Mutex<Vec<ActivityScope>>,
    }

    impl FixedActivityStore {
        fn with(counts: Vec<DailyCategoryCount>) -> Arc<Self> {
            Arc::new(Self {
                counts,
                asked: Mutex::new(Vec::new()),
            })
        }

        fn asked(&self) -> Vec<ActivityScope> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ActivityStore for FixedActivityStore {
        async fn daily_category_counts(
            &self,
            scope: &ActivityScope,
            _: &CalendarRange,
        ) -> Result<Vec<DailyCategoryCount>, DomainError> {
            self.asked.lock().unwrap().push(scope.clone());
            Ok(self.counts.clone())
        }
    }

    struct FailingActivityStore;

    #[async_trait]
    impl ActivityStore for FailingActivityStore {
        async fn daily_category_counts(
            &self,
            _: &ActivityScope,
            _: &CalendarRange,
        ) -> Result<Vec<DailyCategoryCount>, DomainError> {
            Err(DomainError::infra_msg("store unreachable"))
        }
    }

    fn date(day: u8) -> Date {
        Date::from_calendar_date(2026, Month::June, day).unwrap()
    }

    fn range() -> CalendarRange {
        CalendarRange::new(date(1), date(3)).unwrap()
    }

    fn seven_sign_ins_on(day: u8) -> Vec<DailyCategoryCount> {
        vec![DailyCategoryCount {
            date: date(day),
            category: ActivityCategory::Authentication,
            count: 7,
        }]
    }

    fn use_case_over(activity: Arc<dyn ActivityStore>) -> GetCalendarUseCase {
        GetCalendarUseCase::new(GetCalendarPorts {
            activity,
            ..GetCalendarPorts::fakes()
        })
    }

    /// Acme had seven sign-ins on 2 June and none on the days around it. The
    /// calendar shows all three days, the quiet ones at the lowest level and
    /// 2 June at the peak.
    #[test]
    fn a_tenant_calendar_is_zero_filled_and_graded() {
        let use_case = use_case_over(FixedActivityStore::with(seven_sign_ins_on(2)));

        let calendar =
            block_on(use_case.execute(&ActivityViewer::Tenant(test_ctx()), range())).unwrap();

        assert_eq!(calendar.days().len(), 3);
        assert_eq!(calendar.total(), 7);
        assert_eq!(calendar.days()[1].level(), ActivityLevel::Peak);
        assert_eq!(calendar.days()[0].level(), ActivityLevel::None);
        assert_eq!(calendar.categories(), &[ActivityCategory::Authentication]);
    }

    /// Ann, an admin of the prod tenant, asks for the calendar. It counts the
    /// prod tenant's events, the tenant her session is in.
    #[test]
    fn a_tenant_caller_watches_their_own_tenant() {
        let store = FixedActivityStore::with(Vec::new());
        let use_case = use_case_over(store.clone());
        let caller = test_ctx();

        block_on(use_case.execute(&ActivityViewer::Tenant(caller.clone()), range())).unwrap();

        assert_eq!(
            store.asked(),
            vec![ActivityScope::Tenant(caller.tenant_id())]
        );
    }

    /// Ann, the owner of Acme, asks for the calendar from the organization
    /// view. It counts Acme's events, across all its tenants.
    #[test]
    fn an_owner_watches_every_tenant_of_their_organization() {
        let store = FixedActivityStore::with(Vec::new());
        let use_case = use_case_over(store.clone());
        let caller = test_org_caller();

        block_on(use_case.execute(&ActivityViewer::Organization(caller.clone()), range())).unwrap();

        assert_eq!(
            store.asked(),
            vec![ActivityScope::Organization(OrgLogView::new(
                caller.organization_id(),
                LogReach::Every,
            ))]
        );
    }

    /// Max, a member let into one tenant, counts that tenant's events and
    /// the organization's own, and no other tenant's.
    #[test]
    fn a_member_watches_only_the_tenants_they_reach() {
        let store = FixedActivityStore::with(Vec::new());
        let caller = test_org_caller();
        let tenant = TenantId::new();
        let use_case = GetCalendarUseCase::new(GetCalendarPorts {
            activity: store.clone(),
            org_actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
            tenant_grants: Arc::new(FakeOrgTenantGrantStore::holding([platform_grant_to(
                *caller.member(),
                tenant,
            )])),
            ..GetCalendarPorts::fakes()
        });

        block_on(use_case.execute(&ActivityViewer::Organization(caller.clone()), range())).unwrap();

        assert_eq!(
            store.asked(),
            vec![ActivityScope::Organization(OrgLogView::new(
                caller.organization_id(),
                LogReach::Tenants(vec![tenant]),
            ))]
        );
    }

    /// Without the tenant's audit-log view right, reading its calendar is
    /// forbidden before the activity store is queried.
    #[test]
    fn a_tenant_caller_without_the_audit_log_right_is_refused() {
        let store = FixedActivityStore::with(seven_sign_ins_on(2));
        let use_case = GetCalendarUseCase::new(GetCalendarPorts {
            activity: store.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..GetCalendarPorts::fakes()
        });

        let result = block_on(use_case.execute(&ActivityViewer::Tenant(test_ctx()), range()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(store.asked().is_empty());
    }

    /// An organization authority refusal prevents reading the calendar
    /// before the activity store is queried.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let store = FixedActivityStore::with(seven_sign_ins_on(2));
        let use_case = GetCalendarUseCase::new(GetCalendarPorts {
            activity: store.clone(),
            org_actors: Arc::new(FakeOrgActors::refusing(Refusal::Forbidden)),
            ..GetCalendarPorts::fakes()
        });

        let result =
            block_on(use_case.execute(&ActivityViewer::Organization(test_org_caller()), range()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(store.asked().is_empty());
    }

    /// A signed-out session cannot read the tenant's activity calendar.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = GetCalendarUseCase::new(GetCalendarPorts {
            activity: FixedActivityStore::with(seven_sign_ins_on(2)),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..GetCalendarPorts::fakes()
        });

        let result = block_on(use_case.execute(&ActivityViewer::Tenant(test_ctx()), range()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// The store cannot be reached. The caller gets an internal error, not an
    /// empty calendar that would read as no activity.
    #[test]
    fn a_store_failure_is_internal() {
        let use_case = use_case_over(Arc::new(FailingActivityStore));

        let result = block_on(use_case.execute(&ActivityViewer::Tenant(test_ctx()), range()));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// The store answers with a count from 30 June for a calendar of 1 to 3
    /// June. It is refused as corrupt rather than dropped or shown.
    #[test]
    fn counts_outside_the_range_are_refused_as_corrupt() {
        let use_case = use_case_over(FixedActivityStore::with(vec![DailyCategoryCount {
            date: date(30),
            category: ActivityCategory::Authentication,
            count: 1,
        }]));

        let result = block_on(use_case.execute(&ActivityViewer::Tenant(test_ctx()), range()));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
