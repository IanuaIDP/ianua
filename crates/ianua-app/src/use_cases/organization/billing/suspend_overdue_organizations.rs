//! The background sweep that suspends organizations whose payment has been
//! owed for longer than the grace the platform allows.
//!
//! The platform suspends it for not paying, so settling the debt lifts it,
//! and otherwise only the platform does. Owners and the billing contact
//! still sign in while it is suspended, to pay what is owed.

use std::sync::Arc;

use ianua_domain::domains::organization::billing::subscription::OrgSubscription;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::status::{OrganizationStatus, Suspension};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;
use time::Duration;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrgSubscriptionStore, OrganizationStore};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::services::sweep_round::SweepRound;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_organization;
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_organization;

/// The ports [`SuspendOverdueOrganizationsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SuspendOverdueOrganizationsPorts {
    /// Lists the subscriptions a payment is owed on.
    pub subscriptions: Arc<dyn OrgSubscriptionStore>,
    /// Organizations, saved suspended.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Members' sessions, ended when their organization is suspended.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Keeps each suspension, its sessions' end and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Suspends every organization whose payment is overdue beyond the grace.
///
/// It runs as a periodic job of the platform, with nobody asking.
pub struct SuspendOverdueOrganizationsUseCase {
    ports: SuspendOverdueOrganizationsPorts,
    grace: Duration,
}

/// What the sweep did to one organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Swept {
    /// It was suspended now.
    Suspended,
    /// It was left as it is: still within the grace, already suspended by
    /// the platform, or closed.
    Left,
}

impl SuspendOverdueOrganizationsUseCase {
    /// A use case working through `ports`, suspending an organization once
    /// a payment has been owed for longer than `grace`.
    #[must_use]
    pub fn new(ports: SuspendOverdueOrganizationsPorts, grace: Duration) -> Self {
        Self { ports, grace }
    }

    /// Suspends the organization `subscription` belongs to when its
    /// payment is overdue beyond the grace, ends its sessions, and records
    /// the suspension against it.
    async fn swept(
        &self,
        auditor: &RequestAuditor,
        subscription: &OrgSubscription,
    ) -> Result<Swept, AppError> {
        if !subscription.overdue_beyond(self.grace) {
            return Ok(Swept::Left);
        }
        let store = self.ports.organizations.as_ref();
        let mut organization = existing_organization(store, subscription.organization_id()).await?;
        if is_held_already(&organization) {
            return Ok(Swept::Left);
        }
        organization
            .suspend_for_non_payment()
            .map_err(AppError::from_domain)?;
        let kept = self.suspension_kept(auditor, &mut organization);
        kept_together(self.ports.unit_of_work.as_ref(), kept).await?;
        Ok(Swept::Suspended)
    }

    /// Saves `organization` suspended, ends its members' sessions, and
    /// records the suspension against it.
    async fn suspension_kept(
        &self,
        auditor: &RequestAuditor,
        organization: &mut Organization,
    ) -> Result<(), AppError> {
        self.ports
            .organizations
            .save(organization)
            .await
            .or_internal()?;
        sign_out_organization(self.ports.org_sessions.as_ref(), organization.id()).await?;
        auditor
            .with_organization(*organization.id())
            .dispatch_by(&ActorRef::System, organization.take_events())
            .await
            .or_internal()
    }
}

impl Command for SuspendOverdueOrganizationsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<SweepRound, AppError>;

    /// Suspends every organization whose payment has been owed for longer
    /// than the grace, ends its members' sessions, and records
    /// `organization.status_changed` against it, by the platform. An
    /// organization the platform already suspended, or one closed, is left
    /// as it is. Each suspension, its sessions' end and its record are kept
    /// together: an organization whose suspension cannot be kept whole
    /// keeps no change, is logged, counted as failed and found again by the
    /// next sweep.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` if listing the subscriptions fails.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<SweepRound, AppError> {
        let owing = self
            .ports
            .subscriptions
            .list_past_due()
            .await
            .or_internal()?;
        let mut round = SweepRound::default();
        for subscription in &owing {
            round = match self.swept(auditor, subscription).await {
                Ok(Swept::Suspended) => round.with_changed(),
                Ok(Swept::Left) => round,
                Err(error) => {
                    tracing::warn!(
                        organization = %subscription.organization_id(),
                        %error,
                        "overdue organization could not be suspended; left for the next sweep"
                    );
                    round.with_failed()
                }
            };
        }
        Ok(round)
    }
}

/// Whether `organization` needs no suspension: the platform holds it
/// suspended already, or it is closed.
fn is_held_already(organization: &Organization) -> bool {
    matches!(organization.suspended_by(), Suspension::ByPlatform(_))
        || organization.status() == OrganizationStatus::Closed
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::payment::{
        PaymentMethod, SubscriptionState, TrialUse,
    };
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::shared::clock;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::test_support::organization::{
        FakeOrgSubscriptionStore, FakeOrganizationStore, SubscriptionShape, org_store_with,
        test_org, test_subscription,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
    };

    /// The grace the tests run under: a week.
    const GRACE_DAYS: i64 = 7;

    struct Setup {
        uc: SuspendOverdueOrganizationsUseCase,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
        acme: OrganizationId,
    }

    fn owing_for(days: i64) -> Setup {
        let acme = OrganizationId::new();
        let orgs = org_store_with([test_org(acme, "acme")]);
        let shape = SubscriptionShape {
            plan: OrganizationPlan::Starter,
            state: SubscriptionState::PastDue {
                since: clock::now() - Duration::days(days),
            },
            payment: PaymentMethod::Missing,
            trial: TrialUse::Used,
        };
        let subscriptions = FakeOrgSubscriptionStore::holding([test_subscription(acme, shape)]);
        let unit = Arc::new(RecordingUnitOfWork::default());
        Setup {
            uc: SuspendOverdueOrganizationsUseCase::new(
                SuspendOverdueOrganizationsPorts {
                    subscriptions: Arc::new(subscriptions),
                    organizations: orgs.clone(),
                    unit_of_work: unit.clone(),
                    ..SuspendOverdueOrganizationsPorts::fakes()
                },
                Duration::days(GRACE_DAYS),
            ),
            orgs,
            audit: Arc::new(FakeEventDispatcher::new()),
            unit,
            acme,
        }
    }

    fn sweep(s: &Setup) -> SweepRound {
        block_on(s.uc.execute(&(), &test_auditor(s.audit.clone()), ())).unwrap()
    }

    fn stored(s: &Setup) -> Organization {
        s.orgs.stored(&s.acme).unwrap()
    }

    /// Acme has owed a payment for ten days, past the week's grace. The
    /// platform suspends it and records the suspension.
    #[test]
    fn an_organization_overdue_beyond_the_grace_is_suspended() {
        let s = owing_for(10);

        let suspended = sweep(&s);

        assert_eq!((suspended.changed(), suspended.failed()), (1, 0));
        assert_eq!(s.unit.settlements(), [Settlement::Commit]);
        assert_eq!(stored(&s).status(), OrganizationStatus::Suspended);
        assert!(stored(&s).suspended_for_non_payment());
        assert_eq!(
            s.audit.records.lock().unwrap().as_slice(),
            ["organization.status_changed"]
        );
    }

    /// Acme has owed a payment for two days, inside the grace. It stays
    /// active and nothing is recorded.
    #[test]
    fn an_organization_within_the_grace_stays_active() {
        let s = owing_for(2);

        let suspended = sweep(&s);

        assert_eq!(suspended, SweepRound::default());
        assert_eq!(stored(&s).status(), OrganizationStatus::Active);
        assert!(s.audit.records.lock().unwrap().is_empty());
    }

    /// The sweep runs again over Acme, already suspended for the debt. It
    /// is left as it is and nothing more is recorded.
    #[test]
    fn a_second_sweep_leaves_a_suspended_organization_alone() {
        let s = owing_for(10);
        sweep(&s);

        let again = sweep(&s);

        assert_eq!(again, SweepRound::default());
        assert_eq!(s.audit.records.lock().unwrap().len(), 1);
    }

    /// An audit failure while suspending overdue Acme rolls back its unit;
    /// the sweep reports one failure and no completed change.
    #[test]
    fn a_suspension_whose_record_fails_keeps_no_change() {
        let s = owing_for(10);

        let swept =
            block_on(s.uc.execute(&(), &test_auditor(Arc::new(FailingEventDispatcher)), ()))
                .unwrap();

        assert_eq!((swept.changed(), swept.failed()), (0, 1));
        assert_eq!(s.unit.settlements(), [Settlement::Rollback]);
    }
}
