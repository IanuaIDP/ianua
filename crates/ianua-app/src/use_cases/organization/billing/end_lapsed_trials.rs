//! The background sweep that ends trials whose time ran out: an
//! organization with a payment method starts paying, one without owes a
//! payment from the trial's end.

use std::sync::Arc;

use ianua_domain::domains::organization::billing::subscription::OrgSubscription;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgSubscriptionStore;
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::services::sweep_round::SweepRound;
use crate::use_case::Command;

/// The ports [`EndLapsedTrialsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EndLapsedTrialsPorts {
    /// Lists the trials that ran out, across every organization, and saves
    /// each one ended.
    pub subscriptions: Arc<dyn OrgSubscriptionStore>,
    /// Keeps each trial's end and its record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Ends every trial whose time ran out.
///
/// It runs as a periodic job of the platform, with nobody asking.
pub struct EndLapsedTrialsUseCase {
    ports: EndLapsedTrialsPorts,
}

impl EndLapsedTrialsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EndLapsedTrialsPorts) -> Self {
        Self { ports }
    }

    /// Ends `subscription`'s trial, saves it, and records the end against
    /// its organization, the save and the record kept together.
    async fn end(
        &self,
        auditor: &RequestAuditor,
        subscription: &mut OrgSubscription,
    ) -> Result<(), AppError> {
        subscription.end_trial().map_err(AppError::from_domain)?;
        let kept = async {
            self.ports
                .subscriptions
                .save(subscription)
                .await
                .or_internal()?;
            auditor
                .with_organization(*subscription.organization_id())
                .dispatch_by(&ActorRef::System, subscription.take_events())
                .await
                .or_internal()
        };
        kept_together(self.ports.unit_of_work.as_ref(), kept).await
    }
}

impl Command for EndLapsedTrialsUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<SweepRound, AppError>;

    /// Ends every trial that ran out by now and records
    /// `organization.trial_ended` against each organization, by the
    /// platform. Each trial's end and its record are kept together: a trial
    /// whose end cannot be saved or recorded keeps no change, is logged,
    /// counted as failed and found again by the next sweep.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` if listing the trials fails.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<SweepRound, AppError> {
        let lapsed = self
            .ports
            .subscriptions
            .list_trials_ended(clock::now())
            .await
            .or_internal()?;
        let mut round = SweepRound::default();
        for mut subscription in lapsed {
            round = match self.end(auditor, &mut subscription).await {
                Ok(()) => round.with_changed(),
                Err(error) => {
                    tracing::warn!(
                        organization = %subscription.organization_id(),
                        %error,
                        "trial could not be ended; left for the next sweep"
                    );
                    round.with_failed()
                }
            };
        }
        Ok(round)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::payment::{
        PaymentMethod, PaymentReference, SubscriptionState, TrialUse,
    };
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::types::OrganizationId;
    use time::Duration;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::ports::shared::EventDispatcher;
    use crate::test_support::organization::{
        FakeOrgSubscriptionStore, SubscriptionShape, test_subscription,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
    };

    fn trialing(ends_in: Duration, payment: PaymentMethod) -> SubscriptionShape {
        SubscriptionShape {
            plan: OrganizationPlan::Starter,
            state: SubscriptionState::Trialing {
                ends_at: clock::now() + ends_in,
            },
            payment,
            trial: TrialUse::Used,
        }
    }

    fn card() -> PaymentMethod {
        PaymentMethod::OnFile(PaymentReference::new("pm_1NvXyz").unwrap())
    }

    /// One round over `store`, recording through `audit`, its units
    /// settled in `unit`.
    fn round(
        store: &Arc<FakeOrgSubscriptionStore>,
        audit: Arc<dyn EventDispatcher>,
        unit: &Arc<RecordingUnitOfWork>,
    ) -> SweepRound {
        let uc = EndLapsedTrialsUseCase::new(EndLapsedTrialsPorts {
            subscriptions: store.clone(),
            unit_of_work: unit.clone(),
        });
        block_on(uc.execute(&(), &test_auditor(audit), ())).unwrap()
    }

    fn sweep(
        store: &Arc<FakeOrgSubscriptionStore>,
        audit: &Arc<FakeEventDispatcher>,
    ) -> SweepRound {
        round(
            store,
            audit.clone(),
            &Arc::new(RecordingUnitOfWork::default()),
        )
    }

    /// Acme's trial ended yesterday with a card on file, and Globex's
    /// without one. Acme starts paying and Globex owes a payment. Both ends
    /// are recorded.
    #[test]
    fn ended_trials_pay_or_owe() {
        let (acme, globex) = (OrganizationId::new(), OrganizationId::new());
        let store = Arc::new(FakeOrgSubscriptionStore::holding([
            test_subscription(acme, trialing(Duration::days(-1), card())),
            test_subscription(globex, trialing(Duration::days(-1), PaymentMethod::Missing)),
        ]));
        let audit = Arc::new(FakeEventDispatcher::new());

        let swept = sweep(&store, &audit);

        assert_eq!((swept.changed(), swept.failed()), (2, 0));
        assert_eq!(
            store.stored(&acme).unwrap().state(),
            SubscriptionState::Active
        );
        assert!(matches!(
            store.stored(&globex).unwrap().state(),
            SubscriptionState::PastDue { .. }
        ));
        assert_eq!(audit.records.lock().unwrap().len(), 2);
    }

    /// Initech's trial runs another week. It is left running and nothing is
    /// recorded.
    #[test]
    fn a_running_trial_is_left_alone() {
        let initech = OrganizationId::new();
        let store = Arc::new(FakeOrgSubscriptionStore::holding([test_subscription(
            initech,
            trialing(Duration::days(7), PaymentMethod::Missing),
        )]));
        let audit = Arc::new(FakeEventDispatcher::new());

        let swept = sweep(&store, &audit);

        assert_eq!(swept, SweepRound::default());
        assert!(matches!(
            store.stored(&initech).unwrap().state(),
            SubscriptionState::Trialing { .. }
        ));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// When recording an expired trial's end fails, its unit rolls back
    /// and the sweep counts a failure rather than a completed change.
    #[test]
    fn a_trial_whose_record_fails_keeps_no_change() {
        let acme = OrganizationId::new();
        let store = Arc::new(FakeOrgSubscriptionStore::holding([test_subscription(
            acme,
            trialing(Duration::days(-1), card()),
        )]));
        let unit = Arc::new(RecordingUnitOfWork::default());

        let swept = round(&store, Arc::new(FailingEventDispatcher), &unit);

        assert_eq!((swept.changed(), swept.failed()), (0, 1));
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }
}
