//! Receiving a payment notice: the payment provider tells the platform a
//! payment method was added, a charge failed, or what was owed is paid.
//!
//! Nobody signs in for it. The provider's signature on the notice is what
//! lets it in, and the adapter checks it before anything in the notice is
//! read.
//!
//! Settling what was owed lifts a suspension the platform made for not
//! paying, and never one an operator made.
//!
//! The provider delivers an event again whenever an answer is lost, and in
//! no set order. So an event already acted on is acknowledged and acted on
//! no second time, and an event older than one of its kind already applied
//! changes nothing: a failed charge reported after the payment that settled
//! it leaves the organization paid up.

use std::sync::Arc;

use ianua_domain::domains::organization::billing::payment::PaymentReference;
use ianua_domain::domains::organization::billing::subscription::OrgSubscription;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, OrganizationId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{
    EventOrder, EventReceipt, OrgSubscriptionStore, OrganizationStore, PaymentEvent,
    PaymentEventLedger, PaymentNotice, PaymentProvider, PaymentStream, PaymentWebhook,
};
use crate::use_case::Command;
use crate::use_cases::organization::billing::lookup::existing_subscription;
use crate::use_cases::organization::lookup::existing_organization;

/// The ports [`ReceivePaymentNoticeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReceivePaymentNoticePorts {
    /// The payment provider, which verifies and reads its own notices.
    pub payment_provider: Arc<dyn PaymentProvider>,
    /// Organizations' subscriptions.
    pub subscriptions: Arc<dyn OrgSubscriptionStore>,
    /// Organizations, whose suspension for not paying a settlement lifts.
    pub organizations: Arc<dyn OrganizationStore>,
    /// The provider's events acted on, and the newest applied of each kind.
    pub payment_events: Arc<dyn PaymentEventLedger>,
}

/// Records what a verified payment notice reports on the organization's
/// subscription.
pub struct ReceivePaymentNoticeUseCase {
    ports: ReceivePaymentNoticePorts,
}

impl ReceivePaymentNoticeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReceivePaymentNoticePorts) -> Self {
        Self { ports }
    }

    /// Records `change`, reported by `event`, on the subscription of
    /// `organization_id`, saves it, lifts a suspension for not paying once
    /// the debt is settled, and records what they raised against the
    /// organization, by the platform. An event taken before, or older than
    /// one of its kind applied, changes nothing.
    async fn record(
        &self,
        auditor: &RequestAuditor,
        event: &PaymentEvent,
        organization_id: OrganizationId,
        change: PaymentChange,
    ) -> Result<(), AppError> {
        let store = self.ports.subscriptions.as_ref();
        let mut subscription = existing_subscription(store, &organization_id).await?;
        if !self.is_newest(&organization_id, event, &change).await? {
            return Ok(());
        }
        let settles = settles(&change);
        apply(&mut subscription, change)?;
        store.save(&subscription).await.or_internal()?;
        let mut events = subscription.take_events();
        if settles {
            events.extend(self.lifted_suspension(&organization_id).await?);
        }
        auditor
            .with_organization(organization_id)
            .dispatch_by(&ActorRef::System, events)
            .await
            .or_internal()
    }

    /// Whether `event` is taken for the first time and is newer than every
    /// event of its kind applied to `organization_id`, moving the newest on
    /// to it when it is.
    async fn is_newest(
        &self,
        organization_id: &OrganizationId,
        event: &PaymentEvent,
        change: &PaymentChange,
    ) -> Result<bool, AppError> {
        let ledger = self.ports.payment_events.as_ref();
        let receipt = ledger.receive(organization_id, event).await.or_internal()?;
        if receipt == EventReceipt::Repeated {
            return Ok(false);
        }
        let order = ledger
            .advance(organization_id, stream_of(change), event)
            .await
            .or_internal()?;
        Ok(order == EventOrder::Newest)
    }

    /// Lifts the suspension the platform made on `organization_id` for not
    /// paying, saves it, and hands back what it raised. An organization
    /// active, closed, or held by a member or an operator is left as it is.
    async fn lifted_suspension(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let store = self.ports.organizations.as_ref();
        let mut organization = existing_organization(store, organization_id).await?;
        if !organization.suspended_for_non_payment() {
            return Ok(Vec::new());
        }
        organization
            .lift_non_payment_suspension()
            .map_err(AppError::from_domain)?;
        store.save(&organization).await.or_internal()?;
        Ok(organization.take_events())
    }
}

impl Command for ReceivePaymentNoticeUseCase {
    type Caller = ();
    type Input = PaymentWebhook;
    type Output = Result<(), AppError>;

    /// Verifies `webhook` and records what it reports:
    /// `organization.payment_method_changed`,
    /// `organization.payment_failed` or `organization.payment_settled`. A
    /// failure on a subscription already owing, or a settlement when
    /// nothing was owed, records nothing. A notice the platform does not
    /// act on, an event delivered again, and an event older than one of
    /// its kind already applied are acknowledged and change nothing.
    ///
    /// Settling what was owed lifts a suspension the platform made for not
    /// paying, and records `organization.status_changed`. A suspension an
    /// operator made stays until an operator lifts it.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the signature does not verify or the
    ///   notice is too old.
    /// - `AppError::Domain` when a verified notice cannot be read.
    /// - `AppError::NotFound` when the organization it names has no
    ///   subscription, or a settlement names no organization.
    /// - `AppError::Conflict` when a charge is said to have failed while a
    ///   trial runs, when nothing is charged.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        webhook: PaymentWebhook,
    ) -> Result<(), AppError> {
        let notice = self
            .ports
            .payment_provider
            .read_notice(&webhook)
            .map_err(AppError::from_domain)?;
        let Some((organization_id, change)) = change_of(notice.report) else {
            return Ok(());
        };
        self.record(auditor, &notice.event, organization_id, change)
            .await
    }
}

/// What a notice changes on a subscription.
enum PaymentChange {
    /// The provider holds this payment method now.
    Method(PaymentReference),
    /// A charge failed.
    Failed,
    /// What was owed is paid.
    Settled,
}

/// The organization `notice` names and what it changes there, or `None`
/// for a notice the platform does not act on.
fn change_of(notice: PaymentNotice) -> Option<(OrganizationId, PaymentChange)> {
    match notice {
        PaymentNotice::MethodRecorded {
            organization_id,
            reference,
        } => Some((organization_id, PaymentChange::Method(reference))),
        PaymentNotice::PaymentFailed { organization_id } => {
            Some((organization_id, PaymentChange::Failed))
        }
        PaymentNotice::PaymentSettled { organization_id } => {
            Some((organization_id, PaymentChange::Settled))
        }
        PaymentNotice::Ignored => None,
    }
}

/// The kind of change `change` is, kept in order apart from the other.
fn stream_of(change: &PaymentChange) -> PaymentStream {
    match change {
        PaymentChange::Method(_) => PaymentStream::Method,
        PaymentChange::Failed | PaymentChange::Settled => PaymentStream::Payment,
    }
}

/// Whether `change` settles what was owed, which lifts a suspension for not
/// paying.
fn settles(change: &PaymentChange) -> bool {
    matches!(change, PaymentChange::Settled)
}

/// Records `change` on `subscription`.
///
/// # Errors
///
/// - `AppError::Conflict` when a charge failed while a trial runs.
fn apply(subscription: &mut OrgSubscription, change: PaymentChange) -> Result<(), AppError> {
    match change {
        PaymentChange::Method(reference) => subscription.record_payment_method(reference),
        PaymentChange::Failed => subscription
            .record_payment_failed()
            .map_err(AppError::from_domain)?,
        PaymentChange::Settled => subscription.record_payment_settled(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::payment::{
        PaymentMethod, PaymentReference, SubscriptionState, TrialUse,
    };
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::status::OrganizationStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::ActedBy;

    use super::*;
    use crate::test_support::organization::{
        FakeOrgSubscriptionStore, FakeOrganizationStore, FakePaymentEventLedger,
        FakePaymentProvider, SubscriptionShape, org_store_with, test_org, test_payment_event,
        test_payment_webhook, test_subscription,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// Acme, subscribed as `shape`, and a provider reporting `notice`.
    struct Setup {
        uc: ReceivePaymentNoticeUseCase,
        subscriptions: Arc<FakeOrgSubscriptionStore>,
        orgs: Arc<FakeOrganizationStore>,
        audit: Arc<FakeEventDispatcher>,
        acme: OrganizationId,
    }

    impl Setup {
        fn new(shape: SubscriptionShape, provider: FakePaymentProvider) -> Self {
            Self::for_org(OrganizationId::new(), shape, provider)
        }

        fn for_org(
            acme: OrganizationId,
            shape: SubscriptionShape,
            provider: FakePaymentProvider,
        ) -> Self {
            Self::over(test_org(acme, "acme"), shape, provider)
        }

        fn over(
            organization: Organization,
            shape: SubscriptionShape,
            provider: FakePaymentProvider,
        ) -> Self {
            Self::keeping(
                organization,
                shape,
                provider,
                FakePaymentEventLedger::empty(),
            )
        }

        fn keeping(
            organization: Organization,
            shape: SubscriptionShape,
            provider: FakePaymentProvider,
            ledger: FakePaymentEventLedger,
        ) -> Self {
            let acme = *organization.id();
            let subscriptions = Arc::new(FakeOrgSubscriptionStore::holding([test_subscription(
                acme, shape,
            )]));
            let orgs = org_store_with([organization]);
            Self {
                uc: ReceivePaymentNoticeUseCase::new(ReceivePaymentNoticePorts {
                    payment_provider: Arc::new(provider),
                    subscriptions: subscriptions.clone(),
                    organizations: orgs.clone(),
                    payment_events: Arc::new(ledger),
                }),
                subscriptions,
                orgs,
                audit: Arc::new(FakeEventDispatcher::new()),
                acme,
            }
        }

        fn status(&self) -> OrganizationStatus {
            self.orgs.stored(&self.acme).unwrap().status()
        }

        fn receive(&self) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &(),
                &test_auditor(self.audit.clone()),
                test_payment_webhook(),
            ))
        }

        fn stored(&self) -> OrgSubscription {
            self.subscriptions.stored(&self.acme).unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn starter_on(state: SubscriptionState) -> SubscriptionShape {
        SubscriptionShape {
            plan: OrganizationPlan::Starter,
            state,
            payment: PaymentMethod::Missing,
            trial: TrialUse::Used,
        }
    }

    fn reference() -> PaymentReference {
        PaymentReference::new("pm_1NvXyz").unwrap()
    }

    /// Bob finished the checkout. The provider reports Acme's new card and
    /// it is recorded on the subscription.
    #[test]
    fn a_reported_payment_method_is_recorded() {
        let acme = OrganizationId::new();
        let setup = Setup::for_org(
            acme,
            SubscriptionShape::free(),
            FakePaymentProvider::reporting(PaymentNotice::MethodRecorded {
                organization_id: acme,
                reference: reference(),
            }),
        );

        setup.receive().unwrap();

        assert_eq!(
            setup.stored().payment(),
            &PaymentMethod::OnFile(reference())
        );
        assert_eq!(setup.recorded(), ["organization.payment_method_changed"]);
    }

    /// A charge to Acme failed. A payment is owed from now.
    #[test]
    fn a_failed_charge_leaves_a_payment_owed() {
        let acme = OrganizationId::new();
        let setup = Setup::for_org(
            acme,
            starter_on(SubscriptionState::Active),
            FakePaymentProvider::reporting(PaymentNotice::PaymentFailed {
                organization_id: acme,
            }),
        );

        setup.receive().unwrap();

        assert!(matches!(
            setup.stored().state(),
            SubscriptionState::PastDue { .. }
        ));
        assert_eq!(setup.recorded(), ["organization.payment_failed"]);
    }

    /// Acme paid what it owed. The subscription is active again.
    #[test]
    fn a_settled_payment_clears_what_was_owed() {
        let acme = OrganizationId::new();
        let setup = Setup::for_org(
            acme,
            starter_on(SubscriptionState::PastDue {
                since: clock::now(),
            }),
            FakePaymentProvider::reporting(PaymentNotice::PaymentSettled {
                organization_id: acme,
            }),
        );

        setup.receive().unwrap();

        assert_eq!(setup.stored().state(), SubscriptionState::Active);
        assert_eq!(setup.recorded(), ["organization.payment_settled"]);
    }

    /// The provider sends a notice the platform does not act on. It is
    /// acknowledged and nothing is recorded.
    #[test]
    fn an_ignored_notice_changes_nothing() {
        let setup = Setup::new(
            SubscriptionShape::free(),
            FakePaymentProvider::reporting(PaymentNotice::Ignored),
        );

        setup.receive().unwrap();

        assert!(setup.recorded().is_empty());
    }

    /// A failed notice signature is refused; the subscription remains
    /// past due from the same instant and nothing is recorded.
    #[test]
    fn a_notice_whose_signature_fails_is_refused() {
        let since = clock::now();
        let setup = Setup::new(
            starter_on(SubscriptionState::PastDue { since }),
            FakePaymentProvider::refusing_signatures(),
        );

        let result = setup.receive();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().state(), SubscriptionState::PastDue { since });
        assert!(setup.recorded().is_empty());
    }

    /// The provider reports a payment for an organization with no
    /// subscription. It is not found.
    #[test]
    fn a_notice_for_an_unknown_subscription_is_not_found() {
        let setup = Setup::new(
            SubscriptionShape::free(),
            FakePaymentProvider::reporting(PaymentNotice::PaymentSettled {
                organization_id: OrganizationId::new(),
            }),
        );

        let result = setup.receive();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A notice that `id` paid what it owed.
    fn settled(id: OrganizationId) -> FakePaymentProvider {
        FakePaymentProvider::reporting(PaymentNotice::PaymentSettled {
            organization_id: id,
        })
    }

    /// Acme was suspended for not paying and now pays. The suspension is
    /// lifted with the debt, and both are recorded.
    #[test]
    fn settling_lifts_a_suspension_for_non_payment() {
        let mut acme = test_org(OrganizationId::new(), "acme");
        acme.suspend_for_non_payment().unwrap();
        let _suspended = acme.take_events();
        let id = *acme.id();
        let owing = starter_on(SubscriptionState::PastDue {
            since: clock::now(),
        });
        let setup = Setup::over(acme, owing, settled(id));

        setup.receive().unwrap();

        assert_eq!(setup.status(), OrganizationStatus::Active);
        assert_eq!(
            setup.recorded(),
            [
                "organization.payment_settled",
                "organization.status_changed"
            ]
        );
    }

    /// A settlement records payment without lifting an operator's
    /// suspension of the organization.
    #[test]
    fn settling_leaves_an_operators_suspension() {
        let mut acme = test_org(OrganizationId::new(), "acme");
        acme.change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();
        let id = *acme.id();
        let owing = starter_on(SubscriptionState::PastDue {
            since: clock::now(),
        });
        let setup = Setup::over(acme, owing, settled(id));

        setup.receive().unwrap();

        assert_eq!(setup.status(), OrganizationStatus::Suspended);
        assert_eq!(setup.recorded(), ["organization.payment_settled"]);
    }

    /// Two deliveries of the same payment-method notice both succeed but
    /// produce only one change record.
    #[test]
    fn an_event_delivered_twice_is_acted_on_once() {
        let acme = OrganizationId::new();
        let setup = Setup::for_org(
            acme,
            SubscriptionShape::free(),
            FakePaymentProvider::reporting(PaymentNotice::MethodRecorded {
                organization_id: acme,
                reference: reference(),
            }),
        );

        setup.receive().unwrap();
        setup.receive().unwrap();

        assert_eq!(setup.recorded(), ["organization.payment_method_changed"]);
    }

    /// A failure notice older than the applied settlement leaves Acme's
    /// subscription active and produces no audit record.
    #[test]
    fn a_failure_older_than_the_settlement_applied_changes_nothing() {
        let acme = test_org(OrganizationId::new(), "acme");
        let id = *acme.id();
        let paid_at = clock::now();
        let late_failure = FakePaymentProvider::reporting_event(
            test_payment_event("evt_failed", paid_at - time::Duration::minutes(1)),
            PaymentNotice::PaymentFailed {
                organization_id: id,
            },
        );
        let ledger = FakePaymentEventLedger::applied(id, PaymentStream::Payment, paid_at);
        let setup = Setup::keeping(
            acme,
            starter_on(SubscriptionState::Active),
            late_failure,
            ledger,
        );

        setup.receive().unwrap();

        assert_eq!(setup.stored().state(), SubscriptionState::Active);
        assert!(setup.recorded().is_empty());
    }

    /// A charge is said to have failed while Acme trials Starter, when
    /// nothing is charged. It is refused and nothing is recorded.
    #[test]
    fn a_failed_charge_during_a_trial_is_refused() {
        let acme = OrganizationId::new();
        let setup = Setup::for_org(
            acme,
            starter_on(SubscriptionState::Trialing {
                ends_at: clock::now() + time::Duration::days(7),
            }),
            FakePaymentProvider::reporting(PaymentNotice::PaymentFailed {
                organization_id: acme,
            }),
        );

        let result = setup.receive();

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.recorded().is_empty());
    }
}
