//! Subscriptions as tests need them, the in-memory subscription store, a
//! usage counter that answers what a test says, and a payment provider that
//! records its checkouts and reports the notice a test sets.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::organization::billing::payment::{
    BillingCycle, PaymentEventId, PaymentMethod, SubscriptionState, TrialUse,
};
use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
use ianua_domain::domains::organization::billing::subscription::{
    OrgSubscription, OrgSubscriptionRow,
};
use ianua_domain::domains::organization::billing::usage::PlanUsage;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{HttpsUrl, OrganizationId};
use time::OffsetDateTime;

use crate::ports::organization::{
    CheckoutRequest, EventOrder, EventReceipt, OrgSubscriptionStore, PaymentEvent,
    PaymentEventLedger, PaymentNotice, PaymentProvider, PaymentSignature, PaymentStream,
    PaymentWebhook, PlanUsageCounter, ReceivedNotice,
};
use crate::test_support::Fake;

/// The page [`FakePaymentProvider`] sends every checkout to.
pub const TEST_CHECKOUT_URL: &str = "https://pay.example.test/checkout/1";

/// How a test's subscription stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionShape {
    /// The service terms assigned to the test organization.
    pub plan: OrganizationPlan,
    /// Where it stands.
    pub state: SubscriptionState,
    /// How it pays.
    pub payment: PaymentMethod,
    /// Whether it has had its trial.
    pub trial: TrialUse,
}

impl SubscriptionShape {
    /// On Free, paid up, with no payment method and its trial unused: a
    /// subscription as founding a Free organization leaves it.
    #[must_use]
    pub fn free() -> Self {
        Self {
            plan: OrganizationPlan::Free,
            state: SubscriptionState::Active,
            payment: PaymentMethod::Missing,
            trial: TrialUse::Unused,
        }
    }
}

/// A subscription of `organization_id`, billed monthly, standing as
/// `shape` says, started a month ago.
///
/// # Panics
///
/// When `shape` is inconsistent, such as a trial on Free: the test is
/// wrong.
#[must_use]
pub fn test_subscription(
    organization_id: OrganizationId,
    shape: SubscriptionShape,
) -> OrgSubscription {
    let now = clock::now();
    OrgSubscription::reconstitute(OrgSubscriptionRow {
        organization_id,
        plan: shape.plan,
        cycle: BillingCycle::Monthly,
        state: shape.state,
        payment: shape.payment,
        trial: shape.trial,
        created_at: now - time::Duration::days(30),
        updated_at: now - time::Duration::days(30),
    })
    .expect("a consistent subscription row")
}

/// A subscription's stored fields, kept apart so the store can hand back a
/// fresh subscription on every read, as a database does.
#[derive(Clone)]
struct Held {
    organization_id: OrganizationId,
    plan: OrganizationPlan,
    cycle: BillingCycle,
    state: SubscriptionState,
    payment: PaymentMethod,
    trial: TrialUse,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Held {
    /// The stored fields of `subscription`.
    fn of(subscription: &OrgSubscription) -> Self {
        Self {
            organization_id: *subscription.organization_id(),
            plan: subscription.plan(),
            cycle: subscription.cycle(),
            state: subscription.state(),
            payment: subscription.payment().clone(),
            trial: subscription.trial(),
            created_at: subscription.created_at(),
            updated_at: subscription.updated_at(),
        }
    }

    /// The subscription these fields hold.
    fn rebuilt(self) -> OrgSubscription {
        OrgSubscription::reconstitute(OrgSubscriptionRow {
            organization_id: self.organization_id,
            plan: self.plan,
            cycle: self.cycle,
            state: self.state,
            payment: self.payment,
            trial: self.trial,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
        .expect("a subscription the store was handed reads back")
    }
}

/// In-memory subscription store, one subscription per organization.
#[derive(Default)]
pub struct FakeOrgSubscriptionStore {
    held: Mutex<Vec<Held>>,
}

impl FakeOrgSubscriptionStore {
    /// A store holding no subscription.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding these subscriptions.
    #[must_use]
    pub fn holding(subscriptions: impl IntoIterator<Item = OrgSubscription>) -> Self {
        let held = subscriptions.into_iter().map(|s| Held::of(&s)).collect();
        Self {
            held: Mutex::new(held),
        }
    }

    /// The subscription of `organization_id`, as it was last saved.
    #[must_use]
    pub fn stored(&self, organization_id: &OrganizationId) -> Option<OrgSubscription> {
        self.matching(|held| held.organization_id == *organization_id)
            .into_iter()
            .next()
    }

    /// How many subscriptions are held.
    #[must_use]
    pub fn count(&self) -> usize {
        self.held.lock().unwrap().len()
    }

    fn matching(&self, wanted: impl Fn(&Held) -> bool) -> Vec<OrgSubscription> {
        self.held
            .lock()
            .unwrap()
            .iter()
            .filter(|held| wanted(held))
            .cloned()
            .map(Held::rebuilt)
            .collect()
    }
}

#[async_trait]
impl OrgSubscriptionStore for FakeOrgSubscriptionStore {
    async fn find_by_organization(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OrgSubscription>, DomainError> {
        Ok(self.stored(organization_id))
    }

    async fn list_trials_ended(
        &self,
        by: OffsetDateTime,
    ) -> Result<Vec<OrgSubscription>, DomainError> {
        Ok(self.matching(
            |held| matches!(held.state, SubscriptionState::Trialing { ends_at } if ends_at <= by),
        ))
    }

    async fn list_past_due(&self) -> Result<Vec<OrgSubscription>, DomainError> {
        Ok(self.matching(|held| matches!(held.state, SubscriptionState::PastDue { .. })))
    }

    async fn save(&self, subscription: &OrgSubscription) -> Result<(), DomainError> {
        let fresh = Held::of(subscription);
        let mut held = self.held.lock().unwrap();
        match held
            .iter_mut()
            .find(|kept| kept.organization_id == fresh.organization_id)
        {
            Some(kept) => *kept = fresh,
            None => held.push(fresh),
        }
        Ok(())
    }
}

impl Fake for Arc<dyn OrgSubscriptionStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgSubscriptionStore::empty())
    }
}

/// Usage counter answering the same usage for every organization.
pub struct FakePlanUsageCounter {
    usage: PlanUsage,
}

impl FakePlanUsageCounter {
    /// A counter reporting `usage` for every organization.
    #[must_use]
    pub fn counting(usage: PlanUsage) -> Self {
        Self { usage }
    }
}

#[async_trait]
impl PlanUsageCounter for FakePlanUsageCounter {
    async fn usage(&self, _organization_id: &OrganizationId) -> Result<PlanUsage, DomainError> {
        Ok(self.usage.clone())
    }
}

impl Fake for Arc<dyn PlanUsageCounter> {
    fn fake() -> Self {
        Arc::new(FakePlanUsageCounter::counting(PlanUsage::default()))
    }
}

/// The event id [`FakePaymentProvider::reporting`] gives every notice.
pub const TEST_PAYMENT_EVENT: &str = "evt_test";

/// A provider event with `id`, created at `created_at`.
///
/// # Panics
///
/// When `id` is not an event id: the test is wrong.
#[must_use]
pub fn test_payment_event(id: &str, created_at: OffsetDateTime) -> PaymentEvent {
    PaymentEvent {
        id: PaymentEventId::new(id).expect("a valid event id"),
        created_at,
    }
}

/// Payment provider that records every checkout it opens and reports the
/// notice a test set, or refuses every signature when none was set.
#[derive(Default)]
pub struct FakePaymentProvider {
    notice: Option<ReceivedNotice>,
    checkouts: Mutex<Vec<CheckoutRequest>>,
}

impl FakePaymentProvider {
    /// A provider whose every notice verifies and reports `notice`, as the
    /// event [`TEST_PAYMENT_EVENT`] created now.
    #[must_use]
    pub fn reporting(notice: PaymentNotice) -> Self {
        Self::reporting_event(test_payment_event(TEST_PAYMENT_EVENT, clock::now()), notice)
    }

    /// A provider whose every notice verifies and reports `notice`, as
    /// `event`.
    #[must_use]
    pub fn reporting_event(event: PaymentEvent, notice: PaymentNotice) -> Self {
        Self {
            notice: Some(ReceivedNotice {
                event,
                report: notice,
            }),
            checkouts: Mutex::default(),
        }
    }

    /// A provider whose every notice fails its signature check.
    #[must_use]
    pub fn refusing_signatures() -> Self {
        Self::default()
    }

    /// The checkouts opened so far, in order.
    #[must_use]
    pub fn checkouts(&self) -> Vec<CheckoutRequest> {
        self.checkouts.lock().unwrap().clone()
    }
}

#[async_trait]
impl PaymentProvider for FakePaymentProvider {
    async fn start_checkout(&self, request: &CheckoutRequest) -> Result<HttpsUrl, DomainError> {
        self.checkouts.lock().unwrap().push(request.clone());
        Ok(HttpsUrl::new(TEST_CHECKOUT_URL).expect("a valid checkout page"))
    }

    fn read_notice(&self, _webhook: &PaymentWebhook) -> Result<ReceivedNotice, DomainError> {
        self.notice
            .clone()
            .ok_or_else(|| DomainError::unauthorized("the notice's signature does not verify"))
    }
}

impl Fake for Arc<dyn PaymentProvider> {
    fn fake() -> Self {
        Arc::new(FakePaymentProvider::refusing_signatures())
    }
}

/// In-memory ledger of the payment events taken, and the newest applied of
/// each kind.
#[derive(Default)]
pub struct FakePaymentEventLedger {
    taken: Mutex<Vec<PaymentEventId>>,
    marks: Mutex<Vec<(OrganizationId, PaymentStream, OffsetDateTime)>>,
}

impl FakePaymentEventLedger {
    /// A ledger that took nothing yet.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A ledger where an event of `stream` created at `newest_at` was
    /// applied to `organization_id` already.
    #[must_use]
    pub fn applied(
        organization_id: OrganizationId,
        stream: PaymentStream,
        newest_at: OffsetDateTime,
    ) -> Self {
        Self {
            taken: Mutex::default(),
            marks: Mutex::new(vec![(organization_id, stream, newest_at)]),
        }
    }
}

#[async_trait]
impl PaymentEventLedger for FakePaymentEventLedger {
    async fn receive(
        &self,
        _organization_id: &OrganizationId,
        event: &PaymentEvent,
    ) -> Result<EventReceipt, DomainError> {
        let mut taken = self.taken.lock().unwrap();
        if taken.contains(&event.id) {
            return Ok(EventReceipt::Repeated);
        }
        taken.push(event.id.clone());
        Ok(EventReceipt::First)
    }

    async fn advance(
        &self,
        organization_id: &OrganizationId,
        stream: PaymentStream,
        event: &PaymentEvent,
    ) -> Result<EventOrder, DomainError> {
        let mut marks = self.marks.lock().unwrap();
        let held = marks
            .iter_mut()
            .find(|(org, kind, _)| org == organization_id && *kind == stream);
        let Some(mark) = held else {
            marks.push((*organization_id, stream, event.created_at));
            return Ok(EventOrder::Newest);
        };
        if mark.2 > event.created_at {
            return Ok(EventOrder::Stale);
        }
        mark.2 = event.created_at;
        Ok(EventOrder::Newest)
    }
}

impl Fake for Arc<dyn PaymentEventLedger> {
    fn fake() -> Self {
        Arc::new(FakePaymentEventLedger::empty())
    }
}

/// A notice as a provider posts it, with a signature the fake never reads.
#[must_use]
pub fn test_payment_webhook() -> PaymentWebhook {
    PaymentWebhook {
        payload: b"{\"type\":\"test\"}".to_vec(),
        signature: PaymentSignature::new("t=1,v1=fake"),
    }
}
