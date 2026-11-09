//! Events about what an organization pays: its subscription, its trial and
//! its payments.
//!
//! None carries a payment reference. The record says that a card was added
//! or a charge failed, never which card.

use time::OffsetDateTime;

use crate::domains::organization::billing::payment::{BillingCycle, SubscriptionState};
use crate::domains::organization::billing::plan::OrganizationPlan;
use crate::domains::organization::billing::subscription::SubscriptionChanger;
use crate::domains::organization::lifecycle::Organization;
use crate::shared::events::data::EventData;
use crate::shared::events::event::{DomainEvent, organization_event};
use crate::types::OrganizationId;

/// An organization's subscription began, on the plan it was founded on.
#[derive(Debug)]
pub(crate) struct OrgSubscriptionStarted {
    /// The organization subscribed.
    pub(crate) organization_id: OrganizationId,
    /// The plan it started on.
    pub(crate) plan: OrganizationPlan,
    /// Where the subscription stands: trialing, active or past due.
    pub(crate) state: SubscriptionState,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgSubscriptionStarted => crate::types::event_type::OrganizationEvent::SubscriptionStarted,
    fn payload(&self) -> EventData {
        with_state(
            EventData::new().field("plan", self.plan.to_string()),
            self.state,
        )
    }
}

/// An organization's subscription moved to another plan or billing cycle,
/// chosen by a member or arranged by an operator.
#[derive(Debug)]
pub(crate) struct OrgSubscriptionChanged {
    /// The organization whose subscription changed.
    pub(crate) organization_id: OrganizationId,
    /// The plan it was on.
    pub(crate) from: OrganizationPlan,
    /// The plan it is on now.
    pub(crate) to: OrganizationPlan,
    /// How often it is billed now.
    pub(crate) cycle: BillingCycle,
    /// Where the subscription stands now.
    pub(crate) state: SubscriptionState,
    /// Who changed it.
    pub(crate) by: SubscriptionChanger,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgSubscriptionChanged => crate::types::event_type::OrganizationEvent::SubscriptionChanged,
    fn payload(&self) -> EventData {
        with_state(
            EventData::new()
                .change("plan", self.from.to_string(), self.to.to_string())
                .field("cycle", self.cycle.as_str())
                .field("changed_by", self.by.as_str()),
            self.state,
        )
    }
}

/// An organization's trial ran out: it now pays, or owes a payment.
#[derive(Debug)]
pub(crate) struct OrgTrialEnded {
    /// The organization whose trial ended.
    pub(crate) organization_id: OrganizationId,
    /// The plan it trialed.
    pub(crate) plan: OrganizationPlan,
    /// Where the subscription stands now: active, or past due for want of a
    /// payment method.
    pub(crate) state: SubscriptionState,
    /// When the trial ended.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgTrialEnded => crate::types::event_type::OrganizationEvent::TrialEnded,
    fn payload(&self) -> EventData {
        with_state(
            EventData::new().field("plan", self.plan.to_string()),
            self.state,
        )
    }
}

/// The payment provider reported a new payment method for the organization.
#[derive(Debug)]
pub(crate) struct OrgPaymentMethodChanged {
    /// The organization that pays with it.
    pub(crate) organization_id: OrganizationId,
    /// When it was added.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgPaymentMethodChanged => crate::types::event_type::OrganizationEvent::PaymentMethodChanged,
    fn payload(&self) -> EventData {
        EventData::new().field("organization_id", self.organization_id.to_string())
    }
}

/// A charge to the organization failed, and its subscription is past due.
#[derive(Debug)]
pub(crate) struct OrgPaymentFailed {
    /// The organization whose charge failed.
    pub(crate) organization_id: OrganizationId,
    /// When it failed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgPaymentFailed => crate::types::event_type::OrganizationEvent::PaymentFailed,
    fn payload(&self) -> EventData {
        EventData::new().field("organization_id", self.organization_id.to_string())
    }
}

/// What the organization owed was paid, and its subscription is active
/// again.
#[derive(Debug)]
pub(crate) struct OrgPaymentSettled {
    /// The organization that paid.
    pub(crate) organization_id: OrganizationId,
    /// When it was settled.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgPaymentSettled => crate::types::event_type::OrganizationEvent::PaymentSettled,
    fn payload(&self) -> EventData {
        EventData::new().field("organization_id", self.organization_id.to_string())
    }
}

/// A member was sent to the payment provider's page to add the payment
/// method the organization is charged through.
///
/// Nothing the organization keeps changes until the provider reports the
/// method. Without this record, nothing shows who opened the page a card
/// was later added through.
#[derive(Debug)]
pub struct OrgCheckoutStarted {
    /// The organization the checkout is for.
    pub(crate) organization_id: OrganizationId,
    /// When it was opened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgCheckoutStarted {
    /// The record of a checkout opened for `organization`. The page is the
    /// provider's, so no organization aggregate changes.
    #[must_use]
    pub fn observed(organization: &Organization) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *organization.id(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgCheckoutStarted => crate::types::event_type::OrganizationEvent::CheckoutStarted,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// `data` with where the subscription stands, and when its trial ends while
/// it is trialing.
fn with_state(data: EventData, state: SubscriptionState) -> EventData {
    let data = data.field("state", state.as_str());
    let SubscriptionState::Trialing { ends_at } = state else {
        return data;
    };
    data.field("trial_ends_at", ends_at.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::access::session::tests::acme_with;
    use crate::shared::events::event::DomainEventCore;
    use crate::types::TenantId;

    /// Bob opens Acme's checkout page. The record names Acme, carries no
    /// payment detail, and stays out of his colleagues' feeds.
    #[test]
    fn an_opened_checkout_is_observed_for_the_organization() {
        let (acme, _) = acme_with(TenantId::new());

        let event = OrgCheckoutStarted::observed(&acme);

        assert_eq!(event.organization_id(), Some(acme.id()));
        assert!(event.payload().is_empty());
        assert!(!event.event_type().is_notifiable());
    }

    /// A trial that started is recorded with the day it ends, so the
    /// dashboard can say how long is left.
    #[test]
    fn a_trial_start_records_when_it_ends() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let event = OrgSubscriptionStarted {
            organization_id: OrganizationId::new(),
            plan: OrganizationPlan::Starter,
            state: SubscriptionState::Trialing { ends_at: now },
            occurred_at: now,
        };

        let payload = event.payload();

        assert_eq!(payload.get("state"), Some("trialing"));
        assert!(payload.get("trial_ends_at").is_some());
    }

    /// An active subscription is recorded without a trial end.
    #[test]
    fn an_active_subscription_names_no_trial_end() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let event = OrgTrialEnded {
            organization_id: OrganizationId::new(),
            plan: OrganizationPlan::Business,
            state: SubscriptionState::Active,
            occurred_at: now,
        };

        let payload = event.payload();

        assert_eq!(payload.get("state"), Some("active"));
        assert!(payload.get("trial_ends_at").is_none());
    }
}
