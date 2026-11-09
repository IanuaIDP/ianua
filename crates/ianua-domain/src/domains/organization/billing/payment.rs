//! How an organization pays: its billing cycle, the payment method on
//! file, whether it used its trial, and whether it is paid up.

use time::OffsetDateTime;

use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// The payment provider's reference to a stored card or mandate, such
    /// as `pm_1NvXyz`.
    ///
    /// Only the reference. The domain never sees a card number, and the
    /// provider charges against this on its own side.
    pub struct PaymentReference;
}

impl TextValue for PaymentReference {
    const FIELD: &'static str = "payment_reference";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=255)
    }
}

text_value! {
    /// The payment provider's id for one event it reports, such as
    /// `evt_1NvXyz`. Every delivery of the event carries the same id, so it
    /// tells a repeated delivery from a new event.
    pub struct PaymentEventId;
}

impl TextValue for PaymentEventId {
    const FIELD: &'static str = "payment_event_id";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.token(1..=255)
    }
}

/// How often the organization is billed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BillingCycle {
    /// Once a month.
    Monthly,
    /// Once a year, at the annual price.
    Annual,
}

impl BillingCycle {
    /// The stable name storage and records use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monthly => "monthly",
            Self::Annual => "annual",
        }
    }

    /// The cycle a stored name stands for, or `None` for a name the domain
    /// does not define, which storage reports as corrupt.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "monthly" => Some(Self::Monthly),
            "annual" => Some(Self::Annual),
            _ => None,
        }
    }
}

/// How the organization pays, as far as the domain knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentMethod {
    /// No payment method was ever added.
    Missing,
    /// The provider holds one, under this reference.
    OnFile(PaymentReference),
}

/// Whether the organization has had its one free trial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialUse {
    /// It has not, so moving to a paid tier may start one.
    Unused,
    /// It has, running now or over.
    Used,
}

/// Where a subscription stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    /// On a paid tier for free, until `ends_at`.
    Trialing {
        /// When the trial ends.
        ends_at: OffsetDateTime,
    },
    /// Paid up, or on a tier that costs nothing.
    Active,
    /// A payment is owed, since `since`.
    PastDue {
        /// When the payment fell due.
        since: OffsetDateTime,
    },
}

impl SubscriptionState {
    /// The stable name records carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trialing { .. } => "trialing",
            Self::Active => "active",
            Self::PastDue { .. } => "past_due",
        }
    }
}
