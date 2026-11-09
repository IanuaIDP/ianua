//! A subscription as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::organization::billing::payment::{
    PaymentMethod, PaymentReference, SubscriptionState,
};
use ianua_domain::domains::organization::billing::subscription::{
    OrgSubscription, OrgSubscriptionRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const SUBSCRIPTION: Stored = Stored("organization subscription");

/// A subscription as it is read. The store's checked queries fill it.
pub(super) struct SubscriptionRecord {
    pub(super) organization_id: Uuid,
    pub(super) plan: String,
    pub(super) cycle: String,
    pub(super) state: String,
    pub(super) trial_ends_at: Option<OffsetDateTime>,
    pub(super) past_due_since: Option<OffsetDateTime>,
    pub(super) payment_reference: Option<String>,
    pub(super) trial: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl SubscriptionRecord {
    /// The subscription the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word is unknown, the
    /// state's time does not fit its state, the payment reference no
    /// longer passes its rules, or the row breaks a rule the subscription
    /// keeps.
    pub(super) fn into_subscription(self) -> Result<OrgSubscription, DomainError> {
        OrgSubscription::reconstitute(OrgSubscriptionRow {
            organization_id: OrganizationId::from_uuid(self.organization_id),
            plan: SUBSCRIPTION.choice(&self.plan)?,
            cycle: SUBSCRIPTION.choice(&self.cycle)?,
            state: state_from(&self.state, self.trial_ends_at, self.past_due_since)?,
            payment: payment_from(self.payment_reference)?,
            trial: SUBSCRIPTION.choice(&self.trial)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A subscription's columns, as they are written.
pub(super) struct SubscriptionColumns<'a> {
    pub(super) organization_id: &'a Uuid,
    pub(super) plan: &'static str,
    pub(super) cycle: &'static str,
    pub(super) state: &'static str,
    pub(super) trial_ends_at: Option<OffsetDateTime>,
    pub(super) past_due_since: Option<OffsetDateTime>,
    pub(super) payment_reference: Option<&'a str>,
    pub(super) trial: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> SubscriptionColumns<'a> {
    /// The columns `subscription` is written to.
    pub(super) fn of(subscription: &'a OrgSubscription) -> Self {
        let state = subscription.state();
        let (trial_ends_at, past_due_since) = state_times(state);
        Self {
            organization_id: subscription.organization_id().as_uuid(),
            plan: subscription.plan().word(),
            cycle: subscription.cycle().word(),
            state: state.as_str(),
            trial_ends_at,
            past_due_since,
            payment_reference: reference_of(subscription.payment()),
            trial: subscription.trial().word(),
            created_at: subscription.created_at(),
            updated_at: subscription.updated_at(),
        }
    }
}

/// When the trial ends and since when a payment is owed, as the state's
/// two columns hold them.
fn state_times(state: SubscriptionState) -> (Option<OffsetDateTime>, Option<OffsetDateTime>) {
    match state {
        SubscriptionState::Trialing { ends_at } => (Some(ends_at), None),
        SubscriptionState::Active => (None, None),
        SubscriptionState::PastDue { since } => (None, Some(since)),
    }
}

fn state_from(
    word: &str,
    trial_ends_at: Option<OffsetDateTime>,
    past_due_since: Option<OffsetDateTime>,
) -> Result<SubscriptionState, DomainError> {
    match (word, trial_ends_at, past_due_since) {
        ("trialing", Some(ends_at), None) => Ok(SubscriptionState::Trialing { ends_at }),
        ("active", None, None) => Ok(SubscriptionState::Active),
        ("past_due", None, Some(since)) => Ok(SubscriptionState::PastDue { since }),
        _ => Err(DomainError::corrupt_row(
            SUBSCRIPTION.0,
            "a state whose times do not fit it",
        )),
    }
}

fn reference_of(payment: &PaymentMethod) -> Option<&str> {
    match payment {
        PaymentMethod::Missing => None,
        PaymentMethod::OnFile(reference) => Some(reference.as_str()),
    }
}

fn payment_from(reference: Option<String>) -> Result<PaymentMethod, DomainError> {
    let Some(reference) = reference else {
        return Ok(PaymentMethod::Missing);
    };
    SUBSCRIPTION
        .value("payment reference", PaymentReference::new(reference))
        .map(PaymentMethod::OnFile)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each state is written to its word and the one time it carries, and
    /// read back the same.
    #[test]
    fn every_state_reads_back_from_its_columns() {
        let at = OffsetDateTime::UNIX_EPOCH;
        for state in [
            SubscriptionState::Trialing { ends_at: at },
            SubscriptionState::Active,
            SubscriptionState::PastDue { since: at },
        ] {
            let (trial_ends_at, past_due_since) = state_times(state);

            let read = state_from(state.as_str(), trial_ends_at, past_due_since).unwrap();

            assert_eq!(read, state);
        }
    }

    /// Reading a trial state without its end time returns an infrastructure
    /// error.
    #[test]
    fn a_state_without_its_time_is_refused() {
        let read = state_from("trialing", None, None);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
