//! Taking over a consumer: replacing the credential it signs in with.
//!
//! Whoever sets a consumer's credential can sign in as it and act with
//! every role it holds. So replacing it hands all of that to them, and
//! needs what handing it out would need.

use crate::domains::authorization::authority::TenantAccess;
use crate::domains::authorization::permission::ConsumersAction;
use crate::domains::consumers::control::ConsumerControl;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ConsumerId, Human, PrincipalRef};

/// A person who may take over one consumer, as the tenant's records say.
///
/// Sam may update consumers but does not hold the admin role
/// "billing-sync" holds. Without this check, he swaps its key for one of
/// his own, signs in as it and acts as an admin. So the person needs the
/// update right and must hold all the consumer holds.
///
/// It is worked out for one consumer and passes for no other. Only
/// [`ConsumerTakeover::of`] makes one, so what the consumer holds is never
/// the caller's word.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerTakeover<'a> {
    control: ConsumerControl<'a>,
    consumer: ConsumerId,
}

impl<'a> ConsumerTakeover<'a> {
    /// `control`'s person taking over `consumer`, with what the consumer
    /// holds read from `access`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when what the person holds was worked
    ///   out in another tenant.
    /// - [`DomainError::Forbidden`] when they may not update consumers.
    /// - [`DomainError::Forbidden`] when the consumer holds a right they
    ///   may not hand out.
    /// - [`DomainError::Infrastructure`] when the records name a role or
    ///   group that is not there.
    pub fn of<T: TenantScope>(
        control: &ConsumerControl<'a>,
        access: &TenantAccess<'_, T>,
        consumer: &ConsumerId,
    ) -> Result<Self, DomainError> {
        control.ensure_within(&access.tenant)?;
        control.ensure_may(ConsumersAction::Update)?;
        let held = access.standing_of(PrincipalRef::Consumer(*consumer))?;
        control.holds().ensure_may_give(&held.handout())?;
        Ok(Self {
            control: *control,
            consumer: *consumer,
        })
    }

    /// The person taking it over.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.control.by()
    }

    /// Refuses unless this was worked out for `consumer`.
    pub(crate) fn ensure_for(&self, consumer: &ConsumerId) -> Result<(), DomainError> {
        if self.consumer != *consumer {
            return Err(DomainError::forbidden(message!(
                "consumers-the-takeover-was-worked-out-for",
                "the takeover was worked out for another consumer"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::domains::consumers::fixtures::{ConsumerRecords, sam_holding};
    use crate::test_support::authority::anyone_holding;

    const UPDATE: SystemPermission = SystemPermission::Consumers(ConsumersAction::Update);

    /// What "billing-sync" holds: the admin role's rights over users.
    const ADMIN: [SystemPermission; 1] = [SystemPermission::ManageUsers];

    /// The update right does not authorize taking over a consumer whose
    /// user-management rights the caller lacks.
    #[test]
    fn taking_over_a_consumer_needs_everything_it_holds() {
        let consumer = ConsumerId::new();
        let records = ConsumerRecords::consumer_holding(&consumer, &ADMIN);

        let takeover = ConsumerTakeover::of(&sam_holding(&[UPDATE]), &records.access(), &consumer);

        assert!(matches!(takeover, Err(DomainError::Forbidden(_))));
    }

    /// Sam may update consumers and holds everything "billing-sync" holds.
    /// He may take it over.
    #[test]
    fn someone_holding_everything_the_consumer_holds_may_take_it_over() {
        let consumer = ConsumerId::new();
        let records = ConsumerRecords::consumer_holding(&consumer, &ADMIN);
        let sam = sam_holding(&[UPDATE, SystemPermission::ManageUsers]);

        let takeover = ConsumerTakeover::of(&sam, &records.access(), &consumer);

        assert!(takeover.is_ok());
    }

    /// Holding all of a consumer's rights still does not authorize a
    /// takeover without the consumer update right.
    #[test]
    fn taking_over_a_consumer_needs_the_update_right() {
        let consumer = ConsumerId::new();
        let records = ConsumerRecords::consumer_holding(&consumer, &ADMIN);
        let sam = sam_holding(&[SystemPermission::ManageUsers]);

        let takeover = ConsumerTakeover::of(&sam, &records.access(), &consumer);

        assert!(matches!(takeover, Err(DomainError::Forbidden(_))));
    }

    /// Authority resolved in another tenant cannot authorize a consumer
    /// takeover in this tenant, even with the management right.
    #[test]
    fn a_takeover_is_worked_out_in_the_consumers_own_tenant() {
        let consumer = ConsumerId::new();
        let records = ConsumerRecords::consumer_holding(&consumer, &[]);
        let elsewhere = ConsumerControl::new(anyone_holding(&[SystemPermission::ManageConsumers]));

        let takeover = ConsumerTakeover::of(&elsewhere, &records.access(), &consumer);

        assert!(matches!(takeover, Err(DomainError::Forbidden(_))));
    }

    /// A takeover proof issued for a consumer with no roles is rejected
    /// when used for another consumer that holds user-management rights.
    #[test]
    fn a_takeover_passes_for_no_other_consumer() {
        let (cron_job, billing_sync) = (ConsumerId::new(), ConsumerId::new());
        let records = ConsumerRecords::consumer_holding(&billing_sync, &ADMIN);
        let sam = sam_holding(&[UPDATE]);
        let takeover = ConsumerTakeover::of(&sam, &records.access(), &cron_job).unwrap();

        let used = takeover.ensure_for(&billing_sync);

        assert!(matches!(used, Err(DomainError::Forbidden(_))));
    }
}
