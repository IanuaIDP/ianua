//! Who may create and change a tenant's consumers.
//!
//! A consumer acts with every role it is given, and its credential is how
//! it proves who it is. So creating one, turning it off or on, renaming it
//! and replacing its credential each name who does it and need the
//! consumers right for it. Replacing the credential needs more: see
//! [`ConsumerTakeover`](crate::domains::consumers::takeover::ConsumerTakeover).

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::permission::{ConsumersAction, SystemPermission};
use crate::domains::data_classification::level::DataClassLevel;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ActorRef, Human, TenantId};

/// A person creating or changing a consumer, with what they hold.
///
/// Sam may only view consumers. Without this check, he turns
/// "billing-sync" back on after Ann disabled it because its key leaked.
#[derive(Debug, Clone, Copy)]
pub struct ConsumerControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> ConsumerControl<'a> {
    /// The person `authority` names, acting with what it says they hold.
    #[must_use]
    pub fn new(authority: &'a TenantAuthority) -> Self {
        Self { authority }
    }

    /// The person acting.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.authority.who()
    }

    /// The person acting, as the actor a consumer records as its creator.
    pub(crate) fn actor(&self) -> ActorRef {
        ActorRef::from(self.by().account())
    }

    /// Refuses the change unless the person holds the consumers right for
    /// `action`, through their roles or an active break-glass grant.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold it.
    pub fn ensure_may(&self, action: ConsumersAction) -> Result<(), DomainError> {
        self.authority
            .ensure_holds(SystemPermission::Consumers(action))
    }

    /// What the person may hand on: their standing rights, without what a
    /// break-glass grant adds for the emergency.
    #[must_use]
    pub fn holds(&self) -> HeldByGranter<'a> {
        self.authority.standing()
    }

    /// Refuses clearing a consumer for `level` unless the person may see data
    /// of that class themselves.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `level` is above their own
    ///   clearance.
    pub(crate) fn ensure_may_clear(&self, level: DataClassLevel) -> Result<(), DomainError> {
        if level > self.authority.data_clearance() {
            return Err(DomainError::forbidden(message!(
                "consumers-a-consumer-is-cleared-for-no",
                "a consumer is cleared for no more than the person clearing it"
            )));
        }
        Ok(())
    }

    /// Refuses unless what the person holds was worked out in `tenant`.
    pub(crate) fn ensure_within(&self, tenant: &TenantId) -> Result<(), DomainError> {
        self.authority.ensure_within(tenant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authority::anyone_holding;

    /// Holding the consumer creation right alone fails the permission check
    /// for updating an existing consumer.
    #[test]
    fn the_create_right_does_not_update_consumers() {
        let held = [SystemPermission::Consumers(ConsumersAction::Create)];
        let control = ConsumerControl::new(anyone_holding(&held));

        let result = control.ensure_may(ConsumersAction::Update);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Fay manages consumers. That covers creating and updating them.
    #[test]
    fn the_full_consumers_right_covers_every_change() {
        let control = ConsumerControl::new(anyone_holding(&[SystemPermission::ManageConsumers]));

        assert!(control.ensure_may(ConsumersAction::Create).is_ok());
        assert!(control.ensure_may(ConsumersAction::Update).is_ok());
    }
}
