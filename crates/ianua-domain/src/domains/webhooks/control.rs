//! Who may create and change a tenant's webhook subscriptions.
//!
//! A webhook sends the tenant's events to an outside server, signed with a
//! secret. So creating one, stopping or starting its deliveries, and
//! replacing its secret each name who does it and need the webhooks right
//! for it. What a webhook may receive is what the same person may see.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::permission::{SystemPermission, WebhooksAction};
use crate::domains::notifications::category::VisibleTo;
use crate::shared::errors::DomainError;
use crate::types::Human;

/// A person creating or changing a webhook subscription, with what they
/// hold.
///
/// Sam may only view webhooks. Without this check, he resumes a webhook Ann
/// paused because its server was taken over, and events flow to the
/// attacker again.
#[derive(Debug, Clone, Copy)]
pub struct WebhookControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> WebhookControl<'a> {
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

    /// Refuses the change unless the person holds the webhooks right for
    /// `action`, through their roles or an active break-glass grant.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold it.
    pub fn ensure_may(&self, action: WebhooksAction) -> Result<(), DomainError> {
        self.authority
            .ensure_holds(SystemPermission::Webhooks(action))
    }

    /// The events the person acting may see, through their standing rights.
    ///
    /// A break-glass grant does not count. A webhook outlives the emergency,
    /// so what it receives must not rest on access that ends with it.
    #[must_use]
    pub fn visibility(&self) -> VisibleTo<'a> {
        VisibleTo(self.authority.standing().system())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authority::anyone_holding;

    /// Webhook update permission alone does not grant webhook management.
    #[test]
    fn the_update_right_does_not_manage_webhooks() {
        let control = WebhookControl::new(anyone_holding(&[SystemPermission::Webhooks(
            WebhooksAction::Update,
        )]));

        let result = control.ensure_may(WebhooksAction::Manage);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Fay manages webhooks. That covers updating them too.
    #[test]
    fn the_full_webhooks_right_covers_updates() {
        let control = WebhookControl::new(anyone_holding(&[SystemPermission::ManageWebhooks]));

        assert!(control.ensure_may(WebhooksAction::Update).is_ok());
    }
}
