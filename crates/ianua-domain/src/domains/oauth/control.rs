//! Who may register and change a tenant's OAuth clients and API keys.
//!
//! A client decides where codes and tokens for the tenant's people are
//! sent, and a key signs a machine in with the permissions it carries. So
//! every change to one names who makes it and needs the API key right for
//! it. Only a person signed in to the tenant holds one.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::permission::{ApiKeyAction, SystemPermission};
use crate::shared::errors::DomainError;
use crate::types::{ActorRef, Human};

/// What a change to a client or an API key needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthRight {
    /// Registering a client or creating a key. It needs the create right.
    Create,
    /// Renaming one, or changing its scopes or redirects. It needs the
    /// update right.
    Update,
    /// Revoking a client. It needs the revoke right.
    Revoke,
}

impl OAuthRight {
    /// The built-in permission this right is.
    #[must_use]
    pub fn permission(self) -> SystemPermission {
        match self {
            Self::Create => SystemPermission::ApiKeys(ApiKeyAction::Create),
            Self::Update => SystemPermission::ApiKeys(ApiKeyAction::Update),
            Self::Revoke => SystemPermission::ApiKeys(ApiKeyAction::Revoke),
        }
    }
}

/// A person registering or changing a client or an API key, with what they
/// hold.
///
/// Sam may only view API keys. Without this check, he adds his own server
/// to the redirects of the tenant's portal client and collects every code
/// it hands out.
#[derive(Debug, Clone, Copy)]
pub struct OAuthControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> OAuthControl<'a> {
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

    /// The person acting, as the actor a key records as its creator.
    pub(crate) fn actor(&self) -> ActorRef {
        self.authority.actor()
    }

    /// What the person may hand on to a key: their standing rights, without
    /// what a break-glass grant adds for the emergency.
    #[must_use]
    pub fn holds(&self) -> HeldByGranter<'a> {
        self.authority.standing()
    }

    /// Refuses the change unless the person holds `right`, through their
    /// roles or an active break-glass grant.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold it.
    pub fn ensure_may(&self, right: OAuthRight) -> Result<(), DomainError> {
        self.authority.ensure_holds(right.permission())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_support::authority::anyone_holding;

    /// Someone holding `system`, changing clients and keys.
    pub(crate) fn holding(system: &[SystemPermission]) -> OAuthControl<'static> {
        OAuthControl::new(anyone_holding(system))
    }

    /// Someone who manages API keys and clients, and holds every other
    /// permission too, so any scope is theirs to hand on.
    pub(crate) fn key_admin() -> OAuthControl<'static> {
        holding(SystemPermission::all())
    }

    /// Creation permission satisfies the create check but leaves updates
    /// forbidden.
    #[test]
    fn the_create_right_does_not_update_clients() {
        let control = holding(&[SystemPermission::ApiKeys(ApiKeyAction::Create)]);

        assert!(control.ensure_may(OAuthRight::Create).is_ok());
        assert!(matches!(
            control.ensure_may(OAuthRight::Update),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Ann manages API keys. She may create, update and revoke.
    #[test]
    fn the_full_api_key_right_covers_every_change() {
        let control = holding(&[SystemPermission::ManageApiKeys]);

        for right in [OAuthRight::Create, OAuthRight::Update, OAuthRight::Revoke] {
            assert!(control.ensure_may(right).is_ok(), "{right:?}");
        }
    }
}
