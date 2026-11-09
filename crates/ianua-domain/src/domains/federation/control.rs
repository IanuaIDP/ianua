//! Who may change how the tenant signs people in through other providers.
//!
//! A connection decides whom an outside provider may speak for, and how far
//! its word is believed. A SAML app decides what an outside service is told
//! about people. So every change to either, and to SCIM, names who makes
//! it and needs the right for it.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::granter::HeldByGranter;
use crate::domains::authorization::permission::{FederationAction, ScimAction, SystemPermission};
use crate::shared::errors::DomainError;

/// What a change to a connection, a SAML app or SCIM needs.
///
/// A SAML app takes the same rights: adding it needs the create right and
/// the full right, since it is told who people are; a change that sends
/// it more, or checks it less, needs the full right; one that narrows what
/// it gets needs the update right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationRight {
    /// Adding a connection. A new one vouches for nobody and is trusted for
    /// nothing, so this needs only the create right.
    CreateConnection,
    /// A change that only renames, fills profile fields, or stops a
    /// provider from speaking for people. It needs the update right.
    EditConnection,
    /// A change that lets a provider speak for more people, or be believed
    /// more: domains, trust, new accounts, its configuration, turning it
    /// back on. It needs the full federation right.
    TrustConnection,
    /// Deleting a connection, with every link to it. The people it made
    /// accounts for often have no other way in, so this needs the delete
    /// right.
    DeleteConnection,
    /// Any change to SCIM. It needs the SCIM configure right.
    ConfigureScim,
}

impl FederationRight {
    /// The built-in permission this right is.
    #[must_use]
    pub fn permission(self) -> SystemPermission {
        match self {
            Self::CreateConnection => SystemPermission::Federation(FederationAction::Create),
            Self::EditConnection => SystemPermission::Federation(FederationAction::Update),
            Self::TrustConnection => SystemPermission::Federation(FederationAction::Manage),
            Self::DeleteConnection => SystemPermission::Federation(FederationAction::Delete),
            Self::ConfigureScim => SystemPermission::Scim(ScimAction::Configure),
        }
    }
}

/// A person changing a connection or SCIM, with what they hold.
///
/// Sam may only view federation. Without this check, he marks the provider
/// he runs as the authority for every address it sends.
#[derive(Debug, Clone, Copy)]
pub struct FederationControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> FederationControl<'a> {
    /// The person `authority` names, acting with what it says they hold.
    #[must_use]
    pub fn new(authority: &'a TenantAuthority) -> Self {
        Self { authority }
    }

    /// What they may hand on, for a default role a provider gives.
    #[must_use]
    pub fn holds(&self) -> HeldByGranter<'a> {
        self.authority.standing()
    }

    /// Refuses the change unless the person holds `right`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they do not hold it.
    pub fn ensure_may(&self, right: FederationRight) -> Result<(), DomainError> {
        self.authority.ensure_holds(right.permission())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::federation::fixtures::holding;

    /// Holding the connection update permission allows editing a
    /// connection but forbids widening its trust.
    #[test]
    fn the_update_right_edits_but_does_not_widen_trust() {
        let update = [SystemPermission::Federation(FederationAction::Update)];

        let control = holding(&update);

        assert!(control.ensure_may(FederationRight::EditConnection).is_ok());
        assert!(matches!(
            control.ensure_may(FederationRight::TrustConnection),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Fay manages federation. She may do every connection change, and
    /// still no SCIM change, which is its own right.
    #[test]
    fn the_full_federation_right_covers_connections_but_not_scim() {
        let manage = [SystemPermission::ManageFederation];

        let control = holding(&manage);

        for right in [
            FederationRight::CreateConnection,
            FederationRight::EditConnection,
            FederationRight::TrustConnection,
            FederationRight::DeleteConnection,
        ] {
            assert!(control.ensure_may(right).is_ok(), "{right:?}");
        }
        assert!(matches!(
            control.ensure_may(FederationRight::ConfigureScim),
            Err(DomainError::Forbidden(_))
        ));
    }
}
