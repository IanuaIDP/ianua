//! Who may change how the tenant looks and what its mail says.
//!
//! Branding is shown on the page where people type their password, and in
//! the mail that carries their reset and sign-in links. So every change to
//! it names who makes it and needs the branding right.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::permission::{BrandingAction, SystemPermission};
use crate::domains::identity::account::control::RecentProof;
use crate::domains::tenant::control::principal_of;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::Human;

/// The right every branding change needs.
const CHANGES_BRANDING: SystemPermission = SystemPermission::Branding(BrandingAction::Update);

/// A person changing the tenant's branding, with what they hold.
///
/// Sam may only view branding. Without this check, he swaps the logo on the
/// sign-in page for one of his own, or rewrites the password reset mail so
/// it asks people to reply with their password.
#[derive(Debug, Clone, Copy)]
pub struct BrandingControl<'a> {
    authority: &'a TenantAuthority,
}

impl<'a> BrandingControl<'a> {
    /// The person `authority` names, acting with what it says they hold.
    #[must_use]
    pub fn new(authority: &'a TenantAuthority) -> Self {
        Self { authority }
    }

    /// Refuses the change unless the person may update branding.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when they may not.
    pub fn ensure_may_change(&self) -> Result<(), DomainError> {
        self.authority.ensure_holds(CHANGES_BRANDING)
    }

    /// The person acting.
    #[must_use]
    pub fn by(&self) -> &'a Human {
        self.authority.who()
    }

    /// Refuses unless the person proved who they are again just now.
    ///
    /// Moving the tenant's mail moves its password reset and verification
    /// links with it. Someone who stole a session holds it until it ends, so
    /// that change needs more than the session.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` is not a fresh proof of the
    ///   person acting.
    pub fn ensure_proved_recently(&self, proof: &impl RecentProof) -> Result<(), DomainError> {
        if proof.proves_recently(&principal_of(self.by().account())) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "branding-this-change-needs-the-person-to",
            "this change needs the person to prove who they are again"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authority::anyone_holding;

    /// Holding only the branding view right fails the check for permission
    /// to change branding.
    #[test]
    fn the_view_right_changes_nothing() {
        let view = [SystemPermission::Branding(BrandingAction::View)];

        let control = BrandingControl::new(anyone_holding(&view));

        assert!(matches!(
            control.ensure_may_change(),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Fay manages branding, and so may change it.
    #[test]
    fn the_full_branding_right_changes_it() {
        let control = BrandingControl::new(anyone_holding(&[SystemPermission::ManageBranding]));

        assert!(control.ensure_may_change().is_ok());
    }
}
