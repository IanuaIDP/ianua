//! How a member is named and reached: their display name, their address
//! and its proof, and the language and timezone they work in.

use crate::domains::authentication::sessions::sign_in_progress::SignedIn;
use crate::domains::identity::account::address::AccountAddress;
use crate::domains::identity::account::verified_email::{VerificationRefused, VerifiedEmail};
use crate::domains::identity::account::vouching::Vouching;
use crate::domains::identity::tokens::installation_setup::InstallerProof;
use crate::domains::organization::events::members::{
    OrgUserDisplayNameChanged, OrgUserEmailChanged, OrgUserEmailVerified, OrgUserPreferencesUpdated,
};
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::org_user_authority::{
    ensure_may_edit_profile, ensure_may_take_over,
};
use crate::domains::organization::members::org_user_status::{
    InvalidOrgUserTransition, OrgUserStatus,
};
use crate::isolation::organization::scope::ResolvedOrganization;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{DisplayName, Email, Joining, Locale, Preference, PrincipalId, Timezone};

impl OrgUser {
    /// Updates the display name, as `by` decides: the member themselves, or
    /// someone who may update members. Raises
    /// `organization.org_user_display_name_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone else acts without the
    ///   right to update members, or edits an owner without being one.
    pub fn change_display_name(
        &mut self,
        display_name: DisplayName,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        ensure_may_edit_profile(self, by)?;
        let old_display_name = std::mem::replace(&mut self.display_name, display_name);
        self.touch();
        self.raised.raise_organization(OrgUserDisplayNameChanged {
            organization_id: self.organization_id,
            old_display_name,
            new_display_name: self.display_name.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Changes the email address to one nobody has proven yet, as `by`
    /// decides, such as an administrator's correction. The account no longer
    /// counts as holding a verified address until the new one is confirmed.
    ///
    /// Reset links go to this address, so whoever sets it can take the
    /// account. `by` needs the right to update members, and only an owner
    /// changes an owner's address. Someone moving their own address through
    /// the confirm step uses
    /// [`change_verified_email`](Self::change_verified_email). Raises
    /// `organization.org_user_email_changed` with the address it replaced.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is this member. A stolen
    ///   session would otherwise move the address with no fresh sign-in.
    /// - [`DomainError::Forbidden`] when `by` may not update members, or
    ///   this account is an owner and `by` is not one.
    pub fn change_email(&mut self, email: Email, by: &OrgControl<'_>) -> Result<(), DomainError> {
        ensure_may_take_over(self, by)?;
        let old = std::mem::replace(&mut self.address, AccountAddress::unverified(email));
        self.touch();
        self.raised.raise_organization(OrgUserEmailChanged {
            organization_id: self.organization_id,
            old_email: old.email().clone(),
            new_email: self.email().clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Changes the email address to one whose control was proven, such as
    /// through the confirm step of the pending-email-change flow, and keeps
    /// it verified. Following the link sent there proves the person, so
    /// nobody else acts here.
    pub fn change_verified_email(&mut self, email: VerifiedEmail) {
        self.address = AccountAddress::verified(email);
        self.touch();
    }

    /// Marks the user's email address as verified, given `proof` that its
    /// holder controls it.
    ///
    /// Confirming the address activates an account in `PendingVerification`,
    /// so this also moves it to `Active` and records the join. Any other
    /// status is left alone. Verifying an address must not bring back a
    /// deactivated or locked account. Raises
    /// `organization.org_user_email_verified`.
    ///
    /// # Errors
    ///
    /// - [`VerificationRefused::OtherAddress`] when `proof` is for another
    ///   address than the account has.
    /// - [`VerificationRefused::Transition`] if the status rules refuse the
    ///   move to `Active`. They allow it from `PendingVerification`, so this
    ///   does not happen while that rule holds.
    pub fn verify_email(
        &mut self,
        proof: &VerifiedEmail,
    ) -> Result<(), VerificationRefused<InvalidOrgUserTransition>> {
        self.address.confirm(proof)?;
        if self.status == OrgUserStatus::PendingVerification {
            self.move_to(OrgUserStatus::Active)?;
        } else {
            self.touch();
        }
        self.raised.raise_organization(OrgUserEmailVerified {
            organization_id: self.organization_id,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Confirms the installation's first owner with what their setup token
    /// proved: the address is marked verified, as
    /// [`verify_email`](Self::verify_email) does, and the token vouches for
    /// their first sign-in. A risky one may then set a second factor up
    /// there and then, even with no mail server to confirm it. Raises
    /// `organization.org_user_email_verified`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the member never joined: only the
    ///   owner founding made, who joined then, holds a setup token.
    /// - [`DomainError::Forbidden`] when `proof` is for another address
    ///   than the account has.
    pub fn confirm_as_installer(&mut self, proof: &InstallerProof) -> Result<(), DomainError> {
        if self.joining == Joining::NotYet {
            return Err(DomainError::conflict(message!(
                "organization-the-setup-token-confirms-only-the",
                "the setup token confirms only the owner the install made"
            )));
        }
        self.verify_email(proof.address())
            .map_err(installer_refused)?;
        self.vouching = Vouching::Fresh;
        Ok(())
    }

    /// The proof of this member's address, for founding another
    /// organization under it, while `holder` is this member's own finished
    /// sign-in.
    ///
    /// The address was proven when it was verified, and the sign-in shows
    /// the person holding the account is the one asking. Without it,
    /// Mallory, signed in to her own account, founds an organization under
    /// Alice's address already verified, and mail meant for Alice goes to an
    /// organization Mallory runs.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `holder` is someone else's sign-in,
    ///   or this member's address was never verified.
    pub fn vouched_address(
        &self,
        holder: &SignedIn<ResolvedOrganization>,
    ) -> Result<VerifiedEmail, DomainError> {
        if holder.subject() != PrincipalId::from(self.id) {
            return Err(DomainError::forbidden(message!(
                "organization-only-the-member-s-own-sign",
                "only the member's own sign-in vouches for their address"
            )));
        }
        if !self.email_verified() {
            return Err(DomainError::forbidden(message!(
                "organization-an-address-never-verified-is-vouched",
                "an address never verified is vouched for by nobody"
            )));
        }
        Ok(VerifiedEmail::proven(self.email().clone()))
    }

    /// Sets the locale and the timezone, each to their own choice or back
    /// to the organization's, as `by` decides. Raises
    /// `organization.org_user_preferences_updated`, with both as they stand
    /// now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in the cases
    ///   [`change_display_name`](Self::change_display_name) lists.
    pub fn change_preferences(
        &mut self,
        locale: Preference<Locale>,
        timezone: Preference<Timezone>,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        ensure_may_edit_profile(self, by)?;
        self.locale = locale;
        self.timezone = timezone;
        self.touch();
        self.raised.raise_organization(OrgUserPreferencesUpdated {
            organization_id: self.organization_id,
            locale: self.locale.clone(),
            timezone: self.timezone.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }
}

/// The refusal of a setup token's proof the owner's address would not take.
fn installer_refused(refused: VerificationRefused<InvalidOrgUserTransition>) -> DomainError {
    match refused {
        VerificationRefused::OtherAddress => DomainError::forbidden(message!(
            "organization-the-setup-token-was-issued-for",
            "the setup token was issued for another address than the owner has"
        )),
        VerificationRefused::Transition(transition) => DomainError::from(transition),
    }
}
