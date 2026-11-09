//! How a member signs in and changes it: their password, set by themselves
//! or by someone who may update members, and the second factors and
//! passkeys whose changes end the devices remembered before them.

use crate::domains::authentication::credentials::passkey::PasskeyCredential;
use crate::domains::authentication::credentials::password::PasswordHasher;
use crate::domains::authentication::recovery::codes::RecoveryCodeSet;
use crate::domains::authentication::sessions::way_in::WayIn;
use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::domains::organization::events::access::{
    OrgMemberMfaReset, OrgMfaEnrolled, OrgMfaUnenrolled, OrgPasskeyRegistered, OrgPasskeyRemoved,
    OrgRecoveryCodesGenerated, OrgUserPasswordChanged, OrgUserPasswordReset,
};
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::org_user::{OrgPassword, OrgUser};
use crate::domains::organization::members::org_user_authority::ensure_may_take_over;
use crate::isolation::organization::scope::ResolvedOrganization;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{CredentialChange, PasswordHash};

impl OrgUser {
    /// Replaces the password on someone else's account, as `by` decides,
    /// such as an admin resetting it. Raises
    /// `organization.org_user_password_reset`.
    ///
    /// `by` needs the right to update members, and only an owner sets an
    /// owner's password. Someone changing their own password uses
    /// [`change_own_password`](Self::change_own_password) or
    /// [`reset_password`](Self::reset_password), which prove the person.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is this member. A stolen
    ///   session would otherwise set a password without the current one.
    /// - [`DomainError::Forbidden`] when `by` may not update members, or
    ///   this account is an owner and `by` is not one.
    pub fn change_password(
        &mut self,
        hash: PasswordHash,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        ensure_may_take_over(self, by)?;
        self.replace_password(hash);
        self.raised.raise_organization(OrgUserPasswordReset {
            organization_id: self.organization_id,
            org_user_id: self.id,
            org_user_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Replaces the account's password after checking `current` proves its holder.
    /// Raises `organization.org_user_password_changed`.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without a password or when `current` does not match.
    /// Propagates hasher errors, including malformed stored hashes.
    pub fn change_own_password(
        &mut self,
        current: &str,
        new: PasswordHash,
        hasher: &impl PasswordHasher,
    ) -> Result<(), DomainError> {
        self.sign_in_with_password(current, hasher)?;
        self.replace_password(new);
        self.raise_own_password_change();
        Ok(())
    }

    /// Replaces the password for someone who followed a reset link, given
    /// the `proof` that [`OrgPasswordResetToken::redeem`] gives back.
    /// Raises `organization.org_user_password_changed`, as the person's own
    /// change.
    ///
    /// Following a link mailed to the account's address proves the person.
    /// Alice moved to a new address. Without this check, Mallory, who reads
    /// her old mailbox, uses a link sent there and takes the account.
    ///
    /// [`OrgPasswordResetToken::redeem`]: crate::domains::organization::access::token::OrgToken::redeem
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` is for another address than
    ///   the account has.
    pub fn reset_password(
        &mut self,
        hash: PasswordHash,
        proof: &VerifiedEmail,
    ) -> Result<(), DomainError> {
        if proof.as_email() != self.email() {
            return Err(DomainError::forbidden(message!(
                "organization-the-reset-link-went-to-another",
                "the reset link went to another address than the member has"
            )));
        }
        self.replace_password(hash);
        self.raise_own_password_change();
        Ok(())
    }

    /// Raises the person's own change of their password.
    fn raise_own_password_change(&mut self) {
        self.raised.raise_organization(OrgUserPasswordChanged {
            organization_id: self.organization_id,
            occurred_at: self.updated_at,
        });
    }

    /// The way into this account that `raw` gives, when it is the
    /// account's password.
    ///
    /// Only a password checked here starts an organization sign-in, so a
    /// session never opens on the caller's word that it was right. Whether
    /// the member may sign in at all is asked when the session opens.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the account has no password, or
    ///   `raw` is not it.
    /// - The error `hasher` gives when it cannot check the password.
    pub fn sign_in_with_password(
        &self,
        raw: &str,
        hasher: &impl PasswordHasher,
    ) -> Result<WayIn, DomainError> {
        let OrgPassword::Set(hash) = &self.password_hash else {
            return Err(DomainError::forbidden(message!(
                "organization-the-account-has-no-password",
                "the account has no password"
            )));
        };
        if !hasher.verify(raw, hash)? {
            return Err(DomainError::forbidden(message!(
                "authentication-the-password-is-wrong",
                "the password is wrong"
            )));
        }
        Ok(WayIn::by_password(self.id.into()))
    }

    /// Stores `hash` as the password. A changed password is a credential
    /// change, so every device remembered before it stops counting.
    pub(super) fn replace_password(&mut self, hash: PasswordHash) {
        self.password_hash = OrgPassword::Set(hash);
        self.record_credential_change();
    }

    /// Records that the user added or removed a second factor. Every device
    /// they remembered before now stops counting.
    pub fn record_credential_change(&mut self) {
        self.credentials_changed_at = CredentialChange::At {
            at: crate::shared::clock::now(),
        };
        self.touch();
    }

    /// Records that the member set up an authenticator app, which their
    /// sign-ins now ask for. Raises `organization.org_mfa_enrolled`.
    pub fn record_mfa_enrolled(&mut self) {
        self.record_credential_change();
        self.raised.raise_organization(OrgMfaEnrolled {
            organization_id: self.organization_id,
            occurred_at: self.updated_at,
        });
    }

    /// Records that the member switched their authenticator app off.
    /// Raises `organization.org_mfa_unenrolled`.
    pub fn record_mfa_turned_off(&mut self) {
        self.record_credential_change();
        self.raised.raise_organization(OrgMfaUnenrolled {
            organization_id: self.organization_id,
            org_user_id: self.id,
            occurred_at: self.updated_at,
        });
    }

    /// Records that someone who may update members reset this member's
    /// authenticator app, for a member who lost theirs. Raises
    /// `organization.org_member_mfa_reset`.
    pub fn record_mfa_reset(&mut self) {
        self.record_credential_change();
        self.raised.raise_organization(OrgMemberMfaReset {
            organization_id: self.organization_id,
            org_user_id: self.id,
            org_user_label: self.label(),
            occurred_at: self.updated_at,
        });
    }

    /// Records that the member replaced their recovery codes with `set`,
    /// which checked their fresh proof. Raises
    /// `organization.org_recovery_codes_generated`.
    pub fn record_recovery_codes_generated(&mut self, set: &RecoveryCodeSet<ResolvedOrganization>) {
        self.raised.raise_organization(OrgRecoveryCodesGenerated {
            organization_id: self.organization_id,
            count: u8::try_from(set.total()).unwrap_or(u8::MAX),
            occurred_at: set.generated_at(),
        });
    }

    /// Records that the member registered `passkey`. Raises
    /// `organization.org_passkey_registered`.
    pub fn record_passkey_registered(&mut self, passkey: &PasskeyCredential<ResolvedOrganization>) {
        self.record_credential_change();
        self.raised.raise_organization(OrgPasskeyRegistered {
            organization_id: self.organization_id,
            org_user_id: self.id,
            credential_id: passkey.credential_id().clone(),
            occurred_at: self.updated_at,
        });
    }

    /// Records that the member removed `passkey`. Raises
    /// `organization.org_passkey_removed`.
    pub fn record_passkey_removed(&mut self, passkey: &PasskeyCredential<ResolvedOrganization>) {
        self.record_credential_change();
        self.raised.raise_organization(OrgPasskeyRemoved {
            organization_id: self.organization_id,
            org_user_id: self.id,
            credential_id: passkey.credential_id().clone(),
            occurred_at: self.updated_at,
        });
    }
}
