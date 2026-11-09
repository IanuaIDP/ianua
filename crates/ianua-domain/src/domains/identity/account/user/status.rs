//! How an account moves between statuses: someone with the right lets it
//! in or shuts it out, an accepted invitation lets its invitee join, and an
//! erasure closes it and, cancelled, opens it again.

use crate::domains::identity::account::control::AccountControlCheck;
use crate::domains::identity::account::user::User;
use crate::domains::identity::account::user_status::{InvalidUserTransition, UserStatus};
use crate::domains::identity::account::vouching::Vouching;
use crate::domains::identity::invitations::route::AcceptedAddress;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

impl<T: TenantScope> User<T> {
    /// Activates the account under `control`, recording join time for waiting accounts.
    /// Deactivated accounts retain their history. Invitees normally join through
    /// [`Invitation::accept`](crate::domains::identity::invitations::invitation::Invitation::accept).
    /// Raises `identity.user_status_changed` with name and address, except during creation.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another account's control, missing authority,
    /// or permissions held by the account but not the actor.
    /// [`DomainError::InvalidTransition`] if already active or closing; closing requires
    /// cancelling erasure.
    pub fn activate(
        &mut self,
        control: &impl AccountControlCheck,
    ) -> Result<UserStatus, DomainError> {
        let from = self.status;
        let moved = self.let_in(control)?;
        self.status_moved(from);
        Ok(moved)
    }

    /// Locks an active account against sign-in; the caller must end its existing sessions.
    /// Raises `identity.user_status_changed` as [`Self::activate`] does.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another account's control, missing authority,
    /// or permissions held by the account but not the actor.
    /// [`DomainError::InvalidTransition`] unless the account is active.
    pub fn lock(&mut self, control: &impl AccountControlCheck) -> Result<UserStatus, DomainError> {
        let from = self.status;
        let moved = self.shut_out(UserStatus::Locked, control)?;
        self.status_moved(from);
        Ok(moved)
    }

    /// Restores sign-in for a locked account, without bypassing unfinished onboarding.
    /// Raises `identity.user_status_changed` as [`Self::activate`] does.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another account's control, missing authority,
    /// or permissions held by the account but not the actor.
    /// [`DomainError::InvalidTransition`] unless the account is locked.
    pub fn unlock(
        &mut self,
        control: &impl AccountControlCheck,
    ) -> Result<UserStatus, DomainError> {
        let from = self.status;
        let moved = self.let_back_in(control)?;
        self.status_moved(from);
        Ok(moved)
    }

    /// Disables sign-in until [`Self::activate`]; the caller must end every session.
    /// Raises `identity.user_status_changed` as [`Self::activate`] does.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for another account's control, missing authority,
    /// or permissions held by the account but not the actor.
    /// [`DomainError::InvalidTransition`] if already deactivated.
    pub fn deactivate(
        &mut self,
        control: &impl AccountControlCheck,
    ) -> Result<UserStatus, DomainError> {
        let from = self.status;
        let moved = self.shut_out(UserStatus::Deactivated, control)?;
        self.status_moved(from);
        Ok(moved)
    }

    /// Lets in the invited account an invitation was accepted for. A mailed
    /// invitation proved the address, which is marked verified; a handed
    /// over one proved nothing, and the address keeps its standing.
    ///
    /// Either way the invitation proved the person, so it vouches for their
    /// first sign-in: a risky one may set a second factor up there and then,
    /// even where no mail could confirm it. Raises
    /// `identity.user_status_changed`, as [`activate`](Self::activate) does.
    ///
    /// Only [`Invitation::accept`](crate::domains::identity::invitations::invitation::Invitation::accept)
    /// calls this, after it checked the link was for this account.
    pub(crate) fn join_by_invitation(
        &mut self,
        accepted: &AcceptedAddress,
    ) -> Result<(), DomainError> {
        let from = self.status;
        let joined = self.status.try_transition(UserStatus::Active)?;
        if accepted.email() != self.address.email() {
            return Err(moved_off_invited_address());
        }
        if let Some(proof) = accepted.proof() {
            self.address
                .confirm::<InvalidUserTransition>(proof)
                .map_err(|_| moved_off_invited_address())?;
        }
        self.apply_transition(joined)?;
        self.vouching = Vouching::Fresh;
        self.status_moved(from);
        Ok(())
    }

    /// Closes an active account while its erasure waits. Any other status
    /// already keeps it from signing in, so it is left as it is.
    pub(crate) fn close_for_erasure(&mut self) -> Result<(), InvalidUserTransition> {
        if self.status != UserStatus::Active {
            return Ok(());
        }
        self.apply_transition(UserStatus::Closing)?;
        Ok(())
    }

    /// Closes an invited account whose invitation was never accepted.
    pub(crate) fn close_unanswered_invite(&mut self) -> Result<(), InvalidUserTransition> {
        if self.status != UserStatus::Invited {
            return Ok(());
        }
        self.apply_transition(UserStatus::Deactivated)?;
        Ok(())
    }

    /// Opens an account closed for an erasure that was cancelled.
    pub(crate) fn reopen_after_erasure(&mut self) -> Result<(), InvalidUserTransition> {
        if self.status != UserStatus::Closing {
            return Ok(());
        }
        self.apply_transition(UserStatus::Active)?;
        Ok(())
    }
}

/// The refusal for an invitation accepted by an account that has moved off
/// the invited address.
fn moved_off_invited_address() -> DomainError {
    DomainError::forbidden(message!(
        "identity-the-invitation-was-sent-to-an",
        "the invitation was sent to an address the account no longer has"
    ))
}
