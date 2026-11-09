//! How a tenant's directory moves an account: letting it in, shutting it
//! out, deleting it, and the one status record its whole change leaves.

use crate::domains::identity::account::control::{AccountAction, AccountControlCheck};
use crate::domains::identity::account::user::{Origin, User};
use crate::domains::identity::account::user_status::{InvalidUserTransition, UserStatus};
use crate::domains::identity::events::account::UserStatusChanged;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::EventLabel;

/// Which way a tenant's directory moves an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectorySwitch {
    /// Lets a locked or switched-off account back in. Any other account is
    /// left as it is.
    LetIn,
    /// Locks an active account, and switches off one still waiting on its
    /// invitation or its address. Any other account is left as it is.
    ShutOut,
    /// Switches the account off, whatever it stood at, as a directory that
    /// removes people does.
    SwitchOff,
}

impl<T: TenantScope> User<T> {
    /// Moves the account the way its tenant's directory asks, as `control`
    /// allows. Each move raises nothing of its own: the directory records
    /// the account's whole move once its change is done, through
    /// [`close_directory_change`](Self::close_directory_change).
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses the move.
    /// - [`DomainError::InvalidTransition`] when the status rules refuse it.
    pub fn switch_by_directory(
        &mut self,
        switch: DirectorySwitch,
        control: &impl AccountControlCheck,
    ) -> Result<(), DomainError> {
        let moved = match (switch, self.status) {
            (DirectorySwitch::LetIn, UserStatus::Locked) => self.let_back_in(control),
            (DirectorySwitch::LetIn, UserStatus::Deactivated) => self.let_in(control),
            (DirectorySwitch::ShutOut, UserStatus::Active) => {
                self.shut_out(UserStatus::Locked, control)
            }
            (DirectorySwitch::ShutOut, UserStatus::Invited | UserStatus::PendingVerification)
            | (
                DirectorySwitch::SwitchOff,
                UserStatus::Active
                | UserStatus::Invited
                | UserStatus::PendingVerification
                | UserStatus::Locked
                | UserStatus::Closing,
            ) => self.shut_out(UserStatus::Deactivated, control),
            _ => return Ok(()),
        };
        moved.map(drop)
    }

    /// Ends a directory's change to an account read back from storage.
    /// Raises `identity.user_status_changed` when the change moved its
    /// status, once for the whole move, naming the account by its address,
    /// the way the directory knows it. An account opened in the same change
    /// records nothing here.
    pub fn close_directory_change(&mut self) {
        let Origin::Stored(from) = self.origin else {
            return;
        };
        if from == self.status {
            return;
        }
        self.origin = Origin::Stored(self.status);
        self.raised.raise(UserStatusChanged {
            user_id: self.id,
            user_label: EventLabel::of(self.email().as_str()),
            from,
            to: self.status,
            occurred_at: self.updated_at,
        });
    }

    /// Lets the account in, as `control` allows. A closing account stays
    /// closed.
    pub(super) fn let_in(
        &mut self,
        control: &impl AccountControlCheck,
    ) -> Result<UserStatus, DomainError> {
        control.ensure_allowed(&self.id, AccountAction::LetIn)?;
        if self.status == UserStatus::Closing {
            return Err(DomainError::invalid_transition(message!(
                "identity-a-closing-account-comes-back-only",
                "a closing account comes back only when its erasure is cancelled"
            )));
        }
        self.apply_transition(UserStatus::Active)
            .map_err(DomainError::from)
    }

    /// Lets a locked account back in, as `control` allows.
    pub(super) fn let_back_in(
        &mut self,
        control: &impl AccountControlCheck,
    ) -> Result<UserStatus, DomainError> {
        control.ensure_allowed(&self.id, AccountAction::LetIn)?;
        if self.status != UserStatus::Locked {
            return Err(InvalidUserTransition {
                from: self.status,
                to: UserStatus::Active,
            }
            .into());
        }
        self.apply_transition(UserStatus::Active)
            .map_err(DomainError::from)
    }

    /// Shuts the account out at `target`, as `control` allows.
    pub(super) fn shut_out(
        &mut self,
        target: UserStatus,
        control: &impl AccountControlCheck,
    ) -> Result<UserStatus, DomainError> {
        control.ensure_allowed(&self.id, AccountAction::ShutOut)?;
        self.apply_transition(target).map_err(DomainError::from)
    }

    /// Deletes the account for the tenant's directory, which may delete an
    /// account only where it may shut it out. Raises `identity.user_deleted`,
    /// as [`delete`](Self::delete) does.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `control` refuses shutting the
    ///   account out.
    /// - [`DomainError::Conflict`] when it is the tenant's last
    ///   administrator.
    pub fn delete_by_directory(
        &mut self,
        control: &impl AccountControlCheck,
    ) -> Result<(), DomainError> {
        control.ensure_allowed(&self.id, AccountAction::ShutOut)?;
        self.record_deletion();
        Ok(())
    }
}
