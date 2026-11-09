//! What an account raises for the audit trail, and how the trail names it.

use crate::domains::identity::account::address::AccountAddress;
use crate::domains::identity::account::user::{Origin, User};
use crate::domains::identity::account::user_status::UserStatus;
use crate::domains::identity::events::account::{
    UserDeleted, UserEmailChanged, UserStatusChanged, VerificationEmailSent, WelcomeEmailSent,
};
use crate::isolation::scope::TenantScope;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raises, SavedFor};
use crate::types::EventLabel;

impl<T: TenantScope> User<T> {
    /// Raises the move from `from` to the status the account has now,
    /// unless the account has just been created without loading from storage.
    pub(super) fn status_moved(&mut self, from: UserStatus) {
        let Origin::Stored(_) = self.origin else {
            return;
        };
        self.raised.raise(UserStatusChanged {
            user_id: self.id,
            user_label: self.label(),
            from,
            to: self.status,
            occurred_at: self.updated_at,
        });
    }

    /// Raises the move off the address `previous` held onto the one the
    /// account has now.
    pub(super) fn email_moved(&mut self, previous: &AccountAddress) {
        self.raised.raise(UserEmailChanged {
            user_id: self.id,
            user_label: self.label(),
            old_email: previous.email().clone(),
            new_email: self.email().clone(),
            occurred_at: self.updated_at,
        });
    }

    /// Raises the account's deletion.
    pub(super) fn record_deletion(&mut self) {
        self.raised.raise(UserDeleted {
            user_id: self.id,
            email: self.email().clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Notes that a link to confirm the address was mailed and the mailer
    /// took it. Raises `identity.verification_email_sent`; nothing stored
    /// changes.
    pub fn note_verification_mailed(&mut self) {
        self.raised.raise(VerificationEmailSent {
            user_id: self.id,
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Notes that the mail telling the person their account is ready went
    /// out. Raises `identity.welcome_email_sent`; nothing stored changes.
    pub fn note_welcome_mailed(&mut self) {
        self.raised.raise(WelcomeEmailSent {
            user_id: self.id,
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// How the audit trail names this account: its name with its address
    /// in brackets. The text is copied into each event, so the entry stays
    /// readable after the account is gone.
    pub(crate) fn label(&self) -> EventLabel {
        EventLabel::of(&format!(
            "{} ({})",
            self.display_name.as_str(),
            self.email().as_str()
        ))
    }
}

impl<T: TenantScope> Raises for User<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}
