//! A sign-in link mailed to an account, as the audit trail records it.
//!
//! The link itself is a token kept until it is followed, and it is not the
//! mailing. A [`SignInLinkMailing`] stands for the mailing once the mail was
//! accepted: it raises the record, and is dropped once the record is taken.

use std::marker::PhantomData;

use crate::domains::authentication::events::login::MagicLinkRequested;
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};

/// A sign-in link mailed to an account that may sign in, with its record.
#[derive(Debug)]
pub struct SignInLinkMailing<T: TenantScope> {
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> SignInLinkMailing<T> {
    /// A sign-in link was mailed to `holder`. Raises
    /// `authentication.magic_link_requested`, naming the account.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `holder` may not sign in. No link
    ///   goes to an account that a link would not open.
    pub fn mailed(holder: &User<T>) -> Result<Self, DomainError> {
        if !holder.can_authenticate() {
            return Err(DomainError::forbidden(message!(
                "authentication-a-sign-in-link-goes-only",
                "a sign-in link goes only to an account that may sign in"
            )));
        }
        let mut mailing = Self {
            raised: Raised::default(),
            _scope: PhantomData,
        };
        mailing.raised.raise(MagicLinkRequested {
            user_id: *holder.id(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(mailing)
    }
}

impl<T: TenantScope> Raises for SignInLinkMailing<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::account_check::tests::account_with;
    use crate::domains::identity::account::user_status::UserStatus;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::raised;
    use crate::types::{CredentialChange, UserId};

    /// A link is mailed to Ann's active account. The mailing raises
    /// `authentication.magic_link_requested`, naming her account.
    #[test]
    fn a_mailed_link_raises_its_request() {
        let ann = account_with(UserId::new(), UserStatus::Active, CredentialChange::Never);

        let mut mailing = SignInLinkMailing::mailed(&ann).unwrap();

        let events = raised(&mut mailing);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.magic_link_requested"
        );
        assert_eq!(events.len(), 1);
    }

    /// A locked account cannot obtain a sign-in link.
    #[test]
    fn no_link_goes_to_an_account_that_may_not_sign_in() {
        let bob: User<ResolvedTenant> =
            account_with(UserId::new(), UserStatus::Locked, CredentialChange::Never);

        let refused = SignInLinkMailing::mailed(&bob);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }
}
