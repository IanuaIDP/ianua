//! A person changing their own password, as the audit trail records it.
//!
//! The change touches the account's stored password and the moment it last
//! changed how it signs in, and it keeps the session it was made from. None
//! of those is the change itself, so a [`PasswordChange`] stands for it: it
//! admits the person, who just proved who they are again, and raises the
//! record. It is dropped once the record is taken.

use std::marker::PhantomData;

use crate::domains::authentication::events::credential::PasswordChanged;
use crate::domains::identity::account::control::RecentProof;
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::PrincipalId;

/// A password change its account's holder makes, with its record.
#[derive(Debug)]
pub struct PasswordChange<T: TenantScope> {
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> PasswordChange<T> {
    /// Admits `account`'s holder changing their password, once `proof`
    /// shows they proved who they are again just now. Raises
    /// `authentication.password_changed`. The record names nobody: the
    /// holder is its actor, and no hash belongs in it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `proof` is not a fresh proof of
    ///   `account`'s holder.
    pub fn by_holder(account: &User<T>, proof: &impl RecentProof) -> Result<Self, DomainError> {
        if !proof.proves_recently(&PrincipalId::from(*account.id())) {
            return Err(DomainError::forbidden(message!(
                "authentication-only-the-holder-who-just-proved",
                "only the holder who just proved who they are changes their password"
            )));
        }
        let mut change = Self {
            raised: Raised::default(),
            _scope: PhantomData,
        };
        change.raised.raise(PasswordChanged {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(change)
    }
}

impl<T: TenantScope> Raises for PasswordChange<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::builders::user;
    use crate::test_support::events::raised_names;
    use crate::types::UserId;

    /// Ann typed her password again and changes it. The change raises
    /// `authentication.password_changed`.
    #[test]
    fn a_holder_who_proved_herself_raises_the_change() {
        let ann = user(UserId::new(), "ann@acme.com");
        let proof = fresh_proof_of((*ann.id()).into());

        let mut change = PasswordChange::<ResolvedTenant>::by_holder(&ann, &proof).unwrap();

        assert_eq!(
            raised_names(&mut change),
            ["authentication.password_changed"]
        );
    }

    /// Mallory's identity proof cannot authorize a password change for Ann.
    #[test]
    fn another_persons_proof_changes_nothing() {
        let ann = user(UserId::new(), "ann@acme.com");
        let mallorys = fresh_proof_of(PrincipalId::from(UserId::new()));

        let refused = PasswordChange::<ResolvedTenant>::by_holder(&ann, &mallorys);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }
}
