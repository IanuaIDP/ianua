//! Keeping a session through a change of how its account signs in that its
//! own holder made from it.
//!
//! A change of password or second factor ends every session opened before
//! it, so whoever held the old way in is out. The session the holder made
//! the change from stays, once they showed it is them making it.

use crate::domains::authentication::sessions::proved_factor::ProvedFactor;
use crate::domains::authentication::sessions::session::Session;
use crate::domains::authentication::sessions::sign_in_progress::SignedIn;
use crate::domains::identity::account::control::RecentProof;
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{CredentialChange, PrincipalId};

impl<T: TenantScope> Session<T> {
    /// The change of how the account signs in this session was kept
    /// through, or [`CredentialChange::Never`]: its holder's own password
    /// change, a way in they added or removed from it, or the factor its
    /// sign-in set up.
    #[must_use]
    pub fn kept_through(&self) -> CredentialChange {
        self.kept_through
    }

    /// Keeps this session through the password change its own holder just
    /// made from it.
    ///
    /// A new password ends every session opened before it, so whoever held
    /// the old password is out. The session Ann used to change it stays,
    /// since she proved who she is again to change it. Only that one
    /// change is kept through. Any later change ends the session too.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is not this session's, or
    ///   `proof` is not a fresh proof of its holder.
    pub fn keep_through_own_password_change(
        &mut self,
        account: &User<T>,
        proof: &impl RecentProof,
    ) -> Result<(), DomainError> {
        if *account.id() != self.user_id || !proof.proves_recently(&PrincipalId::from(self.user_id))
        {
            return Err(DomainError::forbidden(message!(
                "authentication-only-the-holder-who-just-proved-2",
                "only the holder who just proved who they are keeps their session"
            )));
        }
        self.kept_through = account.credentials_changed_at();
        Ok(())
    }

    /// Keeps this session through the removal of a way in that its own
    /// holder just made from it, such as one of their passkeys.
    ///
    /// The removal ends every session opened before it, so one signed in
    /// with a lost passkey is out. The session Ann removed it from stays.
    /// Taking a way in away hands its holder nothing new, so her finished
    /// sign-in is enough, where adding one asks for a fresh proof, see
    /// [`keep_through_own_password_change`](Self::keep_through_own_password_change).
    /// Only that one change is kept through.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is not this session's, or
    ///   `holder` is someone else's sign-in.
    pub fn keep_through_own_removal(
        &mut self,
        account: &User<T>,
        holder: &SignedIn<T>,
    ) -> Result<(), DomainError> {
        let own = PrincipalId::from(self.user_id);
        if *account.id() != self.user_id || holder.subject() != own {
            return Err(DomainError::forbidden(message!(
                "authentication-only-the-session-s-own-holder",
                "only the session's own holder keeps it through what they removed"
            )));
        }
        self.kept_through = account.credentials_changed_at();
        Ok(())
    }

    /// Keeps this session through the second factor its own holder just set
    /// up from it, proved by `proof`, the code from the new factor that
    /// confirmed it.
    ///
    /// Setting up a factor ends every session opened before it. Pat sets up
    /// an authenticator app from her laptop: the laptop session stays, since
    /// the code only her new app shows proves it is her, while the session
    /// she left open on a shared computer ends. A sign-in still waiting for
    /// this factor is let in by [`answer`](Self::answer) instead, so only a
    /// finished, active session is kept here. Only that one change is kept
    /// through.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is not this session's,
    ///   `proof` was proved for another account, or the session is not an
    ///   active, finished sign-in.
    pub fn keep_through_own_factor_addition(
        &mut self,
        account: &User<T>,
        proof: ProvedFactor,
    ) -> Result<(), DomainError> {
        let own = PrincipalId::from(self.user_id);
        if *account.id() != self.user_id || proof.for_account(own).is_err() {
            return Err(DomainError::forbidden(message!(
                "authentication-only-the-holder-who-proved-the",
                "only the holder who proved the new factor keeps their session"
            )));
        }
        if !self.status.is_active() || !self.progress.is_complete() {
            return Err(DomainError::forbidden(message!(
                "authentication-only-a-finished-session-is-kept",
                "only a finished session is kept through a new factor"
            )));
        }
        self.kept_through = account.credentials_changed_at();
        Ok(())
    }
}
