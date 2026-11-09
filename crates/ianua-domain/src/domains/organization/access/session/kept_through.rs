//! Keeping a member's session through a change of how they sign in that
//! they made from it.
//!
//! A change of password, passkey or second factor ends every session
//! opened before it, so whoever held the old way in is out. The session the
//! member made the change from stays, once they showed it is them making
//! it.

use crate::domains::authentication::sessions::proved_factor::ProvedFactor;
use crate::domains::authentication::sessions::sign_in_progress::SignedIn;
use crate::domains::authentication::sessions::status::SessionStatus;
use crate::domains::identity::account::control::RecentProof;
use crate::domains::organization::access::session::OrgSession;
use crate::domains::organization::members::org_user::OrgUser;
use crate::isolation::organization::scope::ResolvedOrganization;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{CredentialChange, PrincipalId};

impl OrgSession {
    /// The change of how the member signs in this session was kept
    /// through, or [`CredentialChange::Never`]: a change its own holder made
    /// from it, or the factor its sign-in set up.
    #[must_use]
    pub fn kept_through(&self) -> CredentialChange {
        self.kept_through
    }

    /// Keeps this session through the change of how its member signs in
    /// that they just made from it, having proved who they are again: a new
    /// password, or a passkey added.
    ///
    /// The change ends every session opened before it, so whoever held the
    /// old way in is out. Olivia adds a passkey from her laptop's session,
    /// and that session stays. Only that one change is kept through.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `member` is not this session's, or
    ///   `proof` is not a fresh proof of them.
    pub fn keep_through_own_change(
        &mut self,
        member: &OrgUser,
        proof: &impl RecentProof,
    ) -> Result<(), DomainError> {
        let own = PrincipalId::from(self.org_user_id);
        if *member.id() != self.org_user_id || !proof.proves_recently(&own) {
            return Err(DomainError::forbidden(message!(
                "organization-only-the-member-who-just-proved",
                "only the member who just proved who they are keeps their session"
            )));
        }
        self.kept_through = member.credentials_changed_at();
        Ok(())
    }

    /// Keeps this session through the removal of a way in that its own
    /// member just made from it, such as one of their passkeys.
    ///
    /// The removal ends every session opened before it, so one signed in
    /// with a lost passkey is out. The session Olivia removed it from
    /// stays. Taking a way in away hands its holder nothing new, so her
    /// finished sign-in is enough. Only that one change is kept through.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `member` is not this session's, or
    ///   `holder` is someone else's sign-in.
    pub fn keep_through_own_removal(
        &mut self,
        member: &OrgUser,
        holder: &SignedIn<ResolvedOrganization>,
    ) -> Result<(), DomainError> {
        let own = PrincipalId::from(self.org_user_id);
        if *member.id() != self.org_user_id || holder.subject() != own {
            return Err(DomainError::forbidden(message!(
                "organization-only-the-session-s-own-member",
                "only the session's own member keeps it through what they removed"
            )));
        }
        self.kept_through = member.credentials_changed_at();
        Ok(())
    }

    /// Keeps this session through the second factor its own member just
    /// set up from it, proved by `proof`, the code from the new factor that
    /// confirmed it.
    ///
    /// Setting up a factor ends every session opened before it. Olivia sets
    /// up an authenticator app from her laptop: the laptop session stays,
    /// since the code only her new app shows proves it is her, while the
    /// session she left open on a shared computer ends. A sign-in still
    /// waiting for this factor is let in by [`answer`](Self::answer)
    /// instead, so only a finished, active session is kept here. Only that
    /// one change is kept through.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `member` is not this session's,
    ///   `proof` was proved for another account, or the session is not an
    ///   active, finished sign-in.
    pub fn keep_through_own_factor_addition(
        &mut self,
        member: &OrgUser,
        proof: ProvedFactor,
    ) -> Result<(), DomainError> {
        let own = PrincipalId::from(self.org_user_id);
        if *member.id() != self.org_user_id || proof.for_account(own).is_err() {
            return Err(DomainError::forbidden(message!(
                "organization-only-the-member-who-proved-the",
                "only the member who proved the new factor keeps their session"
            )));
        }
        if self.status != SessionStatus::Active || !self.progress.is_complete() {
            return Err(DomainError::forbidden(message!(
                "authentication-only-a-finished-session-is-kept",
                "only a finished session is kept through a new factor"
            )));
        }
        self.kept_through = member.credentials_changed_at();
        Ok(())
    }
}
