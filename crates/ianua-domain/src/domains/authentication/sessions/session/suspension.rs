//! Freezing a session whose requests stopped looking like the person who
//! signed in, and lifting the freeze once they prove a factor again.

use crate::domains::authentication::events::session::{
    SessionResumed, SessionSuspended, SuspensionReason,
};
use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
use crate::domains::authentication::sessions::proved_factor::ProvedFactor;
use crate::domains::authentication::sessions::session::Session;
use crate::domains::authentication::sessions::sign_in_progress::SignInRefused;
use crate::domains::authentication::sessions::status::{InvalidSessionTransition, SessionStatus};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{EventLabel, Fact, PrincipalId};

impl<T: TenantScope> Session<T> {
    /// Freezes this session until the person proves a second factor again,
    /// for `reason`. Raises `authentication.session_suspended`, naming the
    /// holder as `holder_label`, since the platform freezes it, not they.
    ///
    /// It is for a request that does not look like the person who signed
    /// in, because the session's binding broke or its risk rose. Nothing is
    /// lost, but nothing goes through on it until [`resume`](Self::resume).
    ///
    /// # Errors
    ///
    /// - [`InvalidSessionTransition`] when the session is not active.
    pub fn suspend(
        &mut self,
        reason: SuspensionReason,
        holder_label: EventLabel,
    ) -> Result<(), InvalidSessionTransition> {
        self.status = self.status.try_transition(SessionStatus::Suspended)?;
        self.raised.raise(SessionSuspended {
            session_id: self.id,
            user_id: self.user_id,
            user_label: holder_label,
            reason,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Lifts a suspension once the person proves a factor now.
    ///
    /// Only a factor proved live counts. A recovery code stands in for a
    /// lost factor. A followed mailbox link proves no second factor. A
    /// provider's word arrives only with a fresh sign-in. So none of them
    /// resumes a session someone may have taken over. The factor must be
    /// this account's.
    ///
    /// The session then stands at the level the factor proves, lower or
    /// higher than before. Ann signed in with her hardware key. Mallory takes
    /// her session and resumes it with a stolen TOTP code. The session drops
    /// to the level of TOTP, so actions that ask for a hardware key still ask.
    ///
    /// The record of where it was last used starts over. Who proves
    /// themselves here decides where the session is: Pat lifts the freeze
    /// from Berlin, and her next use is not held against the Poznań request
    /// that froze it.
    ///
    /// Raises `authentication.session_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the session is not
    ///   suspended.
    /// - [`DomainError::Forbidden`] when the factor was proved for another
    ///   account, is not one proved live, or does not answer what the
    ///   sign-in still owes.
    /// - [`DomainError::Forbidden`] when the factor falls short of the
    ///   tenant's baseline. The session stays suspended.
    pub fn resume(
        &mut self,
        proof: ProvedFactor,
        policy: &StepUpPolicy,
    ) -> Result<(), DomainError> {
        if !self.status.is_suspended() {
            return Err(DomainError::invalid_transition(message!(
                "authentication-only-a-suspended-session-resumes",
                "only a suspended session resumes"
            )));
        }
        let factor = proof
            .for_account(PrincipalId::from(self.user_id))
            .map_err(resume_refused)?;
        let reproved = self
            .progress
            .reproved(factor, policy)
            .map_err(resume_refused)?;
        self.status = self.status.try_transition(SessionStatus::Active)?;
        self.progress = reproved;
        self.last_use = Fact::Unknown;
        self.raised.raise(SessionResumed {
            session_id: self.id,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }
}

/// Why a suspended session did not resume, in the words its holder reads.
fn resume_refused(refused: SignInRefused) -> DomainError {
    match refused {
        SignInRefused::BelowBaseline(_) => DomainError::forbidden(message!(
            "authentication-this-factor-does-not-reach-the",
            "this factor does not reach the assurance the workspace requires"
        )),
        SignInRefused::NotAccepted { .. }
        | SignInRefused::AlreadyProved
        | SignInRefused::ForAnotherAccount
        | SignInRefused::AccountMayNotSignIn
        | SignInRefused::WayInNotAllowed => DomainError::forbidden(message!(
            "authentication-a-suspended-session-resumes-only-on",
            "a suspended session resumes only on its own account's second factor, proved now"
        )),
    }
}
