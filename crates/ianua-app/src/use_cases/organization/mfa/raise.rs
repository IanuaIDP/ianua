//! Recording a second factor on the member's sign-in it was proved for:
//! the domain decides what the factor answers, and the session is saved.
//! The event each path records drops the cached callers once committed.

use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInRefused;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;

use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgSessionStore;

/// The stores a member's raised session is written through.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::mfa) struct MemberSessionRaise<'a> {
    /// Saves the raised session.
    pub(in crate::use_cases::organization::mfa) sessions: &'a dyn OrgSessionStore,
}

impl MemberSessionRaise<'_> {
    /// Applies `proof` to `member`'s `session` under `policy` and saves it.
    /// A sign-in completed by its newly enrolled factor survives enrollment.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when the sign-in already proved a factor at
    ///   least as strong.
    /// - `AppError::Forbidden` when the factor does not answer what the
    ///   sign-in owes, was proved for another member, or leaves it below
    ///   the organization's baseline.
    /// - `AppError::Internal` if the session cannot be saved.
    pub(in crate::use_cases::organization::mfa) async fn raise(
        &self,
        session: &mut OrgSession,
        member: &OrgUser,
        proof: ProvedFactor,
        policy: &StepUpPolicy,
    ) -> Result<(), AppError> {
        answer(session, member, proof, policy)?;
        self.keep(session).await
    }

    /// Saves `session`, raised already.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the session cannot be saved.
    pub(in crate::use_cases::organization::mfa) async fn keep(
        &self,
        session: &OrgSession,
    ) -> Result<(), AppError> {
        self.sessions.save(session).await.or_internal()
    }
}

/// Records `proof` on `session` of `member` under `policy`, as the domain
/// allows it, without saving it.
///
/// # Errors
///
/// - `AppError::Conflict` when the sign-in already proved a factor at
///   least as strong.
/// - `AppError::Forbidden` when the factor does not answer what the
///   sign-in owes, was proved for another member, or leaves it below the
///   organization's baseline.
pub(in crate::use_cases::organization::mfa) fn answer(
    session: &mut OrgSession,
    member: &OrgUser,
    proof: ProvedFactor,
    policy: &StepUpPolicy,
) -> Result<(), AppError> {
    session
        .answer(member, proof, policy)
        .map_err(refused_member_answer)
}

/// The error a member's sign-in that would not take a factor answers with.
fn refused_member_answer(refused: SignInRefused) -> AppError {
    match refused {
        SignInRefused::AlreadyProved => AppError::Conflict(message!(
            "organization-the-sign-in-already-proved-its",
            "the sign-in already proved its second factor"
        )),
        SignInRefused::NotAccepted { .. }
        | SignInRefused::BelowBaseline(_)
        | SignInRefused::ForAnotherAccount
        | SignInRefused::AccountMayNotSignIn
        | SignInRefused::WayInNotAllowed => AppError::Forbidden(refused.to_string().into()),
    }
}
