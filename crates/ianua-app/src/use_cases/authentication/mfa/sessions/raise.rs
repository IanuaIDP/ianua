//! Recording a second factor on the session it was proved for, which every
//! step-up path shares: the domain decides what the factor answers, and the
//! session is saved. The event each path records drops the cached callers
//! once committed.

use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInRefused;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;

use crate::error::{AppError, OrInternal};
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authentication::mfa::sessions::sign_in_parties::SignInParties;

/// The stores a raised session is written through.
pub(in crate::use_cases::authentication::mfa) struct SessionRaise<'a> {
    /// Saves the raised session.
    pub(in crate::use_cases::authentication::mfa) session_store: &'a dyn SessionStore,
}

/// A factor proved for a session's account, and the tenant's rules for
/// what it must reach.
pub(in crate::use_cases::authentication::mfa) struct Raise<'a> {
    /// The session's account, as it is now.
    pub(in crate::use_cases::authentication::mfa) account: &'a User<ResolvedTenant>,
    /// The factor proved just now.
    pub(in crate::use_cases::authentication::mfa) proof: ProvedFactor,
    /// The tenant's step-up policy.
    pub(in crate::use_cases::authentication::mfa) policy: &'a StepUpPolicy,
}

impl SessionRaise<'_> {
    /// Saves `session`, already raised, so the next request sees how far
    /// it has come.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` if the session cannot be saved.
    pub(in crate::use_cases::authentication::mfa) async fn keep(
        &self,
        tenant: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.session_store.save(tenant, session).await.or_internal()
    }

    /// Records `proof` on the session of `parties`, under their tenant's
    /// policy, as the domain allows it, and saves the session so the next
    /// request sees how far it has come.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` when the session already proved a factor at
    ///   least as strong.
    /// - `AppError::Forbidden` when the factor does not answer what the
    ///   session owes, was proved for another account, or leaves it below
    ///   the tenant's baseline.
    /// - `AppError::Internal` if the session cannot be saved.
    pub(in crate::use_cases::authentication::mfa) async fn raise_parties(
        &self,
        tenant: &ScopedTenant,
        parties: &mut SignInParties,
        proof: ProvedFactor,
    ) -> Result<(), AppError> {
        answer_parties(parties, proof)?;
        self.keep(tenant, &parties.session).await
    }
}

/// Records `proof` on the session of `parties`, under their tenant's
/// policy, as the domain allows it, without saving it yet: a caller that
/// must first claim the proof in storage keeps the session after.
///
/// # Errors
///
/// As [`SessionRaise::raise_parties`], except that nothing is written.
pub(in crate::use_cases::authentication::mfa) fn answer_parties(
    parties: &mut SignInParties,
    proof: ProvedFactor,
) -> Result<(), AppError> {
    let raise = Raise {
        account: &parties.account,
        proof,
        policy: &parties.policy,
    };
    answer(&mut parties.session, raise)
}

/// Records `raise.proof` on `session` as the domain allows it, without
/// saving it yet.
///
/// # Errors
///
/// As [`SessionRaise::raise_parties`], except that nothing is written.
pub(in crate::use_cases::authentication::mfa) fn answer(
    session: &mut Session<ResolvedTenant>,
    raise: Raise<'_>,
) -> Result<(), AppError> {
    session
        .answer(raise.account, raise.proof, raise.policy)
        .map_err(refused_answer)
}

/// The error a sign-in that would not take a factor answers with.
fn refused_answer(refused: SignInRefused) -> AppError {
    match refused {
        SignInRefused::AlreadyProved => AppError::Conflict(message!(
            "authentication-mfa-already-verified",
            "MFA already verified"
        )),
        SignInRefused::NotAccepted { .. }
        | SignInRefused::BelowBaseline(_)
        | SignInRefused::ForAnotherAccount
        | SignInRefused::AccountMayNotSignIn
        | SignInRefused::WayInNotAllowed => AppError::Forbidden(refused.to_string().into()),
    }
}
