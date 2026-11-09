//! Who sets up a second factor, and what lets them.
//!
//! Setting up a factor changes how the account signs in. Whoever steals a
//! session must not add their own authenticator with it, so a person signed
//! in proves who they are again first. A sign-in that waits for the factor
//! the workspace requires carries its own short leave to set it up, and
//! nothing else.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    EnrolledFactor, MfaEnrollment, MfaEnrollmentError, MfaMethod,
};
use ianua_domain::domains::authentication::mfa::offer::FactorOffer;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::{EnrolmentProof, FreshSignIn};
use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::PrincipalId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::services::lookup::{existing_user, owned_session};
use crate::tenancy::ScopedTenant;
use crate::use_cases::authentication::mfa::sessions::sign_in_parties::PendingSignIn;

/// Who sets up, confirms or gives up a second factor.
pub enum FactorSetter {
    /// A person signed in to a session of the tenant.
    SignedIn(Box<CallerContext>),
    /// A sign-in that waits for its person to set up the factor the
    /// workspace requires.
    SigningIn(PendingSignIn),
}

/// What lets the setter set up a factor now.
pub enum SetupProof {
    /// What the signed-in person typed again to prove who they are.
    Reentered(ReenteredProof),
    /// The waiting sign-in itself, which owes the factor and began moments
    /// ago.
    OwedBySignIn,
}

/// The ports that find who sets up a factor, and what lets them.
#[derive(ianua_macros::Fakes)]
pub struct SetterPorts {
    /// The account of a sign-in waiting for its factor.
    pub user_store: Arc<dyn UserStore>,
    /// The session of a sign-in waiting for its factor.
    pub session_store: Arc<dyn SessionStore>,
    /// Who is signed in to a caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what a signed-in person typed again into a fresh proof.
    pub fresh_proofs: Arc<dyn FreshProofs>,
}

impl SetterPorts {
    /// Where a setter's account is read.
    pub(in crate::use_cases::authentication::mfa) fn accounts(&self) -> SetterAccounts<'_> {
        SetterAccounts {
            authorities: self.tenant_authorities.as_ref(),
            users: self.user_store.as_ref(),
        }
    }

    /// Where a setter's leave to set up a factor is worked out.
    pub(in crate::use_cases::authentication::mfa) fn leaves(&self) -> SetupLeaves<'_> {
        SetupLeaves {
            fresh_proofs: self.fresh_proofs.as_ref(),
            sessions: self.session_store.as_ref(),
        }
    }
}

/// The domain's leave to set up a factor, in whichever form it came.
pub(in crate::use_cases::authentication::mfa) enum SetupLeave {
    /// A fresh proof of the person.
    Fresh(FreshSignIn),
    /// A sign-in waiting for the factor it owes.
    Enrolment(EnrolmentProof),
    /// A fresh waiting sign-in that spent a recovery code and still owes
    /// replacement enrollment before it may access the account.
    Recovery(EnrolmentProof),
}

/// Where a setter's account is read.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::mfa) struct SetterAccounts<'a> {
    /// Who is signed in to a caller's session.
    pub(in crate::use_cases::authentication::mfa) authorities: &'a dyn TenantAuthorities,
    /// The tenant's users, for a waiting sign-in's account.
    pub(in crate::use_cases::authentication::mfa) users: &'a dyn UserStore,
}

/// Where a setter's leave to set up a factor is worked out.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::mfa) struct SetupLeaves<'a> {
    /// Turns what a person typed again into a fresh proof of them.
    pub(in crate::use_cases::authentication::mfa) fresh_proofs: &'a dyn FreshProofs,
    /// The tenant's sessions, for a waiting sign-in.
    pub(in crate::use_cases::authentication::mfa) sessions: &'a dyn SessionStore,
}

impl SetterAccounts<'_> {
    /// The tenant the setter acts in and their account, as it is now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when a signed-in setter's session no
    ///   longer counts.
    /// - `AppError::NotFound` when a waiting sign-in's account is gone.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::authentication::mfa) async fn account(
        &self,
        setter: &FactorSetter,
    ) -> Result<(ScopedTenant, User<ResolvedTenant>), AppError> {
        match setter {
            FactorSetter::SignedIn(caller) => {
                let person = self.authorities.signed_in(caller).await?;
                Ok((caller.tenant(), person.account))
            }
            FactorSetter::SigningIn(pending) => {
                let account = existing_user(self.users, &pending.tenant, &pending.user_id).await?;
                Ok((pending.tenant, account))
            }
        }
    }
}

impl SetupLeaves<'_> {
    /// The leave `proof` gives `setter` to set up a factor on `account`.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the proof does not prove the person,
    ///   the waiting sign-in owes no factor to set up or began too long
    ///   ago, or the proof does not fit the setter.
    /// - `AppError::StepUpRequired` when the person has a second factor and
    ///   gave no code from it.
    /// - `AppError::NotFound` when the waiting sign-in's session is gone.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::authentication::mfa) async fn leave(
        &self,
        setter: &FactorSetter,
        account: &User<ResolvedTenant>,
        proof: SetupProof,
    ) -> Result<SetupLeave, AppError> {
        match (setter, proof) {
            (FactorSetter::SignedIn(caller), SetupProof::Reentered(proof)) => {
                let tenant = caller.tenant();
                let fresh = self
                    .fresh_proofs
                    .prove(&tenant, account, proof, caller.origin())
                    .await?;
                Ok(SetupLeave::Fresh(fresh))
            }
            (FactorSetter::SigningIn(pending), SetupProof::OwedBySignIn) => {
                self.enrolment_leave(pending).await
            }
            (FactorSetter::SignedIn(_), SetupProof::OwedBySignIn)
            | (FactorSetter::SigningIn(_), SetupProof::Reentered(_)) => {
                Err(AppError::Forbidden(message!(
                    "authentication-this-proof-does-not-fit-how",
                    "this proof does not fit how you are signed in"
                )))
            }
        }
    }

    /// Reads the holder's waiting session and obtains fresh enrollment
    /// permission, distinguishing recovery from ordinary first enrollment.
    async fn enrolment_leave(&self, pending: &PendingSignIn) -> Result<SetupLeave, AppError> {
        let session = owned_session(
            self.sessions,
            &pending.tenant,
            &pending.session_id,
            &pending.user_id,
        )
        .await?;
        let proof = session.enrolment_proof(clock::now()).ok_or_else(|| {
            AppError::Forbidden(message!(
                "authentication-this-sign-in-does-not-wait",
                "this sign-in does not wait for a second factor to be set up"
            ))
        })?;
        if session.mfa_method() == FactorProved::Proved(MfaFactor::RecoveryCode) {
            return Ok(SetupLeave::Recovery(proof));
        }
        Ok(SetupLeave::Enrolment(proof))
    }
}

/// What a new enrollment sets up, and the tenant's offer of its kind.
pub(in crate::use_cases::authentication::mfa) struct NewFactor<'a> {
    /// The factor, with what answering it needs.
    pub(in crate::use_cases::authentication::mfa) factor: EnrolledFactor,
    /// The tenant's offer of the factor's kind.
    pub(in crate::use_cases::authentication::mfa) offer: &'a FactorOffer,
}

/// A pending enrollment of `subject` setting up `new`, begun on `leave`.
///
/// # Errors
///
/// - `AppError::Forbidden` when `leave` does not let `subject` set up a
///   factor now, or the offer is for another kind of factor.
pub(in crate::use_cases::authentication::mfa) fn begun_enrollment(
    subject: PrincipalId,
    new: NewFactor<'_>,
    leave: &SetupLeave,
) -> Result<MfaEnrollment<ResolvedTenant>, AppError> {
    let NewFactor { factor, offer } = new;
    let begun = match leave {
        SetupLeave::Fresh(proof) => MfaEnrollment::begin(subject, factor, offer, proof),
        SetupLeave::Enrolment(proof) | SetupLeave::Recovery(proof) => {
            MfaEnrollment::begin(subject, factor, offer, proof)
        }
    };
    begun.map_err(|error| enrollment_refused(&error))
}

/// The tenant's offer of `method` to someone setting up a second factor.
///
/// # Errors
///
/// - `AppError::Forbidden` when second factors are off, the tenant does not
///   list `method`, or it cannot reach the tenant's baseline.
pub(in crate::use_cases::authentication::mfa) fn offered(
    workspace: &Tenant,
    method: MfaMethod,
) -> Result<FactorOffer, AppError> {
    workspace
        .auth_config()
        .offer_factor(method)
        .map_err(AppError::from_domain)
}

/// Gives up `enrollment`, a setup never confirmed, on `leave`.
///
/// # Errors
///
/// - `AppError::Forbidden` when `leave` does not let its subject set up a
///   factor now.
/// - `AppError::NotFound` when the enrollment no longer waits to be
///   confirmed.
pub(in crate::use_cases::authentication::mfa) fn abandon_enrollment(
    enrollment: &mut MfaEnrollment<ResolvedTenant>,
    leave: &SetupLeave,
) -> Result<(), AppError> {
    let abandoned = match leave {
        SetupLeave::Fresh(proof) => enrollment.abandon(proof),
        SetupLeave::Enrolment(proof) | SetupLeave::Recovery(proof) => enrollment.abandon(proof),
    };
    abandoned.map_err(|error| enrollment_refused(&error))
}

/// The error an enrollment that would not change answers with.
pub(in crate::use_cases::authentication::mfa) fn enrollment_refused(
    refused: &MfaEnrollmentError,
) -> AppError {
    match refused {
        MfaEnrollmentError::NotPending => AppError::NotFound(message!(
            "authentication-no-pending-mfa-enrollment",
            "no pending MFA enrollment"
        )),
        MfaEnrollmentError::NotActive => AppError::NotFound(message!(
            "authentication-mfa-is-not-enrolled",
            "MFA is not enrolled"
        )),
        MfaEnrollmentError::NotItsCode
        | MfaEnrollmentError::AccountHoldsMore
        | MfaEnrollmentError::NotProvedNow
        | MfaEnrollmentError::NotThisAccount
        | MfaEnrollmentError::NotOffered => AppError::Forbidden(refused.to_string().into()),
    }
}
