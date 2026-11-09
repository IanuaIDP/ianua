//! A member's authenticator, where it is kept and how a code from it is
//! checked: counted towards its lock when wrong, and claimed so it works
//! once when right.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    AnsweredCode, CodeReplay, LockoutPolicy, MfaEnrollment,
};
use ianua_domain::domains::authentication::mfa::verifier::MfaVerifier;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::types::{OrgUserId, OrganizationId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::organization::OrgMfaEnrollmentStore;
use crate::services::authentication::sign_in_steps::{CodeCheck, SeedHolder, ensure_step_unused};

/// Where members' second factors are kept, and what checks their codes.
/// The member use cases that take a code from the authenticator share it.
#[derive(Clone, ianua_macros::Fakes)]
pub struct MemberCodePorts {
    /// Where members' enrollments are kept.
    pub enrollment_store: Arc<dyn OrgMfaEnrollmentStore>,
    /// Opens the factor's stored secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks a code against the secret.
    pub verifier: Arc<dyn MfaVerifier>,
}

impl MemberCodePorts {
    /// The check of the code of a member of `organization` against their
    /// factor, locking it under `lockout`.
    pub(in crate::use_cases::organization::mfa) fn checked(
        &self,
        lockout: LockoutPolicy,
        organization: OrganizationId,
    ) -> MemberCodeCheck<'_> {
        MemberCodeCheck {
            enrollments: self.enrollment_store.as_ref(),
            check: CodeCheck {
                encryptor: self.encryptor.as_ref(),
                verifier: self.verifier.as_ref(),
                lockout,
            },
            holder: SeedHolder::Member(organization),
        }
    }
}

/// A code from a member's authenticator, checked against their factor.
pub(in crate::use_cases::organization::mfa) struct MemberCodeCheck<'a> {
    enrollments: &'a dyn OrgMfaEnrollmentStore,
    check: CodeCheck<'a>,
    holder: SeedHolder,
}

impl MemberCodeCheck<'_> {
    /// `enrollment`'s answer to `code`, for `member`. The enrollment is
    /// saved whatever the answer, so a wrong code counts, and a right one
    /// has its time step claimed.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the code is wrong or was used before.
    /// - `AppError::AccountLocked` after too many wrong codes.
    /// - `AppError::Internal` when the enrollment cannot be saved or the
    ///   code cannot be checked.
    pub(in crate::use_cases::organization::mfa) async fn answered(
        &self,
        member: &OrgUserId,
        enrollment: &mut MfaEnrollment<ResolvedOrganization>,
        code: &str,
    ) -> Result<AnsweredCode, AppError> {
        let outcome = self.check.answer(self.holder, enrollment, code).await;
        self.enrollments
            .save(member, enrollment)
            .await
            .or_internal()?;
        let answered = outcome?;
        self.claim(member, answered.replay()).await?;
        Ok(answered)
    }

    /// Claims the time step `replay` names for `member`, so an
    /// authenticator code works once. A sent code was spent when it was
    /// answered and leaves nothing to claim.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the step was claimed before.
    /// - `AppError::Internal` when the claim cannot be stored.
    async fn claim(&self, member: &OrgUserId, replay: CodeReplay) -> Result<(), AppError> {
        let CodeReplay::ClaimStep(step) = replay else {
            return Ok(());
        };
        let fresh = self
            .enrollments
            .claim_step(member, step)
            .await
            .or_internal()?;
        ensure_step_unused(fresh.into())
    }
}

/// The member's authenticator, provided it is in force, held until the
/// unit of work ends: every caller changes it and saves it, and a second
/// answer at once must wait for this one's count. A pending or turned-off
/// one answers as none.
///
/// # Errors
///
/// - `AppError::NotFound` if the member has no authenticator in force.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization::mfa) async fn member_enrollment_in_force(
    store: &dyn OrgMfaEnrollmentStore,
    member: &OrgUserId,
) -> Result<MfaEnrollment<ResolvedOrganization>, AppError> {
    store
        .hold_by_user(member)
        .await
        .or_internal()?
        .filter(MfaEnrollment::is_active)
        .or_not_found(message!(
            "organization-no-second-factor-is-in-force",
            "no second factor is in force"
        ))
}

/// The member's authenticator, provided it still waits to be confirmed,
/// held until the unit of work ends: its callers change it and save it,
/// and a code answered while confirming it counts towards its lock.
///
/// # Errors
///
/// - `AppError::NotFound` if no setup of theirs is waiting.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization::mfa) async fn member_enrollment_waiting(
    store: &dyn OrgMfaEnrollmentStore,
    member: &OrgUserId,
) -> Result<MfaEnrollment<ResolvedOrganization>, AppError> {
    store
        .hold_by_user(member)
        .await
        .or_internal()?
        .filter(MfaEnrollment::is_pending)
        .or_not_found(message!(
            "organization-no-second-factor-is-waiting-to",
            "no second factor is waiting to be confirmed"
        ))
}
