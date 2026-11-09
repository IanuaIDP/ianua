//! Checking a code from a person's second factor against it, from their
//! authenticator or sent to them, and recording a wrong one in the audit
//! trail.
//!
//! Repeated wrong codes across separate requests are the sign of someone
//! guessing. The factor counts each one towards its lock and raises it,
//! with whether it locked the factor; the trail shows each one.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    AnsweredCode, LockoutPolicy, MfaEnrollment,
};
use ianua_domain::domains::authentication::mfa::verifier::MfaVerifier;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, UserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{
    MfaEnrollmentStore, SecretEncryptor, SentCodeGenerator, SentCodeStore,
};
use crate::services::authentication::account_factor::{FactorChecks, SentCodes, ensure_unused};
use crate::services::authentication::sign_in_steps::{CodeCheck, SentCodeCheck};
use crate::tenancy::ScopedTenant;

/// Where a person's second factor is kept, and what checks its codes. The
/// use cases that take a code from the authenticator share it.
#[derive(Clone, ianua_macros::Fakes)]
pub struct FactorCodePorts {
    /// Where the enrollment is kept.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
    /// Opens the factor's stored secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Checks a code against the secret.
    pub verifier: Arc<dyn MfaVerifier>,
    /// The codes sent for mailed and texted factors.
    pub sent_codes: Arc<dyn SentCodeStore>,
    /// Hashes a typed code the way a sent one was hashed.
    pub sent_code_generator: Arc<dyn SentCodeGenerator>,
}

impl FactorCodePorts {
    /// The check of a code against the factor, locking it under `lockout`
    /// and recording wrong codes through `auditor`.
    pub(in crate::use_cases::authentication::mfa) fn checked<'a>(
        &'a self,
        lockout: LockoutPolicy,
        auditor: &'a RequestAuditor,
    ) -> CheckedCode<'a> {
        CheckedCode {
            enrollments: self.enrollment_store.as_ref(),
            checks: FactorChecks {
                app: CodeCheck {
                    encryptor: self.encryptor.as_ref(),
                    verifier: self.verifier.as_ref(),
                    lockout,
                },
                sent: SentCodes {
                    store: self.sent_codes.as_ref(),
                    check: SentCodeCheck {
                        generator: self.sent_code_generator.as_ref(),
                        lockout,
                    },
                },
            },
            log: FailedFactorLog { auditor },
        }
    }
}

/// Where a wrong second-factor answer is recorded.
pub(in crate::use_cases::authentication::mfa) struct FailedFactorLog<'a> {
    /// Records the failure in the audit trail.
    pub(in crate::use_cases::authentication::mfa) auditor: &'a RequestAuditor,
}

impl FailedFactorLog<'_> {
    /// Records the wrong answer `enrollment` raised, by its owner, once the
    /// enrollment that counted it is saved.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the failure cannot be recorded.
    pub(in crate::use_cases::authentication::mfa) async fn record(
        &self,
        tenant: &ScopedTenant,
        enrollment: &mut MfaEnrollment<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let owner = ActorRef::User(owner_of(enrollment));
        self.auditor
            .dispatch_by(&owner, enrollment.take_events(tenant))
            .await
            .or_internal()
    }
}

/// A code from the factor, from its app or sent for it, checked against
/// the person's factor so it works once.
pub(in crate::use_cases::authentication::mfa) struct CheckedCode<'a> {
    /// Where the enrollment is kept.
    pub(in crate::use_cases::authentication::mfa) enrollments: &'a dyn MfaEnrollmentStore,
    /// Checks the code against the factor, whatever its kind.
    pub(in crate::use_cases::authentication::mfa) checks: FactorChecks<'a>,
    /// Records a wrong code.
    pub(in crate::use_cases::authentication::mfa) log: FailedFactorLog<'a>,
}

impl CheckedCode<'_> {
    /// `enrollment`'s answer to `code`, saved whatever it is. An app's code
    /// has its time step claimed; a sent code was spent when checked. A
    /// wrong code is counted and recorded before the refusal.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the code is wrong or was used before.
    /// - `AppError::AccountLocked` after too many wrong codes.
    /// - `AppError::Internal` when the enrollment cannot be saved or the
    ///   code cannot be checked.
    pub(in crate::use_cases::authentication::mfa) async fn answered(
        &self,
        tenant: &ScopedTenant,
        enrollment: &mut MfaEnrollment<ResolvedTenant>,
        code: &str,
    ) -> Result<AnsweredCode, AppError> {
        let failed_before = enrollment.last_failed_at();
        let answered = self.checks.answer(tenant, enrollment, code).await;
        self.enrollments
            .save(tenant, enrollment)
            .await
            .or_internal()?;
        if enrollment.last_failed_at() != failed_before {
            self.log.record(tenant, enrollment).await?;
        }
        let answered = answered?;
        ensure_unused(self.enrollments, tenant, &owner_of(enrollment), &answered).await?;
        Ok(answered)
    }
}

/// The tenant user `enrollment` belongs to.
pub(in crate::use_cases::authentication::mfa) fn owner_of(
    enrollment: &MfaEnrollment<ResolvedTenant>,
) -> UserId {
    UserId::from_uuid(*enrollment.subject_id().as_uuid())
}
