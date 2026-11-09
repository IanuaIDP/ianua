//! An account's second factor as its row holds it: read back into the
//! enrollment, and written out from it.
//!
//! The words of a factor's kind and status are the ones the organization's
//! factors are stored with, so both planes read the same words.

use ianua_domain::domains::authentication::mfa::enrollment::{
    EnrolledFactor, EnrollmentState, MfaEnrollment, MfaEnrollmentRow, MfaMethod, RecentFailures,
};
use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalId, SealedSecret, TokenHash, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const MFA_ENROLLMENT: Stored = Stored("MFA enrollment");

/// A second factor as it is read. The store's checked queries fill it.
pub(super) struct EnrollmentRecord {
    pub(super) user_id: Uuid,
    pub(super) method: String,
    pub(super) sealed_secret: Option<String>,
    pub(super) phone_number: Option<String>,
    pub(super) status: String,
    pub(super) verified_at: Option<OffsetDateTime>,
    pub(super) recovery_codes_hash: Option<String>,
    pub(super) disabled_at: Option<OffsetDateTime>,
    pub(super) failed_attempts: i64,
    pub(super) last_failed_at: Option<OffsetDateTime>,
    pub(super) enrolled_at: OffsetDateTime,
}

impl EnrollmentRecord {
    /// The enrollment the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a word is unknown, a value
    /// no longer passes its rules, or the row breaks a rule the enrollment
    /// keeps.
    pub(super) fn into_enrollment(self) -> Result<MfaEnrollment<ResolvedTenant>, DomainError> {
        let method: MfaMethod = MFA_ENROLLMENT.choice(&self.method)?;
        let factor = factor_from(method, self.sealed_secret, self.phone_number)?;
        let failed_attempts = u32::try_from(self.failed_attempts).map_err(DomainError::infra)?;
        MfaEnrollment::reconstitute(MfaEnrollmentRow {
            subject_id: PrincipalId::from(UserId::from_uuid(self.user_id)),
            factor,
            state: EnrollmentState::from_stored(
                MFA_ENROLLMENT.choice(&self.status)?,
                self.verified_at,
                self.recovery_codes_hash.map(TokenHash::from_stored),
                self.disabled_at,
            )?,
            failures: RecentFailures::from_stored(failed_attempts, self.last_failed_at)?,
            enrolled_at: self.enrolled_at,
        })
    }
}

/// The factor `method` names, with the one value its kind holds.
fn factor_from(
    method: MfaMethod,
    sealed_secret: Option<String>,
    phone_number: Option<String>,
) -> Result<EnrolledFactor, DomainError> {
    match (method, sealed_secret, phone_number) {
        (MfaMethod::Totp, Some(sealed), None) => MFA_ENROLLMENT
            .value("sealed secret", SealedSecret::new(sealed))
            .map(EnrolledFactor::Totp),
        (MfaMethod::EmailCode, None, None) => Ok(EnrolledFactor::EmailCode),
        (MfaMethod::SmsCode, None, Some(number)) => MFA_ENROLLMENT
            .value("phone number", PhoneNumber::new(number))
            .map(EnrolledFactor::SmsCode),
        (MfaMethod::Totp | MfaMethod::EmailCode | MfaMethod::SmsCode, _, _) => {
            Err(DomainError::corrupt_row(
                MFA_ENROLLMENT.0,
                "a seed or a number its kind of factor does not hold",
            ))
        }
    }
}

/// A second factor's columns, as they are written.
pub(super) struct EnrollmentColumns<'a> {
    pub(super) user_id: Uuid,
    pub(super) method: &'static str,
    pub(super) sealed_secret: Option<&'a str>,
    pub(super) phone_number: Option<&'a str>,
    pub(super) status: &'static str,
    pub(super) verified_at: Option<OffsetDateTime>,
    pub(super) recovery_codes_hash: Option<&'a str>,
    pub(super) disabled_at: Option<OffsetDateTime>,
    pub(super) failed_attempts: i64,
    pub(super) last_failed_at: Option<OffsetDateTime>,
    pub(super) enrolled_at: OffsetDateTime,
}

impl<'a> EnrollmentColumns<'a> {
    /// The columns `enrollment` is written to, as its subject's.
    pub(super) fn of(enrollment: &'a MfaEnrollment<ResolvedTenant>) -> Self {
        let state = enrollment.state();
        let failures = enrollment.failures();
        Self {
            user_id: *enrollment.subject_id().as_uuid(),
            method: enrollment.method().word(),
            sealed_secret: enrollment
                .factor()
                .sealed_secret()
                .map(SealedSecret::as_str),
            phone_number: enrollment.factor().phone_number().map(PhoneNumber::as_str),
            status: enrollment.status().word(),
            verified_at: state.verified_at(),
            recovery_codes_hash: state.recovery_codes_hash().map(TokenHash::as_str),
            disabled_at: state.disabled_at(),
            failed_attempts: i64::from(failures.count()),
            last_failed_at: failures.last_at(),
            enrolled_at: enrollment.enrolled_at(),
        }
    }
}
