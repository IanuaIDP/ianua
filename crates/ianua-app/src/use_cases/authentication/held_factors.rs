//! Whether a person has a second factor set up, counted across every kind
//! they may hold: an authenticator app, mailed or texted codes, and passkeys.
//!
//! A sign-in that counted only the authenticator app would let someone who
//! holds just a passkey skip the proof their passkey could give.

use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::mfa::owed::{CodeFactorHolding, Enrolment, HeldFactors};
use ianua_domain::types::UserId;

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{MfaEnrollmentStore, PasskeyStore};
use crate::tenancy::ScopedTenant;

/// Where a person's second factors are kept.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication) struct FactorSources<'a> {
    /// Second-factor enrollments of every kind.
    pub(in crate::use_cases::authentication) enrollments: &'a dyn MfaEnrollmentStore,
    /// Loads registered credentials when checking available second factors.
    pub(in crate::use_cases::authentication) passkeys: &'a dyn PasskeyStore,
}

impl FactorSources<'_> {
    /// Whether `user_id` holds any second factor they can use.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when a store cannot be read.
    pub(in crate::use_cases::authentication) async fn enrolment_of(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Enrolment, AppError> {
        let code_factor = self
            .enrollments
            .find_by_user(tenant, user_id)
            .await
            .or_internal()?
            .filter(MfaEnrollment::is_active)
            .map_or(CodeFactorHolding::None, |_| CodeFactorHolding::Active);
        let passkeys = self
            .passkeys
            .list_by_user(tenant, user_id)
            .await
            .or_internal()?
            .len();
        Ok(HeldFactors::new(code_factor, passkeys).enrolment())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authentication::{FakeMfaEnrollmentStore, FakePasskeyStore};
    use crate::test_support::{block_on, test_ctx};

    fn enrolment(
        enrollments: &FakeMfaEnrollmentStore,
        passkeys: &FakePasskeyStore,
        ann: UserId,
    ) -> Enrolment {
        let sources = FactorSources {
            enrollments,
            passkeys,
        };
        block_on(sources.enrolment_of(&test_ctx().tenant(), &ann)).unwrap()
    }

    /// Ann set up her authenticator app. She is enrolled.
    #[test]
    fn an_authenticator_app_counts() {
        let ann = UserId::new();

        let held = enrolment(
            &FakeMfaEnrollmentStore::active_for(ann),
            &FakePasskeyStore::empty(),
            ann,
        );

        assert_eq!(held, Enrolment::Enrolled);
    }

    /// Ann holds only a passkey. She is enrolled too, so a sign-in asks her
    /// for it rather than skipping the second factor.
    #[test]
    fn a_passkey_alone_counts() {
        let ann = UserId::new();

        let held = enrolment(
            &FakeMfaEnrollmentStore::empty(),
            &FakePasskeyStore::with_passkey(ann),
            ann,
        );

        assert_eq!(held, Enrolment::Enrolled);
    }

    /// Ann started setting up her authenticator app and never confirmed it,
    /// and has no passkey. She is not enrolled.
    #[test]
    fn an_unconfirmed_app_does_not_count() {
        let ann = UserId::new();

        let held = enrolment(
            &FakeMfaEnrollmentStore::pending_for(ann),
            &FakePasskeyStore::empty(),
            ann,
        );

        assert_eq!(held, Enrolment::NotEnrolled);
    }
}
