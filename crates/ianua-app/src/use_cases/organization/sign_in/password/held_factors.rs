//! Whether a member has a second factor set up, counted across every kind
//! they may hold: an authenticator app and passkeys.
//!
//! A sign-in that counted only the authenticator app would let a member who
//! holds just a passkey skip the proof their passkey could give.

use ianua_domain::domains::authentication::mfa::enrollment::MfaEnrollment;
use ianua_domain::domains::authentication::mfa::owed::{CodeFactorHolding, Enrolment, HeldFactors};
use ianua_domain::types::OrgUserId;

use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgMfaEnrollmentStore, OrgPasskeyStore};

/// Where members' second factors are kept.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization) struct MemberFactorSources<'a> {
    /// Authenticator app enrollments.
    pub(in crate::use_cases::organization) enrollments: &'a dyn OrgMfaEnrollmentStore,
    /// Loads registered credentials when checking the member's available factors.
    pub(in crate::use_cases::organization) passkeys: &'a dyn OrgPasskeyStore,
}

impl MemberFactorSources<'_> {
    /// Whether `member` holds any second factor they can use.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when a store cannot be read.
    pub(in crate::use_cases::organization) async fn held_by(
        &self,
        member: &OrgUserId,
    ) -> Result<Enrolment, AppError> {
        let totp = self
            .enrollments
            .find_by_user(member)
            .await
            .or_internal()?
            .filter(MfaEnrollment::is_active)
            .map_or(CodeFactorHolding::None, |_| CodeFactorHolding::Active);
        let passkeys = self
            .passkeys
            .list_by_user(member)
            .await
            .or_internal()?
            .len();
        Ok(HeldFactors::new(totp, passkeys).enrolment())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::authentication::FakeMfaEnrollmentStore;
    use crate::test_support::block_on;
    use crate::test_support::organization::FakeOrgPasskeyStore;

    fn held(
        enrollments: &FakeMfaEnrollmentStore,
        passkeys: &FakeOrgPasskeyStore,
        olivia: OrgUserId,
    ) -> Enrolment {
        let sources = MemberFactorSources {
            enrollments,
            passkeys,
        };
        block_on(sources.held_by(&olivia)).unwrap()
    }

    /// Olivia, a member, set up her authenticator app. She is enrolled.
    #[test]
    fn an_authenticator_app_counts() {
        let olivia = OrgUserId::new();

        let enrolment = held(
            &FakeMfaEnrollmentStore::active_for(olivia),
            &FakeOrgPasskeyStore::empty(),
            olivia,
        );

        assert_eq!(enrolment, Enrolment::Enrolled);
    }

    /// Olivia holds only a passkey. She is enrolled too, so a sign-in asks
    /// her for it rather than skipping the second factor.
    #[test]
    fn a_passkey_alone_counts() {
        let olivia = OrgUserId::new();

        let enrolment = held(
            &FakeMfaEnrollmentStore::empty(),
            &FakeOrgPasskeyStore::with_passkey(OrganizationId::new(), olivia),
            olivia,
        );

        assert_eq!(enrolment, Enrolment::Enrolled);
    }

    /// Olivia started setting up her authenticator app and never confirmed
    /// it, and has no passkey. She is not enrolled.
    #[test]
    fn an_unconfirmed_app_does_not_count() {
        let olivia = OrgUserId::new();

        let enrolment = held(
            &FakeMfaEnrollmentStore::pending_for(olivia),
            &FakeOrgPasskeyStore::empty(),
            olivia,
        );

        assert_eq!(enrolment, Enrolment::NotEnrolled);
    }
}
