//! Giving up an authenticator setup that was never confirmed, so the person
//! can start again with a new secret.
//!
//! Giving up is the first step of starting again, so it asks for the same
//! proof. Otherwise Mallory, holding Ann's session, gives up each setup Ann
//! starts, and Ann never gets a second factor.

use std::sync::Arc;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::MfaEnrollmentStore;
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::services::authentication::fresh_proof::FreshProofs;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::enrollment::setup_proof::{
    FactorSetter, SetterAccounts, SetupLeaves, SetupProof, abandon_enrollment,
};
use crate::use_cases::authentication::mfa::lookup::existing_pending_enrollment;

/// The ports [`AbandonUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AbandonPorts {
    /// Where enrollments are kept.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
    /// The account of a sign-in waiting for its factor.
    pub user_store: Arc<dyn UserStore>,
    /// The session of a sign-in waiting for its factor.
    pub session_store: Arc<dyn SessionStore>,
    /// Who is signed in to a caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what a signed-in person typed again into a fresh proof.
    pub fresh_proofs: Arc<dyn FreshProofs>,
}

/// Gives up a pending authenticator setup.
pub struct AbandonUseCase {
    ports: AbandonPorts,
}

impl AbandonUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AbandonPorts) -> Self {
        Self { ports }
    }
}

impl Command for AbandonUseCase {
    type Caller = FactorSetter;
    type Input = SetupProof;
    type Output = Result<(), AppError>;

    /// Gives up `setter`'s pending authenticator setup on `proof`. Nothing
    /// is recorded: the setup never protected anything.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when a signed-in setter's session no
    ///   longer counts.
    /// - `AppError::Forbidden` when the proof does not let the setter set up
    ///   a factor now.
    /// - `AppError::StepUpRequired` when the person must give a code from a
    ///   factor they hold.
    /// - `AppError::NotFound` when no setup is pending, or the account or a
    ///   waiting sign-in's session is gone.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        setter: &FactorSetter,
        _: &RequestAuditor,
        proof: SetupProof,
    ) -> Result<(), AppError> {
        let accounts = SetterAccounts {
            authorities: self.ports.tenant_authorities.as_ref(),
            users: self.ports.user_store.as_ref(),
        };
        let leaves = SetupLeaves {
            fresh_proofs: self.ports.fresh_proofs.as_ref(),
            sessions: self.ports.session_store.as_ref(),
        };
        let (tenant, account) = accounts.account(setter).await?;
        let leave = leaves.leave(setter, &account, proof).await?;
        let store = self.ports.enrollment_store.as_ref();
        let mut enrollment = existing_pending_enrollment(store, &tenant, account.id()).await?;
        abandon_enrollment(&mut enrollment, &leave)?;
        store.save(&tenant, &enrollment).await.or_internal()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, right_password, test_caller_id, wrong_password,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn abandon(
        store: &Arc<FakeMfaEnrollmentStore>,
        authorities: FakeTenantAuthorities,
        proof: SetupProof,
    ) -> Result<(), AppError> {
        let use_case = AbandonUseCase::new(AbandonPorts {
            enrollment_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
            ..AbandonPorts::fakes()
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(
            &FactorSetter::SignedIn(Box::new(test_ctx())),
            &auditor,
            proof,
        ))
    }

    fn pending() -> Arc<FakeMfaEnrollmentStore> {
        Arc::new(FakeMfaEnrollmentStore::pending_for(test_caller_id()))
    }

    /// Ann lost the QR she began to scan and types her password again to
    /// start over. Her pending setup is given up.
    #[test]
    fn a_proved_person_gives_up_a_pending_setup() {
        let store = pending();

        abandon(
            &store,
            FakeTenantAuthorities::holding(&[]),
            SetupProof::Reentered(right_password()),
        )
        .unwrap();

        assert!(!store.enrollment_of(test_caller_id()).unwrap().is_pending());
    }

    /// A wrong password cannot abandon Ann's authenticator setup, which remains pending.
    #[test]
    fn a_wrong_password_is_refused() {
        let store = pending();

        let result = abandon(
            &store,
            FakeTenantAuthorities::holding(&[]),
            SetupProof::Reentered(wrong_password()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(store.enrollment_of(test_caller_id()).unwrap().is_pending());
    }

    /// Ann's authenticator is in force, not pending. There is no setup to
    /// give up.
    #[test]
    fn nothing_pending_is_not_found() {
        let store = Arc::new(FakeMfaEnrollmentStore::active_for(test_caller_id()));

        let result = abandon(
            &store,
            FakeTenantAuthorities::holding(&[]),
            SetupProof::Reentered(right_password()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller cannot abandon a pending authenticator setup.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = abandon(
            &pending(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            SetupProof::Reentered(right_password()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
