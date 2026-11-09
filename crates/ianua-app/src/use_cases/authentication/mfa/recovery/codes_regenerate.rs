//! A person signed in replaces their recovery codes with a fresh set, after
//! proving who they are again. Every earlier code stops working at once.

use std::sync::Arc;

use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, TokenHash};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{MfaEnrollmentStore, RecoveryCodeGenerator, RecoveryCodeStore};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::lookup::{
    existing_active_enrollment, existing_recovery_codes,
};

/// How many recovery codes a fresh set holds.
const RECOVERY_CODES: u8 = 10;

/// The ports [`RegenerateRecoveryCodesUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RegenerateRecoveryCodesPorts {
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the person typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// The factor the codes stand in for.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
    /// Keeps the codes.
    pub recovery_store: Arc<dyn RecoveryCodeStore>,
    /// Makes the codes.
    pub recovery_generator: Arc<dyn RecoveryCodeGenerator>,
}

/// The fresh recovery codes, shown once and never kept. They are secrets,
/// so this has no `Debug`.
pub struct RegeneratedRecoveryCodes {
    /// Raw fallback secrets replacing the previous set.
    pub recovery_codes: Vec<Secret>,
}

/// Replaces the signed-in person's recovery codes.
pub struct RegenerateRecoveryCodesUseCase {
    ports: RegenerateRecoveryCodesPorts,
}

impl RegenerateRecoveryCodesUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RegenerateRecoveryCodesPorts) -> Self {
        Self { ports }
    }

    /// A fresh batch of codes, as shown once and as kept.
    async fn fresh_batch(&self) -> Result<(Vec<Secret>, Vec<TokenHash>), AppError> {
        let pairs = self
            .ports
            .recovery_generator
            .generate_batch(RECOVERY_CODES)
            .await
            .or_internal()?;
        Ok(pairs.into_iter().map(|pair| (pair.raw, pair.hash)).unzip())
    }
}

impl Command for RegenerateRecoveryCodesUseCase {
    type Caller = CallerContext;
    type Input = ReenteredProof;
    type Output = Result<RegeneratedRecoveryCodes, AppError>;

    /// Replaces the recovery codes of the person signed in to `caller`'s
    /// session with a fresh set, once `proof` shows it is them, and records
    /// `authentication.recovery_codes_generated`.
    ///
    /// A recovery code gets past the second factor. Mallory steals Ann's
    /// session; without the fresh proof she makes a set of her own and
    /// signs in past Ann's factor from then on.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Forbidden` when the proof does not show it is them.
    /// - `AppError::StepUpRequired` when they gave no code from their factor.
    /// - `AppError::NotFound` when they have no factor in force, or no
    ///   recovery codes.
    /// - `AppError::Internal` on generation, storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        proof: ReenteredProof,
    ) -> Result<RegeneratedRecoveryCodes, AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let tenant = caller.tenant();
        let fresh = self
            .ports
            .fresh_proofs
            .prove(&tenant, &person.account, proof, caller.origin())
            .await?;
        let store = self.ports.enrollment_store.as_ref();
        let factor = existing_active_enrollment(store, &tenant, person.account.id()).await?;
        let recovery = self.ports.recovery_store.as_ref();
        let mut codes = existing_recovery_codes(recovery, &tenant, person.account.id()).await?;
        let (raw, hashes) = self.fresh_batch().await?;
        codes
            .regenerate(hashes, &factor, &fresh)
            .map_err(AppError::from_domain)?;

        recovery.save(&tenant, &codes).await.or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::User(*person.account.id()),
                codes.take_events(&tenant),
            )
            .await
            .or_internal()?;
        Ok(RegeneratedRecoveryCodes {
            recovery_codes: raw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeRecoveryCodeStore, right_password, test_caller_id,
        wrong_password,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        recovery: Arc<FakeRecoveryCodeStore>,
        audit: Arc<FakeEventDispatcher>,
        ports: RegenerateRecoveryCodesPorts,
    }

    impl Fixture {
        fn new() -> Self {
            let recovery = Arc::new(FakeRecoveryCodeStore::with_codes(
                test_caller_id(),
                &["old_1", "old_2"],
            ));
            Self {
                ports: RegenerateRecoveryCodesPorts {
                    enrollment_store: Arc::new(
                        FakeMfaEnrollmentStore::active_for(test_caller_id()),
                    ),
                    recovery_store: recovery.clone(),
                    ..RegenerateRecoveryCodesPorts::fakes()
                },
                recovery,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn regenerate(
            self,
            proof: ReenteredProof,
        ) -> (Result<RegeneratedRecoveryCodes, AppError>, Self) {
            let use_case = RegenerateRecoveryCodesUseCase::new(self.ports);
            let result =
                block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), proof));
            let fixture = Self {
                ports: use_case.ports,
                ..self
            };
            (result, fixture)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann used most of her codes. She types her password again and gets
    /// ten new ones; her old ones are gone, and the new set is recorded.
    #[test]
    fn a_proved_person_gets_a_fresh_set() {
        let (result, fixture) = Fixture::new().regenerate(right_password());

        let fresh = result.unwrap();

        assert_eq!(fresh.recovery_codes.len(), usize::from(RECOVERY_CODES));
        assert_eq!(
            fixture.recovery.remaining(),
            Some(usize::from(RECOVERY_CODES))
        );
        assert_eq!(
            fixture.recorded(),
            ["authentication.recovery_codes_generated"]
        );
    }

    /// A wrong password cannot replace Ann's recovery codes; both existing
    /// codes remain and no event is recorded.
    #[test]
    fn a_wrong_password_is_refused() {
        let (result, fixture) = Fixture::new().regenerate(wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.recovery.remaining(), Some(2));
        assert!(fixture.recorded().is_empty());
    }

    /// Ann's factor was turned off. Codes stand in for no factor, so none
    /// are made.
    #[test]
    fn without_a_factor_in_force_nothing_is_made() {
        let mut fixture = Fixture::new();
        fixture.ports.enrollment_store = Arc::new(FakeMfaEnrollmentStore::empty());

        let (result, fixture) = fixture.regenerate(right_password());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.recovery.remaining(), Some(2));
    }

    /// A signed-out caller cannot regenerate recovery codes.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::new();
        fixture.ports.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = fixture.regenerate(right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
