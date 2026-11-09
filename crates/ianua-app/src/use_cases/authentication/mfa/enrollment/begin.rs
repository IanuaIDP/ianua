//! Starting to set up an authenticator app: a new secret, shown once as the
//! QR the app scans, kept as a pending enrollment until a code confirms it.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    EnrolledFactor, MfaEnrollment, MfaMethod,
};
use ianua_domain::domains::authentication::mfa::offer::FactorOffer;
use ianua_domain::domains::authentication::mfa::verifier::{MfaVerifier, TotpSeed};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Label, OtpauthUrl, PrincipalId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{MfaEnrollmentStore, SecretEncryptor};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::refused::already_enrolled;
use crate::services::authentication::sign_in_steps::SeedHolder;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::mfa::enrollment::setup_proof::{
    FactorSetter, NewFactor, SetterPorts, SetupLeave, SetupProof, abandon_enrollment,
    begun_enrollment, offered,
};

/// What a person scans to set up their authenticator app.
pub struct EnrollmentQr {
    /// The `otpauth://` URI for the QR code. It carries the secret.
    pub otpauth_uri: OtpauthUrl,
}

/// The ports [`BeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BeginPorts {
    /// Where enrollments are kept.
    pub enrollment_store: Arc<dyn MfaEnrollmentStore>,
    /// Seals and opens the secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Makes the secret and the QR's URI.
    pub verifier: Arc<dyn MfaVerifier>,
    /// The tenant, for whether it allows second factors at all.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Who sets the factor up, and what lets them.
    pub setter: SetterPorts,
}

/// Starts setting up an authenticator app.
pub struct BeginUseCase {
    issuer: Label,
    ports: BeginPorts,
}

impl BeginUseCase {
    /// A use case working through `ports`, listing accounts in the
    /// authenticator under `issuer`.
    #[must_use]
    pub fn new(issuer: Label, ports: BeginPorts) -> Self {
        Self { issuer, ports }
    }

    /// The enrollment `account` already has, in force or waiting to be
    /// confirmed, if any.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage failure.
    async fn existing_enrollment(
        &self,
        tenant: &ScopedTenant,
        account: &User<ResolvedTenant>,
    ) -> Result<Option<MfaEnrollment<ResolvedTenant>>, AppError> {
        self.ports
            .enrollment_store
            .find_by_user(tenant, account.id())
            .await
            .or_internal()
    }

    /// Gives up `enrollment`, a setup waiting to be confirmed, on `leave`,
    /// so a new secret replaces it.
    async fn give_up(
        &self,
        tenant: &ScopedTenant,
        mut enrollment: MfaEnrollment<ResolvedTenant>,
        leave: &SetupLeave,
    ) -> Result<(), AppError> {
        abandon_enrollment(&mut enrollment, leave)?;
        self.ports
            .enrollment_store
            .save(tenant, &enrollment)
            .await
            .or_internal()
    }

    /// A new secret, kept as a pending enrollment begun on `setup`'s leave
    /// under its offer, whose start is recorded through `auditor` by the
    /// account's holder.
    async fn fresh(
        &self,
        auditor: &RequestAuditor,
        setup: &AppSetup<'_>,
    ) -> Result<EnrollmentQr, AppError> {
        let seed = self.ports.verifier.generate_secret().or_internal()?;
        let place =
            SeedHolder::TenantUser(**setup.tenant).place(PrincipalId::from(*setup.account.id()));
        let sealed = self
            .ports
            .encryptor
            .encrypt(seed.expose(), &place)
            .await
            .or_internal()?;
        let new = NewFactor {
            factor: EnrolledFactor::Totp(sealed),
            offer: setup.offer,
        };
        let mut enrollment =
            begun_enrollment(PrincipalId::from(*setup.account.id()), new, setup.leave)?;
        self.ports
            .enrollment_store
            .save(setup.tenant, &enrollment)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::User(*setup.account.id()),
                enrollment.take_events(setup.tenant),
            )
            .await
            .or_internal()?;
        self.started(&seed, setup.account)
    }

    /// The `otpauth://` URI an authenticator scans for `seed`, listing the
    /// account under the issuer and its address.
    fn started(
        &self,
        seed: &TotpSeed,
        account: &User<ResolvedTenant>,
    ) -> Result<EnrollmentQr, AppError> {
        let raw = self.ports.verifier.build_otpauth_uri(
            seed,
            self.issuer.as_str(),
            account.email().as_str(),
        );
        let otpauth_uri = OtpauthUrl::new(raw.expose()).or_internal()?;
        Ok(EnrollmentQr { otpauth_uri })
    }
}

impl Command for BeginUseCase {
    type Caller = FactorSetter;
    type Input = SetupProof;
    type Output = Result<EnrollmentQr, AppError>;

    /// Starts setting up `setter`'s authenticator app on `proof`, and
    /// records `authentication.mfa_enrollment_started`.
    ///
    /// An enrollment already waiting to be confirmed is given up and a new
    /// secret replaces it, so a setup's secret is only ever shown once.
    /// A waiting sign-in that spent a recovery code may replace the lost
    /// active factor while its enrollment proof remains fresh.
    /// Ann starts setting up her authenticator and scans the QR. Mallory,
    /// holding Ann's password, signs in and is asked to set one up too.
    /// Without this, she is handed Ann's secret and reads Ann's codes from
    /// then on. Starting again records the new start, and the person
    /// scans the new QR.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid setter session; `Forbidden` for disabled factors or inadequate setup proof.
    /// - `AppError::StepUpRequired` when a held factor's code is needed.
    /// - `AppError::NotFound` for a missing tenant, account or waiting session.
    /// - `AppError::Conflict` for an active authenticator; `Internal` on generation, sealing or storage failure.
    async fn execute(
        &self,
        setter: &FactorSetter,
        auditor: &RequestAuditor,
        proof: SetupProof,
    ) -> Result<EnrollmentQr, AppError> {
        let (tenant, account) = self.ports.setter.accounts().account(setter).await?;
        let workspace = existing_tenant(self.ports.tenant_store.as_ref(), &tenant).await?;
        let offer = offered(&workspace, MfaMethod::Totp)?;
        let leave = self
            .ports
            .setter
            .leaves()
            .leave(setter, &account, proof)
            .await?;
        let held = self.existing_enrollment(&tenant, &account).await?;
        let setup = AppSetup {
            tenant: &tenant,
            account: &account,
            leave: &leave,
            offer: &offer,
        };
        match held {
            Some(enrollment)
                if enrollment.is_active() && !matches!(leave, SetupLeave::Recovery(_)) =>
            {
                Err(already_enrolled())
            }
            Some(enrollment) if enrollment.is_pending() => {
                self.give_up(&tenant, enrollment, &leave).await?;
                self.fresh(auditor, &setup).await
            }
            _ => self.fresh(auditor, &setup).await,
        }
    }
}

/// An authenticator app about to be set up: where, for whom, on what leave
/// and under which offer.
struct AppSetup<'a> {
    /// The tenant the account is in.
    tenant: &'a ScopedTenant,
    /// The account setting it up.
    account: &'a User<ResolvedTenant>,
    /// What lets them set it up now.
    leave: &'a SetupLeave,
    /// The tenant's offer of an authenticator app.
    offer: &'a FactorOffer,
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::{AuthMethod, MfaPolicy};
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::types::{SessionId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeMfaEnrollmentStore, FakeSessionStore, right_password, session_signed_in,
        test_caller_id, wrong_password,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::mfa::sessions::sign_in_parties::PendingSignIn;

    fn mfa(policy: MfaPolicy) -> Arc<dyn TenantStore> {
        tenant_store_signing_in_with(TenantAuthSettings {
            mfa_policy: policy,
            ..TenantAuthSettings::default()
        })
    }

    fn owing_setup() -> SignInProgressRow {
        SignInProgressRow {
            method: AuthMethod::Password,
            factor: FactorProved::NoneYet,
            owed: SecondFactor::Enrol,
        }
    }

    struct Fixture {
        enrollments: Arc<FakeMfaEnrollmentStore>,
        ports: BeginPorts,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn over(enrollments: FakeMfaEnrollmentStore) -> Self {
            let enrollments = Arc::new(enrollments);
            Self {
                ports: BeginPorts {
                    enrollment_store: enrollments.clone(),
                    tenant_store: mfa(MfaPolicy::Optional),
                    ..BeginPorts::fakes()
                },
                enrollments,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn begin_as(
            self,
            setter: &FactorSetter,
            proof: SetupProof,
        ) -> (Result<EnrollmentQr, AppError>, Self) {
            let use_case = BeginUseCase::new(Label::new("issuer", "Acme").unwrap(), self.ports);
            let result =
                block_on(use_case.execute(setter, &test_auditor(self.audit.clone()), proof));
            let fixture = Self {
                ports: use_case.ports,
                ..self
            };
            (result, fixture)
        }

        fn begin(self, proof: SetupProof) -> (Result<EnrollmentQr, AppError>, Self) {
            self.begin_as(&FactorSetter::SignedIn(Box::new(test_ctx())), proof)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn reentered() -> SetupProof {
        SetupProof::Reentered(right_password())
    }

    /// Ann, who typed her password again, starts setting up her
    /// authenticator. She gets the QR for her account, a pending enrollment
    /// is kept, and the start is recorded.
    #[test]
    fn a_proved_person_starts_a_pending_enrollment() {
        let (result, fixture) = Fixture::over(FakeMfaEnrollmentStore::empty()).begin(reentered());

        let started = result.unwrap();

        assert!(
            started
                .otpauth_uri
                .as_str()
                .starts_with("otpauth://totp/Acme:")
        );
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .unwrap()
                .is_pending()
        );
        assert_eq!(
            fixture.recorded(),
            ["authentication.mfa_enrollment_started"]
        );
    }

    /// Restarting pending enrollment replaces its secret, keeps the setup
    /// pending and records a fresh enrollment start.
    #[test]
    fn a_pending_enrollment_is_replaced_by_a_new_secret() {
        let store = FakeMfaEnrollmentStore::pending_for(test_caller_id());
        let before = store.enrollment_of(test_caller_id()).unwrap();

        let (result, fixture) = Fixture::over(store).begin(reentered());

        result.unwrap();
        let after = fixture.enrollments.enrollment_of(test_caller_id()).unwrap();
        assert!(after.is_pending());
        assert_ne!(after.factor(), before.factor());
        assert_eq!(
            fixture.recorded(),
            ["authentication.mfa_enrollment_started"]
        );
    }

    /// Ann already has an authenticator in force. Starting another is a
    /// conflict.
    #[test]
    fn an_active_authenticator_is_a_conflict() {
        let (result, _) =
            Fixture::over(FakeMfaEnrollmentStore::active_for(test_caller_id())).begin(reentered());

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// A recovered waiting sign-in still owes enrollment under a stronger
    /// baseline. Its fresh leave replaces the lost active factor with a
    /// pending secret, without granting account access.
    #[test]
    fn a_recovered_sign_in_can_replace_its_lost_active_authenticator() {
        let ann = test_caller_id();
        let session = session_signed_in(
            ann,
            SignInProgressRow {
                factor: FactorProved::Proved(MfaFactor::RecoveryCode),
                ..owing_setup()
            },
        );
        let pending = PendingSignIn {
            tenant: test_ctx().tenant(),
            session_id: *session.id(),
            user_id: ann,
        };
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::active_for(ann));
        fixture.ports.setter.session_store = Arc::new(FakeSessionStore::with_session(session));
        fixture.ports.setter.user_store = Arc::new(FakeUserStore::with_user(ann, "ann@acme.test"));
        let (result, fixture) =
            fixture.begin_as(&FactorSetter::SigningIn(pending), SetupProof::OwedBySignIn);
        result.unwrap();
        assert!(fixture.enrollments.enrollment_of(ann).unwrap().is_pending());
        assert_eq!(
            fixture.recorded(),
            ["authentication.mfa_enrollment_started"]
        );
    }

    /// A wrong password cannot start enrollment or save an authenticator.
    #[test]
    fn a_wrong_password_is_refused() {
        let (result, fixture) = Fixture::over(FakeMfaEnrollmentStore::empty())
            .begin(SetupProof::Reentered(wrong_password()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .is_none()
        );
    }

    /// A signed-out caller cannot begin authenticator enrollment.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::empty());
        fixture.ports.setter.tenant_authorities =
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = fixture.begin(reentered());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ann's workspace has second factors switched off. Nobody can set one
    /// up there.
    #[test]
    fn nobody_sets_up_a_factor_while_the_tenant_has_them_off() {
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::empty());
        fixture.ports.tenant_store = mfa(MfaPolicy::Disabled);

        let (result, fixture) = fixture.begin(reentered());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(
            fixture
                .enrollments
                .enrollment_of(test_caller_id())
                .is_none()
        );
    }

    /// Ann signs in to a workspace that requires a factor she does not have
    /// yet. Her waiting sign-in lets her set one up without typing her
    /// password again.
    #[test]
    fn a_sign_in_owing_a_factor_sets_one_up() {
        let ann = UserId::new();
        let session = session_signed_in(ann, owing_setup());
        let pending = PendingSignIn {
            tenant: test_ctx().tenant(),
            session_id: *session.id(),
            user_id: ann,
        };
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::empty());
        fixture.ports.setter.session_store = Arc::new(FakeSessionStore::with_session(session));
        fixture.ports.setter.user_store = Arc::new(FakeUserStore::with_user(ann, "ann@acme.test"));

        let (result, fixture) =
            fixture.begin_as(&FactorSetter::SigningIn(pending), SetupProof::OwedBySignIn);

        result.unwrap();
        assert!(fixture.enrollments.enrollment_of(ann).unwrap().is_pending());
    }

    /// A sign-in awaiting an existing factor's code cannot begin a new enrollment.
    #[test]
    fn a_sign_in_owing_a_code_cannot_set_one_up() {
        let ann = UserId::new();
        let session = session_signed_in(
            ann,
            SignInProgressRow {
                owed: SecondFactor::Verify,
                ..owing_setup()
            },
        );
        let pending = PendingSignIn {
            tenant: test_ctx().tenant(),
            session_id: *session.id(),
            user_id: ann,
        };
        let mut fixture = Fixture::over(FakeMfaEnrollmentStore::empty());
        fixture.ports.setter.session_store = Arc::new(FakeSessionStore::with_session(session));
        fixture.ports.setter.user_store = Arc::new(FakeUserStore::with_user(ann, "ann@acme.test"));

        let (result, _) =
            fixture.begin_as(&FactorSetter::SigningIn(pending), SetupProof::OwedBySignIn);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A waiting sign-in that names an account nobody has is not found.
    #[test]
    fn a_sign_in_for_an_unknown_account_is_not_found() {
        let pending = PendingSignIn {
            tenant: test_ctx().tenant(),
            session_id: SessionId::new(),
            user_id: UserId::new(),
        };

        let (result, _) = Fixture::over(FakeMfaEnrollmentStore::empty())
            .begin_as(&FactorSetter::SigningIn(pending), SetupProof::OwedBySignIn);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
