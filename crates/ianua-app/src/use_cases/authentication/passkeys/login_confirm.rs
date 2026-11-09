//! Finishing a passkey sign-in: the browser's answer to the challenge is
//! checked against the ceremony kept on the server, and the passkey's owner
//! gets a session.
//!
//! A passkey is something its holder has and unlocks, so it signs them in
//! at AAL2 on its own. A key whose attestation showed hardware proves a
//! hardware key, AAL3. The session records which, so a sign-in with a
//! synced passkey never passes for one with a hardware key.

use std::sync::Arc;
use std::time::Instant;

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::account_check::MaySignIn;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::SpentPasskey;
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::authentication::sessions::session::{CreateSessionParams, Session};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInRefused;
use ianua_domain::domains::authentication::sessions::way_in::WayIn;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Fact, SessionId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{PasskeyCeremonyStore, PasskeyStore, PasskeyVerifier};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::passkey_answer::{PasskeyAnswering, PresentedAssertion};
use crate::services::authentication::sign_in_gate::{self, ClientOrigin};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::signed_in_event::record_login;
use crate::use_cases::authentication::timing::elapsed_millis;

/// What the browser sends back to finish a passkey sign-in.
pub struct LoginConfirmRequest {
    /// The passkey's answer to the challenge.
    pub assertion: PresentedAssertion,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// A passkey sign-in that went through. It holds the refresh token, so it
/// has no `Debug`.
pub struct LoginSuccess {
    /// The new session.
    pub session_id: SessionId,
    /// The raw refresh token, sent to the client and never stored.
    pub refresh_token: Secret,
    /// What the sign-in still owes in the way of a second factor.
    pub second_factor: SecondFactor,
    /// The tenant signed in to.
    pub tenant_id: TenantId,
    /// The tenant's display name.
    pub tenant_name: String,
    /// The passkey owner's display name.
    pub display_name: String,
}

/// The ports [`LoginConfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct LoginConfirmPorts {
    /// The tenant's passkeys, whose use is counted.
    pub passkey_store: Arc<dyn PasskeyStore>,
    /// Checks the passkey's answer.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// The ceremonies in flight, spent here.
    pub ceremony_store: Arc<dyn PasskeyCeremonyStore>,
    /// Where the new session is kept.
    pub session_store: Arc<dyn SessionStore>,
    /// The passkey owners' accounts.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant, which admits the sign-in and sets its rules.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Makes the session's refresh token.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Signs the owner of a passkey in once it answered a challenge.
pub struct LoginConfirmUseCase {
    ports: LoginConfirmPorts,
}

/// What a session is opened from: the tenant, the passkey's owner, their
/// answer and where it came from.
struct Opening<'a> {
    tenant: &'a Tenant,
    owner: &'a User<ResolvedTenant>,
    spent: &'a SpentPasskey,
    origin: &'a ClientOrigin,
}

impl LoginConfirmUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: LoginConfirmPorts) -> Self {
        Self { ports }
    }

    fn answering(&self) -> PasskeyAnswering<'_> {
        PasskeyAnswering {
            passkeys: self.ports.passkey_store.as_ref(),
            ceremonies: self.ports.ceremony_store.as_ref(),
            verifier: self.ports.verifier.as_ref(),
        }
    }

    /// The account `passkey` belongs to. A missing account answers like a
    /// wrong credential.
    async fn owner_of(
        &self,
        tenant: &ScopedTenant,
        passkey: &PasskeyCredential<ResolvedTenant>,
    ) -> Result<User<ResolvedTenant>, AppError> {
        self.ports
            .user_store
            .find_by_id(tenant, passkey.user_id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-invalid-credentials",
                "invalid credentials"
            ))
    }

    /// The session the passkey's answer opens, with its raw refresh token.
    ///
    /// The passkey both begins the sign-in and proves its factor, so the
    /// session records a hardware key when the key was attested as one.
    fn opened(&self, at: &Opening<'_>) -> Result<(Session<ResolvedTenant>, Secret), AppError> {
        let config = at.tenant.auth_config();
        let policy = config.step_up_policy();
        let way_in = WayIn::by_passkey(at.spent).map_err(AppError::from_domain)?;
        let account = MaySignIn::proven(at.owner, way_in, SecondFactor::Verify, policy)
            .map_err(refusal_error)?;
        let (raw, hash) = self
            .ports
            .token_generator
            .generate()
            .or_internal()?
            .into_parts();
        let mut session = Session::create(
            account,
            CreateSessionParams {
                id: SessionId::new(),
                refresh_token_hash: hash,
                ip_address: at.origin.ip_address.clone(),
                user_agent: Fact::from_option(at.origin.user_agent.clone()),
                timeout: config.session_timeout().map_err(AppError::from_domain)?,
            },
        );
        let factor = ProvedFactor::by_passkey(at.spent).map_err(AppError::from_domain)?;
        session
            .answer(at.owner, factor, policy)
            .map_err(refusal_error)?;
        Ok((session, raw))
    }

    /// Keeps `session`, stamps its account as signed in, and records the
    /// sign-in through `auditor`, by its holder, timed from `started`.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        session: &mut Session<ResolvedTenant>,
        started: Instant,
    ) -> Result<(), AppError> {
        self.ports
            .session_store
            .save(tenant, session)
            .await
            .or_internal()?;
        record_login(self.ports.user_store.as_ref(), tenant, session.user_id()).await?;
        session.record_sign_in(elapsed_millis(started));
        let holder = ActorRef::User(*session.user_id());
        auditor
            .dispatch_by(&holder, session.take_events(tenant))
            .await
            .or_internal()
    }
}

impl Command for LoginConfirmUseCase {
    type Caller = ScopedTenant;
    type Input = LoginConfirmRequest;
    type Output = Result<LoginSuccess, AppError>;

    /// Checks the passkey's answer against the ceremony it names, opens a
    /// session for the passkey's owner and records
    /// `authentication.login_succeeded`.
    ///
    /// A ceremony opened for someone accepts only their passkey; one opened
    /// for nobody accepts any passkey of the tenant, whose owner it signs
    /// in. The ceremony is spent before the answer is checked, so a failed
    /// answer burns it.
    ///
    /// # Errors
    ///
    /// - `AppError::TenantUnavailable` when the tenant is not open for
    ///   sign-in.
    /// - `AppError::Forbidden` when the tenant does not take passkeys, or
    ///   not from where the request came; when the answer does not verify,
    ///   or comes from another account's passkey than the ceremony was
    ///   opened for; or when the passkey falls short of the assurance the
    ///   tenant requires.
    /// - `AppError::NotFound` when the ceremony or the passkey is unknown,
    ///   or its owner may not sign in, all alike on purpose.
    /// - `AppError::Domain` when the ceremony expired, was used, or was
    ///   opened for a registration, or the passkey's counter went
    ///   backwards.
    /// - `AppError::Internal` when a store fails or no token can be made.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: LoginConfirmRequest,
    ) -> Result<LoginSuccess, AppError> {
        let started = Instant::now();
        let ip = request.origin.ip_address.as_ref();
        let tenant_store = self.ports.tenant_store.as_ref();
        let (record, _) =
            sign_in_gate::admit(tenant_store, tenant, AuthMethod::Passkey, ip).await?;
        let answered = self
            .answering()
            .answered(tenant, &request.assertion)
            .await?;
        let owner = self.owner_of(tenant, &answered.passkey).await?;
        let opening = Opening {
            tenant: &record,
            owner: &owner,
            spent: &answered.spent,
            origin: &request.origin,
        };
        let (mut session, refresh_token) = self.opened(&opening)?;
        self.keep(tenant, auditor, &mut session, started).await?;
        Ok(login_success(&opening, &session, refresh_token))
    }
}

/// What a refused sign-in answers.
///
/// An account that may not sign in answers like a wrong credential, so
/// the passkey's holder learns nothing more about it.
fn refusal_error(refused: SignInRefused) -> AppError {
    match refused {
        SignInRefused::AccountMayNotSignIn | SignInRefused::ForAnotherAccount => {
            AppError::NotFound(message!(
                "authentication-invalid-credentials",
                "invalid credentials"
            ))
        }
        SignInRefused::BelowBaseline(_) => AppError::Forbidden(message!(
            "authentication-this-passkey-does-not-reach-the",
            "this passkey does not reach the assurance the workspace requires"
        )),
        SignInRefused::NotAccepted { .. } | SignInRefused::AlreadyProved => {
            AppError::Forbidden(message!(
                "authentication-this-passkey-does-not-finish-the",
                "this passkey does not finish the sign-in"
            ))
        }
        SignInRefused::WayInNotAllowed => AppError::Forbidden(message!(
            "authentication-this-account-signs-in-another-way-2",
            "this account signs in another way than a passkey"
        )),
    }
}

/// What a passkey sign-in hands back.
fn login_success(
    opening: &Opening<'_>,
    session: &Session<ResolvedTenant>,
    refresh_token: Secret,
) -> LoginSuccess {
    LoginSuccess {
        session_id: *session.id(),
        refresh_token,
        second_factor: session.owed(),
        tenant_id: *opening.tenant.id(),
        tenant_name: opening.tenant.display_name().as_str().to_owned(),
        display_name: opening.owner.display_name().as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::passkey_ceremony::TargetedPurpose;
    use ianua_domain::domains::authentication::risk_engine::assessment::RiskLevel;
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::authentication::risk_engine::step_up::{
        MfaTrigger, StepUpPolicy, StepUpPolicyParams,
    };
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::types::{CeremonyId, Email, PasskeyCredentialId, UserId};

    use super::*;
    use crate::test_support::authentication::{
        FakePasskeyCeremonyStore, FakePasskeyStore, FakePasskeyVerifier, FakeSessionStore,
        FakeUserLookup, VerifiedAs, ceremony_lifetime, discoverable_ceremony, kept_ceremony,
        passkey_credential_id, passkey_owner, targeted_ceremony,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::tenant::{tenant_store_in_status, tenant_store_signing_in_with};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::passkeys::{LoginBeginPorts, LoginBeginUseCase};

    struct Fixture {
        ann: UserId,
        passkeys: Arc<FakePasskeyStore>,
        ceremonies: Arc<FakePasskeyCeremonyStore>,
        verifier: Arc<FakePasskeyVerifier>,
        users: Arc<FakeUserStore>,
        tenants: Arc<dyn TenantStore>,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn ann_holding(passkeys: FakePasskeyStore, ann: UserId) -> Self {
            Self {
                ann,
                passkeys: Arc::new(passkeys),
                ceremonies: Arc::new(FakePasskeyCeremonyStore::new()),
                verifier: Arc::new(FakePasskeyVerifier::succeeding()),
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                tenants: tenant_store_signing_in_with(TenantAuthSettings::default()),
                sessions: Arc::new(FakeSessionStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ann_with_a_passkey() -> Self {
            let ann = UserId::new();
            Self::ann_holding(FakePasskeyStore::with_passkey(ann), ann)
        }

        fn open_for(&self, user_id: UserId) -> CeremonyId {
            kept_ceremony(
                &self.ceremonies,
                &targeted_ceremony(user_id, TargetedPurpose::Authentication),
            )
        }

        fn open_for_nobody(&self) -> CeremonyId {
            kept_ceremony(&self.ceremonies, &discoverable_ceremony())
        }

        fn confirm_in(
            &self,
            tenant: &ScopedTenant,
            ceremony_id: CeremonyId,
            credential_id: PasskeyCredentialId,
        ) -> Result<LoginSuccess, AppError> {
            let use_case = LoginConfirmUseCase::new(LoginConfirmPorts {
                passkey_store: self.passkeys.clone(),
                verifier: self.verifier.clone(),
                ceremony_store: self.ceremonies.clone(),
                session_store: self.sessions.clone(),
                user_store: self.users.clone(),
                tenant_store: self.tenants.clone(),
                ..LoginConfirmPorts::fakes()
            });
            let request = LoginConfirmRequest {
                assertion: PresentedAssertion {
                    ceremony_id,
                    credential_id,
                    response: vec![0x01],
                },
                origin: ClientOrigin::default(),
            };
            block_on(use_case.execute(tenant, &test_auditor(self.audit.clone()), request))
        }

        fn confirm(&self, ceremony_id: CeremonyId) -> Result<LoginSuccess, AppError> {
            self.confirm_in(&test_ctx().tenant(), ceremony_id, passkey_credential_id())
        }

        fn session_of(&self, success: &LoginSuccess) -> Session<ResolvedTenant> {
            self.sessions.get_session(&success.session_id).unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn hardware_keys_only() -> TenantAuthSettings {
        let policy = StepUpPolicy::new(StepUpPolicyParams {
            baseline_aal: AssuranceLevel::Aal3,
            sensitive_aal: AssuranceLevel::Aal3,
            new_device: MfaTrigger::Ignored,
            new_country: MfaTrigger::Ignored,
            mfa_risk_threshold: RiskLevel::Critical,
            deny_risk_threshold: RiskLevel::Critical,
        })
        .unwrap();
        TenantAuthSettings {
            enabled_methods: vec![AuthMethod::Passkey],
            step_up_policy: policy,
            ..TenantAuthSettings::default()
        }
    }

    /// Ann answers her challenge with her passkey. She gets a session and
    /// her sign-in is recorded.
    #[test]
    fn a_verified_answer_opens_a_session_and_is_recorded() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(fixture.ann);

        let success = fixture.confirm(ceremony).unwrap();

        assert!(!success.refresh_token.expose().is_empty());
        assert_eq!(fixture.sessions.session_count(), 1);
        assert_eq!(fixture.recorded(), vec!["authentication.login_succeeded"]);
    }

    /// Ann signs in with her synced passkey. Her session says so: a passkey
    /// sign-in, its factor a passkey, nothing more owed, at AAL2.
    #[test]
    fn a_passkey_signs_in_at_aal2_owing_nothing() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(fixture.ann);

        let success = fixture.confirm(ceremony).unwrap();

        let session = fixture.session_of(&success);
        assert_eq!(session.auth_method(), AuthMethod::Passkey);
        assert_eq!(
            session.mfa_method(),
            FactorProved::Proved(MfaFactor::Passkey)
        );
        assert_eq!(session.owed(), SecondFactor::NotOwed);
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal2);
    }

    /// Ann signs in with the hardware key whose attestation showed it is
    /// one. Her session records a hardware key, at AAL3.
    #[test]
    fn an_attested_hardware_key_signs_in_at_aal3() {
        let ann = UserId::new();
        let fixture = Fixture::ann_holding(FakePasskeyStore::with_hardware_key(ann), ann);
        let ceremony = fixture.open_for(ann);

        let success = fixture.confirm(ceremony).unwrap();

        let session = fixture.session_of(&success);
        assert_eq!(
            session.mfa_method(),
            FactorProved::Proved(MfaFactor::HardwareKey)
        );
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal3);
    }

    /// A synced passkey below the hardware-key assurance baseline is
    /// forbidden and creates no session.
    #[test]
    fn a_passkey_below_the_baseline_is_refused() {
        let fixture = Fixture {
            tenants: tenant_store_signing_in_with(hardware_keys_only()),
            ..Fixture::ann_with_a_passkey()
        };
        let ceremony = fixture.open_for(fixture.ann);

        let result = fixture.confirm(ceremony);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// Ann's sign-in answers with the tenant and her name, as a password
    /// sign-in does.
    #[test]
    fn the_answer_names_the_tenant_and_the_person() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(fixture.ann);

        let success = fixture.confirm(ceremony).unwrap();

        assert_eq!(success.second_factor, SecondFactor::NotOwed);
        assert_eq!(success.tenant_id, test_ctx().tenant_id());
        assert_eq!(success.display_name, "Test User");
    }

    /// Ann's session is Ann's: the passkey's owner is signed in.
    #[test]
    fn the_session_belongs_to_the_passkeys_owner() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(fixture.ann);

        let success = fixture.confirm(ceremony).unwrap();

        assert_eq!(fixture.session_of(&success).user_id(), &fixture.ann);
    }

    /// Disabling passkey sign-in forbids confirmation and creates no session.
    #[test]
    fn a_tenant_without_passkeys_refuses_the_sign_in() {
        let fixture = Fixture {
            tenants: tenant_store_signing_in_with(TenantAuthSettings {
                enabled_methods: vec![AuthMethod::Password],
                ..TenantAuthSettings::default()
            }),
            ..Fixture::ann_with_a_passkey()
        };
        let ceremony = fixture.open_for(fixture.ann);

        let result = fixture.confirm(ceremony);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// A suspended tenant returns TenantUnavailable and creates no passkey session.
    #[test]
    fn a_suspended_tenant_refuses_the_sign_in() {
        let fixture = Fixture {
            tenants: tenant_store_in_status(TenantStatus::Suspended),
            ..Fixture::ann_with_a_passkey()
        };
        let ceremony = fixture.open_for(fixture.ann);

        let result = fixture.confirm(ceremony);

        assert!(matches!(result, Err(AppError::TenantUnavailable(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// An unknown ceremony returns NotFound and creates no session.
    #[test]
    fn an_unknown_ceremony_is_not_found() {
        let fixture = Fixture::ann_with_a_passkey();

        let result = fixture.confirm(CeremonyId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// Confirming the decoy issued for an unknown address returns NotFound.
    #[test]
    fn a_decoy_is_refused_like_an_unknown_ceremony() {
        let fixture = Fixture::ann_with_a_passkey();
        let begin = LoginBeginUseCase::new(
            ceremony_lifetime(),
            LoginBeginPorts {
                user_lookup: Arc::new(FakeUserLookup::holding([passkey_owner(
                    fixture.ann,
                    "ann@acme.test",
                )])),
                ceremony_store: fixture.ceremonies.clone(),
                ..LoginBeginPorts::fakes()
            },
        );
        let decoy = block_on(begin.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            Email::new("nobody@acme.test").unwrap(),
        ))
        .unwrap();

        let result = fixture.confirm(decoy.ceremony_id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reusing a completed ceremony returns a domain error and leaves one
    /// session stored.
    #[test]
    fn a_ceremony_settles_one_sign_in() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(fixture.ann);
        fixture.confirm(ceremony).unwrap();

        let replay = fixture.confirm(ceremony);

        assert!(matches!(replay, Err(AppError::Domain(_))));
        assert_eq!(fixture.sessions.session_count(), 1);
    }

    /// Confirming a ceremony through another tenant returns NotFound.
    #[test]
    fn a_ceremony_does_not_cross_tenants() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(fixture.ann);
        let elsewhere = ScopedTenant::for_test(TenantId::new());

        let result = fixture.confirm_in(&elsewhere, ceremony, passkey_credential_id());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A ceremony bound to another account rejects the passkey as forbidden
    /// and creates no session.
    #[test]
    fn a_ceremony_refuses_another_accounts_passkey() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(UserId::new());

        let result = fixture.confirm(ceremony);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// A failed passkey verification is forbidden, creates no session and
    /// records no sign-in event.
    #[test]
    fn an_answer_that_does_not_verify_is_refused() {
        let fixture = Fixture {
            verifier: Arc::new(FakePasskeyVerifier::failing()),
            ..Fixture::ann_with_a_passkey()
        };
        let ceremony = fixture.open_for(fixture.ann);

        let result = fixture.confirm(ceremony);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A failed verification consumes the ceremony: retrying with a successful
    /// verifier returns a domain error and still creates no session.
    #[test]
    fn a_failed_answer_burns_the_ceremony() {
        let failing = Fixture {
            verifier: Arc::new(FakePasskeyVerifier::failing()),
            ..Fixture::ann_with_a_passkey()
        };
        let ceremony = failing.open_for(failing.ann);
        let _ = failing.confirm(ceremony);
        let retrying = Fixture {
            verifier: Arc::new(FakePasskeyVerifier::succeeding()),
            ..failing
        };

        let retry = retrying.confirm(ceremony);

        assert!(matches!(retry, Err(AppError::Domain(_))));
        assert_eq!(retrying.sessions.session_count(), 0);
    }

    /// An assertion naming an unknown passkey returns NotFound.
    #[test]
    fn an_unknown_passkey_is_not_found() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(fixture.ann);
        let unknown = PasskeyCredentialId::new(vec![99, 99, 99]).unwrap();

        let result = fixture.confirm_in(&test_ctx().tenant(), ceremony, unknown);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann's authenticator reports its counter went up. The passkey keeps
    /// the new count, so a cloned key shows up later.
    #[test]
    fn the_reported_sign_count_is_kept() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(fixture.ann);

        fixture.confirm(ceremony).unwrap();

        let kept = block_on(
            fixture
                .passkeys
                .find_by_credential_id(&test_ctx().tenant(), &passkey_credential_id()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(kept.sign_count(), 1);
    }

    /// Ann answers a ceremony opened for nobody. It is checked the way a
    /// discoverable answer is, which ties the passkey to the person it
    /// signs in.
    #[test]
    fn a_ceremony_for_nobody_is_checked_as_discoverable() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for_nobody();

        fixture.confirm(ceremony).unwrap();

        assert_eq!(
            fixture.verifier.verified_as(),
            vec![VerifiedAs::Discoverable]
        );
    }

    /// Ann answers a ceremony opened for her. It is checked against her
    /// own passkeys.
    #[test]
    fn a_ceremony_for_someone_is_checked_against_their_passkeys() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for(fixture.ann);

        fixture.confirm(ceremony).unwrap();

        assert_eq!(
            fixture.verifier.verified_as(),
            vec![VerifiedAs::BoundToUser]
        );
    }

    /// Ann's browser offered her passkey before she typed anything. The
    /// passkey names her, so she is signed in.
    #[test]
    fn a_ceremony_for_nobody_signs_in_the_passkeys_owner() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for_nobody();

        let success = fixture.confirm(ceremony).unwrap();

        assert_eq!(fixture.session_of(&success).user_id(), &fixture.ann);
    }

    /// Replaying a discoverable ceremony returns a domain error and leaves
    /// only the first session stored.
    #[test]
    fn a_ceremony_for_nobody_settles_one_sign_in() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for_nobody();
        fixture.confirm(ceremony).unwrap();

        let replay = fixture.confirm(ceremony);

        assert!(matches!(replay, Err(AppError::Domain(_))));
        assert_eq!(fixture.sessions.session_count(), 1);
    }

    /// An unknown passkey in a discoverable ceremony returns NotFound and
    /// creates no session.
    #[test]
    fn a_ceremony_for_nobody_refuses_an_unknown_passkey() {
        let fixture = Fixture::ann_with_a_passkey();
        let ceremony = fixture.open_for_nobody();
        let unknown = PasskeyCredentialId::new(vec![99, 99, 99]).unwrap();

        let result = fixture.confirm_in(&test_ctx().tenant(), ceremony, unknown);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }

    /// A deactivated account's passkey returns NotFound and creates no session.
    #[test]
    fn a_switched_off_account_cannot_sign_in() {
        let fixture = Fixture::ann_with_a_passkey();
        let users = FakeUserStore::empty();
        users.add(stored_user(
            fixture.ann,
            "ann@acme.test",
            UserStatus::Deactivated,
        ));
        let fixture = Fixture {
            users: Arc::new(users),
            ..fixture
        };
        let ceremony = fixture.open_for(fixture.ann);

        let result = fixture.confirm(ceremony);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 0);
    }
}
