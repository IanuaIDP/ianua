//! Finishing an app sign-in with a second factor.

use std::sync::Arc;

use ianua_domain::domains::authentication::device_trust::DeviceSecret;
use ianua_domain::domains::authentication::sessions::mfa_challenge::MfaChallenge;
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DomainName, Label, SessionId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::password::log_in::device_on_host;
use crate::use_cases::authentication::app_sign_in::relay::common::{AppSignInCommon, OnTarget};
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::mfa::{VerificationRequest, VerificationUseCase};
use crate::use_cases::authentication::sessions::device_trust::{
    RememberSignedInDeviceUseCase, RememberSignedInRequest,
};

/// A second-factor answer. Holds the challenge token and the code, so it has
/// no `Debug`.
pub struct AppCompleteMfaRequest {
    /// The challenge token handed out when the password was accepted.
    pub challenge: Secret,
    /// The code from their authenticator.
    pub code: String,
    /// The secret for the host's device cookie when the person asked to
    /// remember this device: a fresh one the gateway made for this browser.
    pub remember: Option<DeviceSecret>,
    /// Where to send them afterwards, if they came from somewhere.
    pub return_to: Option<ReturnPath>,
}

/// Answers an open challenge with a second-factor code.
pub struct AppCompleteMfaUseCase {
    common: Arc<AppSignInCommon>,
    mfa: Arc<VerificationUseCase>,
    remember: Arc<RememberSignedInDeviceUseCase>,
}

impl AppCompleteMfaUseCase {
    /// A use case checking codes through the dashboard's own `mfa`, and
    /// remembering the device through `remember`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        mfa: Arc<VerificationUseCase>,
        remember: Arc<RememberSignedInDeviceUseCase>,
    ) -> Self {
        Self {
            common,
            mfa,
            remember,
        }
    }

    /// The secret of the device remembered for the sign-in on `session_id`,
    /// when the person asked and it could be remembered there.
    ///
    /// A device that may not be remembered, such as one past the most a
    /// person may hold, leaves the sign-in as it is: the person is in,
    /// only not remembered. A request whose client or address could not be
    /// told remembers nothing, since the device's record names both.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the device or the session cannot be kept
    /// or recorded.
    async fn remembered(
        &self,
        on: &OnTarget<'_>,
        auditor: &RequestAuditor,
        session_id: SessionId,
        secret: Option<DeviceSecret>,
    ) -> Result<Option<DeviceSecret>, AppError> {
        let ctx = on.ctx;
        let (Some(secret), Some(user_agent), Some(ip)) =
            (secret, ctx.user_agent.clone(), ctx.ip_address.clone())
        else {
            return Ok(None);
        };
        let request = RememberSignedInRequest {
            session_id,
            secret: device_on_host(on.target, secret.clone()),
            device_name: device_name(&ctx.host)?,
            user_agent,
            ip,
        };
        match self.remember.execute(&ctx.tenant, auditor, request).await {
            Ok(_) => Ok(Some(secret)),
            Err(refusal) if refusal.is_client_error() => Ok(None),
            Err(failure) => Err(failure),
        }
    }

    /// Counts a code the check refused against the challenge, and passes
    /// the refusal on. A check that could not run refused nothing, so it
    /// costs the person no attempt.
    async fn refused(
        &self,
        ctx: &AppSignInContext,
        challenge: &mut MfaChallenge<ResolvedTenant>,
        refusal: AppError,
    ) -> Result<AppSignInOutcome, AppError> {
        if refusal.is_server_error() {
            return Err(refusal);
        }
        challenge.record_failure();
        self.common
            .ports
            .challenge_store
            .save(&ctx.tenant, challenge)
            .await
            .or_internal()?;
        Err(refusal)
    }
}

impl Command for AppCompleteMfaUseCase {
    type Caller = AppSignInContext;
    type Input = AppCompleteMfaRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Answers the challenge with the code, signing the person in once it is
    /// accepted. A refused code is counted against the challenge; a check
    /// that failed on our side is not.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or the
    ///   challenge is unknown, closed or its session gone.
    /// - `AppError::Forbidden`, `AppError::Conflict` or
    ///   `AppError::AccountLocked` as the second-factor check refuses the
    ///   code.
    /// - `AppError::Internal` on persistence or signing failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppCompleteMfaRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let mut challenge = self.common.open_challenge(ctx, &request.challenge).await?;
        let session = self.common.challenged_session(ctx, &challenge).await?;
        let verification = VerificationRequest {
            session_id: *session.id(),
            user_id: *session.user_id(),
            code: request.code,
        };
        if let Err(refusal) = self.mfa.execute(&ctx.tenant, &auditor, verification).await {
            return self.refused(ctx, &mut challenge, refusal).await;
        }
        self.common.spend_challenge(ctx, challenge).await?;
        let on = OnTarget {
            ctx,
            target: &target,
        };
        let remembered = self
            .remembered(&on, &auditor, *session.id(), request.remember)
            .await?;
        self.common
            .open_remembering(&on, session.id(), request.return_to, remembered)
            .await
    }
}

/// The name a device remembered on `host` shows in the person's device
/// list, or a plainer one when the host is too long for a name.
///
/// # Errors
///
/// `AppError::Internal` when neither reads as a name, which never happens.
fn device_name(host: &DomainName) -> Result<Label, AppError> {
    Label::new("device_name", format!("Browser on {host}"))
        .or_else(|_| Label::new("device_name", "Browser on an app's sign-in"))
        .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::authentication::device_trust::{PresentedSecret, SignInPlace};
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::session::Session;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::test_support::fakes::FakeMfaVerifier;
    use ianua_domain::types::{
        Fact, HttpsUrl, IpAddress, SealedSecret, ServiceId, UserAgent, UserId,
    };

    use super::*;
    use crate::acting::tenant::{TenantActing, TenantActingPorts, TenantCredentialPorts};
    use crate::ports::authentication::{
        MfaChallengeStore, SealedFor, SecretEncryptor, TrustedDeviceStore,
    };
    use crate::test_support::authentication::{
        FakeAppSessionTokens, FakeEncryptor, FakeMfaChallengeStore, FakeMfaEnrollmentStore,
        FakeSessionStore, FakeTrustedDeviceStore, SHOP_HOST, app_sign_in_lifetimes,
        app_sign_in_services, app_sign_in_target_ports, clone_session, cross_host_ctx, lockout,
        password_session, shop_with_app_sign_in,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::oauth::hash_of;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::authentication::mfa::VerificationPorts;
    use crate::use_cases::authentication::mfa::codes::failed_factor::FactorCodePorts;
    use crate::use_cases::authentication::sessions::device_trust::{Policy, RememberSignedInPorts};

    const RIGHT_CODE: &str = "123456";
    const CHALLENGE: &str = "challenge-token";

    /// An encryptor that cannot open anything, as when the key service is
    /// down.
    struct BrokenEncryptor;

    #[async_trait]
    impl SecretEncryptor for BrokenEncryptor {
        async fn encrypt(&self, _: &[u8], _: &SealedFor) -> Result<SealedSecret, DomainError> {
            Err(DomainError::infra_msg("key service unreachable"))
        }

        async fn decrypt(&self, _: &SealedSecret, _: &SealedFor) -> Result<Vec<u8>, DomainError> {
            Err(DomainError::infra_msg("key service unreachable"))
        }
    }

    struct Fixture {
        use_case: AppCompleteMfaUseCase,
        shop: ServiceId,
        tokens: Arc<FakeAppSessionTokens>,
        challenges: Arc<FakeMfaChallengeStore>,
        devices: Arc<FakeTrustedDeviceStore>,
        bob: UserId,
    }

    fn mfa(
        sessions: Arc<FakeSessionStore>,
        user_id: UserId,
        encryptor: Arc<dyn SecretEncryptor>,
    ) -> VerificationUseCase {
        VerificationUseCase::new(
            lockout(),
            VerificationPorts {
                session_store: sessions,
                user_store: Arc::new(FakeUserStore::with_user(user_id, "bob@acme.test")),
                tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                codes: FactorCodePorts {
                    enrollment_store: Arc::new(FakeMfaEnrollmentStore::active_for(user_id)),
                    encryptor,
                    verifier: Arc::new(FakeMfaVerifier {
                        valid_code: RIGHT_CODE.to_owned(),
                    }),
                    ..FactorCodePorts::fakes()
                },
                ..VerificationPorts::fakes()
            },
        )
    }

    fn fixture_with(encryptor: Arc<dyn SecretEncryptor>) -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let user_id = UserId::new();
        let waiting = password_session(user_id, "hash", SecondFactor::Verify);
        let sessions = Arc::new(FakeSessionStore::with_session(clone_session(&waiting)));
        let challenges = Arc::new(FakeMfaChallengeStore::default());
        save_challenge(&challenges, &waiting);
        let tokens = Arc::new(FakeAppSessionTokens::default());
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            session_store: sessions.clone(),
            challenge_store: challenges.clone(),
            tokens: tokens.clone(),
            ..SignInPorts::fakes()
        };
        let common = sign_in_common(ports);
        let devices = Arc::new(FakeTrustedDeviceStore::empty());
        let remember = remember_device(&devices, &sessions, user_id);
        Fixture {
            use_case: AppCompleteMfaUseCase::new(
                Arc::new(common),
                Arc::new(mfa(sessions, user_id, encryptor)),
                Arc::new(remember),
            ),
            shop: shop_id,
            tokens,
            challenges,
            devices,
            bob: user_id,
        }
    }

    /// Stores the browser challenge for the session still awaiting its second factor.
    fn save_challenge(store: &FakeMfaChallengeStore, waiting: &Session<ResolvedTenant>) {
        let lifetime = app_sign_in_lifetimes().mfa_challenge;
        let challenge = MfaChallenge::issue(waiting, hash_of(CHALLENGE), lifetime).unwrap();
        block_on(store.save(&test_ctx().tenant(), &challenge)).unwrap();
    }

    /// Resolves the shop's sign-in target using the fixture's URL and session lifetimes.
    fn sign_in_common(ports: SignInPorts) -> AppSignInCommon {
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        AppSignInCommon::new(ports, base, app_sign_in_lifetimes())
    }

    /// Remembering Bob's device uses his session and current tenant authority.
    fn remember_device(
        devices: &Arc<FakeTrustedDeviceStore>,
        sessions: &Arc<FakeSessionStore>,
        user_id: UserId,
    ) -> RememberSignedInDeviceUseCase {
        RememberSignedInDeviceUseCase::new(
            Policy {
                max_devices_per_user: 5,
            },
            RememberSignedInPorts {
                device_store: devices.clone(),
                session_store: sessions.clone(),
                tenant_authorities: Arc::new(TenantActing::new(TenantActingPorts {
                    tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                    tenant: TenantCredentialPorts {
                        users: Arc::new(FakeUserStore::with_user(user_id, "bob@acme.test")),
                        sessions: sessions.clone(),
                        ..TenantCredentialPorts::fakes()
                    },
                    ..TenantActingPorts::fakes()
                })),
                ..RememberSignedInPorts::fakes()
            },
        )
    }

    fn fixture() -> Fixture {
        fixture_with(Arc::new(FakeEncryptor))
    }

    fn answer(f: &Fixture, code: &str) -> Result<AppSignInOutcome, AppError> {
        answer_from(f, code, None, &cross_host_ctx(f.shop, SHOP_HOST))
    }

    fn answer_from(
        f: &Fixture,
        code: &str,
        remember: Option<DeviceSecret>,
        ctx: &AppSignInContext,
    ) -> Result<AppSignInOutcome, AppError> {
        let request = AppCompleteMfaRequest {
            challenge: Secret::new(CHALLENGE),
            code: code.to_owned(),
            remember,
            return_to: None,
        };
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(f.use_case.execute(ctx, &auditor, request))
    }

    /// Bob's browser on the shop's host, whose client and address the
    /// gateway told.
    fn bobs_browser(f: &Fixture) -> AppSignInContext {
        AppSignInContext {
            ip_address: Some(IpAddress::new("203.0.113.7").unwrap()),
            user_agent: Some(UserAgent::new("Mozilla/5.0").unwrap()),
            ..cross_host_ctx(f.shop, SHOP_HOST)
        }
    }

    fn laptop() -> DeviceSecret {
        DeviceSecret::new("ab".repeat(32)).unwrap()
    }

    /// Bob types his code and asks the shop to remember his laptop. It is
    /// remembered by its secret bound to the shop's host, the answer hands
    /// the secret back for the host's device cookie, and the session token
    /// names the laptop.
    #[test]
    fn asking_to_remember_the_device_remembers_it_on_this_host() {
        let f = fixture();

        let outcome = answer_from(&f, RIGHT_CODE, Some(laptop()), &bobs_browser(&f)).unwrap();

        let AppSignInOutcome::SignedIn { remembered, .. } = outcome else {
            panic!("Bob is signed in");
        };
        assert_eq!(remembered, Some(laptop()));
        assert_eq!(f.devices.count(), 1);
        let on_shop = PresentedSecret::new(
            laptop(),
            SignInPlace::AppHost(DomainName::new(SHOP_HOST).unwrap()),
        );
        let held = block_on(f.devices.list_by_user(&test_ctx().tenant(), &f.bob))
            .unwrap()
            .remove(0);
        assert_eq!(held.secret_hash(), &hash_of(on_shop.bound().expose()));
        let named = f.tokens.named_devices.lock().unwrap().clone();
        assert_eq!(named, [Fact::Known(*held.id())]);
    }

    /// Bob does not ask. Nothing is remembered, and no device cookie is
    /// handed back.
    #[test]
    fn a_sign_in_not_asking_remembers_nothing() {
        let f = fixture();

        let outcome = answer_from(&f, RIGHT_CODE, None, &bobs_browser(&f)).unwrap();

        assert!(matches!(
            outcome,
            AppSignInOutcome::SignedIn {
                remembered: None,
                ..
            }
        ));
        assert_eq!(f.devices.count(), 0);
    }

    /// A wrong factor code is refused even when remembering the browser is
    /// requested, and no device is stored.
    #[test]
    fn a_wrong_code_remembers_nothing() {
        let f = fixture();

        let outcome = answer_from(&f, "000000", Some(laptop()), &bobs_browser(&f));

        assert!(matches!(outcome, Err(AppError::Forbidden(_))));
        assert_eq!(f.devices.count(), 0);
    }

    fn failures(f: &Fixture) -> u8 {
        block_on(
            f.challenges
                .find_by_token_hash(&test_ctx().tenant(), &hash_of(CHALLENGE)),
        )
        .unwrap()
        .map_or(0, |challenge| challenge.failed_attempts())
    }

    /// Bob types the code his authenticator shows. He is signed in on the
    /// shop's host and the challenge is gone.
    #[test]
    fn the_right_code_signs_in_on_the_host() {
        let f = fixture();

        let outcome = answer(&f, RIGHT_CODE);

        assert!(matches!(outcome, Ok(AppSignInOutcome::SignedIn { .. })));
        assert_eq!(f.challenges.count(), 0);
        assert_eq!(f.tokens.minted.lock().unwrap().len(), 1);
    }

    /// A wrong factor code is refused, adds one challenge failure, and
    /// mints no cookie.
    #[test]
    fn a_wrong_code_is_refused_and_counted() {
        let f = fixture();

        let outcome = answer(&f, "000000");

        assert!(matches!(outcome, Err(AppError::Forbidden(_))));
        assert_eq!(failures(&f), 1);
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// Three wrong codes close the challenge. A correct code then returns
    /// not found, and no cookie is minted.
    #[test]
    fn a_closed_challenge_is_refused() {
        let f = fixture();
        for _ in 0..3 {
            let _ = answer(&f, "000000");
        }

        let outcome = answer(&f, RIGHT_CODE);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// Repeating a successful factor answer with the spent challenge returns
    /// not found.
    #[test]
    fn a_replayed_challenge_is_refused() {
        let f = fixture();
        answer(&f, RIGHT_CODE).unwrap();

        let replayed = answer(&f, RIGHT_CODE);

        assert!(matches!(replayed, Err(AppError::NotFound(_))));
    }

    /// The key service is down when Bob types his code. The check fails on
    /// our side, so it costs Bob none of his attempts.
    #[test]
    fn a_check_that_fails_on_our_side_spends_no_attempt() {
        let f = fixture_with(Arc::new(BrokenEncryptor));

        let outcome = answer(&f, RIGHT_CODE);

        assert!(matches!(outcome, Err(AppError::Internal(_))));
        assert_eq!(failures(&f), 0);
    }
}
