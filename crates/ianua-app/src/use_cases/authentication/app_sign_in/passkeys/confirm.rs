//! Signing in at an app's address with a passkey's answer to its challenge.

use std::sync::Arc;

use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::services::authentication::passkey_answer::PresentedAssertion;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::{
    AppSignInCommon, OnTarget, Proved, without_mailed_link,
};
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::passkeys::{LoginConfirmRequest, LoginConfirmUseCase};

/// A passkey's answer to a challenge from an app's address.
pub struct AppPasskeyConfirmRequest {
    /// The passkey's answer, naming the ceremony it answers.
    pub assertion: PresentedAssertion,
    /// Where to send them afterwards, if they came from somewhere.
    pub return_to: Option<ReturnPath>,
}

/// Signs the owner of a passkey in on an app's host.
pub struct AppPasskeyConfirmUseCase {
    common: Arc<AppSignInCommon>,
    confirm: Arc<LoginConfirmUseCase>,
}

impl AppPasskeyConfirmUseCase {
    /// A use case checking answers through the dashboard's own `confirm`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        confirm: Arc<LoginConfirmUseCase>,
    ) -> Self {
        Self { common, confirm }
    }
}

impl Command for AppPasskeyConfirmUseCase {
    type Caller = AppSignInContext;
    type Input = AppPasskeyConfirmRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Checks the answer against the ceremony kept on the server through the
    /// dashboard's own passkey sign-in, then signs the passkey's owner in on
    /// the app's host, or asks for a second factor when the workspace wants
    /// more than the passkey proved.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or the
    ///   ceremony or passkey is unknown, or its owner may not sign in.
    /// - `AppError::Forbidden` if the workspace takes no passkeys, the answer
    ///   does not verify or falls short of what the workspace requires, or
    ///   the sign-in owes a step an app's host does not take.
    /// - `AppError::TenantUnavailable` and `AppError::Domain` as the
    ///   dashboard's own passkey sign-in reports them.
    /// - `AppError::Internal` on persistence or signing failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppPasskeyConfirmRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let AppPasskeyConfirmRequest {
            assertion,
            return_to,
        } = request;
        let confirm = LoginConfirmRequest {
            assertion,
            origin: ctx.origin(),
        };
        let success = self.confirm.execute(&ctx.tenant, &auditor, confirm).await?;
        let proved = Proved {
            session_id: success.session_id,
            owed: without_mailed_link(success.second_factor)?,
            return_to,
        };
        let on = OnTarget {
            ctx,
            target: &target,
        };
        self.common.onward(&on, proved).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::passkey_ceremony::TargetedPurpose;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::types::{CeremonyId, HttpsUrl, ServiceId, UserId};

    use super::*;
    use crate::test_support::authentication::{
        FakeAppSessionTokens, FakePasskeyCeremonyStore, FakePasskeyStore, FakePasskeyVerifier,
        FakeSessionStore, SHOP_HOST, app_sign_in_lifetimes, app_sign_in_services,
        app_sign_in_target_ports, cross_host_ctx, kept_ceremony, passkey_credential_id,
        shop_with_app_sign_in, targeted_ceremony,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::authentication::passkeys::LoginConfirmPorts;

    /// The shop, Ann with a passkey, and what was minted and opened.
    struct Fixture {
        use_case: AppPasskeyConfirmUseCase,
        shop: ServiceId,
        ann: UserId,
        ceremonies: Arc<FakePasskeyCeremonyStore>,
        sessions: Arc<FakeSessionStore>,
        tokens: Arc<FakeAppSessionTokens>,
    }

    /// The shop signing people in on [`SHOP_HOST`], over a workspace where
    /// Ann holds a passkey that `verifier` checks answers of.
    fn fixture(verifier: FakePasskeyVerifier) -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let ann = UserId::new();
        let ceremonies = Arc::new(FakePasskeyCeremonyStore::new());
        let sessions = Arc::new(FakeSessionStore::empty());
        let tokens = Arc::new(FakeAppSessionTokens::default());
        let confirm = confirmation(ann, verifier, &ceremonies, &sessions);
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            session_store: sessions.clone(),
            tokens: tokens.clone(),
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(ports, base, app_sign_in_lifetimes());
        Fixture {
            use_case: AppPasskeyConfirmUseCase::new(Arc::new(common), Arc::new(confirm)),
            shop: shop_id,
            ann,
            ceremonies,
            sessions,
            tokens,
        }
    }

    /// Ann's passkey answers are checked against the shared ceremony and session stores.
    fn confirmation(
        ann: UserId,
        verifier: FakePasskeyVerifier,
        ceremonies: &Arc<FakePasskeyCeremonyStore>,
        sessions: &Arc<FakeSessionStore>,
    ) -> LoginConfirmUseCase {
        LoginConfirmUseCase::new(LoginConfirmPorts {
            passkey_store: Arc::new(FakePasskeyStore::with_passkey(ann)),
            verifier: Arc::new(verifier),
            ceremony_store: ceremonies.clone(),
            session_store: sessions.clone(),
            user_store: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
            tenant_store: tenant_store_signing_in_with(TenantAuthSettings::default()),
            ..LoginConfirmPorts::fakes()
        })
    }

    /// A ceremony opened for Ann's passkeys and kept.
    fn opened_for_ann(f: &Fixture) -> CeremonyId {
        kept_ceremony(
            &f.ceremonies,
            &targeted_ceremony(f.ann, TargetedPurpose::Authentication),
        )
    }

    /// Ann's passkey answers `ceremony_id` at `service`'s sign-in on the
    /// shop's host.
    fn confirm(
        f: &Fixture,
        service: ServiceId,
        ceremony_id: CeremonyId,
    ) -> Result<AppSignInOutcome, AppError> {
        let request = AppPasskeyConfirmRequest {
            assertion: PresentedAssertion {
                ceremony_id,
                credential_id: passkey_credential_id(),
                response: vec![0x01],
            },
            return_to: None,
        };
        block_on(f.use_case.execute(
            &cross_host_ctx(service, SHOP_HOST),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))
    }

    /// Ann answers the shop's challenge with her passkey. A session cookie
    /// is minted for the shop's host, and she lands where the shop sends
    /// people.
    #[test]
    fn a_verified_answer_signs_in_on_the_host() {
        let f = fixture(FakePasskeyVerifier::succeeding());
        let ceremony = opened_for_ann(&f);

        let outcome = confirm(&f, f.shop, ceremony).unwrap();

        let AppSignInOutcome::SignedIn { return_to, .. } = outcome else {
            panic!("Ann is signed in");
        };
        assert_eq!(return_to.as_str(), "/");
        assert_eq!(
            f.tokens.minted.lock().unwrap().as_slice(),
            [format!("session:{SHOP_HOST}:shop")]
        );
    }

    /// A passkey answer that fails verification is refused without creating
    /// a session or minting a cookie.
    #[test]
    fn an_answer_that_does_not_verify_is_refused() {
        let f = fixture(FakePasskeyVerifier::failing());
        let ceremony = opened_for_ann(&f);

        let outcome = confirm(&f, f.shop, ceremony);

        assert!(outcome.is_err());
        assert_eq!(f.sessions.session_count(), 0);
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// An answer naming an unknown ceremony is refused without creating a
    /// session or minting a cookie.
    #[test]
    fn an_unknown_ceremony_is_refused() {
        let f = fixture(FakePasskeyVerifier::succeeding());

        let outcome = confirm(&f, f.shop, CeremonyId::new());

        assert!(outcome.is_err());
        assert_eq!(f.sessions.session_count(), 0);
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// A passkey confirmation for an unknown service returns not found,
    /// leaves its ceremony stored, and opens no session.
    #[test]
    fn a_service_without_app_sign_in_here_is_not_found() {
        let f = fixture(FakePasskeyVerifier::succeeding());
        let ceremony = opened_for_ann(&f);

        let outcome = confirm(&f, ServiceId::new(), ceremony);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert_eq!(f.ceremonies.len(), 1);
        assert_eq!(f.sessions.session_count(), 0);
    }
}
