//! Signing out at an app's address.

use std::sync::Arc;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::context::{CallerContext, CallerIdentity, Credential};
use crate::error::AppError;
use crate::ports::authentication::AppSessionClaim;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::relay::target::Target;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::sessions::{LogoutUseCase, SigningOut};

/// Ends the session an app host's cookie holds.
pub struct AppLogOutUseCase {
    common: Arc<AppSignInCommon>,
    logout: Arc<LogoutUseCase>,
}

impl AppLogOutUseCase {
    /// A use case ending sessions through the dashboard's own `logout`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        logout: Arc<LogoutUseCase>,
    ) -> Self {
        Self { common, logout }
    }

    /// What the cookie's `token` claims, provided it is a session of this
    /// app; `None` for no token, one that does not verify, or another
    /// app's.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the token cannot be read at all, such as
    /// when the signing keys cannot be reached.
    async fn own_claim(
        &self,
        ctx: &AppSignInContext,
        target: &Target,
        token: Option<&Secret>,
    ) -> Result<Option<AppSessionClaim>, AppError> {
        let Some(token) = token else {
            return Ok(None);
        };
        let read = self
            .common
            .ports
            .tokens
            .read(&ctx.tenant, token, &target.host)
            .await;
        let claim = match read {
            Ok(claim) => claim,
            Err(DomainError::Unauthorized(_)) => return Ok(None),
            Err(failed) => return Err(AppError::internal(failed)),
        };
        Ok((claim.service_id == *target.service.id()).then_some(claim))
    }
}

impl Command for AppLogOutUseCase {
    type Caller = AppSignInContext;
    type Input = Option<Secret>;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Ends the session the cookie's token holds, if it is this app's, as
    /// the person signed in to it. A missing, foreign or already-ended
    /// session is still answered as signed out: the browser's cookies go
    /// either way.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here.
    /// - `AppError::Internal` if the cookie cannot be read or the session
    ///   cannot be ended.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        session: Option<Secret>,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let Some(claim) = self.own_claim(ctx, &target, session.as_ref()).await? else {
            return Ok(AppSignInOutcome::SignedOut);
        };
        let holder = SigningOut::SignedIn(Box::new(holder_of(&target, &claim)?));
        let ended = self.logout.execute(&holder, &auditor, ()).await;
        match ended {
            Ok(())
            | Err(AppError::NotFound(_) | AppError::Conflict(_) | AppError::Unauthenticated) => {
                Ok(AppSignInOutcome::SignedOut)
            }
            Err(failed) => Err(failed),
        }
    }
}

/// The person the cookie's `claim` says is signed in, as a caller of the
/// app's tenant coming with that session.
fn holder_of(target: &Target, claim: &AppSessionClaim) -> Result<CallerContext, AppError> {
    CallerContext::new(
        CallerIdentity::TenantUser(claim.user_id),
        Credential::TenantSession(claim.session_id),
        *target.org.id(),
        *target.tenant.id(),
        target.org.limits(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::types::{DomainName, Fact, HttpsUrl, ServiceId, SessionId, UserId};

    use super::*;
    use crate::ports::authentication::{
        AppAccessGrant, AppSessionGrant, AppSessionTokens, IssuedAppSession,
    };
    use crate::tenancy::ScopedTenant;
    use crate::test_support::authentication::{
        FakeAppSessionTokens, FakeSessionStore, SHOP_HOST, app_sign_in_lifetimes,
        app_sign_in_services, app_sign_in_target_ports, clone_session, cross_host_ctx,
        password_session, shop_with_app_sign_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::authentication::sessions::LogoutPorts;

    struct Fixture {
        use_case: AppLogOutUseCase,
        shop: ServiceId,
        sessions: Arc<FakeSessionStore>,
        session_id: SessionId,
    }

    /// Reads no token: the keys that verify them cannot be reached.
    struct UnreachableKeys;

    #[async_trait]
    impl AppSessionTokens for UnreachableKeys {
        async fn issue(
            &self,
            _: &ScopedTenant,
            _: &AppSessionGrant,
        ) -> Result<IssuedAppSession, DomainError> {
            Err(DomainError::infra_msg("the signing keys are unreachable"))
        }

        async fn issue_access(
            &self,
            _: &ScopedTenant,
            _: &AppAccessGrant,
        ) -> Result<IssuedAppSession, DomainError> {
            Err(DomainError::infra_msg("the signing keys are unreachable"))
        }

        async fn read(
            &self,
            _: &ScopedTenant,
            _: &Secret,
            _: &DomainName,
        ) -> Result<AppSessionClaim, DomainError> {
            Err(DomainError::infra_msg("the signing keys are unreachable"))
        }
    }

    fn fixture_claiming(service_of: impl FnOnce(ServiceId) -> ServiceId) -> Fixture {
        fixture_reading(|session_id, user_id, shop_id| {
            Arc::new(FakeAppSessionTokens {
                claim: Mutex::new(Some(AppSessionClaim {
                    session_id,
                    user_id,
                    service_id: service_of(shop_id),
                    idle_timeout: None,
                    signed_in_from: Fact::Unknown,
                })),
                ..FakeAppSessionTokens::default()
            })
        })
    }

    fn fixture_reading(
        tokens_for: impl FnOnce(SessionId, UserId, ServiceId) -> Arc<dyn AppSessionTokens>,
    ) -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let bob = UserId::new();
        let mut session = password_session(bob, "hash", SecondFactor::NotOwed);
        session.bind_to_app(shop_id).unwrap();
        let session_id = *session.id();
        let sessions = Arc::new(FakeSessionStore::with_session(clone_session(&session)));
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            tokens: tokens_for(session_id, bob, shop_id),
            ..SignInPorts::fakes()
        };
        let logout = LogoutUseCase::new(LogoutPorts {
            session_store: sessions.clone(),
            ..LogoutPorts::fakes()
        });
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(ports, base, app_sign_in_lifetimes());
        Fixture {
            use_case: AppLogOutUseCase::new(Arc::new(common), Arc::new(logout)),
            shop: shop_id,
            sessions,
            session_id,
        }
    }

    fn log_out(f: &Fixture, cookie: Option<&str>) -> Result<AppSignInOutcome, AppError> {
        let ctx = cross_host_ctx(f.shop, SHOP_HOST);
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(f.use_case.execute(&ctx, &auditor, cookie.map(Secret::new)))
    }

    /// Bob signs out on the shop. His session ends and the cookies go.
    #[test]
    fn signing_out_ends_the_cookies_session() {
        let f = fixture_claiming(|shop| shop);

        let outcome = log_out(&f, Some("cookie"));

        assert!(matches!(outcome, Ok(AppSignInOutcome::SignedOut)));
        assert_eq!(
            f.sessions.get_status(&f.session_id),
            Some(SessionStatus::Revoked)
        );
    }

    /// Bob signs out twice. The session already ended, and he is still
    /// answered as signed out.
    #[test]
    fn signing_out_of_an_ended_session_still_signs_out() {
        let f = fixture_claiming(|shop| shop);
        log_out(&f, Some("cookie")).unwrap();

        let again = log_out(&f, Some("cookie"));

        assert!(matches!(again, Ok(AppSignInOutcome::SignedOut)));
    }

    /// A browser with no cookie signs out. Nothing is ended, and it is
    /// answered as signed out.
    #[test]
    fn signing_out_without_a_cookie_signs_out() {
        let f = fixture_claiming(|shop| shop);

        let outcome = log_out(&f, None);

        assert!(matches!(outcome, Ok(AppSignInOutcome::SignedOut)));
        assert_eq!(
            f.sessions.get_status(&f.session_id),
            Some(SessionStatus::Active)
        );
    }

    /// The keys that verify Bob's cookie cannot be reached when he signs
    /// out. That is a failure on our side, not a sign-out: he is not told
    /// he is signed out while his session goes on.
    #[test]
    fn a_cookie_that_cannot_be_read_fails_as_an_error() {
        let f = fixture_reading(|_, _, _| Arc::new(UnreachableKeys));

        let outcome = log_out(&f, Some("cookie"));

        assert!(matches!(outcome, Err(AppError::Internal(_))));
        assert_eq!(
            f.sessions.get_status(&f.session_id),
            Some(SessionStatus::Active)
        );
    }

    /// Another app's cookie receives a signed-out response from the shop
    /// while the shop's stored session remains active.
    #[test]
    fn another_apps_cookie_ends_nothing() {
        let f = fixture_claiming(|_| ServiceId::new());

        let outcome = log_out(&f, Some("cookie"));

        assert!(matches!(outcome, Ok(AppSignInOutcome::SignedOut)));
        assert_eq!(
            f.sessions.get_status(&f.session_id),
            Some(SessionStatus::Active)
        );
    }
}
