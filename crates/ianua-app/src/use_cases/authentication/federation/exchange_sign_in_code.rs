//! Swapping a single sign-on's one-time code for its session.
//!
//! The session the identity provider opened has a token nobody was ever
//! shown. The dashboard swaps the code for a session carrying it on under a
//! token handed to the caller, out of the address bar. The code works once.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::account_check::SessionCheck;
use ianua_domain::domains::authentication::sessions::session::{RotationRefused, Session};
use ianua_domain::domains::authentication::sessions::sign_in_code::RedeemedSignInCode;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, SessionId};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SignInCodeStore;
use crate::ports::federation::{ProviderSession, ProviderSessionStore};
use crate::ports::identity::UserStore;
use crate::ports::oauth::CodeHasher;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// A one-time code to swap, with the value the dashboard that started the
/// sign-in kept.
pub struct ExchangeSignInCodeRequest {
    /// The code from the address bar.
    pub code: Secret,
    /// The value the dashboard made when it started the sign-in and kept
    /// to itself since.
    pub dashboard_state: Secret,
}

/// The ports [`ExchangeSignInCodeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExchangeSignInCodePorts {
    /// Hashes the presented code.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// The codes issued and not yet used.
    pub codes: Arc<dyn SignInCodeStore>,
    /// The sessions the codes stand in for.
    pub sessions: Arc<dyn SessionStore>,
    /// The account a session belongs to, as it stands now.
    pub users: Arc<dyn UserStore>,
    /// The tenant, for its session timeouts.
    pub tenants: Arc<dyn TenantStore>,
    /// Mints the refresh token handed to the caller.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The provider sessions behind sessions here, which move to the
    /// session handed over.
    pub provider_sessions: Arc<dyn ProviderSessionStore>,
}

/// The session a code was swapped for.
pub struct ExchangedSession {
    /// The session to use from now on.
    pub session_id: SessionId,
    /// Its refresh token, shown this once.
    pub refresh_token: Secret,
    /// What the session still owes in the way of a second factor.
    pub second_factor: SecondFactor,
}

/// Swaps a single sign-on's one-time code for its session.
pub struct ExchangeSignInCodeUseCase {
    ports: ExchangeSignInCodePorts,
}

impl ExchangeSignInCodeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ExchangeSignInCodePorts) -> Self {
        Self { ports }
    }

    /// The session the request's code stands in for, with the code spent
    /// for it, when it comes from the dashboard that started the sign-in.
    async fn redeemed_session(
        &self,
        tenant: &ScopedTenant,
        request: &ExchangeSignInCodeRequest,
        now: OffsetDateTime,
    ) -> Result<(Session<ResolvedTenant>, RedeemedSignInCode), AppError> {
        let hasher = self.ports.code_hasher.as_ref();
        let code_hash = hasher.hash_code(&request.code).await.or_internal()?;
        let dashboard_hash = hasher
            .hash_code(&request.dashboard_state)
            .await
            .or_internal()?;
        let mut code = self
            .ports
            .codes
            .take(tenant, &code_hash)
            .await
            .or_internal()?
            .ok_or_else(refused_code)?;
        let redeemed = code
            .redeem(now, &dashboard_hash)
            .map_err(AppError::from_domain)?;
        self.ports.codes.save(tenant, &code).await.or_internal()?;
        let session = self
            .ports
            .sessions
            .find_by_id(tenant, redeemed.session_id())
            .await
            .or_internal()?
            .ok_or_else(refused_code)?;
        Ok((session, redeemed))
    }

    /// The session carried on under a new token the caller is given, once
    /// the domain hands over the one the provider opened for `code`. It
    /// still owes whatever second factor the provider's sign-in owed.
    async fn handed_over(
        &self,
        tenant: &ScopedTenant,
        parent: &mut Session<ResolvedTenant>,
        code: &RedeemedSignInCode,
        now: OffsetDateTime,
    ) -> Result<(Session<ResolvedTenant>, Secret), AppError> {
        let account = self
            .ports
            .users
            .find_by_id(tenant, parent.user_id())
            .await
            .or_internal()?
            .ok_or_else(refused_code)?;
        let timeout = existing_tenant(self.ports.tenants.as_ref(), tenant)
            .await?
            .auth_config()
            .session_timeout()
            .map_err(AppError::from_domain)?;
        let check = SessionCheck {
            account: &account,
            timeout: &timeout,
            now,
        };
        let (raw, hash) = self
            .ports
            .token_generator
            .generate()
            .or_internal()?
            .into_parts();
        let session = Session::hand_over(parent, code, SessionId::new(), hash, &check)
            .map_err(refused_rotation)?;
        Ok((session, raw))
    }

    /// Moves the provider session behind `retired` to `handed_over`, so a
    /// logout the provider asks for, or one sent to it, still reaches the
    /// session the person goes on with.
    async fn provider_session_carried(
        &self,
        tenant: &ScopedTenant,
        retired: &SessionId,
        handed_over: &SessionId,
    ) -> Result<(), AppError> {
        let store = self.ports.provider_sessions.as_ref();
        let Some(behind) = store.find_by_session(tenant, retired).await.or_internal()? else {
            return Ok(());
        };
        let carried = ProviderSession {
            session_id: *handed_over,
            ..behind
        };
        store.save(tenant, &carried).await.or_internal()?;
        store.delete_by_session(tenant, retired).await.or_internal()
    }
}

impl Command for ExchangeSignInCodeUseCase {
    type Caller = ScopedTenant;
    type Input = ExchangeSignInCodeRequest;
    type Output = Result<ExchangedSession, AppError>;

    /// Swaps the request's code for the session it stands in for, when the
    /// dashboard that started the sign-in asks, retiring the one
    /// whose token nobody was shown and moving the provider session behind
    /// it, if any, to the new one. The new session ends when the sign-in
    /// would have, and still owes the second factor the provider's sign-in
    /// owed, which the caller answers on it next. Records
    /// `authentication.sign_in_code_exchanged`.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` if the code is unknown, used or lapsed, came
    ///   to another dashboard than the one that started the sign-in, its
    ///   session or account is gone, or the session no longer counts: it
    ///   ended or was carried on before, or its account may not sign in.
    /// - `AppError::NotFound` if the tenant no longer exists.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: ExchangeSignInCodeRequest,
    ) -> Result<ExchangedSession, AppError> {
        let now = clock::now();
        let (mut retired, code) = self.redeemed_session(tenant, &request, now).await?;
        let (mut session, refresh_token) =
            self.handed_over(tenant, &mut retired, &code, now).await?;
        self.ports
            .sessions
            .save(tenant, &session)
            .await
            .or_internal()?;
        self.ports
            .sessions
            .save(tenant, &retired)
            .await
            .or_internal()?;
        self.provider_session_carried(tenant, retired.id(), session.id())
            .await?;
        let holder = ActorRef::User(*session.user_id());
        auditor
            .dispatch_by(&holder, session.take_events(tenant))
            .await
            .or_internal()?;
        Ok(ExchangedSession {
            session_id: *session.id(),
            refresh_token,
            second_factor: session.owed(),
        })
    }
}

/// The answer for a code that stands in for nothing that may be used, the
/// same whatever the reason so the code's fate is not told apart.
fn refused_code() -> AppError {
    AppError::Forbidden(message!(
        "authentication-sign-in-code-is-unknown-or",
        "sign-in code is unknown or used"
    ))
}

/// Why the provider's session could not be handed over.
fn refused_rotation(refused: RotationRefused) -> AppError {
    match refused {
        RotationRefused::NotUsable => AppError::Forbidden(message!(
            "authentication-this-sign-in-has-ended",
            "this sign-in has ended"
        )),
        RotationRefused::Transition(transition) => AppError::internal(transition),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::sessions::sign_in_code::{
        CodeHolders, SignInCode, SignInCodeRow,
    };
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{
        ConnectionId, FederatedSubject, Lifetime, SessionIndex, TokenHash, Usage, UserId,
    };

    use super::*;
    use crate::test_support::authentication::{
        FakeSessionStore, FakeSignInCodes, password_session,
    };
    use crate::test_support::federation::FakeProviderSessions;
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::oauth::{FakeCodeHasher, hash_of};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const CODE: &str = "code-from-the-callback";

    /// The value the dashboard that started the sign-in keeps.
    const DASHBOARD: &str = "the-dashboards-own-value";
    const UNSHOWN: &str = "unshown-refresh-hash";

    struct Fixture {
        ann: UserId,
        session_id: SessionId,
        sessions: Arc<FakeSessionStore>,
        codes: Arc<FakeSignInCodes>,
        users: Arc<FakeUserStore>,
        provider_sessions: Arc<FakeProviderSessions>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn with(session: Session<ResolvedTenant>) -> Self {
            let ann = *session.user_id();
            let session_id = *session.id();
            let codes = Arc::new(FakeSignInCodes::empty());
            let holders = CodeHolders {
                code: hash_of(CODE),
                dashboard: hash_of(DASHBOARD),
            };
            let issued =
                SignInCode::issue(&session, holders, Lifetime::seconds(60).unwrap()).unwrap();
            block_on(codes.save(&test_ctx().tenant(), &issued)).unwrap();
            let users = FakeUserStore::empty();
            users.add(stored_user(ann, "ann@acme.com", UserStatus::Active));
            Self {
                ann,
                session_id,
                sessions: Arc::new(FakeSessionStore::with_session(session)),
                codes,
                users: Arc::new(users),
                provider_sessions: Arc::new(FakeProviderSessions::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn signed_in() -> Self {
            Self::with(password_session(
                UserId::new(),
                UNSHOWN,
                SecondFactor::NotOwed,
            ))
        }

        fn exchange(&self, code: &str) -> Result<ExchangedSession, AppError> {
            self.exchange_from(code, DASHBOARD)
        }

        /// Swaps `code` from the dashboard whose kept value is `dashboard`.
        fn exchange_from(&self, code: &str, dashboard: &str) -> Result<ExchangedSession, AppError> {
            let use_case = ExchangeSignInCodeUseCase::new(ExchangeSignInCodePorts {
                code_hasher: Arc::new(FakeCodeHasher::new()),
                codes: self.codes.clone(),
                sessions: self.sessions.clone(),
                users: self.users.clone(),
                tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                provider_sessions: self.provider_sessions.clone(),
                ..ExchangeSignInCodePorts::fakes()
            });
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                ExchangeSignInCodeRequest {
                    code: Secret::new(code),
                    dashboard_state: Secret::new(dashboard),
                },
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann comes back from her provider with the code. She gets a session of
    /// her own with a token she is shown, the one nobody was shown is
    /// retired, and the swap is recorded.
    #[test]
    fn a_code_is_swapped_for_a_session_and_the_unshown_one_retired() {
        let fixture = Fixture::signed_in();

        let exchanged = fixture.exchange(CODE).unwrap();

        let session = fixture.sessions.get_session(&exchanged.session_id).unwrap();
        assert_eq!(session.user_id(), &fixture.ann);
        assert_eq!(exchanged.second_factor, SecondFactor::NotOwed);
        assert_eq!(
            fixture.sessions.get_status(&fixture.session_id),
            Some(SessionStatus::Revoked)
        );
        assert_eq!(
            fixture.recorded(),
            vec!["authentication.sign_in_code_exchanged"]
        );
    }

    /// Ann signed in through Acme's SAML provider, which named her session
    /// there. After the swap her provider session stands behind the session
    /// she goes on with, so the provider's logout still reaches it, and no
    /// longer behind the one retired.
    #[test]
    fn the_provider_session_moves_to_the_session_handed_over() {
        let fixture = Fixture::signed_in();
        let tenant = test_ctx().tenant();
        let behind = ProviderSession {
            session_id: fixture.session_id,
            connection_id: ConnectionId::new(),
            subject: FederatedSubject::new("ann-at-acme").unwrap(),
            session_index: SessionIndex::new("_acme-session").unwrap(),
        };
        block_on(fixture.provider_sessions.save(&tenant, &behind)).unwrap();

        let exchanged = fixture.exchange(CODE).unwrap();

        let moved = block_on(
            fixture
                .provider_sessions
                .find_by_session(&tenant, &exchanged.session_id),
        )
        .unwrap();
        assert_eq!(
            moved,
            Some(ProviderSession {
                session_id: exchanged.session_id,
                ..behind
            })
        );
        let left = block_on(
            fixture
                .provider_sessions
                .find_by_session(&tenant, &fixture.session_id),
        )
        .unwrap();
        assert_eq!(left, None);
    }

    /// Ann's new session ends when her sign-in would have: swapping the code
    /// does not lengthen it.
    #[test]
    fn the_new_session_ends_when_the_sign_in_does() {
        let fixture = Fixture::signed_in();
        let ends = fixture
            .sessions
            .get_session(&fixture.session_id)
            .unwrap()
            .expires_at();

        let exchanged = fixture.exchange(CODE).unwrap();

        let session = fixture.sessions.get_session(&exchanged.session_id).unwrap();
        assert_eq!(session.expires_at(), ends);
    }

    /// Exchanging a sign-in code a second time is forbidden.
    #[test]
    fn a_code_works_once() {
        let fixture = Fixture::signed_in();
        fixture.exchange(CODE).unwrap();

        let replayed = fixture.exchange(CODE);

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
    }

    /// An unknown sign-in code is refused without recording an exchange.
    #[test]
    fn an_unknown_code_is_refused() {
        let fixture = Fixture::signed_in();

        let result = fixture.exchange("made-up");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Signing out the original session prevents its code from being exchanged.
    #[test]
    fn a_code_for_a_session_ended_since_is_refused() {
        let fixture = Fixture::signed_in();
        let mut session = fixture.sessions.get_session(&fixture.session_id).unwrap();
        session
            .sign_out(&TokenHash::from_stored(UNSHOWN.to_owned()))
            .unwrap();
        block_on(fixture.sessions.save(&test_ctx().tenant(), &session)).unwrap();

        let result = fixture.exchange(CODE);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A dashboard value different from the one bound to the code prevents exchange.
    #[test]
    fn a_code_swapped_from_another_dashboard_is_refused() {
        let fixture = Fixture::signed_in();

        let result = fixture.exchange_from(CODE, "anns-own-dashboard-value");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A code whose expiry is one minute in the past cannot be exchanged.
    #[test]
    fn a_lapsed_code_is_refused() {
        let fixture = Fixture::signed_in();
        let codes = Arc::new(FakeSignInCodes::empty());
        let lapsed = SignInCode::reconstitute(SignInCodeRow {
            token_hash: hash_of(CODE),
            dashboard_hash: hash_of(DASHBOARD),
            session_id: fixture.session_id,
            expires_at: clock::now() - time::Duration::minutes(1),
            usage: Usage::Unused,
        })
        .unwrap();
        block_on(codes.save(&test_ctx().tenant(), &lapsed)).unwrap();
        let fixture = Fixture { codes, ..fixture };

        let result = fixture.exchange(CODE);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann's tenant asks for her code after her provider signs her in. The
    /// code is swapped for a session that still owes it, which she answers
    /// next. Until then the session counts for nothing.
    #[test]
    fn a_sign_in_still_owing_a_factor_is_handed_over_owing_it() {
        let fixture = Fixture::with(password_session(
            UserId::new(),
            UNSHOWN,
            SecondFactor::Verify,
        ));

        let exchanged = fixture.exchange(CODE).unwrap();

        let session = fixture.sessions.get_session(&exchanged.session_id).unwrap();
        assert_eq!(exchanged.second_factor, SecondFactor::Verify);
        assert!(!session.is_usable(clock::now()));
        assert_eq!(
            fixture.sessions.get_status(&fixture.session_id),
            Some(SessionStatus::Revoked)
        );
    }

    /// Locking Ann's account after code issuance prevents the exchange.
    #[test]
    fn a_code_for_a_locked_account_is_refused() {
        let fixture = Fixture::signed_in();
        let users = FakeUserStore::empty();
        users.add(stored_user(fixture.ann, "ann@acme.com", UserStatus::Locked));
        let fixture = Fixture {
            users: Arc::new(users),
            ..fixture
        };

        let result = fixture.exchange(CODE);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
