//! Refreshing a session: its refresh token is swapped for a new one, and a
//! new session carries the sign-in on until the original would have ended.
//!
//! A token used again after it was swapped can only be a copy, so it ends
//! every session its user holds. So does a token two refreshes present at
//! the same moment: only one of them swaps it.

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::account_check::SessionCheck;
use ianua_domain::domains::authentication::sessions::session::{RotationRefused, Session};
use ianua_domain::domains::authentication::tokens::refresh::{RefreshToken, RefreshTokenGenerator};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, SessionId, UserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::sessions::holder::{HolderSources, account_label};
use crate::use_cases::authentication::sessions::lookup::owned_refresh_session;

/// A session carried on under a new refresh token.
pub struct RefreshSuccess {
    /// The new session.
    pub session_id: SessionId,
    /// The new raw refresh token, sent to the client and never stored.
    pub refresh_token: Secret,
}

/// The refresh token to swap, and whose session it must be.
pub struct TokenRefreshRequest {
    /// The raw refresh token the client presented.
    pub refresh_token: Secret,
    /// The user the session must belong to.
    pub user_id: UserId,
}

/// The ports [`TokenRefreshUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RefreshPorts {
    /// The tenant's sessions.
    pub session_store: Arc<dyn SessionStore>,
    /// Makes the new refresh token, and hashes a presented one.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// The tenant's users, for the account the session is held to.
    pub users: Arc<dyn UserStore>,
    /// Tenants, for the session timeouts.
    pub tenants: Arc<dyn TenantStore>,
}

/// Swaps a refresh token for a new one.
pub struct TokenRefreshUseCase {
    ports: RefreshPorts,
}

impl TokenRefreshUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RefreshPorts) -> Self {
        Self { ports }
    }

    /// The user's session holding `raw`, while it is not ended.
    ///
    /// A token ended by signing out is refused and nothing more, so a client
    /// retrying with a stale token does not sign its user out everywhere. A
    /// token that was swapped before is a copy: every session the user
    /// holds ends.
    async fn unended_session(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: &TokenRefreshRequest,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        let hash = self
            .ports
            .token_generator
            .hash_raw(request.refresh_token.expose());
        let store = self.ports.session_store.as_ref();
        let mut session = owned_refresh_session(store, tenant, &hash, &request.user_id).await?;
        if !session.is_revoked() {
            return Ok(session);
        }
        if !self.was_rotated(tenant, &session).await? {
            return Err(AppError::Unauthenticated);
        }
        Err(self.reuse_refused(tenant, auditor, &mut session).await)
    }

    /// The refusal of a token used again after it was swapped, once every
    /// session its user holds has ended; or the error ending them failed
    /// with.
    async fn reuse_refused(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        session: &mut Session<ResolvedTenant>,
    ) -> AppError {
        match self.end_everything(tenant, auditor, session).await {
            Ok(()) => AppError::Forbidden(message!(
                "authentication-token-reuse-detected",
                "token reuse detected"
            )),
            Err(failed) => failed,
        }
    }

    async fn was_rotated(
        &self,
        tenant: &ScopedTenant,
        session: &Session<ResolvedTenant>,
    ) -> Result<bool, AppError> {
        self.ports
            .session_store
            .was_rotated(tenant, session.id())
            .await
            .or_internal()
    }

    /// Ends every session of the user whose swapped token came back, and
    /// records it. A failure is an error: a theft response that silently
    /// did not happen leaves the stolen token family alive.
    async fn end_everything(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        session: &mut Session<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let store = self.ports.session_store.as_ref();
        store
            .revoke_all_by_user(tenant, session.user_id())
            .await
            .or_internal()?;
        let account = self
            .ports
            .users
            .find_by_id(tenant, session.user_id())
            .await
            .or_internal()?;
        session.record_token_theft(account_label(account.as_ref(), session.user_id()));
        auditor
            .dispatch_by(&ActorRef::System, session.take_events(tenant))
            .await
            .or_internal()
    }

    /// A new session carrying `parent` on under a fresh token, with the
    /// raw token; `parent` is retired.
    async fn rotated(
        &self,
        tenant: &ScopedTenant,
        parent: &mut Session<ResolvedTenant>,
    ) -> Result<(Secret, Session<ResolvedTenant>), AppError> {
        let sources = HolderSources {
            users: self.ports.users.as_ref(),
            tenants: self.ports.tenants.as_ref(),
        };
        let (account, timeout) = sources.holder(tenant, parent.user_id()).await?;
        let check = SessionCheck {
            account: &account,
            timeout: &timeout,
            now: clock::now(),
        };
        let (raw, hash) = self
            .ports
            .token_generator
            .generate()
            .map(RefreshToken::into_parts)
            .or_internal()?;
        let child = Session::rotate(parent, SessionId::new(), hash, &check).map_err(refused)?;
        Ok((raw, child))
    }

    /// Retires `parent` and keeps `child` in one write, while no other
    /// refresh retired `parent` first. One that did presented the same
    /// token: two refreshes of one token are a copy in use, so it is
    /// refused as reuse, and every session the user holds ends.
    async fn save_rotation(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        rotation: Rotation<'_>,
    ) -> Result<(), AppError> {
        let Rotation { parent, child } = rotation;
        let store = self.ports.session_store.as_ref();
        if store.rotate(tenant, parent, child).await.or_internal()? {
            return Ok(());
        }
        Err(self.reuse_refused(tenant, auditor, parent).await)
    }
}

impl Command for TokenRefreshUseCase {
    type Caller = ScopedTenant;
    type Input = TokenRefreshRequest;
    type Output = Result<RefreshSuccess, AppError>;

    /// Swaps the refresh token for a new one under a new session and
    /// records `authentication.token_refreshed`. The new session ends when
    /// the original sign-in does.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the token matches none of the user's own
    ///   dashboard sessions, or the session no longer counts: it expired,
    ///   went idle, never finished signing in, or its account may no longer
    ///   sign in or changed how it does.
    /// - `AppError::Forbidden` if the token was swapped before and is used
    ///   again, or another refresh swapped it at the same moment, which
    ///   ends every session the user holds.
    /// - `AppError::Unauthenticated` if the session was ended by signing
    ///   out.
    /// - `AppError::Domain` if the tenant's timeouts make no policy.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: TokenRefreshRequest,
    ) -> Result<RefreshSuccess, AppError> {
        let mut parent = self.unended_session(tenant, auditor, &request).await?;
        let (raw, mut child) = self.rotated(tenant, &mut parent).await?;
        let rotation = Rotation {
            parent: &mut parent,
            child: &child,
        };
        self.save_rotation(tenant, auditor, rotation).await?;
        let holder = ActorRef::User(*child.user_id());
        auditor
            .dispatch_by(&holder, child.take_events(tenant))
            .await
            .or_internal()?;
        Ok(RefreshSuccess {
            session_id: *child.id(),
            refresh_token: raw,
        })
    }
}

/// One refresh's swap: the session retired and the one that carries on.
struct Rotation<'a> {
    parent: &'a mut Session<ResolvedTenant>,
    child: &'a Session<ResolvedTenant>,
}

/// The error a session that cannot be carried on answers with.
fn refused(refusal: RotationRefused) -> AppError {
    match refusal {
        RotationRefused::NotUsable => AppError::NotFound(message!(
            "authentication-the-session-no-longer-counts",
            "the session no longer counts"
        )),
        RotationRefused::Transition(transition) => AppError::internal(transition),
    }
}

/// The record of every session ending because a swapped token came back,
/// attributed to the system since nobody legitimate asked for it.
#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{ServiceId, TokenHash};

    use super::*;
    use crate::test_support::authentication::{FakeSessionStore, password_session};
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor,
        test_ctx,
    };

    const ANN_TOKEN: &str = "fake_refresh_ann";
    const ANN_HASH: &str = "fake_hash_ann";
    const ANN_ADDRESS: &str = "ann@acme.test";

    struct Fixture {
        ann: UserId,
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn holding(sessions: Vec<Session<ResolvedTenant>>, ann: UserId) -> Self {
            Self {
                ann,
                users: Arc::new(FakeUserStore::with_user(ann, ANN_ADDRESS)),
                sessions: Arc::new(FakeSessionStore::holding_in(
                    test_ctx().tenant_id(),
                    sessions,
                )),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn signed_in() -> (Self, SessionId) {
            let ann = UserId::new();
            let session = password_session(ann, ANN_HASH, SecondFactor::NotOwed);
            let id = *session.id();
            (Self::holding(vec![session], ann), id)
        }

        fn refresh(&self, raw: &str) -> Result<RefreshSuccess, AppError> {
            self.refresh_as(self.ann, raw, &test_auditor(self.audit.clone()))
        }

        fn refresh_as(
            &self,
            user_id: UserId,
            raw: &str,
            auditor: &RequestAuditor,
        ) -> Result<RefreshSuccess, AppError> {
            let use_case = self.use_case(self.sessions.clone());
            block_on(use_case.execute(&test_ctx().tenant(), auditor, request(user_id, raw)))
        }

        /// Two refreshes of Ann's `raw` arriving together: both read her
        /// session `id` before either swapped it.
        fn refresh_twice_at_once(&self, id: &SessionId, raw: &str) -> Vec<Result<(), AppError>> {
            let seen = FakeSessionStore::with_session(self.sessions.get_session(id).unwrap());
            let use_case =
                self.use_case(Arc::new(ReadBeforeWrite::new(seen, self.sessions.clone())));
            (0..2)
                .map(|_| {
                    let auditor = test_auditor(self.audit.clone());
                    block_on(use_case.execute(
                        &test_ctx().tenant(),
                        &auditor,
                        request(self.ann, raw),
                    ))
                    .map(|_| ())
                })
                .collect()
        }

        fn use_case(&self, sessions: Arc<dyn SessionStore>) -> TokenRefreshUseCase {
            TokenRefreshUseCase::new(RefreshPorts {
                session_store: sessions,
                users: self.users.clone(),
                tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                ..RefreshPorts::fakes()
            })
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn revoked_everything(&self) -> u32 {
            *self.sessions.revoke_all_count.lock().unwrap()
        }
    }

    /// `user_id`'s refresh presenting `raw`.
    fn request(user_id: UserId, raw: &str) -> TokenRefreshRequest {
        TokenRefreshRequest {
            refresh_token: Secret::new(raw),
            user_id,
        }
    }

    /// Ann's session holding [`ANN_HASH`], already swapped for a newer one:
    /// retired, with a child naming it as its parent.
    fn swapped_away(ann: UserId) -> Vec<Session<ResolvedTenant>> {
        let mut parent = password_session(ann, ANN_HASH, SecondFactor::NotOwed);
        let account = stored_user(ann, ANN_ADDRESS, UserStatus::Active);
        let timeout = test_tenant_for_ctx()
            .auth_config()
            .session_timeout()
            .unwrap();
        let check = SessionCheck {
            account: &account,
            timeout: &timeout,
            now: clock::now(),
        };
        let child = Session::rotate(
            &mut parent,
            SessionId::new(),
            TokenHash::from_stored("fake_hash_child".to_owned()),
            &check,
        )
        .unwrap();
        vec![parent, child]
    }

    /// Ann refreshes. A new session carries her sign-in on under a new
    /// token, the old one is retired, and the refresh is recorded.
    #[test]
    fn a_refresh_carries_the_session_on_and_retires_the_old_one() {
        let (fixture, old) = Fixture::signed_in();

        let success = fixture.refresh(ANN_TOKEN).unwrap();

        assert_ne!(success.session_id, old);
        assert_ne!(success.refresh_token.expose(), ANN_TOKEN);
        assert_eq!(
            fixture.sessions.get_status(&old),
            Some(SessionStatus::Revoked)
        );
        assert_eq!(fixture.sessions.session_count(), 2);
        assert_eq!(fixture.recorded(), ["authentication.token_refreshed"]);
    }

    /// Refreshing an unknown token returns NotFound.
    #[test]
    fn an_unknown_token_is_not_found() {
        let (fixture, _) = Fixture::signed_in();

        let result = fixture.refresh("fake_refresh_mallory");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A refresh token paired with another user's identifier returns NotFound.
    #[test]
    fn a_token_of_another_user_is_not_found() {
        let (fixture, _) = Fixture::signed_in();
        let auditor = test_auditor(fixture.audit.clone());

        let result = fixture.refresh_as(UserId::new(), ANN_TOKEN, &auditor);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Refreshing an app-bound session returns NotFound without creating
    /// another session.
    #[test]
    fn an_app_session_cannot_be_refreshed() {
        let ann = UserId::new();
        let mut session = password_session(ann, ANN_HASH, SecondFactor::NotOwed);
        session.bind_to_app(ServiceId::new()).unwrap();
        let fixture = Fixture::holding(vec![session], ann);

        let result = fixture.refresh(ANN_TOKEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 1);
    }

    /// Reusing a rotated token is forbidden, invokes revocation of the user's
    /// sessions and records the session-revoked event.
    #[test]
    fn a_swapped_token_used_again_ends_every_session() {
        let ann = UserId::new();
        let fixture = Fixture::holding(swapped_away(ann), ann);

        let result = fixture.refresh(ANN_TOKEN);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.revoked_everything(), 1);
        assert_eq!(fixture.recorded(), ["authentication.session_revoked"]);
    }

    /// Two refreshes reading the same parent yield one success and one
    /// forbidden result, invoke session revocation, and record refresh and
    /// revocation events in that order.
    #[test]
    fn two_refreshes_of_one_token_at_once_end_every_session() {
        let (fixture, id) = Fixture::signed_in();

        let results = fixture.refresh_twice_at_once(&id, ANN_TOKEN);

        assert!(results[0].is_ok());
        assert!(matches!(results[1], Err(AppError::Forbidden(_))));
        assert_eq!(fixture.revoked_everything(), 1);
        assert_eq!(
            fixture.recorded(),
            [
                "authentication.token_refreshed",
                "authentication.session_revoked"
            ]
        );
    }

    /// Ann signed out, and her client retries with the old token. It is
    /// refused, and her other devices stay signed in.
    #[test]
    fn a_token_ended_by_signing_out_is_refused_and_nothing_more() {
        let ann = UserId::new();
        let mut session = password_session(ann, ANN_HASH, SecondFactor::NotOwed);
        session
            .sign_out(&TokenHash::from_stored(ANN_HASH.to_owned()))
            .unwrap();
        let fixture = Fixture::holding(vec![session], ann);

        let result = fixture.refresh(ANN_TOKEN);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.revoked_everything(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A session still awaiting its second factor returns NotFound on
    /// refresh without creating another session.
    #[test]
    fn an_unfinished_sign_in_is_not_refreshed() {
        let ann = UserId::new();
        let fixture = Fixture::holding(
            vec![password_session(ann, ANN_HASH, SecondFactor::Verify)],
            ann,
        );

        let result = fixture.refresh(ANN_TOKEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.sessions.session_count(), 1);
    }

    /// Refreshing a locked user's session returns NotFound.
    #[test]
    fn a_session_of_a_locked_account_is_not_refreshed() {
        let (signed_in, _) = Fixture::signed_in();
        let locked = FakeUserStore::empty();
        locked.add(stored_user(signed_in.ann, ANN_ADDRESS, UserStatus::Locked));
        let fixture = Fixture {
            users: Arc::new(locked),
            ..signed_in
        };

        let result = fixture.refresh(ANN_TOKEN);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The response to a reused token must be on the record. When the record
    /// cannot be written, the refresh fails as an error, not as a quiet
    /// refusal.
    #[test]
    fn theft_whose_record_cannot_be_written_fails_as_an_error() {
        let ann = UserId::new();
        let fixture = Fixture::holding(swapped_away(ann), ann);
        let auditor = test_auditor(Arc::new(FailingEventDispatcher));

        let result = fixture.refresh_as(ann, ANN_TOKEN, &auditor);

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
