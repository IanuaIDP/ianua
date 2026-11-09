//! Signing out: ending one session, as whoever holds it asks.
//!
//! The refresh token a client holds shows the session is theirs to end,
//! even a sign-in still waiting for its second factor. A caller who came
//! with a session, as an app's cookie carries one, ends it while it still
//! counts for the person signed in to it.

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::ActorRef;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`LogoutUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct LogoutPorts {
    /// The tenant's sessions.
    pub session_store: Arc<dyn SessionStore>,
    /// Hashes a presented refresh token the way it was stored.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// Who is signed in to a caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Who signs out, and what shows the session is theirs.
pub enum SigningOut {
    /// Whoever holds the refresh token, in `tenant`. It ends the session it
    /// belongs to, whether or not the sign-in finished.
    ByToken {
        /// The tenant the session is in.
        tenant: ScopedTenant,
        /// The refresh token the client holds.
        refresh_token: Secret,
    },
    /// The person signed in to the session the caller came with.
    SignedIn(Box<CallerContext>),
}

impl SigningOut {
    fn tenant(&self) -> ScopedTenant {
        match self {
            Self::ByToken { tenant, .. } => *tenant,
            Self::SignedIn(caller) => caller.tenant(),
        }
    }
}

/// Ends one session.
pub struct LogoutUseCase {
    ports: LogoutPorts,
}

impl LogoutUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: LogoutPorts) -> Self {
        Self { ports }
    }

    /// The session holding the refresh token `raw`, signed out by it.
    async fn signed_out_by_token(
        &self,
        tenant: &ScopedTenant,
        raw: &Secret,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        let hash = self.ports.token_generator.hash_raw(raw.expose());
        let mut session = self
            .ports
            .session_store
            .find_by_refresh_token_hash(tenant, &hash)
            .await
            .or_internal()?
            .or_not_found(message!("app-session-not-found", "session not found"))?;
        session.sign_out(&hash).map_err(ending_error)?;
        Ok(session)
    }

    /// The session `caller` came with, ended by the person signed in to it.
    async fn ended_by_its_holder(
        &self,
        caller: &CallerContext,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let mut session = person.session;
        session.revoke(&person.signed_in).map_err(ending_error)?;
        Ok(session)
    }

    async fn ended(&self, who: &SigningOut) -> Result<Session<ResolvedTenant>, AppError> {
        match who {
            SigningOut::ByToken {
                tenant,
                refresh_token,
            } => self.signed_out_by_token(tenant, refresh_token).await,
            SigningOut::SignedIn(caller) => self.ended_by_its_holder(caller).await,
        }
    }
}

impl Command for LogoutUseCase {
    type Caller = SigningOut;
    type Input = ();
    type Output = Result<(), AppError>;

    /// Ends the session `who` holds and records
    /// `authentication.session_revoked`.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if no session holds the refresh token.
    /// - `AppError::Unauthenticated` if the caller's session no longer
    ///   counts.
    /// - `AppError::Conflict` if the session already ended.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        who: &SigningOut,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<(), AppError> {
        let tenant = who.tenant();
        let mut session = self.ended(who).await?;
        self.ports
            .session_store
            .save(&tenant, &session)
            .await
            .or_internal()?;
        let holder = ActorRef::User(*session.user_id());
        auditor
            .dispatch_by(&holder, session.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// The error a session that cannot be ended answers with: one already
/// ended is a conflict.
fn ending_error(error: DomainError) -> AppError {
    match error {
        DomainError::InvalidTransition(_) => AppError::Conflict(message!(
            "authentication-the-session-has-already-ended",
            "the session has already ended"
        )),
        other => AppError::from_domain(other),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::types::{SessionId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeSessionStore, password_session};
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };

    const ANN_TOKEN: &str = "fake_refresh_ann";
    const ANN_HASH: &str = "fake_hash_ann";

    struct Fixture {
        session_id: SessionId,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn holding(session: Session<ResolvedTenant>) -> Self {
            Self {
                session_id: *session.id(),
                sessions: Arc::new(FakeSessionStore::with_session(session)),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn signed_in() -> Self {
            Self::holding(password_session(
                UserId::new(),
                ANN_HASH,
                SecondFactor::NotOwed,
            ))
        }

        fn log_out_as(
            &self,
            authorities: FakeTenantAuthorities,
            who: &SigningOut,
        ) -> Result<(), AppError> {
            let use_case = LogoutUseCase::new(LogoutPorts {
                session_store: self.sessions.clone(),
                tenant_authorities: Arc::new(authorities),
                ..LogoutPorts::fakes()
            });
            block_on(use_case.execute(who, &test_auditor(self.audit.clone()), ()))
        }

        fn log_out(&self, who: &SigningOut) -> Result<(), AppError> {
            self.log_out_as(FakeTenantAuthorities::holding(&[]), who)
        }

        fn status(&self) -> Option<SessionStatus> {
            self.sessions.get_status(&self.session_id)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn by_token(raw: &str) -> SigningOut {
        SigningOut::ByToken {
            tenant: test_ctx().tenant(),
            refresh_token: Secret::new(raw),
        }
    }

    /// Ann signs out with the refresh token her browser holds. Her session
    /// ends and the sign-out is recorded.
    #[test]
    fn signing_out_by_token_ends_the_session_and_audits() {
        let fixture = Fixture::signed_in();

        fixture.log_out(&by_token(ANN_TOKEN)).unwrap();

        assert_eq!(fixture.status(), Some(SessionStatus::Revoked));
        assert_eq!(fixture.recorded(), ["authentication.session_revoked"]);
    }

    /// Ann typed her password and closes the tab before her code. The token
    /// her browser holds still ends the half-finished sign-in.
    #[test]
    fn an_unfinished_sign_in_is_ended_by_its_token() {
        let fixture = Fixture::holding(password_session(
            UserId::new(),
            ANN_HASH,
            SecondFactor::Verify,
        ));

        fixture.log_out(&by_token(ANN_TOKEN)).unwrap();

        assert_eq!(fixture.status(), Some(SessionStatus::Revoked));
    }

    /// Ann signs out of the session her app cookie carries. It ends, and
    /// the sign-out is recorded.
    #[test]
    fn the_session_a_caller_came_with_is_ended_by_its_holder() {
        let fixture = Fixture {
            session_id: test_session_id(),
            ..Fixture::signed_in()
        };

        fixture
            .log_out(&SigningOut::SignedIn(Box::new(test_ctx())))
            .unwrap();

        assert_eq!(fixture.status(), Some(SessionStatus::Revoked));
        assert_eq!(fixture.recorded(), ["authentication.session_revoked"]);
    }

    /// Signing out by refresh token records the session-revoked event used
    /// by caller-cache invalidation.
    #[test]
    fn signing_out_records_what_drops_the_cached_caller() {
        let fixture = Fixture::signed_in();

        fixture.log_out(&by_token(ANN_TOKEN)).unwrap();

        assert_eq!(fixture.recorded(), ["authentication.session_revoked"]);
    }

    /// Ann signs herself out. The record names her as the actor and does
    /// not repeat her in its details.
    #[test]
    fn the_record_names_the_user_only_as_the_actor() {
        let fixture = Fixture::signed_in();

        fixture.log_out(&by_token(ANN_TOKEN)).unwrap();

        let payload = fixture.audit.payload_of("authentication.session_revoked");
        assert!(payload.value("user").is_none());
        assert_eq!(payload.get("reason"), Some("logout"));
    }

    /// An unknown refresh token returns NotFound, leaves the existing
    /// session active and records no event.
    #[test]
    fn an_unknown_token_is_not_found() {
        let fixture = Fixture::signed_in();

        let result = fixture.log_out(&by_token("fake_refresh_mallory"));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.status(), Some(SessionStatus::Active));
        assert!(fixture.recorded().is_empty());
    }

    /// Ann signs out twice with the same token. The second time the session
    /// has already ended, and nothing more is recorded.
    #[test]
    fn signing_out_twice_is_a_conflict() {
        let fixture = Fixture::signed_in();
        fixture.log_out(&by_token(ANN_TOKEN)).unwrap();

        let again = fixture.log_out(&by_token(ANN_TOKEN));

        assert!(matches!(again, Err(AppError::Conflict(_))));
        assert_eq!(fixture.recorded().len(), 1);
    }

    /// A signed-out caller is unauthenticated and records no logout event.
    #[test]
    fn a_caller_whose_session_no_longer_counts_is_refused() {
        let fixture = Fixture::signed_in();

        let result = fixture.log_out_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &SigningOut::SignedIn(Box::new(test_ctx())),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(fixture.recorded().is_empty());
    }
}
