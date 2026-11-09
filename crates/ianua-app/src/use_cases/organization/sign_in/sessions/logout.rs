//! A member signing out of one of their own sessions.
//!
//! The session is named by id, and every member can list session ids. So
//! only the member's own session is ended here; anyone else's reads as
//! absent. Ending another member's session is a platform action, taken
//! through [`RevokeMemberSessionUseCase`].
//!
//! [`RevokeMemberSessionUseCase`]: crate::use_cases::organization::sign_in::RevokeMemberSessionUseCase

use std::sync::Arc;

use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActedBy, ActorRef, OrgUserId, SessionId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgSessionStore;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_org_session;

/// The ports [`OrgLogoutUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgLogoutPorts {
    /// Members' sessions.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Ends one of the caller's own sessions.
pub struct OrgLogoutUseCase {
    ports: OrgLogoutPorts,
}

impl OrgLogoutUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgLogoutPorts) -> Self {
        Self { ports }
    }
}

impl Command for OrgLogoutUseCase {
    type Caller = OrgCaller;
    type Input = SessionId;
    type Output = Result<(), AppError>;

    /// Ends the caller's own session `session_id` and records
    /// `organization.org_session_revoked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the organization turns the caller away.
    /// - `AppError::NotFound` when the session does not exist or is someone
    ///   else's.
    /// - `AppError::Domain` when the session was already ended.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        session_id: SessionId,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let store = self.ports.sessions.as_ref();
        let mut session = existing_org_session(store, organization.id(), &session_id).await?;
        ensure_own_session(&session, actor.member().id())?;
        session
            .revoke(ActedBy::By(control))
            .map_err(AppError::from_domain)?;
        store.save(&session).await.or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*session.org_user_id()),
                session.take_events(),
            )
            .await
            .or_internal()
    }
}

/// Refuses someone else's session as though it did not exist, so the
/// answer never confirms that an id names a live session.
fn ensure_own_session(session: &OrgSession, member: &OrgUserId) -> Result<(), AppError> {
    if session.org_user_id() == member {
        return Ok(());
    }
    Err(AppError::NotFound(message!(
        "app-session-not-found",
        "session not found"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        RecordingOrgSessionStore, org_session_for, org_session_of, password_only, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: OrgLogoutUseCase,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn holding(session: OrgSession, actors: FakeOrgActors) -> Self {
            let sessions = Arc::new(RecordingOrgSessionStore::holding([session]));
            Self {
                uc: OrgLogoutUseCase::new(OrgLogoutPorts {
                    sessions: sessions.clone(),
                    org_actors: Arc::new(actors),
                }),
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn sign_out(&self, session_id: SessionId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                session_id,
            ))
        }

        fn revoked(&self, session_id: &SessionId) -> bool {
            self.sessions
                .saved()
                .iter()
                .any(|session| session.id() == session_id && !session.is_valid())
        }
    }

    /// A session of the test caller, Alice.
    fn callers_session() -> OrgSession {
        let caller = test_org_caller();
        org_session_for(
            *caller.member(),
            caller.organization_id(),
            TenantId::new(),
            password_only(),
        )
    }

    /// Alice signs out of her session. It ends, and the sign-out is
    /// recorded: the event the token cache drops her cached caller by.
    #[test]
    fn signing_out_ends_the_session() {
        let session = callers_session();
        let id = *session.id();
        let setup = Setup::holding(session, FakeOrgActors::in_role(OrgRole::Member));

        setup.sign_out(id).unwrap();

        assert!(setup.revoked(&id));
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_session_revoked"]
        );
    }

    /// Another member's session is treated as not found and is not revoked,
    /// even when the caller is an owner.
    #[test]
    fn someone_elses_session_cannot_be_ended() {
        let caller = test_org_caller();
        let sam = test_org_user(caller.organization_id(), "sam@acme.com", OrgRole::Owner);
        let session = org_session_of(&sam, TenantId::new(), password_only());
        let id = *session.id();
        let setup = Setup::holding(session, FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.sign_out(id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!setup.revoked(&id));
    }

    /// A signed-out caller cannot revoke the requested session.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let session = callers_session();
        let id = *session.id();
        let setup = Setup::holding(session, FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.sign_out(id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(!setup.revoked(&id));
    }

    /// A caller refused by the organization cannot sign out a session, and
    /// no audit event is recorded.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let session = callers_session();
        let id = *session.id();
        let setup = Setup::holding(session, FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.sign_out(id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }
}
