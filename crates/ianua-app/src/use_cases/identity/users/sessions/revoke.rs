//! Revoke user session: ends one of a user's sessions, as the person ends
//! one of their own, such as on a laptop they left signed in, or as someone
//! who may shut users out ends it for them.

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, SessionId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::shared::SessionStore;
use crate::services::lookup::owned_session;
use crate::use_case::Command;
use crate::use_cases::identity::account_control::account_control;
use crate::use_cases::identity::whose::Whose;

/// Whose session to end, and which.
pub struct RevokeSessionRequest {
    /// The signed-in person's own, or another user's.
    pub whose: Whose,
    /// The session to end.
    pub session_id: SessionId,
}

/// The ports [`RevokeSessionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeSessionPorts {
    /// The tenant's sessions.
    pub session_store: Arc<dyn SessionStore>,
    /// The tenant's records of who holds what.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Ends one of a user's sessions.
pub struct RevokeSessionUseCase {
    ports: RevokeSessionPorts,
}

impl RevokeSessionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeSessionPorts) -> Self {
        Self { ports }
    }

    /// The session `request` names, ended as the caller may, and who ended
    /// it.
    async fn ended(
        &self,
        ctx: &CallerContext,
        request: RevokeSessionRequest,
    ) -> Result<(Session<ResolvedTenant>, ActorRef), AppError> {
        let RevokeSessionRequest { whose, session_id } = request;
        match whose {
            Whose::Own => {
                let person = self.ports.tenant_authorities.signed_in(ctx).await?;
                let holder = *person.account.id();
                let mut session = self.session_of(ctx, &session_id, &holder).await?;
                session
                    .revoke(&person.signed_in)
                    .map_err(AppError::from_domain)?;
                Ok((session, ActorRef::User(holder)))
            }
            Whose::OnBehalfOf(user_id) => {
                let session = self.ended_for(ctx, &session_id, &user_id).await?;
                Ok((session, ctx.actor()))
            }
        }
    }

    /// `user_id`'s session `session_id`, ended by a caller who may shut
    /// them out.
    async fn ended_for(
        &self,
        ctx: &CallerContext,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let records = self.ports.access_records.as_ref();
        let tenant = ctx.tenant();
        let shutting_out = AccountAction::ShutOut;
        let control = account_control(records, &tenant, &authority, user_id, shutting_out).await?;
        let mut session = self.session_of(ctx, session_id, user_id).await?;
        session.revoke(&control).map_err(AppError::from_domain)?;
        Ok(session)
    }

    /// `user_id`'s session `session_id`.
    async fn session_of(
        &self,
        ctx: &CallerContext,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<Session<ResolvedTenant>, AppError> {
        let store = self.ports.session_store.as_ref();
        owned_session(store, &ctx.tenant(), session_id, user_id).await
    }
}

impl Command for RevokeSessionUseCase {
    type Caller = CallerContext;
    type Input = RevokeSessionRequest;
    type Output = Result<(), AppError>;

    /// Ends `request.session_id` of `request.whose` and records
    /// `authentication.session_revoked`. It stops working at once.
    ///
    /// Ending someone's session throws them out, as a lock does. Sam may
    /// only edit profiles; without the domain's check he signs Ann out of
    /// every device in the middle of an incident she is handling.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or a person ending their own came with no session.
    /// - `AppError::Forbidden` when the caller may not shut users out,
    ///   checked before anything is read so a made-up id is refused the
    ///   same as a real one, or the user holds more than the caller.
    /// - `AppError::NotFound` when the user has no such session.
    /// - `AppError::Domain` when the session already ended.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: RevokeSessionRequest,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let (mut session, actor) = self.ended(ctx, request).await?;

        self.ports
            .session_store
            .save(&tenant, &session)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&actor, session.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeSessionStore, password_session, test_caller_id};
    use crate::test_support::identity::access_where_holds;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn revoke(
        ports: RevokeSessionPorts,
        whose: Whose,
        session_id: SessionId,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let request = RevokeSessionRequest { whose, session_id };
        let result = block_on(RevokeSessionUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ));
        (result, sink)
    }

    fn holding(sessions: &Arc<FakeSessionStore>) -> RevokeSessionPorts {
        RevokeSessionPorts {
            session_store: sessions.clone(),
            ..RevokeSessionPorts::fakes()
        }
    }

    /// Ann left her laptop signed in at a café. From her phone she ends that
    /// session; it is revoked and recorded.
    #[test]
    fn a_person_ends_one_of_their_sessions() {
        let laptop = password_session(test_caller_id(), "laptop", SecondFactor::NotOwed);
        let id = *laptop.id();
        let sessions = Arc::new(FakeSessionStore::with_session(laptop));

        let (result, sink) = revoke(holding(&sessions), Whose::Own, id);

        result.unwrap();
        assert_eq!(sessions.get_status(&id), Some(SessionStatus::Revoked));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authentication.session_revoked"]
        );
    }

    /// Claiming another person's session as one's own returns not found
    /// and leaves that session active.
    #[test]
    fn someone_elses_session_is_not_found() {
        let anns = password_session(UserId::new(), "anns", SecondFactor::NotOwed);
        let id = *anns.id();
        let sessions = Arc::new(FakeSessionStore::with_session(anns));

        let (result, _) = revoke(holding(&sessions), Whose::Own, id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(sessions.get_status(&id), Some(SessionStatus::Active));
    }

    /// Bob's laptop was stolen. Ann, an admin, ends its session for him.
    #[test]
    fn an_admin_ends_someones_session() {
        let bob = UserId::new();
        let laptop = password_session(bob, "bobs-laptop", SecondFactor::NotOwed);
        let id = *laptop.id();
        let sessions = Arc::new(FakeSessionStore::with_session(laptop));

        let (result, _) = revoke(holding(&sessions), Whose::OnBehalfOf(bob), id);

        result.unwrap();
        assert_eq!(sessions.get_status(&id), Some(SessionStatus::Revoked));
    }

    /// User-update rights do not permit revoking Bob's session. It remains
    /// active, and no revocation event is recorded.
    #[test]
    fn a_caller_who_may_not_shut_users_out_is_refused() {
        let bob = UserId::new();
        let laptop = password_session(bob, "bobs-laptop", SecondFactor::NotOwed);
        let id = *laptop.id();
        let sessions = Arc::new(FakeSessionStore::with_session(laptop));
        let ports = RevokeSessionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Update),
            ])),
            ..holding(&sessions)
        };

        let (result, sink) = revoke(ports, Whose::OnBehalfOf(bob), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(sessions.get_status(&id), Some(SessionStatus::Active));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// User-deactivation rights do not permit revoking Bob's session while
    /// he holds broader user-management rights.
    #[test]
    fn a_user_holding_more_than_the_caller_stays_signed_in() {
        let bob = UserId::new();
        let laptop = password_session(bob, "bobs-laptop", SecondFactor::NotOwed);
        let id = *laptop.id();
        let sessions = Arc::new(FakeSessionStore::with_session(laptop));
        let ports = RevokeSessionPorts {
            access_records: access_where_holds(bob, &[SystemPermission::ManageUsers]),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Users(UserAction::Deactivate),
            ])),
            ..holding(&sessions)
        };

        let (result, _) = revoke(ports, Whose::OnBehalfOf(bob), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out person cannot revoke a session through the own-session route.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let sessions = Arc::new(FakeSessionStore::empty());
        let ports = RevokeSessionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..holding(&sessions)
        };

        let (result, _) = revoke(ports, Whose::Own, SessionId::new());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
