//! Sign out other sessions: the signed-in person ends every session they
//! hold except the one they are using, as after losing a phone.

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignedIn;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`SignOutOtherSessionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SignOutOtherSessionsPorts {
    /// The tenant's sessions.
    pub session_store: Arc<dyn SessionStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Ends every session of the signed-in person but the one they use.
pub struct SignOutOtherSessionsUseCase {
    ports: SignOutOtherSessionsPorts,
}

impl SignOutOtherSessionsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SignOutOtherSessionsPorts) -> Self {
        Self { ports }
    }

    /// The active sessions `person` holds besides the one they came with.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` on storage failure.
    async fn others_held(
        &self,
        tenant: &ScopedTenant,
        person: &SignedInAccount,
    ) -> Result<Vec<Session<ResolvedTenant>>, AppError> {
        let held = self
            .ports
            .session_store
            .list_active_by_user(tenant, person.account.id())
            .await
            .or_internal()?;
        Ok(held
            .into_iter()
            .filter(|held| held.id() != person.session.id())
            .collect())
    }

    /// Ends `session` as `signed_in` and saves it, with what records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the session refuses to end.
    /// - `AppError::Internal` on storage failure.
    async fn ended(
        &self,
        tenant: &ScopedTenant,
        mut session: Session<ResolvedTenant>,
        signed_in: &SignedIn<ResolvedTenant>,
    ) -> Result<Vec<DomainEvent>, AppError> {
        session.revoke(signed_in).map_err(AppError::from_domain)?;
        self.ports
            .session_store
            .save(tenant, &session)
            .await
            .or_internal()?;
        Ok(session.take_events(tenant))
    }
}

impl Command for SignOutOtherSessionsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<u64, AppError>;

    /// Ends every active session of the person signed in to `ctx`'s session
    /// except that one, records `authentication.session_revoked` for each,
    /// and answers how many ended.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<u64, AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let tenant = ctx.tenant();
        let others = self.others_held(&tenant, &person).await?;
        let mut events: Vec<DomainEvent> = Vec::new();
        let mut ended: u64 = 0;
        for session in others {
            events.extend(self.ended(&tenant, session, &person.signed_in).await?);
            ended = ended.saturating_add(1);
        }
        auditor
            .dispatch_by(&ActorRef::User(*person.account.id()), events)
            .await
            .or_internal()?;
        Ok(ended)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeSessionStore, password_session, test_caller_id};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn sign_out(
        sessions: &Arc<FakeSessionStore>,
        authorities: FakeTenantAuthorities,
    ) -> (Result<u64, AppError>, Arc<FakeEventDispatcher>) {
        let sink = Arc::new(FakeEventDispatcher::new());
        let use_case = SignOutOtherSessionsUseCase::new(SignOutOtherSessionsPorts {
            session_store: sessions.clone(),
            tenant_authorities: Arc::new(authorities),
            ..SignOutOtherSessionsPorts::fakes()
        });
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), ()));
        (result, sink)
    }

    /// Ann lost her phone. From her laptop she signs out everywhere else:
    /// the phone's session ends and it is recorded.
    #[test]
    fn every_other_session_ends() {
        let phone = password_session(test_caller_id(), "phone", SecondFactor::NotOwed);
        let id = *phone.id();
        let sessions = Arc::new(FakeSessionStore::with_session(phone));

        let (result, sink) = sign_out(&sessions, FakeTenantAuthorities::holding(&[]));

        assert_eq!(result.unwrap(), 1);
        assert_eq!(sessions.get_status(&id), Some(SessionStatus::Revoked));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authentication.session_revoked"]
        );
    }

    /// Bob's session is not Ann's. Signing out her other sessions leaves it.
    #[test]
    fn another_persons_sessions_stay() {
        let bobs = password_session(
            ianua_domain::types::UserId::new(),
            "bob",
            SecondFactor::NotOwed,
        );
        let id = *bobs.id();
        let sessions = Arc::new(FakeSessionStore::with_session(bobs));

        let (result, _) = sign_out(&sessions, FakeTenantAuthorities::holding(&[]));

        assert_eq!(result.unwrap(), 0);
        assert_eq!(sessions.get_status(&id), Some(SessionStatus::Active));
    }

    /// A signed-out person cannot end their other sessions.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let sessions = Arc::new(FakeSessionStore::empty());

        let (result, _) = sign_out(
            &sessions,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
