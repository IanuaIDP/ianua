//! List user sessions: the sessions a user holds that are still active, for
//! the person themselves or for someone who may view users.

use std::sync::Arc;

use ianua_domain::domains::authentication::sessions::session::Session;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::services::lookup::existing_user;
use crate::use_case::Query;
use crate::use_cases::identity::whose::{Whose, readable_account};

/// The ports [`ListSessionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListSessionsPorts {
    /// The tenant's sessions.
    pub session_store: Arc<dyn SessionStore>,
    /// The tenant's users, so a user it does not hold is not found.
    pub user_store: Arc<dyn UserStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists a user's active sessions.
pub struct ListSessionsUseCase {
    ports: ListSessionsPorts,
}

impl ListSessionsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListSessionsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListSessionsUseCase {
    type Caller = CallerContext;
    type Input = Whose;
    type Output = Result<Vec<Session<ResolvedTenant>>, AppError>;

    /// The active sessions of `whose`, newest sign-in first: where and when
    /// each began and was last used. A session's tokens are never part of
    /// what is shown.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or a person listing their own came with no session.
    /// - `AppError::Forbidden` when the caller lists another user's without
    ///   the right to view users.
    /// - `AppError::NotFound` when the tenant holds no such user, as for a
    ///   user of another tenant.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        whose: Whose,
    ) -> Result<Vec<Session<ResolvedTenant>>, AppError> {
        let authorities = self.ports.tenant_authorities.as_ref();
        let user_id = readable_account(authorities, ctx, whose).await?;
        let tenant = ctx.tenant();
        existing_user(self.ports.user_store.as_ref(), &tenant, &user_id).await?;
        self.ports
            .session_store
            .list_active_by_user(&tenant, &user_id)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakeSessionStore, password_session, test_caller_id};
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{block_on, test_ctx};

    fn list(
        sessions: FakeSessionStore,
        users: FakeUserStore,
        authorities: FakeTenantAuthorities,
        whose: Whose,
    ) -> Result<Vec<Session<ResolvedTenant>>, AppError> {
        let use_case = ListSessionsUseCase::new(ListSessionsPorts {
            session_store: Arc::new(sessions),
            user_store: Arc::new(users),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), whose))
    }

    fn may_view_users() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Users(UserAction::View)])
    }

    /// Ann is signed in on her laptop and her phone. She sees both.
    #[test]
    fn a_person_sees_their_own_sessions() {
        let ann = test_caller_id();
        let sessions = FakeSessionStore::holding_in(
            test_ctx().tenant_id(),
            [
                password_session(ann, "laptop", SecondFactor::NotOwed),
                password_session(ann, "phone", SecondFactor::NotOwed),
            ],
        );

        let listed = list(
            sessions,
            FakeUserStore::with_user(ann, "ann@example.com"),
            FakeTenantAuthorities::holding(&[]),
            Whose::Own,
        )
        .unwrap();

        assert_eq!(listed.len(), 2);
    }

    /// Ann, who may view users, sees Bob's sessions while looking into a
    /// stolen laptop.
    #[test]
    fn an_admin_sees_someones_sessions() {
        let bob = UserId::new();
        let sessions = FakeSessionStore::with_session(password_session(
            bob,
            "bobs-laptop",
            SecondFactor::NotOwed,
        ));

        let listed = list(
            sessions,
            FakeUserStore::with_user(bob, "bob@example.com"),
            may_view_users(),
            Whose::OnBehalfOf(bob),
        )
        .unwrap();

        assert_eq!(listed[0].user_id(), &bob);
    }

    /// Listing sessions for a user absent from the tenant returns not found
    /// instead of an empty session list.
    #[test]
    fn a_user_the_tenant_does_not_hold_is_not_found() {
        let result = list(
            FakeSessionStore::empty(),
            FakeUserStore::empty(),
            may_view_users(),
            Whose::OnBehalfOf(UserId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without user-viewing rights cannot list another user's sessions.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let result = list(
            FakeSessionStore::empty(),
            FakeUserStore::empty(),
            FakeTenantAuthorities::holding(&[]),
            Whose::OnBehalfOf(UserId::new()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out person cannot list their own sessions.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(
            FakeSessionStore::empty(),
            FakeUserStore::empty(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Whose::Own,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
