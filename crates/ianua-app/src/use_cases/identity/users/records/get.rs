//! Get user: one user of the tenant, by id.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::use_case::Query;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads users.
    pub user_store: Arc<dyn UserStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one user of the caller's tenant.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = UserId;
    type Output = Result<User<ResolvedTenant>, AppError>;

    /// The user with `user_id`, for a caller who may view users.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view users.
    /// - `AppError::NotFound` if the user doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        user_id: UserId,
    ) -> Result<User<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Users(UserAction::View))
            .map_err(AppError::from_domain)?;
        existing_user(self.ports.user_store.as_ref(), &ctx.tenant(), &user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{block_on, test_ctx};

    fn use_case_over(users: FakeUserStore) -> GetUseCase {
        GetUseCase::new(GetPorts {
            user_store: Arc::new(users),
            ..GetPorts::fakes()
        })
    }

    /// Ann looks Alice up by her id and gets her account.
    #[test]
    fn a_user_is_found_by_id() {
        let alice = UserId::new();
        let use_case = use_case_over(FakeUserStore::with_user(alice, "alice@acme.com"));

        let user = block_on(use_case.execute(&test_ctx(), alice)).unwrap();

        assert_eq!(*user.id(), alice);
        assert_eq!(user.email().as_str(), "alice@acme.com");
    }

    /// Ann looks up an id the tenant does not have. It is not found.
    #[test]
    fn an_unknown_user_is_not_found() {
        let use_case = use_case_over(FakeUserStore::empty());

        let result = block_on(use_case.execute(&test_ctx(), UserId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without user-viewing rights cannot read Alice's account.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let alice = UserId::new();
        let use_case = GetUseCase::new(GetPorts {
            user_store: Arc::new(FakeUserStore::with_user(alice, "alice@acme.com")),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
        });

        let result = block_on(use_case.execute(&test_ctx(), alice));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller cannot look up a user account.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let use_case = GetUseCase::new(GetPorts {
            user_store: Arc::new(FakeUserStore::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        });

        let result = block_on(use_case.execute(&test_ctx(), UserId::new()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
