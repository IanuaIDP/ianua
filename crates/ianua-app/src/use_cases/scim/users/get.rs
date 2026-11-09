//! Get SCIM user: one of the tenant's users, as the directory reads it.

use std::sync::Arc;

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::UserId;

use crate::acting::ScimAuthorities;
use crate::context::ScimCaller;
use crate::error::AppError;
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_user;
use crate::use_case::Query;

/// The ports [`GetScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Reads the tenant's users.
    pub user_store: Arc<dyn UserStore>,
}

/// Reads one of a tenant's users for its directory.
pub struct GetScimUseCase {
    ports: GetScimPorts,
}

impl GetScimUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetScimPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetScimUseCase {
    type Caller = ScimCaller;
    type Input = UserId;
    type Output = Result<User<ResolvedTenant>, AppError>;

    /// The tenant's user with `user_id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the directory's token is missing,
    ///   not the tenant's current one, or SCIM is switched off.
    /// - `AppError::NotFound` when the tenant has no such user.
    /// - `AppError::Internal` on lookup failure.
    async fn execute(
        &self,
        caller: &ScimCaller,
        user_id: UserId,
    ) -> Result<User<ResolvedTenant>, AppError> {
        self.ports.scim_authorities.endpoint(caller).await?;
        existing_user(self.ports.user_store.as_ref(), caller.tenant(), &user_id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::scim::{SignInRefusal, refused_sign_in, scim_caller, signed_in};

    fn use_case(
        scim_authorities: Arc<dyn ScimAuthorities>,
        users: FakeUserStore,
    ) -> GetScimUseCase {
        GetScimUseCase::new(GetScimPorts {
            scim_authorities,
            user_store: Arc::new(users),
        })
    }

    /// Okta reads Ada's record. It gets her account.
    #[test]
    fn a_user_is_read() {
        let ada = UserId::new();
        let use_case = use_case(signed_in(), FakeUserStore::with_user(ada, "ada@acme.com"));

        let user = block_on(use_case.execute(&scim_caller(), ada)).unwrap();

        assert_eq!(user.email().as_str(), "ada@acme.com");
    }

    /// A directory authenticated in Acme receives not found for a user stored in Globex.
    #[test]
    fn a_user_of_another_tenant_is_not_found() {
        let alan = UserId::new();
        let users = FakeUserStore::empty();
        users.add_in(
            TenantId::new(),
            stored_user(alan, "alan@globex.com", UserStatus::Active),
        );
        let use_case = use_case(signed_in(), users);

        let result = block_on(use_case.execute(&scim_caller(), alan));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Missing, incorrect and rotated tokens, and disabled SCIM, each prevent reading Ada.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        let ada = UserId::new();
        for refusal in SignInRefusal::ALL {
            let (scim_authorities, caller) = refused_sign_in(refusal);
            let use_case = use_case(
                scim_authorities,
                FakeUserStore::with_user(ada, "ada@acme.com"),
            );

            let result = block_on(use_case.execute(&caller, ada));

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
        }
    }
}
