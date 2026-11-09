//! List user links: the providers an account can be signed in through, one
//! link per connection, for the account's holder or an admin.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
use ianua_domain::domains::federation::link::FederatedLink;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::UserId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::FederatedLinkStore;
use crate::use_case::Query;

/// Whose links to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Of {
    /// The caller's own account, from their own sign-in.
    OwnAccount,
    /// Another user's account, for an admin.
    User(UserId),
}

/// The ports [`ListUserUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListUserPorts {
    /// The links between accounts and providers.
    pub links: Arc<dyn FederatedLinkStore>,
    /// Who the caller is, and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the links an account holds.
pub struct ListUserUseCase {
    ports: ListUserPorts,
}

impl ListUserUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListUserPorts) -> Self {
        Self { ports }
    }

    /// The account whose links `whose` names, once the caller may read
    /// them: their own from their own sign-in, another's when they may view
    /// users.
    async fn account_of(&self, ctx: &CallerContext, whose: Of) -> Result<UserId, AppError> {
        let Of::User(user_id) = whose else {
            let person = self.ports.tenant_authorities.signed_in(ctx).await?;
            return Ok(*person.account.id());
        };
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Users(UserAction::View))
            .map_err(AppError::from_domain)?;
        Ok(user_id)
    }
}

impl Query for ListUserUseCase {
    type Caller = CallerContext;
    type Input = Of;
    type Output = Result<Vec<FederatedLink<ResolvedTenant>>, AppError>;

    /// Every link the account holds, oldest first: the connection, the
    /// subject the provider knows them by, and when it was made and last
    /// confirmed.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or they list their own links without a tenant
    ///   session.
    /// - `AppError::Forbidden` when an admin may not view users.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        whose: Of,
    ) -> Result<Vec<FederatedLink<ResolvedTenant>>, AppError> {
        let user_id = self.account_of(ctx, whose).await?;
        self.ports
            .links
            .list_by_user(&ctx.tenant(), &user_id)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;
    use ianua_domain::types::ConnectionId;

    use super::*;
    use crate::context::CallerIdentity;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeFederatedLinkStore, test_link};
    use crate::test_support::{block_on, test_ctx};

    /// The test caller's own account.
    fn caller_account() -> UserId {
        let CallerIdentity::TenantUser(user_id) = *test_ctx().identity() else {
            unreachable!("the test caller is a tenant user");
        };
        user_id
    }

    /// A store where `user_id` is linked at Okta and at Google.
    fn linked(user_id: UserId) -> FakeFederatedLinkStore {
        let store = FakeFederatedLinkStore::empty();
        let tenant = test_ctx().tenant();
        for connection in [ConnectionId::new(), ConnectionId::new()] {
            block_on(store.save(&tenant, &test_link(connection, user_id, clock::now()))).unwrap();
        }
        store
    }

    fn list(
        store: FakeFederatedLinkStore,
        authorities: FakeTenantAuthorities,
        whose: Of,
    ) -> Result<Vec<FederatedLink<ResolvedTenant>>, AppError> {
        let use_case = ListUserUseCase::new(ListUserPorts {
            links: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), whose))
    }

    /// Ann opens her linked accounts. She sees both providers she signs in
    /// through.
    #[test]
    fn a_holder_lists_their_own_links() {
        let links = list(
            linked(caller_account()),
            FakeTenantAuthorities::holding(&[]),
            Of::OwnAccount,
        )
        .unwrap();

        assert_eq!(links.len(), 2);
    }

    /// Sam may view users. He opens Bob's linked accounts and sees them.
    #[test]
    fn an_admin_who_may_view_users_lists_anothers_links() {
        let bob = UserId::new();
        let view = [SystemPermission::Users(UserAction::View)];

        let links = list(
            linked(bob),
            FakeTenantAuthorities::holding(&view),
            Of::User(bob),
        )
        .unwrap();

        assert_eq!(links.len(), 2);
    }

    /// A caller without user-viewing rights cannot list Bob's provider links.
    #[test]
    fn a_caller_without_the_right_cannot_list_anothers_links() {
        let bob = UserId::new();

        let result = list(
            linked(bob),
            FakeTenantAuthorities::holding(&[]),
            Of::User(bob),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list its own account's provider links.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(
            linked(caller_account()),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Of::OwnAccount,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
