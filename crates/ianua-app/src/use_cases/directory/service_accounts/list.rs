//! List service accounts: the accounts applications bind to the tenant's
//! directory as, by name.

use std::sync::Arc;

use ianua_domain::domains::authentication::directory_service::account::DirectoryServiceAccount;
use ianua_domain::domains::authorization::permission::{AuthConfigAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::DirectoryServiceAccountStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// The tenant's service accounts.
    pub accounts: Arc<dyn DirectoryServiceAccountStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the tenant's directory service accounts.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<DirectoryServiceAccount<ResolvedTenant>>, AppError>;

    /// Every account, by name, for a caller who may view sign-in settings.
    /// No secret is kept to show: only each one's hash.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not view sign-in settings.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<DirectoryServiceAccount<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::AuthConfig(AuthConfigAction::View))
            .map_err(AppError::from_domain)?;
        self.ports.accounts.list(&ctx.tenant()).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
    use ianua_domain::domains::authentication::directory_service::scope::DirectoryAccess;
    use ianua_domain::types::DirectoryServiceAccountId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::directory_service::{FakeServiceAccountStore, test_service_account};
    use crate::test_support::{block_on, test_ctx};

    fn list(
        authorities: FakeTenantAuthorities,
    ) -> Result<Vec<DirectoryServiceAccount<ResolvedTenant>>, AppError> {
        let jira = test_service_account(
            DirectoryServiceAccountId::new(),
            DirectoryAccess::ReadOnly,
            ServiceAccountStatus::Active,
        );
        let use_case = ListUseCase::new(ListPorts {
            accounts: Arc::new(FakeServiceAccountStore::holding(
                &test_ctx().tenant(),
                [jira],
            )),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    /// Ann may view sign-in settings. She sees Jira's account.
    #[test]
    fn a_viewer_lists_the_accounts() {
        let view = [SystemPermission::AuthConfig(AuthConfigAction::View)];

        let accounts = list(FakeTenantAuthorities::holding(&view)).unwrap();

        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].name().as_str(), "jira");
    }

    /// A caller without sign-in-settings access cannot list the tenant's
    /// directory service accounts.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let result = list(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Replaying a signed-out session returns an authentication error
    /// instead of a service-account listing.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
