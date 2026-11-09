//! Get service account: one account an application binds to the tenant's
//! directory as.

use std::sync::Arc;

use ianua_domain::domains::authentication::directory_service::account::DirectoryServiceAccount;
use ianua_domain::domains::authorization::permission::{AuthConfigAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::DirectoryServiceAccountId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::directory::DirectoryServiceAccountStore;
use crate::use_case::Query;
use crate::use_cases::directory::service_accounts::lookup::existing_service_account;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// The tenant's service accounts.
    pub accounts: Arc<dyn DirectoryServiceAccountStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one directory service account.
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
    type Input = DirectoryServiceAccountId;
    type Output = Result<DirectoryServiceAccount<ResolvedTenant>, AppError>;

    /// The account with `id`, for a caller who may view sign-in settings.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not view sign-in settings.
    /// - `AppError::NotFound` if the account doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: DirectoryServiceAccountId,
    ) -> Result<DirectoryServiceAccount<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::AuthConfig(AuthConfigAction::View))
            .map_err(AppError::from_domain)?;
        existing_service_account(self.ports.accounts.as_ref(), &ctx.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
    use ianua_domain::domains::authentication::directory_service::scope::DirectoryAccess;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::directory_service::{FakeServiceAccountStore, test_service_account};
    use crate::test_support::{block_on, test_ctx};

    fn jira() -> DirectoryServiceAccountId {
        DirectoryServiceAccountId::from_uuid(uuid::Uuid::from_u128(9))
    }

    fn get(
        authorities: FakeTenantAuthorities,
        id: DirectoryServiceAccountId,
    ) -> Result<DirectoryServiceAccount<ResolvedTenant>, AppError> {
        let account = test_service_account(
            jira(),
            DirectoryAccess::ReadOnly,
            ServiceAccountStatus::Active,
        );
        let use_case = GetUseCase::new(GetPorts {
            accounts: Arc::new(FakeServiceAccountStore::holding(
                &test_ctx().tenant(),
                [account],
            )),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), id))
    }

    /// Ann may view sign-in settings. She opens Jira's account.
    #[test]
    fn a_viewer_reads_the_account() {
        let view = [SystemPermission::AuthConfig(AuthConfigAction::View)];

        let account = get(FakeTenantAuthorities::holding(&view), jira()).unwrap();

        assert_eq!(account.name().as_str(), "jira");
    }

    /// Ann names an account Acme does not have. It is not found.
    #[test]
    fn an_unknown_account_is_not_found() {
        let result = get(
            FakeTenantAuthorities::holding_everything(),
            DirectoryServiceAccountId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without sign-in-settings access cannot read Jira's
    /// directory account.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let result = get(FakeTenantAuthorities::holding(&[]), jira());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Replaying a signed-out session returns an authentication error
    /// instead of Jira's account.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = get(FakeTenantAuthorities::refusing(Refusal::SignedOut), jira());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
