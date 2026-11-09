//! List accounts: the integration accounts a tenant connected, a page at a
//! time, for someone who may view workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::workflows::IntegrationAccountStore;
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Keeps the accounts.
    pub accounts: Arc<dyn IntegrationAccountStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists integration accounts.
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
    type Input = PageRequest;
    type Output = Result<Page<IntegrationAccount<ResolvedTenant>>, AppError>;

    /// The page `page` asks for of the tenant's accounts, oldest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        page: PageRequest,
    ) -> Result<Page<IntegrationAccount<ResolvedTenant>>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        self.ports
            .accounts
            .list(&ctx.tenant(), &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::account::AccountSharing;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::workflows::{FakeIntegrationAccountStore, person, sheets_account};
    use crate::test_support::{block_on, test_ctx};

    fn listing(
        authorities: FakeTenantAuthorities,
    ) -> Result<Page<IntegrationAccount<ResolvedTenant>>, AppError> {
        let account = sheets_account(&person("bob@corp.test"), AccountSharing::Tenant);
        let use_case = ListUseCase::new(ListPorts {
            accounts: Arc::new(FakeIntegrationAccountStore::holding(&account)),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), PageRequest::default()))
    }

    /// Ann may view workflows. She sees Bob's finance sheets account among
    /// the tenant's accounts.
    #[test]
    fn a_viewer_sees_the_tenants_accounts() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Workflows(WorkflowAction::View)]);

        let page = listing(viewer).unwrap();

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].name().as_str(), "Finance sheets");
    }

    /// A caller without workflow view rights cannot list integration accounts.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = listing(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list integration accounts.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = listing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
