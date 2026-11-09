//! Delete service account: an application's account is retired, so it
//! binds no more and every connection bound as it reads nothing more.

use std::sync::Arc;

use ianua_domain::domains::authentication::directory_service::control::DirectoryControlCheck as _;
use ianua_domain::domains::authentication::directory_service::scope::DirectoryAccess;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::DirectoryServiceAccountId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::DirectoryServiceAccountStore;
use crate::use_case::Command;
use crate::use_cases::directory::service_accounts::lookup::existing_service_account;

/// The account to delete.
pub struct DeleteRequest {
    /// The account.
    pub id: DirectoryServiceAccountId,
}

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Keeps the tenant's service accounts.
    pub accounts: Arc<dyn DirectoryServiceAccountStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a service account.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = DeleteRequest;
    type Output = Result<(), AppError>;

    /// Deletes the account and records
    /// `authentication.directory_service_account_deleted`. A connection
    /// bound as it finds the account gone at its next search, and reads
    /// nothing more.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not hand out the access the
    ///   account has.
    /// - `AppError::NotFound` if the account doesn't exist.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DeleteRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_may_grant(DirectoryAccess::ReadOnly)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.accounts.as_ref();
        let mut account = existing_service_account(store, &tenant, &request.id).await?;
        account.delete(&authority).map_err(AppError::from_domain)?;
        store.delete(&tenant, account.id()).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), account.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
    use ianua_domain::domains::authorization::permission::{AuthConfigAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::directory_service::{FakeServiceAccountStore, test_service_account};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded(
        access: DirectoryAccess,
    ) -> (Arc<FakeServiceAccountStore>, DirectoryServiceAccountId) {
        let id = DirectoryServiceAccountId::new();
        let account = test_service_account(id, access, ServiceAccountStatus::Active);
        let store = FakeServiceAccountStore::holding(&test_ctx().tenant(), [account]);
        (Arc::new(store), id)
    }

    fn delete(
        store: Arc<FakeServiceAccountStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        id: DirectoryServiceAccountId,
    ) -> Result<(), AppError> {
        let use_case = DeleteUseCase::new(DeletePorts {
            accounts: store,
            tenant_authorities: Arc::new(authorities),
        });
        let request = DeleteRequest { id };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    /// Jira is retired. Ann deletes its account; it is gone and the
    /// deletion is recorded.
    #[test]
    fn an_account_is_deleted_and_recorded() {
        let (store, id) = seeded(DirectoryAccess::ReadOnly);
        let audit = Arc::new(FakeEventDispatcher::new());

        delete(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            id,
        )
        .unwrap();

        assert_eq!(store.count(), 0);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["authentication.directory_service_account_deleted"]
        );
    }

    /// A caller with the right over sign-in settings alone cannot delete
    /// an account; it stays and no deletion is audited.
    #[test]
    fn deleting_an_account_needs_the_right_over_users() {
        let (store, id) = seeded(DirectoryAccess::ReadOnly);
        let audit = Arc::new(FakeEventDispatcher::new());
        let settings_only = [SystemPermission::AuthConfig(AuthConfigAction::Update)];

        let result = delete(
            store.clone(),
            FakeTenantAuthorities::holding(&settings_only),
            &audit,
            id,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann names an account Acme does not have. It is not found.
    #[test]
    fn an_unknown_account_is_not_found() {
        let (store, _) = seeded(DirectoryAccess::ReadOnly);
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = delete(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            DirectoryServiceAccountId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
