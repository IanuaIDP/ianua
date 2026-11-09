//! Change service account status: switch an application's account off, so
//! it binds no more, or on again.

use std::sync::Arc;

use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
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

/// The account, and whether it may bind.
pub struct ChangeStatusRequest {
    /// The account.
    pub id: DirectoryServiceAccountId,
    /// On or off.
    pub status: ServiceAccountStatus,
}

/// The ports [`ChangeStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeStatusPorts {
    /// Keeps the tenant's service accounts.
    pub accounts: Arc<dyn DirectoryServiceAccountStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Switches a service account on or off.
pub struct ChangeStatusUseCase {
    ports: ChangeStatusPorts,
}

impl ChangeStatusUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeStatusPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeStatusUseCase {
    type Caller = CallerContext;
    type Input = ChangeStatusRequest;
    type Output = Result<(), AppError>;

    /// Switches the account and records
    /// `authentication.directory_service_account_status_changed`. Switched
    /// off, it binds no more, and binds made before stop counting at their
    /// next request.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not hand out the access the
    ///   account has.
    /// - `AppError::NotFound` if the account doesn't exist.
    /// - `AppError::Domain` if it is already in that status.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeStatusRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_may_grant(DirectoryAccess::ReadOnly)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.accounts.as_ref();
        let mut account = existing_service_account(store, &tenant, &request.id).await?;
        let switched = match request.status {
            ServiceAccountStatus::Active => account.enable(&authority),
            ServiceAccountStatus::Disabled => account.disable(&authority),
        };
        switched.map_err(AppError::from_domain)?;

        store.save(&tenant, &account).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), account.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{AuthConfigAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::directory_service::{FakeServiceAccountStore, test_service_account};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded(
        access: DirectoryAccess,
        status: ServiceAccountStatus,
    ) -> (Arc<FakeServiceAccountStore>, DirectoryServiceAccountId) {
        let id = DirectoryServiceAccountId::new();
        let account = test_service_account(id, access, status);
        let store = FakeServiceAccountStore::holding(&test_ctx().tenant(), [account]);
        (Arc::new(store), id)
    }

    fn switch(
        store: Arc<FakeServiceAccountStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        request: ChangeStatusRequest,
    ) -> Result<(), AppError> {
        let use_case = ChangeStatusUseCase::new(ChangeStatusPorts {
            accounts: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn kept_status(
        store: &FakeServiceAccountStore,
        id: &DirectoryServiceAccountId,
    ) -> ServiceAccountStatus {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .status()
    }

    /// Jira is retired. Ann switches its account off; it binds no more and
    /// the change is recorded.
    #[test]
    fn an_account_is_switched_off_and_recorded() {
        let (store, id) = seeded(DirectoryAccess::ReadOnly, ServiceAccountStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeStatusRequest {
            id,
            status: ServiceAccountStatus::Disabled,
        };

        switch(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request,
        )
        .unwrap();

        assert_eq!(kept_status(&store, &id), ServiceAccountStatus::Disabled);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["authentication.directory_service_account_status_changed"]
        );
    }

    /// Ann switches on an account that is on already. She is told it is in
    /// the wrong state.
    #[test]
    fn an_account_already_on_cannot_be_switched_on() {
        let (store, id) = seeded(DirectoryAccess::ReadOnly, ServiceAccountStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeStatusRequest {
            id,
            status: ServiceAccountStatus::Active,
        };

        let result = switch(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// A caller with the right over sign-in settings alone cannot enable
    /// an account; it stays disabled and no status change is audited.
    #[test]
    fn switching_an_account_needs_the_right_over_users() {
        let (store, id) = seeded(DirectoryAccess::ReadOnly, ServiceAccountStatus::Disabled);
        let audit = Arc::new(FakeEventDispatcher::new());
        let settings_only = [SystemPermission::AuthConfig(AuthConfigAction::Update)];
        let request = ChangeStatusRequest {
            id,
            status: ServiceAccountStatus::Active,
        };

        let result = switch(
            store.clone(),
            FakeTenantAuthorities::holding(&settings_only),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(kept_status(&store, &id), ServiceAccountStatus::Disabled);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann names an account Acme does not have. It is not found.
    #[test]
    fn an_unknown_account_is_not_found() {
        let (store, _) = seeded(DirectoryAccess::ReadOnly, ServiceAccountStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeStatusRequest {
            id: DirectoryServiceAccountId::new(),
            status: ServiceAccountStatus::Disabled,
        };

        let result = switch(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot submit a service-account status change.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded(DirectoryAccess::ReadOnly, ServiceAccountStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeStatusRequest {
            id,
            status: ServiceAccountStatus::Disabled,
        };

        let result = switch(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
