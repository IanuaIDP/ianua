//! Change service account scope: what an application's account may do in
//! the directory, and where.

use std::sync::Arc;

use ianua_domain::domains::authentication::directory_service::control::DirectoryControlCheck as _;
use ianua_domain::domains::authentication::directory_service::scope::{
    DirectoryAccess, ServiceAccountScope,
};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::DirectoryServiceAccountId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::DirectoryServiceAccountStore;
use crate::use_case::Command;
use crate::use_cases::directory::service_accounts::lookup::existing_service_account;

/// The account, and the scope it gets.
pub struct ChangeScopeRequest {
    /// The account.
    pub id: DirectoryServiceAccountId,
    /// What it may do from now on, and where.
    pub scope: ServiceAccountScope,
}

/// The ports [`ChangeScopeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeScopePorts {
    /// Keeps the tenant's service accounts.
    pub accounts: Arc<dyn DirectoryServiceAccountStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes what a service account may do, and where.
pub struct ChangeScopeUseCase {
    ports: ChangeScopePorts,
}

impl ChangeScopeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeScopePorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeScopeUseCase {
    type Caller = CallerContext;
    type Input = ChangeScopeRequest;
    type Output = Result<(), AppError>;

    /// Replaces the account's scope and records
    /// `authentication.directory_service_account_scope_changed`. The caller
    /// must be able to hand out the access it gets. Binds made before read
    /// the new scope at their next request.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not hand out the access.
    /// - `AppError::NotFound` if the account doesn't exist.
    /// - `AppError::Internal` on audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeScopeRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_may_grant(DirectoryAccess::ReadOnly)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let store = self.ports.accounts.as_ref();
        let mut account = existing_service_account(store, &tenant, &request.id).await?;
        account
            .change_scope(request.scope, &authority)
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &account).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), account.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
    use ianua_domain::domains::authentication::directory_service::scope::BaseDn;
    use ianua_domain::domains::authorization::permission::{AuthConfigAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::directory_service::{
        FakeServiceAccountStore, PEOPLE_DN, test_service_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A subtree other than the one the seeded account reaches.
    const GROUPS_DN: &str = "ou=groups,dc=acme,dc=example";

    fn seeded() -> (Arc<FakeServiceAccountStore>, DirectoryServiceAccountId) {
        let id = DirectoryServiceAccountId::new();
        let account =
            test_service_account(id, DirectoryAccess::ReadOnly, ServiceAccountStatus::Active);
        let store = FakeServiceAccountStore::holding(&test_ctx().tenant(), [account]);
        (Arc::new(store), id)
    }

    fn scope(base: &str) -> ServiceAccountScope {
        ServiceAccountScope::new(DirectoryAccess::ReadOnly, vec![BaseDn::new(base).unwrap()])
            .unwrap()
    }

    fn change(
        store: Arc<FakeServiceAccountStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        request: ChangeScopeRequest,
    ) -> Result<(), AppError> {
        let use_case = ChangeScopeUseCase::new(ChangeScopePorts {
            accounts: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn kept_bases(store: &FakeServiceAccountStore, id: &DirectoryServiceAccountId) -> Vec<String> {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
            .scope()
            .base_dns()
            .iter()
            .map(|base| base.as_str().to_owned())
            .collect()
    }

    /// GitLab now reads groups instead. Ann points its account there; it
    /// is saved and recorded.
    #[test]
    fn the_scope_is_changed_and_recorded() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeScopeRequest {
            id,
            scope: scope(GROUPS_DN),
        };

        change(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request,
        )
        .unwrap();

        assert_eq!(kept_bases(&store, &id), [GROUPS_DN]);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["authentication.directory_service_account_scope_changed"]
        );
    }

    /// Ann names an account Acme does not have. It is not found.
    #[test]
    fn an_unknown_account_is_not_found() {
        let (store, _) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeScopeRequest {
            id: DirectoryServiceAccountId::new(),
            scope: scope(PEOPLE_DN),
        };

        let result = change(
            store,
            FakeTenantAuthorities::holding_everything(),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller with the right over sign-in settings alone cannot change
    /// Jira's scope; it stays as it was and no change is audited.
    #[test]
    fn changing_the_scope_needs_the_right_over_users() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let settings_only = [SystemPermission::AuthConfig(AuthConfigAction::Update)];
        let before = kept_bases(&store, &id);
        let request = ChangeScopeRequest {
            id,
            scope: scope(GROUPS_DN),
        };

        let result = change(
            store.clone(),
            FakeTenantAuthorities::holding(&settings_only),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(kept_bases(&store, &id), before);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot submit a service-account scope change.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let request = ChangeScopeRequest {
            id,
            scope: scope(PEOPLE_DN),
        };

        let result = change(
            store,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &audit,
            request,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
