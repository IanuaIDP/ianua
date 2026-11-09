//! Create service account: an account an application such as Jira binds to
//! the tenant's directory as, instead of a person's password.

use std::sync::Arc;

use ianua_domain::domains::authentication::directory_service::account::{
    DirectoryServiceAccount, NewServiceAccount,
};
use ianua_domain::domains::authentication::directory_service::control::DirectoryControlCheck as _;
use ianua_domain::domains::authentication::directory_service::scope::{
    ServiceAccountName, ServiceAccountScope,
};
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::DirectoryServiceAccountId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::{DirectoryServiceAccountStore, ServiceAccountSecrets};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The account to make.
pub struct CreateRequest {
    /// The name it binds with.
    pub name: ServiceAccountName,
    /// What it may do, and where.
    pub scope: ServiceAccountScope,
}

/// The account made, and its secret, shown this once. Holds the secret, so
/// it has no `Debug`.
pub struct CreatedServiceAccount {
    /// The created identity that future directory binds refer to.
    pub id: DirectoryServiceAccountId,
    /// The secret it binds with. Only its hash is kept.
    pub secret: Secret,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Keeps the tenant's service accounts.
    pub accounts: Arc<dyn DirectoryServiceAccountStore>,
    /// Makes the secret.
    pub secrets: Arc<dyn ServiceAccountSecrets>,
    /// Checks the plan has room for another account.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Makes a directory service account.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// Refuses an account beyond the plan's ceiling.
    async fn ensure_within_limit(&self, ctx: &CallerContext) -> Result<(), AppError> {
        self.ports
            .limit_enforcer
            .check_tenant_limit(
                ctx.plan_limits(),
                &ctx.tenant(),
                ResourceKind::DirectoryServiceAccounts,
            )
            .await
            .map_err(AppError::from_domain)
    }

    /// Refuses a name another account of the tenant binds with.
    async fn ensure_name_free(
        &self,
        tenant: &ScopedTenant,
        name: &ServiceAccountName,
    ) -> Result<(), AppError> {
        let taken = self
            .ports
            .accounts
            .find_by_name(tenant, name)
            .await
            .or_internal()?;
        if taken.is_some() {
            return Err(AppError::Conflict(message!(
                "directory-another-service-account-has-this-name",
                "another service account has this name"
            )));
        }
        Ok(())
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<CreatedServiceAccount, AppError>;

    /// Makes an active account and records
    /// `authentication.directory_service_account_created`. Its secret comes
    /// back once; only the hash is kept. The caller must be able to change
    /// sign-in settings and hold the right over users the access reaches.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not hand out the access, or
    ///   the plan's limit is reached.
    /// - `AppError::Conflict` if another account has the name.
    /// - `AppError::Internal` on secret, audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<CreatedServiceAccount, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_may_grant(request.scope.access())
            .map_err(AppError::from_domain)?;
        self.ensure_within_limit(ctx).await?;
        let tenant = ctx.tenant();
        self.ensure_name_free(&tenant, &request.name).await?;
        let (secret, secret_hash) = self.ports.secrets.generate().await.or_internal()?;
        let new = NewServiceAccount {
            name: request.name,
            secret_hash,
            scope: request.scope,
        };
        let mut account =
            DirectoryServiceAccount::create(new, &authority).map_err(AppError::from_domain)?;

        self.ports
            .accounts
            .save(&tenant, &account)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), account.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(CreatedServiceAccount {
            id: *account.id(),
            secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::directory_service::scope::{
        BaseDn, DirectoryAccess,
    };
    use ianua_domain::domains::authorization::permission::{
        AuthConfigAction, SystemPermission, UserAction,
    };

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::directory_service::{
        FakeServiceAccountStore, PEOPLE_DN, service_secret_hash,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    /// Who may hand out directory access.
    const READ_GRANTER: [SystemPermission; 2] = [
        SystemPermission::AuthConfig(AuthConfigAction::Update),
        SystemPermission::Users(UserAction::View),
    ];

    fn request(access: DirectoryAccess) -> CreateRequest {
        CreateRequest {
            name: ServiceAccountName::new("jira").unwrap(),
            scope: ServiceAccountScope::new(access, vec![BaseDn::new(PEOPLE_DN).unwrap()]).unwrap(),
        }
    }

    fn create(
        ports: CreatePorts,
        audit: &Arc<FakeEventDispatcher>,
        request: CreateRequest,
    ) -> Result<CreatedServiceAccount, AppError> {
        let use_case = CreateUseCase::new(ports);
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn ports_over(
        store: Arc<FakeServiceAccountStore>,
        authorities: FakeTenantAuthorities,
    ) -> CreatePorts {
        CreatePorts {
            accounts: store,
            tenant_authorities: Arc::new(authorities),
            ..CreatePorts::fakes()
        }
    }

    /// Ann sets up Jira with read-only access to Acme's people. Jira's
    /// secret is shown once, only its hash is kept, and the account is
    /// recorded.
    #[test]
    fn an_account_is_made_and_its_secret_shown_once() {
        let store = Arc::new(FakeServiceAccountStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());

        let created = create(
            ports_over(store.clone(), FakeTenantAuthorities::holding(&READ_GRANTER)),
            &audit,
            request(DirectoryAccess::ReadOnly),
        )
        .unwrap();

        let kept = block_on(store.find_by_id(&test_ctx().tenant(), &created.id))
            .unwrap()
            .unwrap();
        assert_eq!(
            *kept.secret_hash(),
            service_secret_hash(created.secret.expose())
        );
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["authentication.directory_service_account_created"]
        );
    }

    /// Ann names a second account `jira`. The name is taken, so it is
    /// refused.
    #[test]
    fn a_name_already_used_conflicts() {
        let store = Arc::new(FakeServiceAccountStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let ports = || ports_over(store.clone(), FakeTenantAuthorities::holding_everything());
        create(ports(), &audit, request(DirectoryAccess::ReadOnly)).unwrap();

        let result = create(ports(), &audit, request(DirectoryAccess::ReadOnly));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(store.count(), 1);
    }

    /// A full plan forbids creating another directory service account,
    /// leaving both the account store and audit empty.
    #[test]
    fn a_full_plan_refuses_another_account() {
        let store = Arc::new(FakeServiceAccountStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let ports = CreatePorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports_over(store.clone(), FakeTenantAuthorities::holding_everything())
        };

        let result = create(ports, &audit, request(DirectoryAccess::ReadOnly));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// The right over sign-in settings alone cannot make an account;
    /// neither an account nor an audit event is saved.
    #[test]
    fn making_an_account_needs_the_right_over_users() {
        let store = Arc::new(FakeServiceAccountStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let settings_only = [SystemPermission::AuthConfig(AuthConfigAction::Update)];

        let result = create(
            ports_over(
                store.clone(),
                FakeTenantAuthorities::holding(&settings_only),
            ),
            &audit,
            request(DirectoryAccess::ReadOnly),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session receives an authentication error when creating
    /// a read-only service account.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeServiceAccountStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = create(
            ports_over(store, FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            &audit,
            request(DirectoryAccess::ReadOnly),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
