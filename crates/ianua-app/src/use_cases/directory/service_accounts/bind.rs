//! Bind service account: an application such as Jira, GitLab or SSSD binds
//! to the tenant's directory as its own account, with its secret.
//!
//! The tenant admits the bind first, as it admits a sign-in, and binds are
//! held to the tenant's bind rate. Every refusal reads the same, so a bind
//! never tells an unknown organization, tenant or account from a wrong
//! secret, and the secret is hashed whether or not the account exists.

use std::sync::Arc;

use ianua_domain::domains::authentication::directory_service::bind::ServiceAccountBind;
use ianua_domain::domains::authentication::directory_service::scope::ServiceAccountName;
use ianua_domain::domains::authentication::events::login::LoginFailureReason;
use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::operations::directory_attempt::DirectoryBindAttempt;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, Fact, IpAddress};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::{BindThrottle, DirectoryServiceAccountStore, ServiceAccountSecrets};
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::sign_in_gate;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::directory::admission::{
    ensure_within_bind_rate, invalid_credentials, named_tenant,
};
use crate::use_cases::directory::principal::DirectoryBase;
use crate::use_cases::directory::service_accounts::service_principal::ServiceAccountPrincipal;

/// One service account bind, as the LDAP adapter read it off the
/// connection. It holds the secret, so it has no `Debug`.
pub struct BindRequest {
    /// The organization and tenant the bind DN names.
    pub base: DirectoryBase,
    /// The account the bind DN names.
    pub name: ServiceAccountName,
    /// The secret presented with the bind.
    pub secret: Secret,
    /// The client's address, or that it could not be told.
    pub ip_address: Fact<IpAddress>,
}

/// What checking a bind came to: the bind, or why it is refused.
type Checked = Result<ServiceAccountBind<ResolvedTenant>, LoginFailureReason>;

/// The ports [`BindUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BindPorts {
    /// Finds the organization the DN names.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Finds the tenant the DN names, which admits the bind.
    pub tenants: Arc<dyn TenantStore>,
    /// Holds each tenant's binds to a rate.
    pub throttle: Arc<dyn BindThrottle>,
    /// Finds the account the DN names.
    pub accounts: Arc<dyn DirectoryServiceAccountStore>,
    /// Hashes the presented secret.
    pub secrets: Arc<dyn ServiceAccountSecrets>,
}

/// Binds directory connections as service accounts.
pub struct BindUseCase {
    ports: BindPorts,
}

impl BindUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: BindPorts) -> Self {
        Self { ports }
    }

    /// The bind the account named in `request` makes with its secret, or
    /// why it is refused. The secret is hashed first, whether or not the
    /// account exists.
    async fn bound(
        &self,
        tenant: &ScopedTenant,
        request: &BindRequest,
        trail: &mut DirectoryBindAttempt<ResolvedTenant>,
    ) -> Result<Checked, AppError> {
        let presented = self.ports.secrets.hash(&request.secret);
        let found = self
            .ports
            .accounts
            .find_by_name(tenant, &request.name)
            .await
            .or_internal()?;
        let Some(account) = found else {
            return Ok(Err(LoginFailureReason::UserNotFound));
        };
        match account.bind(&presented) {
            Ok(bind) => {
                trail.record_service_bind(&account);
                Ok(Ok(bind))
            }
            Err(DomainError::Forbidden(_)) => Ok(Err(LoginFailureReason::BadPassword)),
            Err(other) => Err(AppError::from_domain(other)),
        }
    }
}

impl Command for BindUseCase {
    type Caller = ();
    type Input = BindRequest;
    type Output = Result<ServiceAccountPrincipal, AppError>;

    /// Binds the connection as the account `request` names, when the
    /// secret presented is its own and it is switched on.
    ///
    /// A bind records `authentication.directory_service_bound`; a refused
    /// one in a known tenant records `authentication.login_failed`, naming
    /// the account it tried.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` ("invalid credentials") for an unknown
    ///   organization, tenant or account, a wrong secret, or an account
    ///   switched off, all alike.
    /// - `AppError::TooManyRequests` when the tenant's bind rate is exceeded.
    /// - `AppError::TenantUnavailable` when the tenant is suspended, archived
    ///   or deleted.
    /// - `AppError::Forbidden` when the tenant takes no password sign-in, or
    ///   none from where the bind came from.
    /// - `AppError::Internal` on storage, throttle or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: BindRequest,
    ) -> Result<ServiceAccountPrincipal, AppError> {
        let tenants = self.ports.tenants.as_ref();
        let organizations = self.ports.organizations.as_ref();
        let (organization, tenant) = named_tenant(organizations, tenants, &request.base).await?;
        ensure_within_bind_rate(self.ports.throttle.as_ref(), &tenant).await?;
        let client_ip = request.ip_address.as_ref();
        sign_in_gate::admit(tenants, &tenant, AuthMethod::Password, client_ip).await?;
        let auditor = auditor.with_organization(organization).with_tenant(*tenant);
        let mut trail =
            DirectoryBindAttempt::naming_service(&request.name, request.ip_address.clone());
        let checked = self.bound(&tenant, &request, &mut trail).await?;
        if let Err(reason) = checked.as_ref() {
            trail.record_refusal(*reason);
        }
        auditor
            .dispatch_by(&ActorRef::System, trail.take_events(&tenant))
            .await
            .or_internal()?;
        let bind = checked.map_err(|_| invalid_credentials())?;
        Ok(ServiceAccountPrincipal::bound(
            bind,
            organization,
            tenant,
            request.base,
        ))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::directory_service::account::ServiceAccountStatus;
    use ianua_domain::domains::authentication::directory_service::scope::DirectoryAccess;
    use ianua_domain::types::DirectoryServiceAccountId;

    use super::*;
    use crate::test_support::directory_service::{
        FakeServiceAccountStore, JIRA_SECRET, jira_binds, service_bind_ports, test_service_account,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn holding_jira(status: ServiceAccountStatus) -> Arc<FakeServiceAccountStore> {
        let id = DirectoryServiceAccountId::new();
        let jira = test_service_account(id, DirectoryAccess::ReadOnly, status);
        Arc::new(FakeServiceAccountStore::holding(
            &test_ctx().tenant(),
            [jira],
        ))
    }

    fn bind(
        accounts: Arc<FakeServiceAccountStore>,
        audit: &Arc<FakeEventDispatcher>,
        secret: &str,
    ) -> Result<ServiceAccountPrincipal, AppError> {
        let use_case = BindUseCase::new(service_bind_ports(accounts));
        block_on(use_case.execute(&(), &test_auditor(audit.clone()), jira_binds(secret)))
    }

    /// Jira binds to Acme's directory with its own secret. The connection is
    /// bound as Jira's account, and the bind is recorded.
    #[test]
    fn an_account_binds_with_its_secret() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let principal = bind(
            holding_jira(ServiceAccountStatus::Active),
            &audit,
            JIRA_SECRET,
        )
        .unwrap();

        assert_eq!(**principal.tenant(), test_ctx().tenant_id());
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["authentication.directory_service_bound"]
        );
    }

    /// A wrong secret prevents binding as Jira and records a failed login.
    #[test]
    fn a_wrong_secret_is_refused_and_recorded() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = bind(holding_jira(ServiceAccountStatus::Active), &audit, "guess");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["authentication.login_failed"]
        );
    }

    /// Jira's correct secret cannot bind once its account is disabled.
    #[test]
    fn a_switched_off_account_binds_nothing() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = bind(
            holding_jira(ServiceAccountStatus::Disabled),
            &audit,
            JIRA_SECRET,
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// An absent service account returns invalid credentials rather than
    /// revealing that the requested name is unused.
    #[test]
    fn an_unknown_account_reads_as_a_wrong_secret() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = bind(
            Arc::new(FakeServiceAccountStore::empty()),
            &audit,
            JIRA_SECRET,
        );

        let Err(AppError::NotFound(message)) = result else {
            panic!("an unknown account is refused");
        };
        assert_eq!(message, "invalid credentials");
    }
}
