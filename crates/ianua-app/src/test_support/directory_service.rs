//! Fakes for the accounts applications bind to the directory as, and their
//! secrets.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::directory_service::account::{
    DirectoryServiceAccount, DirectoryServiceAccountRow, ServiceAccountStatus,
};
use ianua_domain::domains::authentication::directory_service::scope::{
    BaseDn, DirectoryAccess, ServiceAccountName, ServiceAccountScope,
};
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{DirectoryServiceAccountId, Fact, TenantId, TenantSlug, TokenHash};

use crate::ports::TenantScoped;
use crate::ports::directory::{DirectoryServiceAccountStore, ServiceAccountSecrets};
use crate::tenancy::ScopedTenant;
use crate::test_support::authentication::AllowingThrottle;
use crate::test_support::organization::{org_store_with, test_org};
use crate::test_support::tenant::{cfg, tenant_store_in_status};
use crate::test_support::{Fake, FakeEventDispatcher, block_on, test_auditor, test_ctx};
use crate::use_case::Command;
use crate::use_cases::directory::principal::DirectoryBase;
use crate::use_cases::directory::service_accounts::service_principal::ServiceAccountPrincipal;
use crate::use_cases::directory::service_accounts::{BindPorts, BindRequest, BindUseCase};

/// The subtree Jira's account reads.
pub const PEOPLE_DN: &str = "ou=people,dc=acme,dc=test";

/// Jira's secret, the one its account is kept by.
pub const JIRA_SECRET: &str = "jira-secret";

/// The part of the directory a bind in the test tenant names: `acme` of
/// `acme-corp`.
///
/// # Panics
///
/// Never: both slugs are valid.
#[must_use]
pub fn acme_base() -> DirectoryBase {
    let slug = |value: &str| TenantSlug::new(value, &cfg().slug).expect("a valid slug");
    DirectoryBase {
        organization: slug("acme-corp"),
        tenant: slug("acme"),
    }
}

/// The ports a service account bind in the test tenant reads: `acme-corp`
/// and its active tenant `acme`, a throttle that lets every bind through,
/// and `accounts`.
#[must_use]
pub fn service_bind_ports(accounts: Arc<FakeServiceAccountStore>) -> BindPorts {
    BindPorts {
        organizations: org_store_with([test_org(test_ctx().organization_id(), "acme-corp")]),
        tenants: tenant_store_in_status(TenantStatus::Active),
        throttle: Arc::new(AllowingThrottle),
        accounts,
        ..BindPorts::fakes()
    }
}

/// Jira binding to the test tenant with `secret`.
#[must_use]
pub fn jira_binds(secret: &str) -> BindRequest {
    BindRequest {
        base: acme_base(),
        name: ServiceAccountName::new("jira").expect("a valid name"),
        secret: Secret::new(secret),
        ip_address: Fact::Unknown,
    }
}

/// Jira bound to the test tenant with its secret, through `accounts`.
///
/// # Panics
///
/// When the bind is refused, which it is not while `accounts` holds Jira's
/// account switched on.
#[must_use]
pub fn jira_bound(accounts: Arc<FakeServiceAccountStore>) -> ServiceAccountPrincipal {
    let use_case = BindUseCase::new(service_bind_ports(accounts));
    let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
    block_on(use_case.execute(&(), &auditor, jira_binds(JIRA_SECRET)))
        .expect("Jira binds with its secret")
}

/// The hash a [`FakeServiceAccountSecrets`] keeps `raw` by.
#[must_use]
pub fn service_secret_hash(raw: &str) -> TokenHash {
    TokenHash::from_stored(format!("hash:{raw}"))
}

/// Jira's account, `jira`, under `id`, in `status`, with `access` under
/// [`PEOPLE_DN`], kept by the hash of [`JIRA_SECRET`].
///
/// # Panics
///
/// Never: every value is a literal that is valid.
#[must_use]
pub fn test_service_account(
    id: DirectoryServiceAccountId,
    access: DirectoryAccess,
    status: ServiceAccountStatus,
) -> DirectoryServiceAccount<ResolvedTenant> {
    let now = clock::now();
    DirectoryServiceAccount::reconstitute(DirectoryServiceAccountRow {
        id,
        name: ServiceAccountName::new("jira").expect("a valid name"),
        secret_hash: service_secret_hash(JIRA_SECRET),
        scope: ServiceAccountScope::new(
            access,
            vec![BaseDn::new(PEOPLE_DN).expect("a valid base DN")],
        )
        .expect("one base DN"),
        status,
        created_at: now,
        secret_changed_at: now,
    })
    .expect("an account whose secret was set when it was made is a consistent row")
}

/// In-memory store of service accounts, each kept under its tenant.
#[derive(Default)]
pub struct FakeServiceAccountStore {
    accounts: Mutex<Vec<(TenantId, DirectoryServiceAccount<ResolvedTenant>)>>,
}

impl TenantScoped for FakeServiceAccountStore {}

impl FakeServiceAccountStore {
    /// A store holding no account.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `accounts` in `tenant`.
    #[must_use]
    pub fn holding(
        tenant: &ScopedTenant,
        accounts: impl IntoIterator<Item = DirectoryServiceAccount<ResolvedTenant>>,
    ) -> Self {
        let kept = accounts
            .into_iter()
            .map(|account| (**tenant, account))
            .collect();
        Self {
            accounts: Mutex::new(kept),
        }
    }

    /// How many accounts are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.accounts.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: &ScopedTenant,
        keeps: impl Fn(&DirectoryServiceAccount<ResolvedTenant>) -> bool,
    ) -> Result<Vec<DirectoryServiceAccount<ResolvedTenant>>, DomainError> {
        self.accounts
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, account)| tenant == &**tenant_id && keeps(account))
            .map(|(_, account)| copy_account(account))
            .collect()
    }
}

#[async_trait]
impl DirectoryServiceAccountStore for FakeServiceAccountStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DirectoryServiceAccountId,
    ) -> Result<Option<DirectoryServiceAccount<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |account| account.id() == id)?;
        Ok(found.into_iter().next())
    }

    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &ServiceAccountName,
    ) -> Result<Option<DirectoryServiceAccount<ResolvedTenant>>, DomainError> {
        let found = self.matching(tenant_id, |account| account.name() == name)?;
        Ok(found.into_iter().next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<DirectoryServiceAccount<ResolvedTenant>>, DomainError> {
        let mut found = self.matching(tenant_id, |_| true)?;
        found.sort_by(|a, b| a.name().as_str().cmp(b.name().as_str()));
        Ok(found)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        account: &DirectoryServiceAccount<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_account(account)?;
        let mut accounts = self.accounts.lock().unwrap();
        let taken = accounts.iter().any(|(tenant, kept)| {
            tenant == &**tenant_id && kept.name() == account.name() && kept.id() != account.id()
        });
        if taken {
            return Err(DomainError::conflict("another account has this name"));
        }
        accounts.retain(|(tenant, kept)| !(tenant == &**tenant_id && kept.id() == account.id()));
        accounts.push((**tenant_id, copy));
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &DirectoryServiceAccountId,
    ) -> Result<(), DomainError> {
        self.accounts
            .lock()
            .unwrap()
            .retain(|(tenant, kept)| !(tenant == &**tenant_id && kept.id() == id));
        Ok(())
    }
}

impl Fake for Arc<dyn DirectoryServiceAccountStore> {
    fn fake() -> Self {
        Arc::new(FakeServiceAccountStore::empty())
    }
}

/// `account` written out and read back, as storage would return it.
fn copy_account(
    account: &DirectoryServiceAccount<ResolvedTenant>,
) -> Result<DirectoryServiceAccount<ResolvedTenant>, DomainError> {
    DirectoryServiceAccount::reconstitute(DirectoryServiceAccountRow {
        id: *account.id(),
        name: account.name().clone(),
        secret_hash: account.secret_hash().clone(),
        scope: account.scope().clone(),
        status: account.status(),
        created_at: account.created_at(),
        secret_changed_at: account.secret_changed_at(),
    })
}

/// Secrets counted `service-secret-1`, `service-secret-2` and so on, each
/// kept by [`service_secret_hash`].
#[derive(Default)]
pub struct FakeServiceAccountSecrets {
    made: Mutex<u32>,
}

#[async_trait]
impl ServiceAccountSecrets for FakeServiceAccountSecrets {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        let mut made = self.made.lock().unwrap();
        *made = made.saturating_add(1);
        let raw = format!("service-secret-{made}");
        let hash = service_secret_hash(&raw);
        Ok((Secret::new(raw), hash))
    }

    fn hash(&self, presented: &Secret) -> TokenHash {
        service_secret_hash(presented.expose())
    }
}

impl Fake for Arc<dyn ServiceAccountSecrets> {
    fn fake() -> Self {
        Arc::new(FakeServiceAccountSecrets::default())
    }
}
