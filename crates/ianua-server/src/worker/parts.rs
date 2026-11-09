//! What every part of the worker builds its use cases from: the platform,
//! the configuration, and the few adapters more than one part takes, each
//! built once here.

mod domains;
mod mail;

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::domain::{DnsResolver, TlsProvisioner};
use ianua_app::ports::organization::OrganizationStore;
use ianua_app::ports::scheduling::{JobQueue, JobTimer};
use ianua_app::ports::shared::RecordedEvents;
use ianua_app::ports::tenant::TenantStore;
use ianua_app::services::account_grants::{AccountGrants, AccountGrantsPorts};
use ianua_app::services::account_now::{AccountsNow, AccountsNowPorts};
use ianua_app::services::issuers::TenantIssuers;
use ianua_app::use_cases::domain::certificates::TlsProvisioners;
use ianua_app::use_cases::workflows::executions::CompanyActions;
use ianua_domain::shared::config::DomainLimits;
use ianua_infra::integrations::InstalledGrantExchanger;
use ianua_infra::postgres::agents::PgRelationshipResolver;
use ianua_infra::postgres::crypto::PgSigningKeyStore;
use ianua_infra::postgres::identity::PgUserStore;
use ianua_infra::postgres::organization::{
    PgOrgTenantGrantStore, PgOrgUserStore, PgOrganizationStore,
};
use ianua_infra::postgres::scheduling::PgJobQueue;
use ianua_infra::postgres::shared::PgRecordedEvents;
use ianua_infra::postgres::tenant::PgTenantStore;
use ianua_infra::postgres::workflows::{PgGrantExchangeLease, PgIntegrationAccountStore};
use ianua_infra::runtime::LocalJobTimer;

pub(super) use self::mail::Mail;
use crate::assembly::{Assembly, assembly};
use crate::config::Config;
use crate::error::ServerError;
use crate::platform::Platform;

/// What the worker's use cases, handlers and planners are built from.
pub(super) struct Parts<'a> {
    /// The shared core.
    pub(super) platform: &'a Platform,
    /// Every setting.
    pub(super) config: &'a Config,
    /// The job queue every job is queued on and claimed from.
    pub(super) jobs: Arc<dyn JobQueue>,
    /// Ends a job's time to run.
    pub(super) timer: Arc<dyn JobTimer>,
    /// Loads tenant standing and scopes background operations to the correct owner.
    pub(super) tenants: Arc<dyn TenantStore>,
    /// Loads company standing and ownership for background operations.
    pub(super) organizations: Arc<dyn OrganizationStore>,
    /// A tenant's recorded events, read back by their record's id.
    pub(super) recorded_events: Arc<dyn RecordedEvents>,
    /// The mail every use case sends, and the handler that delivers it.
    pub(super) mail: Mail,
    /// The DNS lookups that prove a domain.
    pub(super) resolver: Arc<dyn DnsResolver>,
    /// The provisioners certificates are ordered through.
    pub(super) tls: TlsProvisioners,
    /// DNS-01 issuance for platform-owned tenant roots and wildcards.
    pub(super) platform_tls: Arc<dyn TlsProvisioner>,
    /// The tries a job the worker queues gets, where the work sets none of
    /// its own.
    pub(super) attempts: NonZeroU32,
    /// What people hold now, worked out from their accounts as they stand:
    /// those a workflow acts for, and those behind an agent run's
    /// delegation.
    pub(super) accounts_now: Arc<AccountsNow>,
    /// What keeps accounts' short-lived tokens good just before a call.
    pub(super) grants: Arc<AccountGrants>,
    /// The dashboard's own actions, which a workflow's company steps are
    /// made through, built as the API builds them.
    pub(super) company: Arc<CompanyActions>,
}

impl<'a> Parts<'a> {
    /// The parts `platform` and `config` make.
    ///
    /// # Errors
    ///
    /// [`ServerError`] when the mail cannot be built.
    pub(super) fn build(platform: &'a Platform, config: &'a Config) -> Result<Self, ServerError> {
        let databases = &platform.databases;
        let jobs: Arc<dyn JobQueue> = Arc::new(PgJobQueue::new(Arc::clone(databases)));
        let (tenants, organizations) = (tenant_store(platform), organization_store(platform));
        let mail = mail::mail(platform, config, &jobs)?;
        let resolver = Arc::clone(&platform.dns);
        let accounts_now = accounts_now(platform, &organizations);
        let grants = account_grants(platform, config);
        let company = company_actions(platform, config)?;
        Ok(Self {
            recorded_events: Arc::new(PgRecordedEvents::new(Arc::clone(databases))),
            timer: Arc::new(LocalJobTimer),
            tls: domains::provisioners(platform, config, &resolver),
            platform_tls: domains::platform_provisioner(platform, config, &resolver),
            attempts: config.worker.jobs.max_attempts,
            platform,
            config,
            jobs,
            tenants,
            organizations,
            mail,
            resolver,
            accounts_now,
            grants,
            company,
        })
    }

    /// The auditor work that no request asked for records through.
    pub(super) fn system_auditor(&self) -> RequestAuditor {
        RequestAuditor::system(Arc::clone(&self.platform.event_dispatcher))
    }

    /// The tenants' signing keys, sealed at rest under the platform's
    /// sealer.
    pub(super) fn signing_keys(&self) -> Arc<PgSigningKeyStore> {
        let sealer: Arc<dyn SecretEncryptor> = self.platform.secrets.encryptor.clone();
        Arc::new(PgSigningKeyStore::new(
            Arc::clone(&self.platform.databases),
            sealer,
        ))
    }

    /// The issuer each tenant's tokens carry, under the platform's own
    /// address.
    pub(super) fn issuers(&self) -> TenantIssuers {
        TenantIssuers::new(
            Arc::clone(&self.tenants),
            Arc::clone(&self.organizations),
            self.config.deployment.app_base_url.clone(),
        )
    }
}

/// The tenants, as every worker part reads them.
fn tenant_store(platform: &Platform) -> Arc<dyn TenantStore> {
    Arc::new(PgTenantStore::new(
        Arc::clone(&platform.databases),
        DomainLimits::default(),
    ))
}

/// The organizations, as every worker part reads them.
fn organization_store(platform: &Platform) -> Arc<dyn OrganizationStore> {
    Arc::new(PgOrganizationStore::new(
        Arc::clone(&platform.databases),
        DomainLimits::default(),
    ))
}

/// Builds workflow company actions through the same assembly used by the API.
fn company_actions(
    platform: &Platform,
    config: &Config,
) -> Result<Arc<CompanyActions>, ServerError> {
    let Assembly { adapters, settings } = assembly(platform, config)?;
    Ok(Arc::new(ianua_assembly::company(&adapters, &settings)))
}

/// What keeps accounts' short-lived tokens good just before a call.
fn account_grants(platform: &Platform, config: &Config) -> Arc<AccountGrants> {
    let databases = &platform.databases;
    let limit = config.integrations.timeout;
    Arc::new(AccountGrants::new(AccountGrantsPorts {
        accounts: Arc::new(PgIntegrationAccountStore::new(Arc::clone(databases))),
        exchanger: Arc::new(InstalledGrantExchanger::new(
            Arc::clone(&platform.integrations),
            platform.secrets.encryptor.clone(),
            limit,
        )),
        lease: Arc::new(PgGrantExchangeLease::for_exchanges_within(
            Arc::clone(databases),
            limit,
        )),
        unit_of_work: Arc::clone(&platform.unit_of_work),
    }))
}

/// What people hold now, read through the platform's stores.
fn accounts_now(
    platform: &Platform,
    organizations: &Arc<dyn OrganizationStore>,
) -> Arc<AccountsNow> {
    let databases = &platform.databases;
    Arc::new(AccountsNow::new(AccountsNowPorts {
        access_records: Arc::clone(&platform.access_records),
        users: Arc::new(PgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        org_users: Arc::new(PgOrgUserStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        organizations: Arc::clone(organizations),
        org_grants: Arc::new(PgOrgTenantGrantStore::new(Arc::clone(databases))),
        relationships: Arc::new(PgRelationshipResolver::new(Arc::clone(databases))),
    }))
}
