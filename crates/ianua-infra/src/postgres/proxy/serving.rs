//! What the gateway serves across every tenant: the two stores of
//! `ports/proxy/serving.rs`, read under the gateway's own role.
//!
//! The tenants and their organizations' slugs, and the certificates, are
//! kept in the platform database; a tenant's registered domains are tenant
//! rows, in the platform database or in one of the tenant's own. So the
//! domains that serve are read once from the platform database, as
//! platform work, and from each tenant's own database at once, as the
//! sweeps read them: no one query reaches across databases. A tenant that
//! lives apart is read from its own database alone.
//!
//! Every read is held to [`READ_TIMEOUT`], so a database that hangs fails
//! the read rather than the gateway's reload.

mod record;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::{join_all, try_join_all};
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::proxy::{
    CrossTenantHosts, CrossTenantServedCertificates, HostedTenant, ServedBundle, ServedCertificate,
};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::{DomainError, causes};
use ianua_domain::types::{DomainName, TenantId};
use uuid::Uuid;

use self::record::{Certified, HostedRecord, ServingDomain, ServingRecord};
use crate::postgres::domain::certificates::Keys;
use crate::postgres::domain::certificates::record::CertificateRecord;
use crate::postgres::domain::platform::CertificateRecord as PlatformCertificateRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long one read of what the gateway serves may take.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// `read`, failed when it does not answer within [`READ_TIMEOUT`].
async fn in_time<T>(read: impl Future<Output = Result<T, DomainError>>) -> Result<T, DomainError> {
    tokio::time::timeout(READ_TIMEOUT, read)
        .await
        .map_err(|_| DomainError::infra_msg("what the gateway serves was not read in time"))?
}

/// The domains of `tenant` that serve, read from the database it lives in.
async fn serving_of(
    databases: &Databases,
    tenant: TenantId,
) -> Result<Vec<ServingRecord>, DomainError> {
    scoped(
        databases,
        RowScope::Tenant(tenant),
        async move |connection| {
            sqlx::query_file_as!(
                ServingRecord,
                "queries/registered_domains/serving_of_tenant.sql",
                tenant.as_uuid()
            )
            .fetch_all(connection)
            .await
        },
    )
    .await
}

/// The domains of every tenant that serve, wherever each tenant lives.
async fn serving_everywhere(databases: &Databases) -> Result<Vec<ServingDomain>, DomainError> {
    let apart = databases.with_own_database();
    let shared = scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file_as!(ServingRecord, "queries/registered_domains/serving.sql")
            .fetch_all(connection)
            .await
    });
    let own = apart.iter().map(|tenant| serving_of(databases, *tenant));
    let (shared, own) = futures_util::try_join!(shared, try_join_all(own))?;
    let living_apart: HashSet<TenantId> = apart.into_iter().collect();
    shared
        .into_iter()
        .filter(|record| !living_apart.contains(&record.tenant()))
        .chain(own.into_iter().flatten())
        .map(ServingRecord::into_serving)
        .collect()
}

/// The Postgres read of every tenant the gateway serves, with the names
/// each is served on.
pub struct PgCrossTenantHosts {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgCrossTenantHosts {
    /// A read of the tenants in `databases`, checking each slug against
    /// `limits` as it is read back.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }

    /// Every tenant not deleted, with its organization's slug.
    async fn hosted(&self) -> Result<Vec<HostedRecord>, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(HostedRecord, "queries/tenants/hosted.sql")
                .fetch_all(connection)
                .await
        })
        .await
    }

    /// The tenant `tenant_id`, with its organization's slug, if it is kept.
    async fn hosted_one(&self, tenant_id: &TenantId) -> Result<Option<HostedRecord>, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                HostedRecord,
                "queries/tenants/hosted_one.sql",
                tenant_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await
    }

    /// Every tenant served now, each with its serving domains.
    async fn every_hosted(&self) -> Result<Vec<HostedTenant>, DomainError> {
        let (records, domains) =
            futures_util::try_join!(self.hosted(), serving_everywhere(&self.databases))?;
        let mut named: HashMap<TenantId, Vec<DomainName>> = HashMap::new();
        for domain in domains {
            named.entry(domain.tenant).or_default().push(domain.name);
        }
        records
            .into_iter()
            .filter_map(|record| {
                let domains = named.remove(&record.tenant()).unwrap_or_default();
                record.into_hosted(domains, &self.limits.slug).transpose()
            })
            .collect()
    }

    /// The tenant `tenant_id` as it is served now, if it is.
    async fn one_hosted(&self, tenant_id: &TenantId) -> Result<Option<HostedTenant>, DomainError> {
        let Some(record) = self.hosted_one(tenant_id).await? else {
            return Ok(None);
        };
        let domains = serving_of(&self.databases, *tenant_id)
            .await?
            .into_iter()
            .map(|record| record.into_serving().map(|domain| domain.name))
            .collect::<Result<Vec<_>, _>>()?;
        record.into_hosted(domains, &self.limits.slug)
    }
}

#[async_trait]
impl CrossTenantHosts for PgCrossTenantHosts {
    async fn all(&self) -> Result<Vec<HostedTenant>, DomainError> {
        in_time(self.every_hosted()).await
    }

    async fn find(&self, tenant_id: &TenantId) -> Result<Option<HostedTenant>, DomainError> {
        in_time(self.one_hosted(tenant_id)).await
    }
}

/// The Postgres read of the certificate every serving domain is answered
/// with, its private key opened.
pub struct PgCrossTenantServedCertificates {
    databases: Arc<Databases>,
    keys: Keys,
    encryptor: Arc<dyn SecretEncryptor>,
}

impl PgCrossTenantServedCertificates {
    /// A read of the certificates in `databases`, their keys opened by
    /// `encryptor`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, encryptor: Arc<dyn SecretEncryptor>) -> Self {
        Self {
            databases,
            keys: Keys::new(Arc::clone(&encryptor)),
            encryptor,
        }
    }

    /// The newest certificate of each domain `ids` names.
    async fn newest_of(&self, ids: &[Uuid]) -> Result<Vec<CertificateRecord>, DomainError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                CertificateRecord,
                "queries/domain_certificates/current_of_domains.sql",
                ids
            )
            .fetch_all(connection)
            .await
        })
        .await
    }

    /// The certificate `record` holds, served for `domain`, or `None`, and
    /// logged, when it belongs to another tenant than the domain's
    /// registration or its key does not open.
    async fn served(
        &self,
        record: CertificateRecord,
        domain: &ServingDomain,
    ) -> Option<ServedCertificate> {
        if record.tenant() != domain.tenant {
            tracing::warn!(
                domain = %domain.name.as_str(),
                "a certificate is held by another tenant than the domain's registration; it is not served"
            );
            return None;
        }
        match self.keys.opened(record).await {
            Ok(bundle) => Some(ServedCertificate {
                tenant_id: domain.tenant,
                domain: domain.name.clone(),
                bundle: bundle.into(),
            }),
            Err(error) => {
                tracing::error!(
                    domain = %domain.name.as_str(),
                    error = %causes(&error),
                    "a domain's certificate does not open; the domain is not served with it"
                );
                None
            }
        }
    }

    /// The current certificate of every certified domain that serves.
    async fn every_current(&self) -> Result<Vec<ServedCertificate>, DomainError> {
        let certified: HashMap<Uuid, ServingDomain> = serving_everywhere(&self.databases)
            .await?
            .into_iter()
            .filter(|domain| domain.certified == Certified::Yes)
            .map(|domain| (*domain.id.as_uuid(), domain))
            .collect();
        let ids: Vec<Uuid> = certified.keys().copied().collect();
        let records = self.newest_of(&ids).await?;
        let served = join_all(records.into_iter().filter_map(|record| {
            let domain = certified.get(&record.domain_id)?;
            Some(self.served(record, domain))
        }))
        .await;
        let mut served: Vec<_> = served.into_iter().flatten().collect();
        served.extend(self.platform_pairs().await?);
        Ok(served)
    }

    /// Opens current platform pairs, dropping a corrupt pair while preserving other tenants.
    async fn platform_pairs(&self) -> Result<Vec<ServedCertificate>, DomainError> {
        let records = self.platform_records().await?;
        let mut served = Vec::with_capacity(records.len().saturating_mul(2));
        for record in records {
            match record.opened(self.encryptor.as_ref()).await {
                Ok(certificate) => {
                    let certificate = Arc::new(certificate);
                    let wildcard = DomainName::new(format!("*.{}", certificate.root().as_str()))
                        .map_err(DomainError::infra)?;
                    for domain in [certificate.root().clone(), wildcard] {
                        served.push(ServedCertificate {
                            tenant_id: *certificate.tenant_id(),
                            domain,
                            bundle: ServedBundle::Platform(Arc::clone(&certificate)),
                        });
                    }
                }
                Err(error) => {
                    tracing::error!(error = %causes(&error), "a platform certificate does not open; it is not served")
                }
            }
        }
        Ok(served)
    }

    /// Reads platform certificate rows under the gateway's platform scope.
    async fn platform_records(&self) -> Result<Vec<PlatformCertificateRecord>, DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                PlatformCertificateRecord,
                "queries/platform_certificates/served.sql"
            )
            .fetch_all(connection)
            .await
        })
        .await
    }
}

#[async_trait]
impl CrossTenantServedCertificates for PgCrossTenantServedCertificates {
    async fn current(&self) -> Result<Vec<ServedCertificate>, DomainError> {
        in_time(self.every_current()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::domain::{CertificateStore, RegisteredDomainStore};
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_app::ports::tenant::TenantStore;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::tenant::custom_domains::certificate::CertificateBundle;
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        RegisteredDomain, RegisteredDomainRow,
    };
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::domains::tenant::lifecycle::{Tenant, TenantRow};
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{CertificateId, DomainId, OrganizationId};

    use super::*;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::postgres::domain::{PgCertificateStore, PgRegisteredDomainStore};
    use crate::postgres::organization::PgOrganizationStore;
    use crate::postgres::tenant::PgTenantStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::domain::{
        certificate_row, proved_domain_row, registered_domain_row,
    };
    use crate::test_support::rows::organization::organization_row;
    use crate::test_support::rows::tenant::tenant_row;

    struct Fixture {
        db: TestDb,
        encryptor: Arc<dyn SecretEncryptor>,
        organization: OrganizationId,
    }

    /// A fresh database holding the organization `acme`, keys sealed with
    /// a real sealer so a key moved between rows does not open.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        Fixture {
            db,
            encryptor: Arc::new(AesGcmSecretEncryptor::new(
                SealingKey::new("k1", [7; 32]).unwrap(),
                Vec::new(),
            )),
            organization: *organization.id(),
        }
    }

    impl Fixture {
        /// A tenant of `acme` under `slug`, standing at `status`.
        async fn tenant(&self, slug: &str, status: TenantStatus) -> ScopedTenant {
            let tenant = Tenant::reconstitute(TenantRow {
                status,
                ..tenant_row(self.organization, slug)
            })
            .unwrap();
            PgTenantStore::new(Arc::clone(&self.db.databases), DomainLimits::default())
                .save(&tenant)
                .await
                .unwrap();
            ScopedTenant::for_background(*tenant.id())
        }

        /// `row` registered for `tenant`.
        async fn registered(&self, tenant: &ScopedTenant, row: RegisteredDomainRow) -> DomainId {
            let domain: RegisteredDomain<ResolvedTenant> =
                RegisteredDomain::reconstitute(row).unwrap();
            PgRegisteredDomainStore::new(Arc::clone(&self.db.databases))
                .save(tenant, &domain)
                .await
                .unwrap();
            *domain.id()
        }

        /// A certificate the platform issued for `domain` of `tenant`, at
        /// `issued` seconds from the fixed moment.
        async fn certified(
            &self,
            tenant: &ScopedTenant,
            domain: DomainId,
            issued: i64,
        ) -> CertificateId {
            let bundle = CertificateBundle::reconstitute(certificate_row(domain, issued)).unwrap();
            PgCertificateStore::new(Arc::clone(&self.db.databases), Arc::clone(&self.encryptor))
                .save(tenant, &bundle)
                .await
                .unwrap();
            *bundle.id()
        }

        /// The hosts as the gateway's role reads them.
        fn hosts(&self) -> PgCrossTenantHosts {
            PgCrossTenantHosts::new(Arc::clone(&self.db.gateway), DomainLimits::default())
        }

        /// The certificates as the gateway's role reads them.
        fn certificates(&self) -> PgCrossTenantServedCertificates {
            PgCrossTenantServedCertificates::new(
                Arc::clone(&self.db.gateway),
                Arc::clone(&self.encryptor),
            )
        }
    }

    /// A proved registration of `name` whose certificate is active.
    fn active(name: &str) -> RegisteredDomainRow {
        RegisteredDomainRow {
            tls_status: TlsStatus::Active,
            ..proved_domain_row(name)
        }
    }

    /// A proved registration of `name` that needs no certificate.
    fn needing_none(name: &str) -> RegisteredDomainRow {
        RegisteredDomainRow {
            tls_status: TlsStatus::NotRequired,
            ..proved_domain_row(name)
        }
    }

    fn names(hosted: &HostedTenant) -> Vec<&str> {
        let mut names: Vec<&str> = hosted.domains.iter().map(DomainName::as_str).collect();
        names.sort_unstable();
        names
    }

    /// The gateway, signed in as its own role, reads every open tenant with
    /// its slugs and the domains that serve: proved, and with an active
    /// certificate where one is needed. A claim not yet proved, or one
    /// still waiting for its certificate, is not among them.
    #[tokio::test]
    async fn the_gateway_reads_each_open_tenant_with_its_serving_domains() {
        let fx = fixture().await;
        let shop = fx.tenant("shop", TenantStatus::Active).await;
        fx.registered(&shop, active("login.acme.example")).await;
        fx.registered(&shop, needing_none("*.apps.acme.example"))
            .await;
        fx.registered(&shop, proved_domain_row("waiting.acme.example"))
            .await;
        fx.registered(&shop, registered_domain_row("unproved.acme.example"))
            .await;

        let all = fx.hosts().all().await.unwrap();

        assert_eq!(all.len(), 1);
        let hosted = &all[0];
        assert_eq!(hosted.tenant_id, *shop);
        assert_eq!(hosted.organization_slug.as_str(), "acme");
        assert_eq!(hosted.slug.as_str(), "shop");
        assert_eq!(names(hosted), ["*.apps.acme.example", "login.acme.example"]);
    }

    /// Host reads omit a suspended tenant both from the full list and
    /// individual lookup, while including a tenant being provisioned.
    #[tokio::test]
    async fn a_tenant_closed_to_requests_is_not_served() {
        let fx = fixture().await;
        let suspended = fx.tenant("closed", TenantStatus::Suspended).await;
        let provisioning = fx.tenant("fresh", TenantStatus::Provisioning).await;
        fx.registered(&suspended, active("closed.acme.example"))
            .await;

        let all = fx.hosts().all().await.unwrap();
        let one = fx.hosts().find(&suspended).await.unwrap();
        let open = fx.hosts().find(&provisioning).await.unwrap();

        let served: Vec<TenantId> = all.iter().map(|hosted| hosted.tenant_id).collect();
        assert_eq!(served, [*provisioning]);
        assert!(one.is_none());
        assert_eq!(open.unwrap().tenant_id, *provisioning);
    }

    /// One tenant read by itself is what the whole read lists for it, and
    /// a tenant not kept is not served.
    #[tokio::test]
    async fn one_tenant_reads_as_the_whole_read_lists_it() {
        let fx = fixture().await;
        let shop = fx.tenant("shop", TenantStatus::Active).await;
        fx.registered(&shop, active("login.acme.example")).await;

        let one = fx.hosts().find(&shop).await.unwrap().unwrap();
        let gone = fx.hosts().find(&TenantId::new()).await.unwrap();

        assert_eq!(names(&one), ["login.acme.example"]);
        assert_eq!(one.slug.as_str(), "shop");
        assert!(gone.is_none());
    }

    /// A tenant with a database of its own has its domains read from that
    /// database, beside the tenants of the platform's.
    #[tokio::test]
    async fn a_tenant_living_apart_is_read_from_its_own_database() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = fx.tenant("apart", TenantStatus::Active).await;
        fx.db.databases.register(*apart, own.as_dedicated());
        fx.registered(&apart, active("apart.acme.example")).await;
        let hosts = PgCrossTenantHosts::new(Arc::clone(&fx.db.databases), DomainLimits::default());

        let all = hosts.all().await.unwrap();

        assert_eq!(all.len(), 1);
        assert_eq!(names(&all[0]), ["apart.acme.example"]);
    }

    /// The gateway, signed in as its own role, reads the newest certificate
    /// of every domain answered with one, its key opened; a domain that
    /// needs none, or waits for one, is answered with none.
    #[tokio::test]
    async fn the_gateway_reads_the_newest_certificate_of_each_certified_domain() {
        let fx = fixture().await;
        let shop = fx.tenant("shop", TenantStatus::Active).await;
        let login = fx.registered(&shop, active("login.acme.example")).await;
        let plain = fx
            .registered(&shop, needing_none("plain.acme.example"))
            .await;
        let waiting = fx
            .registered(&shop, proved_domain_row("waiting.acme.example"))
            .await;
        fx.certified(&shop, login, 0).await;
        let newest = fx.certified(&shop, login, 10).await;
        fx.certified(&shop, plain, 0).await;
        fx.certified(&shop, waiting, 0).await;

        let current = fx.certificates().current().await.unwrap();

        assert_eq!(current.len(), 1);
        let served = &current[0];
        assert_eq!(served.tenant_id, *shop);
        assert_eq!(served.domain.as_str(), "login.acme.example");
        assert_eq!(served.bundle.id(), &newest);
        assert!(
            served
                .bundle
                .private_key_pem()
                .expose()
                .contains("PRIVATE KEY")
        );
    }

    /// Copying the login domain's sealed key onto the pay domain's
    /// certificate excludes pay from the served certificates while keeping
    /// login available.
    #[tokio::test]
    async fn a_certificate_whose_key_does_not_open_is_left_out() {
        let fx = fixture().await;
        let shop = fx.tenant("shop", TenantStatus::Active).await;
        let login = fx.registered(&shop, active("login.acme.example")).await;
        let pay = fx.registered(&shop, active("pay.acme.example")).await;
        let source = fx.certified(&shop, login, 0).await;
        fx.certified(&shop, pay, 0).await;
        fx.db
            .tamper(&format!(
                "UPDATE domain_certificates SET private_key = source.private_key \
                 FROM domain_certificates source \
                 WHERE source.id = '{}' AND domain_certificates.domain_id = '{}'",
                source.as_uuid(),
                pay.as_uuid()
            ))
            .await;

        let current = fx.certificates().current().await.unwrap();

        let served: Vec<&str> = current.iter().map(|cert| cert.domain.as_str()).collect();
        assert_eq!(served, ["login.acme.example"]);
    }

    /// An invalid stored domain name makes the host list fail as corrupt
    /// storage.
    #[tokio::test]
    async fn a_serving_domain_that_breaks_its_rules_is_refused() {
        let fx = fixture().await;
        let shop = fx.tenant("shop", TenantStatus::Active).await;
        fx.registered(&shop, active("login.acme.example")).await;
        fx.db
            .tamper("UPDATE registered_domains SET domain = 'not a name'")
            .await;

        let read = fx.hosts().all().await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
