//! Reconcile tenant addresses and renew their certificate pairs.
//!
//! This sweep reads current desired state, so a lost event or job cannot lose
//! a tenant's certificate forever. Leases and retry delays live in storage.
//! A failed renewal keeps the old certificate until its actual expiry.

use std::sync::Arc;

use futures_util::future::try_join_all;
use ianua_domain::domains::tenant::hosts::{
    PlatformAddressing, PlatformCertificate, PlatformCertificateRow, PlatformHostParts,
    PlatformHosts, ReadableAddress,
};
use ianua_domain::shared::clock;
use ianua_domain::types::{CertificateId, DomainName};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{
    CertificateParser, PlatformCertificateOrder, PlatformCertificateStore,
    PlatformCertificateTarget, PlatformZoneSettings, TlsProvisioner,
};
use crate::ports::proxy::{CrossTenantHosts, HostedTenant};
use crate::use_case::Command;

/// The DNS configuration for nested platform certificates.
pub struct PlatformCertificateSettings {
    /// The base under which the platform owns and serves every tenant label.
    pub base_domain: DomainName,
    /// The authoritative nameservers and gateway address.
    pub zones: PlatformZoneSettings,
}

/// The ports the platform certificate sweep needs.
#[derive(ianua_macros::Fakes)]
pub struct MaintainPlatformCertificatesPorts {
    /// Current tenants, including their random label and readable consent.
    pub hosts: Arc<dyn CrossTenantHosts>,
    /// Desired pairs, leases, retry delays and sealed certificates.
    pub certificates: Arc<dyn PlatformCertificateStore>,
    /// The DNS-01 authority, never an HTTP-01 fallback.
    pub provisioner: Arc<dyn TlsProvisioner>,
    /// Checks the issued key and reads actual names and validity dates.
    pub parser: Arc<dyn CertificateParser>,
}

/// Keeps every enabled tenant address supplied with a certificate pair.
pub struct MaintainPlatformCertificatesUseCase {
    ports: MaintainPlatformCertificatesPorts,
    settings: Option<PlatformCertificateSettings>,
}

impl MaintainPlatformCertificatesUseCase {
    /// Uses `settings` for nested addressing. Without them it withdraws old
    /// platform orders and keys, as flat or disabled deployments require.
    #[must_use]
    pub fn new(
        ports: MaintainPlatformCertificatesPorts,
        settings: Option<PlatformCertificateSettings>,
    ) -> Self {
        Self { ports, settings }
    }

    /// Reconciles desired roots in one bulk write before claiming any work.
    async fn synchronize(&self) -> Result<(), AppError> {
        let Some(settings) = &self.settings else {
            return self
                .ports
                .certificates
                .synchronize(&[], None)
                .await
                .or_internal();
        };
        let hosted = self.ports.hosts.all().await.or_internal()?;
        let targets = hosted
            .iter()
            .flat_map(|tenant| targets(tenant, &settings.base_domain))
            .collect::<Vec<_>>();
        self.ports
            .certificates
            .synchronize(&targets, Some(&settings.zones))
            .await
            .or_internal()
    }

    /// Issues the exact root and wildcard, validates the result and saves it
    /// under the lease. Storage discards results for withdrawn or stale work.
    async fn issue(&self, order: &PlatformCertificateOrder) -> Result<(), AppError> {
        let certificate = self.issued_pair(order).await?;
        self.ports
            .certificates
            .save(&certificate)
            .await
            .or_internal()
    }

    /// Obtains and validates both names before the certificate can be saved.
    async fn issued_pair(
        &self,
        order: &PlatformCertificateOrder,
    ) -> Result<PlatformCertificate, AppError> {
        let (certificate_pem, private_key_pem) = self
            .ports
            .provisioner
            .provision_pair(&order.target.root)
            .await
            .or_internal()?;
        let parsed = self
            .ports
            .parser
            .parse(&certificate_pem, &private_key_pem)
            .or_internal()?;
        PlatformCertificate::issued(
            PlatformCertificateRow {
                id: order.id,
                tenant_id: order.target.tenant_id,
                root: order.target.root.clone(),
                certificate_pem,
                private_key_pem,
                issued_at: clock::now(),
                expires_at: clock::now(),
            },
            &parsed,
        )
        .or_internal()
    }

    /// Claims each order immediately before issuing it. Failed attempts are
    /// delayed durably; empty queues stop this lane without further reads.
    async fn issue_due(&self) -> Result<u32, AppError> {
        let mut issued = 0;
        for _ in 0..16 {
            let Some(order) = self
                .ports
                .certificates
                .claim_next(CertificateId::new())
                .await
                .or_internal()?
            else {
                break;
            };
            match self.issue(&order).await {
                Ok(()) => issued += 1,
                Err(error) => {
                    self.ports
                        .certificates
                        .record_failure(&order)
                        .await
                        .or_internal()?;
                    tracing::warn!(tenant_id = %order.target.tenant_id, root = %order.target.root, %error, "platform certificate order delayed after failure");
                }
            }
        }
        Ok(issued)
    }
}

impl Command for MaintainPlatformCertificatesUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u32, AppError>;

    /// Reconciles addresses and processes at most sixty-four leased pairs,
    /// with four orders in flight. Failed orders do not stop other tenants. This
    /// maintenance does not fabricate tenant consent or provisioning events.
    ///
    /// # Errors
    ///
    /// Returns `Internal` on catalog, reconciliation or lease-storage failure.
    async fn execute(&self, (): &(), _auditor: &RequestAuditor, (): ()) -> Result<u32, AppError> {
        self.synchronize().await?;
        let issued = try_join_all((0..4).map(|_| self.issue_due())).await?;
        Ok(issued.into_iter().sum())
    }
}

/// The random root and only the readable root whose tenant opted in.
fn targets(tenant: &HostedTenant, base: &DomainName) -> Vec<PlatformCertificateTarget> {
    let names = PlatformHosts::under(
        base,
        PlatformHostParts {
            label: &tenant.platform_label,
            organization_slug: &tenant.organization_slug,
            tenant_slug: &tenant.slug,
            readable: tenant.readable_address,
        },
        PlatformAddressing::Nested,
    );
    names
        .names()
        .map(|root| PlatformCertificateTarget {
            tenant_id: tenant.tenant_id,
            root: root.clone(),
            readable: if names.readable() == Some(root) {
                ReadableAddress::On
            } else {
                ReadableAddress::Off
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::hosts::PlatformLabel;
    use ianua_domain::shared::config::SlugLimits;
    use ianua_domain::types::{IpAddress, TenantId, TenantSlug};

    use super::*;
    use crate::test_support::domain::{FakeHostedTenants, FakePlatformCertificates};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// An active tenant whose public names contain no readable slug by default.
    fn hosted() -> HostedTenant {
        HostedTenant {
            tenant_id: TenantId::new(),
            platform_label: PlatformLabel::new("k7f3q9").unwrap(),
            readable_address: ReadableAddress::Off,
            organization_slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            slug: TenantSlug::new("main", &SlugLimits::default()).unwrap(),
            domains: Vec::new(),
        }
    }

    /// A nested deployment using its authoritative nameserver for DNS-01.
    fn settings() -> PlatformCertificateSettings {
        PlatformCertificateSettings {
            base_domain: DomainName::new("apps.example.com").unwrap(),
            zones: PlatformZoneSettings {
                nameservers: vec![DomainName::new("ns1.example.com").unwrap()],
                address: IpAddress::new("203.0.113.9").unwrap(),
            },
        }
    }

    /// A missed event cannot lose consent changes: each round reads current
    /// state, adds readable names only while on, and withdraws all pairs
    /// when the deployment changes to flat or disabled. No consent is fabricated.
    #[test]
    fn reconciliation_follows_consent_without_creating_audit_events() {
        let hosts = Arc::new(FakeHostedTenants::default());
        hosts.0.lock().unwrap().push(hosted());
        let certificates = Arc::new(FakePlatformCertificates::default());
        let audit = Arc::new(FakeEventDispatcher::new());
        let mut use_case = MaintainPlatformCertificatesUseCase::new(
            MaintainPlatformCertificatesPorts {
                hosts: hosts.clone(),
                certificates: certificates.clone(),
                ..MaintainPlatformCertificatesPorts::fakes()
            },
            Some(settings()),
        );
        let auditor = test_auditor(audit.clone());
        block_on(use_case.execute(&(), &auditor, ())).unwrap();
        assert_eq!(certificates.targets.lock().unwrap().len(), 1);
        hosts.0.lock().unwrap()[0].readable_address = ReadableAddress::On;
        block_on(use_case.execute(&(), &auditor, ())).unwrap();
        assert_eq!(certificates.targets.lock().unwrap().len(), 2);
        hosts.0.lock().unwrap()[0].readable_address = ReadableAddress::Off;
        block_on(use_case.execute(&(), &auditor, ())).unwrap();
        assert_eq!(certificates.targets.lock().unwrap().len(), 1);
        use_case.settings = None;
        block_on(use_case.execute(&(), &auditor, ())).unwrap();
        assert!(certificates.targets.lock().unwrap().is_empty());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A round with seventy failing certificate orders attempts only sixty-four.
    /// Each attempt records a failure, six orders remain and no certificate
    /// is saved.
    #[test]
    fn failed_orders_are_delayed_and_each_round_is_bounded() {
        let certificates = Arc::new(FakePlatformCertificates::default());
        let target = targets(&hosted(), &settings().base_domain).remove(0);
        *certificates.orders.lock().unwrap() = (0..70)
            .map(|_| PlatformCertificateOrder {
                id: CertificateId::new(),
                target: target.clone(),
            })
            .collect();
        let use_case = MaintainPlatformCertificatesUseCase::new(
            MaintainPlatformCertificatesPorts {
                certificates: certificates.clone(),
                ..MaintainPlatformCertificatesPorts::fakes()
            },
            Some(settings()),
        );
        let audit = test_auditor(Arc::new(FakeEventDispatcher::new()));
        assert_eq!(block_on(use_case.execute(&(), &audit, ())).unwrap(), 0);
        assert_eq!(certificates.failures.lock().unwrap().len(), 64);
        assert_eq!(certificates.orders.lock().unwrap().len(), 6);
        assert!(certificates.saved.lock().unwrap().is_empty());
    }
}
