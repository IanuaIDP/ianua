//! Provision TLS: issue the certificate a verified domain is waiting for.
//!
//! The worker runs it for each queued certificate job, with no caller of its
//! own: the tenant pressed the button, or a sweep verified the domain, long
//! before the authority is asked.

use std::sync::Arc;

use ianua_domain::domains::tenant::custom_domains::certificate::CertificateBundle;
use ianua_domain::domains::tenant::custom_domains::registered_domain::{
    DomainConnection, RegisteredDomain,
};
use ianua_domain::domains::tenant::custom_domains::verification_status::{
    TlsStatus, VerificationStatus,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{CertificateStore, RegisteredDomainStore, TlsProvisioner};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::domain::certificates::issuance::issued_certificate;
use crate::use_cases::domain::lookup::existing_domain;
use crate::use_cases::domain::verification::verified::ProvisionTlsJob;

/// The two ways control of a hostname can be proved to an authority.
///
/// Which one applies is decided by who holds the DNS, and only the domain
/// knows that. So the choice is made here, not inside a provisioner that
/// sees a bare hostname and would have to look the answer up again.
#[derive(Clone, ianua_macros::Fakes)]
pub struct TlsProvisioners {
    /// For a domain the tenant still points at us, proved over HTTP-01 by
    /// the proxy answering on their hostname.
    pub self_managed: Arc<dyn TlsProvisioner>,
    /// For a domain delegated to us, proved over DNS-01 by writing the
    /// record ourselves. That is what makes renewal need no tenant action,
    /// and the only proof a wildcard can ever have.
    pub delegated: Arc<dyn TlsProvisioner>,
}

impl TlsProvisioners {
    /// The provisioner for a domain with this connection.
    #[must_use]
    pub fn for_connection(&self, connection: DomainConnection) -> &Arc<dyn TlsProvisioner> {
        match connection {
            DomainConnection::Delegated => &self.delegated,
            DomainConnection::SelfManaged => &self.self_managed,
        }
    }

    /// One provisioner for both, for deployments where the distinction does
    /// not arise: development, and any install with delegation switched off.
    #[must_use]
    pub fn uniform(provisioner: Arc<dyn TlsProvisioner>) -> Self {
        Self {
            self_managed: provisioner.clone(),
            delegated: provisioner,
        }
    }
}

/// The ports [`ProvisionTlsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ProvisionTlsPorts {
    /// Loads and updates the domain registration.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Stores the issued certificate.
    pub certificate_store: Arc<dyn CertificateStore>,
    /// How a certificate is obtained, by connection.
    pub tls_provisioners: TlsProvisioners,
    /// Keeps the certificate, the domain and the record of them together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Issues the certificate for one verified domain.
pub struct ProvisionTlsUseCase {
    ports: ProvisionTlsPorts,
}

impl ProvisionTlsUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ProvisionTlsPorts) -> Self {
        Self { ports }
    }
}

impl Command for ProvisionTlsUseCase {
    type Caller = ();
    type Input = ProvisionTlsJob;
    type Output = Result<(), AppError>;

    /// Issues the certificate `job` names, marks the domain as serving it,
    /// and records `tenant.domain_tls_provisioned` against the domain's
    /// tenant.
    ///
    /// The authority is asked outside the unit of work. The certificate, the
    /// domain and the record are kept together.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant has no such domain.
    /// - `AppError::Conflict` if the domain is not verified, or its
    ///   certificate is already active.
    /// - `AppError::Internal` on provisioning, persistence or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        job: ProvisionTlsJob,
    ) -> Result<(), AppError> {
        let tenant = ScopedTenant::for_background(job.tenant_id);
        let mut domain =
            existing_domain(self.ports.domain_store.as_ref(), &tenant, &job.domain_id).await?;
        ensure_awaiting_certificate(&domain)?;
        let cert = issued_certificate(&self.ports.tls_provisioners, &domain).await?;
        domain
            .mark_tls_active(&cert)
            .map_err(AppError::from_domain)?;

        let auditor = auditor.with_tenant(job.tenant_id);
        let issued = IssuedFor {
            tenant: &tenant,
            domain: &mut domain,
            cert: &cert,
        };
        kept_together(
            self.ports.unit_of_work.as_ref(),
            store_and_record(&self.ports, &auditor, issued),
        )
        .await
    }
}

/// Refuses a domain that is not ready for a first certificate.
///
/// Verified is the whole of what is required. Asking for a certificate is
/// itself the statement that traffic will arrive here over TLS.
///
/// # Errors
///
/// - `AppError::Conflict` if the domain is not verified, or its certificate
///   is already active.
pub(super) fn ensure_awaiting_certificate(
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    if domain.verification_status() != VerificationStatus::Verified {
        return Err(AppError::Conflict(message!(
            "domain-the-domain-must-be-verified-before",
            "the domain must be verified before it gets a certificate"
        )));
    }
    if domain.tls_status() == TlsStatus::Active {
        return Err(AppError::Conflict(message!(
            "domain-the-domain-s-certificate-is-already",
            "the domain's certificate is already active"
        )));
    }
    Ok(())
}

/// A certificate issued for one tenant's domain.
struct IssuedFor<'a> {
    /// The tenant owning the domain.
    tenant: &'a ScopedTenant,
    /// The domain, now serving the certificate.
    domain: &'a mut RegisteredDomain<ResolvedTenant>,
    /// The certificate.
    cert: &'a CertificateBundle,
}

/// Stores the certificate and the domain now serving it, then records the
/// issuance.
async fn store_and_record(
    ports: &ProvisionTlsPorts,
    auditor: &RequestAuditor,
    issued: IssuedFor<'_>,
) -> Result<(), AppError> {
    ports
        .certificate_store
        .save(issued.tenant, issued.cert)
        .await
        .or_internal()?;
    ports
        .domain_store
        .save(issued.tenant, issued.domain)
        .await
        .or_internal()?;
    auditor
        .dispatch(&issued.domain.take_events(issued.tenant))
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{CertificatePem, DomainId, DomainName, TenantId};

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::test_support::domain::{
        DomainSeed, FakeCertificateStore, FakeDomainStore, FakeTlsProvisioner,
        RefusingTlsProvisioner, TEST_CERTIFICATE_PEM,
    };
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    struct Fixture {
        use_case: ProvisionTlsUseCase,
        domains: Arc<FakeDomainStore>,
        certificates: Arc<FakeCertificateStore>,
        audit: Arc<FakeEventDispatcher>,
        unit: Arc<RecordingUnitOfWork>,
    }

    fn fixture_with(
        domain: RegisteredDomain<ResolvedTenant>,
        provisioners: TlsProvisioners,
    ) -> Fixture {
        let domains = Arc::new(FakeDomainStore::holding(tenant_id(), [domain]));
        let certificates = Arc::new(FakeCertificateStore::empty());
        let unit = Arc::new(RecordingUnitOfWork::default());
        let use_case = ProvisionTlsUseCase::new(ProvisionTlsPorts {
            domain_store: domains.clone(),
            certificate_store: certificates.clone(),
            tls_provisioners: provisioners,
            unit_of_work: unit.clone(),
        });
        Fixture {
            use_case,
            domains,
            certificates,
            audit: Arc::new(FakeEventDispatcher::new()),
            unit,
        }
    }

    fn fixture(domain: RegisteredDomain<ResolvedTenant>) -> Fixture {
        fixture_with(
            domain,
            TlsProvisioners::uniform(Arc::new(FakeTlsProvisioner)),
        )
    }

    fn tenant_id() -> TenantId {
        test_ctx().tenant_id()
    }

    fn provision(f: &Fixture, domain_id: DomainId) -> Result<(), AppError> {
        block_on(f.use_case.execute(
            &(),
            &test_auditor(f.audit.clone()),
            ProvisionTlsJob {
                tenant_id: tenant_id(),
                domain_id,
            },
        ))
    }

    /// Acme's verified domain gets its certificate. The certificate is
    /// stored, the domain serves it, and the issuance is recorded against
    /// Acme.
    #[test]
    fn a_verified_domain_gets_its_certificate() {
        let domain = DomainSeed::verified("auth.acme.test").build();
        let id = *domain.id();
        let f = fixture(domain);

        provision(&f, id).unwrap();

        assert_eq!(f.certificates.count(), 1);
        assert_eq!(
            f.domains.domain_of(tenant_id(), &id).unwrap().tls_status(),
            TlsStatus::Active
        );
        assert_eq!(
            f.audit.tenant_of("tenant.domain_tls_provisioned"),
            Some(tenant_id())
        );
    }

    /// Acme's domain is not verified yet. A certificate for a name nobody
    /// proved may be for someone else's name, so it is refused.
    #[test]
    fn an_unverified_domain_is_refused() {
        let domain = DomainSeed::pending("auth.acme.test").build();
        let id = *domain.id();
        let f = fixture(domain);

        let result = provision(&f, id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(f.certificates.count(), 0);
    }

    /// Acme's domain already serves a certificate. Another is not issued.
    #[test]
    fn a_domain_with_an_active_certificate_is_refused() {
        let domain = DomainSeed::verified("auth.acme.test")
            .tls(TlsStatus::Active)
            .build();
        let id = *domain.id();
        let f = fixture(domain);

        let result = provision(&f, id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// The job names a domain Acme no longer has. It is not found.
    #[test]
    fn an_unknown_domain_is_not_found() {
        let f = fixture(DomainSeed::verified("auth.acme.test").build());

        let result = provision(&f, DomainId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The authority refuses the order. Nothing is stored, and the domain
    /// keeps waiting for its certificate.
    #[test]
    fn a_refused_order_stores_nothing() {
        let domain = DomainSeed::verified("auth.acme.test").delegated().build();
        let id = *domain.id();
        let f = fixture_with(
            domain,
            TlsProvisioners::uniform(Arc::new(RefusingTlsProvisioner)),
        );

        let result = provision(&f, id);

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(f.certificates.count(), 0);
        assert_eq!(
            f.domains.domain_of(tenant_id(), &id).unwrap().tls_status(),
            TlsStatus::Provisioning
        );
    }

    /// The certificate, the domain and the record of them are kept as one
    /// unit.
    #[test]
    fn the_certificate_and_its_record_are_stored_as_one_unit() {
        let domain = DomainSeed::verified("auth.acme.test").build();
        let id = *domain.id();
        let f = fixture(domain);

        provision(&f, id).unwrap();

        assert_eq!(f.unit.settlements(), vec![Settlement::Commit]);
    }

    /// Records which provisioner was asked.
    struct NamedProvisioner {
        name: &'static str,
        asked: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl TlsProvisioner for NamedProvisioner {
        async fn provision(
            &self,
            _domain: &DomainName,
        ) -> Result<(CertificatePem, Secret), DomainError> {
            self.asked.lock().unwrap().push(self.name);
            Ok((
                CertificatePem::new(TEST_CERTIFICATE_PEM)?,
                Secret::new("key"),
            ))
        }
    }

    fn proof_asked_for(domain: RegisteredDomain<ResolvedTenant>) -> Vec<&'static str> {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let id = *domain.id();
        let f = fixture_with(
            domain,
            TlsProvisioners {
                self_managed: Arc::new(NamedProvisioner {
                    name: "http-01",
                    asked: asked.clone(),
                }),
                delegated: Arc::new(NamedProvisioner {
                    name: "dns-01",
                    asked: asked.clone(),
                }),
            },
        );
        provision(&f, id).unwrap();
        asked.lock().unwrap().clone()
    }

    /// Acme delegated its domain. Control is proved through DNS, which is
    /// what makes renewal need nothing from Acme.
    #[test]
    fn a_delegated_domain_is_proved_over_dns() {
        let domain = DomainSeed::verified("auth.acme.test").delegated().build();

        assert_eq!(proof_asked_for(domain), ["dns-01"]);
    }

    /// Acme runs its own DNS, so there is no zone we can write into. Control
    /// is proved by the proxy answering on the hostname.
    #[test]
    fn a_self_managed_domain_is_proved_over_http() {
        let domain = DomainSeed::verified("auth.acme.test").build();

        assert_eq!(proof_asked_for(domain), ["http-01"]);
    }
}
