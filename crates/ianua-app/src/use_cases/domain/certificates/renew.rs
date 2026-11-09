//! Renew certificates: issue a fresh certificate for every one the platform
//! issued that nears its expiry, and warn tenants whose own uploaded
//! certificate does.

use std::sync::Arc;

use ianua_domain::domains::tenant::custom_domains::certificate::{CertificateBundle, Renewal};
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{DomainId, TenantId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{CertificateStore, CrossTenantCertificateStore, RegisteredDomainStore};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::domain::certificates::TlsProvisioners;
use crate::use_cases::domain::certificates::issuance::issued_certificate;
use crate::use_cases::domain::lookup::existing_domain;

/// The ports [`RenewUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenewPorts {
    /// Stores each replacement for the tenant whose domain it serves.
    pub certificate_store: Arc<dyn CertificateStore>,
    /// Lists expiring certificates across tenants, tells which one serves
    /// each domain now, and drops the ones a newer certificate replaced.
    pub expiring_certificates: Arc<dyn CrossTenantCertificateStore>,
    /// Loads the domain each certificate serves, and saves it serving the
    /// renewal.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// How a certificate is obtained, by connection.
    ///
    /// A delegated domain renews over DNS-01, which is the point of
    /// delegating: nobody has to do anything. Renewing it over HTTP-01 would
    /// make renewal depend on the proxy answering, the dependency delegation
    /// exists to remove.
    pub tls_provisioners: TlsProvisioners,
    /// Keeps each renewed certificate and the record of it together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// What the sweep did with one expiring certificate.
enum Swept {
    /// The platform issued a fresh one in its place.
    Renewed,
    /// The tenant uploaded it, so the tenant was warned instead.
    Reported,
    /// A newer certificate serves its domain, so it was dropped.
    Superseded,
}

/// Renews certificates nearing their expiry, as a periodic task.
pub struct RenewUseCase {
    ports: RenewPorts,
    threshold_days: u32,
}

impl RenewUseCase {
    /// A use case working through `ports`, renewing certificates that expire
    /// within `threshold_days`.
    #[must_use]
    pub fn new(ports: RenewPorts, threshold_days: u32) -> Self {
        Self {
            ports,
            threshold_days,
        }
    }

    /// Renews `cert` when the platform renews it, and reports it when the
    /// tenant does. A certificate a newer one replaced is only dropped.
    ///
    /// # Errors
    ///
    /// As [`renew_once`] and [`Self::report_once`], and
    /// `AppError::Internal` if the serving certificate cannot be looked up.
    async fn swept_once(
        &self,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
        cert: &CertificateBundle,
    ) -> Result<Swept, AppError> {
        if !serves_now(&self.ports, cert).await? {
            clean_up_before(&self.ports, cert.domain_id()).await;
            return Ok(Swept::Superseded);
        }
        match cert.renewal() {
            Renewal::ByPlatform => renew_once(&self.ports, auditor, tenant_id, cert)
                .await
                .map(|()| Swept::Renewed),
            Renewal::ByTenant => self
                .report_once(auditor, tenant_id, cert)
                .await
                .map(|()| Swept::Reported),
        }
    }

    /// Warns the tenant `tenant_id` that `cert`, which it uploaded, runs
    /// out soon, and marks its domain expired once it has run out. Nobody
    /// renews an uploaded certificate for the tenant.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the domain is gone.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn report_once(
        &self,
        auditor: &RequestAuditor,
        tenant_id: TenantId,
        cert: &CertificateBundle,
    ) -> Result<(), AppError> {
        let tenant = ScopedTenant::for_background(tenant_id);
        let mut domain =
            existing_domain(self.ports.domain_store.as_ref(), &tenant, cert.domain_id()).await?;
        domain
            .report_expiring(cert, self.threshold_days)
            .map_err(AppError::from_domain)?;
        if lapsed(&domain, cert) {
            domain.mark_tls_expired().map_err(AppError::from_domain)?;
        }

        let auditor = auditor.with_tenant(tenant_id);
        let saved = save_and_record(&self.ports, &auditor, &tenant, &mut domain);
        kept_together(self.ports.unit_of_work.as_ref(), saved).await
    }
}

impl Command for RenewUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u32, AppError>;

    /// Works through every certificate expiring within the threshold and
    /// returns how many were renewed.
    ///
    /// A certificate the platform issued is renewed, recording
    /// `tenant.domain_tls_provisioned` against the tenant whose domain it
    /// serves. Only a domain verified now, that was given a certificate
    /// before, is renewed, and a renewal sets it serving again even after a
    /// lapse. A certificate that has already run out and cannot be renewed
    /// leaves its domain marked expired, so it is no longer shown as
    /// serving.
    ///
    /// A certificate the tenant uploaded is never renewed: asking an ACME
    /// authority would replace it behind the tenant's back. The tenant is
    /// warned with `tenant.domain_certificate_expiring` instead, and its
    /// domain is marked expired once the certificate has run out.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if listing expiring certificates fails.
    /// A certificate that cannot be renewed or reported is logged and
    /// skipped.
    async fn execute(&self, (): &(), auditor: &RequestAuditor, (): ()) -> Result<u32, AppError> {
        let expiring = self
            .ports
            .expiring_certificates
            .list_expiring(self.threshold_days)
            .await
            .or_internal()?;

        let mut renewed = 0u32;
        for (tenant_id, cert) in &expiring {
            match self.swept_once(auditor, *tenant_id, cert).await {
                Ok(Swept::Renewed) => renewed = renewed.saturating_add(1),
                Ok(Swept::Reported | Swept::Superseded) => {}
                Err(error) => tracing::warn!(
                    domain_id = %cert.domain_id(),
                    %error,
                    "certificate renewal failed; skipping it"
                ),
            }
        }
        Ok(renewed)
    }
}

/// Whether `cert` is the certificate its domain serves now, rather than one
/// a newer issue or upload replaced.
///
/// # Errors
///
/// Returns `AppError::Internal` on lookup failure.
async fn serves_now(ports: &RenewPorts, cert: &CertificateBundle) -> Result<bool, AppError> {
    let current = ports
        .expiring_certificates
        .find_by_domain_id(cert.domain_id())
        .await
        .or_internal()?;
    Ok(current.is_some_and(|current| current.id() == cert.id()))
}

/// Replaces `cert` with a fresh one for the same domain, sets the domain
/// serving it, and records the issuance against `tenant_id`. The authority
/// is asked outside the unit of work; the new certificate, the domain and
/// the record are kept together.
async fn renew_once(
    ports: &RenewPorts,
    auditor: &RequestAuditor,
    tenant_id: TenantId,
    cert: &CertificateBundle,
) -> Result<(), AppError> {
    let tenant = ScopedTenant::for_background(tenant_id);
    let mut domain =
        existing_domain(ports.domain_store.as_ref(), &tenant, cert.domain_id()).await?;
    let renewed = match fresh_certificate(ports, &domain).await {
        Ok(renewed) => renewed,
        Err(error) => {
            mark_expired_once_lapsed(ports, &tenant, cert, domain).await?;
            return Err(error);
        }
    };
    domain
        .mark_tls_renewed(&renewed)
        .map_err(AppError::from_domain)?;

    let auditor = auditor.with_tenant(tenant_id);
    let stored = store_and_record(ports, &auditor, &tenant, &mut domain, &renewed);
    kept_together(ports.unit_of_work.as_ref(), stored).await?;
    clean_up_before(ports, renewed.domain_id()).await;
    Ok(())
}

/// A fresh certificate for `domain`, asked for only once the domain says it
/// may be renewed.
///
/// # Errors
///
/// - `AppError::Conflict` when the domain is not verified, or never asked
///   for a certificate.
/// - `AppError::Internal` if the authority refuses.
async fn fresh_certificate(
    ports: &RenewPorts,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<CertificateBundle, AppError> {
    domain.ensure_renewable().map_err(AppError::from_domain)?;
    issued_certificate(&ports.tls_provisioners, domain).await
}

/// Whether `cert` has run out while `domain` still shows it as serving.
fn lapsed(domain: &RegisteredDomain<ResolvedTenant>, cert: &CertificateBundle) -> bool {
    cert.is_expired() && domain.tls_status() != TlsStatus::Expired
}

/// Marks `domain` as no longer serving once `cert`, which could not be
/// renewed, has run out.
async fn mark_expired_once_lapsed(
    ports: &RenewPorts,
    tenant: &ScopedTenant,
    cert: &CertificateBundle,
    mut domain: RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    if !lapsed(&domain, cert) {
        return Ok(());
    }
    domain.mark_tls_expired().map_err(AppError::from_domain)?;
    ports.domain_store.save(tenant, &domain).await.or_internal()
}

/// Stores the renewed certificate and the domain serving it, then records
/// it.
async fn store_and_record(
    ports: &RenewPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    domain: &mut RegisteredDomain<ResolvedTenant>,
    renewed: &CertificateBundle,
) -> Result<(), AppError> {
    ports
        .certificate_store
        .save(tenant, renewed)
        .await
        .or_internal()?;
    save_and_record(ports, auditor, tenant, domain).await
}

/// Saves `domain`, then records what it raised.
async fn save_and_record(
    ports: &RenewPorts,
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    domain: &mut RegisteredDomain<ResolvedTenant>,
) -> Result<(), AppError> {
    ports
        .domain_store
        .save(tenant, domain)
        .await
        .or_internal()?;
    auditor
        .dispatch(&domain.take_events(tenant))
        .await
        .or_internal()
}

/// Drops every certificate of `domain_id` but the newest. A failure only
/// leaves old rows behind until the next sweep, so it is logged rather than
/// allowed to undo a renewal that already succeeded.
async fn clean_up_before(ports: &RenewPorts, domain_id: &DomainId) {
    let Err(error) = ports.expiring_certificates.cleanup(domain_id).await else {
        return;
    };
    tracing::warn!(
        %domain_id,
        %error,
        "failed to clean up old certificates"
    );
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;
    use time::Duration;

    use super::*;
    use crate::test_support::domain::{
        DomainSeed, FakeCertificateStore, FakeDomainStore, FakeTlsProvisioner,
        RefusingTlsProvisioner, test_certificate, test_uploaded_certificate,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Fixture {
        use_case: RenewUseCase,
        domains: Arc<FakeDomainStore>,
        certificates: Arc<FakeCertificateStore>,
        audit: Arc<FakeEventDispatcher>,
        owner: TenantId,
    }

    fn fixture_with(provisioner: TlsProvisioners) -> Fixture {
        let domains = Arc::new(FakeDomainStore::empty());
        let certificates = Arc::new(FakeCertificateStore::empty());
        let use_case = RenewUseCase::new(
            RenewPorts {
                certificate_store: certificates.clone(),
                expiring_certificates: certificates.clone(),
                domain_store: domains.clone(),
                tls_provisioners: provisioner,
                ..RenewPorts::fakes()
            },
            30,
        );
        Fixture {
            use_case,
            domains,
            certificates,
            audit: Arc::new(FakeEventDispatcher::new()),
            owner: TenantId::new(),
        }
    }

    fn fixture() -> Fixture {
        fixture_with(TlsProvisioners::uniform(Arc::new(FakeTlsProvisioner)))
    }

    /// Acme's `host`, served by a certificate that runs out in `days`.
    fn serving(f: &Fixture, host: &str, days: i64) -> DomainId {
        let domain = DomainSeed::verified(host).tls(TlsStatus::Active).build();
        let id = *domain.id();
        let tenant = ScopedTenant::for_test(f.owner);
        block_on(f.domains.save(&tenant, &domain)).unwrap();
        let cert = test_certificate(id, clock::now() + Duration::days(days));
        block_on(f.certificates.save(&tenant, &cert)).unwrap();
        id
    }

    /// Acme's `host`, served by a certificate Acme uploaded that runs out
    /// in `days`.
    fn serving_uploaded(f: &Fixture, host: &str, days: i64) -> DomainId {
        let domain = DomainSeed::verified(host).tls(TlsStatus::Active).build();
        let id = *domain.id();
        let tenant = ScopedTenant::for_test(f.owner);
        block_on(f.domains.save(&tenant, &domain)).unwrap();
        let cert = test_uploaded_certificate(id, host, clock::now() + Duration::days(days));
        block_on(f.certificates.save(&tenant, &cert)).unwrap();
        id
    }

    fn renew(f: &Fixture) -> Result<u32, AppError> {
        block_on(f.use_case.execute(&(), &test_auditor(f.audit.clone()), ()))
    }

    /// Acme's certificate runs out in ten days. It is replaced with one good
    /// for ninety.
    #[test]
    fn a_certificate_near_expiry_is_replaced_with_one_good_for_ninety_days() {
        let f = fixture();
        let id = serving(&f, "acme.test", 10);

        assert_eq!(renew(&f).unwrap(), 1);

        let stored = block_on(f.certificates.find_by_domain_id(&id))
            .unwrap()
            .unwrap();
        let ahead = stored.expires_at() - clock::now();
        assert!((ahead - Duration::days(90)).abs() < Duration::minutes(1));
    }

    /// Two of Acme's certificates are near expiry. Both are renewed and
    /// counted.
    #[test]
    fn every_expiring_certificate_is_counted() {
        let f = fixture();
        serving(&f, "acme.test", 10);
        serving(&f, "auth.acme.test", 5);

        assert_eq!(renew(&f).unwrap(), 2);
    }

    /// Acme's certificate has sixty days left. It is left alone.
    #[test]
    fn a_certificate_far_from_expiry_is_left_alone() {
        let f = fixture();
        serving(&f, "acme.test", 60);

        assert_eq!(renew(&f).unwrap(), 0);
        assert_eq!(f.certificates.count(), 1);
    }

    /// One certificate's domain was removed. It does not stop the batch and
    /// is not counted as renewed.
    #[test]
    fn a_certificate_whose_domain_is_gone_is_skipped_not_counted() {
        let f = fixture();
        let orphan = test_certificate(DomainId::new(), clock::now() + Duration::days(10));
        block_on(
            f.certificates
                .save(&ScopedTenant::for_test(f.owner), &orphan),
        )
        .unwrap();
        serving(&f, "acme.test", 10);

        assert_eq!(renew(&f).unwrap(), 1);
    }

    /// The renewal is recorded against Acme, the tenant owning the
    /// certificate, not a tenant made up on the spot.
    #[test]
    fn a_renewal_is_recorded_against_the_tenant_owning_the_certificate() {
        let f = fixture();
        serving(&f, "acme.test", 10);

        renew(&f).unwrap();

        assert_eq!(
            f.audit.tenant_of("tenant.domain_tls_provisioned"),
            Some(f.owner)
        );
    }

    /// Acme's certificate ran out yesterday and the authority refuses to
    /// renew it. The domain is marked expired rather than still shown as
    /// serving.
    #[test]
    fn an_expired_certificate_that_cannot_be_renewed_marks_its_domain_expired() {
        let f = fixture_with(TlsProvisioners::uniform(Arc::new(RefusingTlsProvisioner)));
        let id = serving(&f, "acme.test", -1);

        assert_eq!(renew(&f).unwrap(), 0);

        assert_eq!(
            f.domains.domain_of(f.owner, &id).unwrap().tls_status(),
            TlsStatus::Expired
        );
    }

    /// Acme's `host`, in `seed`'s state, served by a certificate that runs
    /// out in `days`.
    fn serving_as(f: &Fixture, seed: DomainSeed, days: i64) -> DomainId {
        let domain = seed.build();
        let id = *domain.id();
        let tenant = ScopedTenant::for_test(f.owner);
        block_on(f.domains.save(&tenant, &domain)).unwrap();
        let cert = test_certificate(id, clock::now() + Duration::days(days));
        block_on(f.certificates.save(&tenant, &cert)).unwrap();
        id
    }

    /// Losing domain proof prevents renewal of its expiring certificate;
    /// the existing certificate remains stored and no renewal is audited.
    #[test]
    fn a_domain_that_lost_its_proof_is_not_renewed() {
        let f = fixture();
        let seed = DomainSeed::verified("acme.test")
            .lost()
            .tls(TlsStatus::Active);
        serving_as(&f, seed, 10);

        assert_eq!(renew(&f).unwrap(), 0);

        assert_eq!(f.certificates.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Acme's certificate ran out before it could be renewed, and the
    /// domain was marked expired. The renewal that then comes through sets
    /// it serving again.
    #[test]
    fn a_renewal_after_a_lapse_sets_the_domain_serving_again() {
        let f = fixture();
        let seed = DomainSeed::verified("acme.test").tls(TlsStatus::Expired);
        let id = serving_as(&f, seed, -1);

        assert_eq!(renew(&f).unwrap(), 1);

        assert_eq!(
            f.domains.domain_of(f.owner, &id).unwrap().tls_status(),
            TlsStatus::Active
        );
    }

    /// Acme's certificate has ten days left and the authority refuses to
    /// renew it for now. The domain keeps serving it.
    #[test]
    fn a_refused_renewal_before_expiry_leaves_the_domain_serving() {
        let f = fixture_with(TlsProvisioners::uniform(Arc::new(RefusingTlsProvisioner)));
        let id = serving(&f, "acme.test", 10);

        assert_eq!(renew(&f).unwrap(), 0);

        assert_eq!(
            f.domains.domain_of(f.owner, &id).unwrap().tls_status(),
            TlsStatus::Active
        );
    }

    /// An expiring upload is reported against its owning tenant rather than
    /// counted as renewed; one certificate remains and TLS stays active.
    #[test]
    fn an_uploaded_certificate_is_reported_not_renewed() {
        let f = fixture();
        let id = serving_uploaded(&f, "auth.acme.test", 10);

        assert_eq!(renew(&f).unwrap(), 0);

        assert_eq!(f.certificates.count(), 1);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            vec!["tenant.domain_certificate_expiring"]
        );
        assert_eq!(
            f.audit.tenant_of("tenant.domain_certificate_expiring"),
            Some(f.owner)
        );
        assert_eq!(
            f.domains.domain_of(f.owner, &id).unwrap().tls_status(),
            TlsStatus::Active
        );
    }

    /// The certificate Acme uploaded ran out yesterday. Acme is warned and
    /// the domain is marked expired rather than still shown as serving.
    #[test]
    fn a_lapsed_uploaded_certificate_marks_its_domain_expired() {
        let f = fixture();
        let id = serving_uploaded(&f, "auth.acme.test", -1);

        renew(&f).unwrap();

        assert_eq!(
            f.domains.domain_of(f.owner, &id).unwrap().tls_status(),
            TlsStatus::Expired
        );
    }

    /// A superseded ACME certificate is removed without renewal or an audit
    /// event, leaving the tenant's uploaded certificate current.
    #[test]
    fn a_replaced_certificate_is_dropped_not_renewed() {
        let f = fixture();
        let id = serving(&f, "auth.acme.test", 10);
        let later = clock::now() + Duration::days(60);
        let upload = test_uploaded_certificate(id, "auth.acme.test", later);
        block_on(
            f.certificates
                .save(&ScopedTenant::for_test(f.owner), &upload),
        )
        .unwrap();

        assert_eq!(renew(&f).unwrap(), 0);

        let current = block_on(f.certificates.find_by_domain_id(&id))
            .unwrap()
            .unwrap();
        assert_eq!(current.id(), upload.id());
        assert_eq!(f.certificates.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }
}
