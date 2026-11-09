//! Upload certificate: serve a certificate the tenant brings itself on one
//! of its verified domains, in place of whatever serves it now.
//!
//! The same step uploads the first certificate and replaces one already
//! serving, whether that one was issued through ACME or uploaded before.
//! The domain tells the two apart and records which it was.

use std::sync::Arc;

use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::domains::tenant::custom_domains::certificate::CertificateBundle;
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::domains::tenant::custom_domains::uploaded_certificate::CertificateUpload;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, DomainId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::{CertificateParser, CertificateStore, RegisteredDomainStore};
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::domain::certificates::detail::CertificateDetail;
use crate::use_cases::domain::lookup::{acting_tenant, existing_domain};

/// A certificate the tenant uploads for one of its domains.
///
/// `Debug` is not derived: the request carries the private key.
pub struct UploadRequest {
    /// The registered hostname this certificate will serve.
    pub domain_id: DomainId,
    /// The certificate chain, leaf first, PEM-encoded.
    pub certificate_pem: CertificatePem,
    /// The leaf's private key, PEM-encoded.
    pub private_key_pem: Secret,
}

/// The ports [`UploadUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UploadPorts {
    /// Loads the domain, and saves it serving the upload.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Stores the upload, sealing its key, and drops the certificate it
    /// replaces.
    pub certificate_store: Arc<dyn CertificateStore>,
    /// Reads what the uploaded chain says about itself.
    pub certificate_parser: Arc<dyn CertificateParser>,
    /// Loads the tenant the domain is registered in.
    pub tenants: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Serves a certificate the tenant uploaded on one of its domains.
pub struct UploadUseCase {
    ports: UploadPorts,
}

impl UploadUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UploadPorts) -> Self {
        Self { ports }
    }

    /// The certificate `request` uploads, read by the parser and accepted
    /// by the domain for `domain`.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the chain or key cannot be read, the key
    ///   is not the leaf's, or the certificate names no host.
    /// - `AppError::Forbidden` when `control` may not change the domains.
    /// - `AppError::Conflict` when the domain is not verified, or the
    ///   certificate does not name it or is not valid now.
    fn accepted(
        &self,
        request: UploadRequest,
        domain: &RegisteredDomain<ResolvedTenant>,
        scope: &ResolvedTenant,
        control: TenantControl<'_>,
    ) -> Result<CertificateBundle, AppError> {
        let UploadRequest {
            certificate_pem,
            private_key_pem,
            ..
        } = request;
        let parsed = self
            .ports
            .certificate_parser
            .parse(&certificate_pem, &private_key_pem)
            .map_err(AppError::from_domain)?;
        let upload = CertificateUpload {
            certificate_pem,
            private_key_pem,
            parsed,
        };
        CertificateBundle::upload(upload, domain, scope, control).map_err(AppError::from_domain)
    }

    /// Stores `cert`, drops `previous`, the certificate it replaces, and
    /// saves `domain` serving it.
    ///
    /// Dropping the replaced one matters: left behind, an ACME certificate
    /// would still come up for renewal and be issued over the tenant's own.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` on persistence failure.
    async fn store(
        &self,
        tenant: &ScopedTenant,
        domain: &RegisteredDomain<ResolvedTenant>,
        cert: &CertificateBundle,
        previous: Option<&CertificateBundle>,
    ) -> Result<(), AppError> {
        let store = self.ports.certificate_store.as_ref();
        store.save(tenant, cert).await.or_internal()?;
        if let Some(previous) = previous {
            store.delete(tenant, previous.id()).await.or_internal()?;
        }
        self.ports
            .domain_store
            .save(tenant, domain)
            .await
            .or_internal()
    }
}

impl Command for UploadUseCase {
    type Caller = CallerContext;
    type Input = UploadRequest;
    type Output = Result<CertificateDetail, AppError>;

    /// Serves the uploaded certificate on the caller's verified domain and
    /// records `tenant.domain_certificate_uploaded`, or
    /// `tenant.domain_certificate_replaced` when one was serving already.
    /// The certificate it replaces is dropped. The private key is sealed by
    /// the store and never comes back, in the answer or the record.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without domain-change rights.
    /// - `AppError::NotFound` for a missing tenant domain; `Domain` for an unreadable chain/key or mismatched key.
    /// - `AppError::Conflict` for an unverified domain or a certificate not naming it or not valid now.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: UploadRequest,
    ) -> Result<CertificateDetail, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = TenantControl::new(&authority);
        control
            .ensure_may(&caller.tenant_id(), TenantArea::Domains)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let scope = acting_tenant(self.ports.tenants.as_ref(), caller).await?;
        let store = self.ports.domain_store.as_ref();
        let mut domain = existing_domain(store, &tenant, &request.domain_id).await?;
        let previous = self
            .ports
            .certificate_store
            .find_current(&tenant, domain.id())
            .await
            .or_internal()?;
        let cert = self.accepted(request, &domain, &scope, control)?;
        domain
            .serve_uploaded(&cert, &scope, control)
            .map_err(AppError::from_domain)?;

        self.store(&tenant, &domain, &cert, previous.as_ref())
            .await?;
        auditor
            .dispatch_by(&caller.actor(), domain.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(CertificateDetail::from(&cert))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{DomainAction, SystemPermission};
    use ianua_domain::domains::tenant::custom_domains::certificate::{CertificateSource, Renewal};
    use ianua_domain::domains::tenant::custom_domains::uploaded_certificate::ParsedCertificate;
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::{
        DomainSeed, FakeCertificateParser, FakeCertificateStore, FakeDomainStore, parsed_for,
        test_certificate, test_chain, test_private_key,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const HOST: &str = "auth.acme.test";

    struct Fixture {
        use_case: UploadUseCase,
        domains: Arc<FakeDomainStore>,
        certificates: Arc<FakeCertificateStore>,
        audit: Arc<FakeEventDispatcher>,
        id: DomainId,
    }

    fn fixture_with(
        seed: DomainSeed,
        parser: FakeCertificateParser,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        let domain = seed.build();
        let id = *domain.id();
        let domains = Arc::new(FakeDomainStore::holding(test_ctx().tenant_id(), [domain]));
        let certificates = Arc::new(FakeCertificateStore::empty());
        let use_case = UploadUseCase::new(UploadPorts {
            domain_store: domains.clone(),
            certificate_store: certificates.clone(),
            certificate_parser: Arc::new(parser),
            tenants: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            tenant_authorities: Arc::new(authorities),
        });
        Fixture {
            use_case,
            domains,
            certificates,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
        }
    }

    fn fixture_reading(parsed: ParsedCertificate) -> Fixture {
        fixture_with(
            DomainSeed::verified(HOST),
            FakeCertificateParser::reading(parsed),
            FakeTenantAuthorities::holding_everything(),
        )
    }

    fn fixture() -> Fixture {
        fixture_reading(parsed_for(HOST, 60))
    }

    fn upload(f: &Fixture, domain_id: DomainId) -> Result<CertificateDetail, AppError> {
        let request = UploadRequest {
            domain_id,
            certificate_pem: test_chain(),
            private_key_pem: test_private_key(),
        };
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    fn nothing_changed(f: &Fixture) -> bool {
        f.certificates.count() == 0 && f.audit.records.lock().unwrap().is_empty()
    }

    /// Ann uploads Acme's own certificate for its verified domain. It is
    /// stored, the domain serves it, the upload is recorded, and the answer
    /// says the tenant renews it.
    #[test]
    fn an_uploaded_certificate_is_stored_served_and_recorded() {
        let f = fixture();

        let detail = upload(&f, f.id).unwrap();

        assert_eq!(detail.renewal, Renewal::ByTenant);
        assert_eq!(f.certificates.count(), 1);
        let domain = f.domains.domain_of(test_ctx().tenant_id(), &f.id).unwrap();
        assert_eq!(domain.tls_status(), TlsStatus::Active);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            vec!["tenant.domain_certificate_uploaded"]
        );
    }

    /// The upload result's debug representation contains no private-key
    /// PEM marker.
    #[test]
    fn the_answer_never_shows_the_private_key() {
        let f = fixture();

        let detail = upload(&f, f.id).unwrap();

        assert!(!format!("{detail:?}").contains("PRIVATE KEY"));
    }

    /// Acme's domain serves a certificate issued through ACME, and Ann
    /// uploads Acme's own. The replacement is recorded and the ACME one is
    /// dropped.
    ///
    /// Only the uploaded certificate remains stored, excluding the
    /// replaced ACME certificate from later renewal candidates.
    #[test]
    fn an_upload_replaces_the_certificate_serving_and_drops_it() {
        let f = fixture_with(
            DomainSeed::verified(HOST).tls(TlsStatus::Active),
            FakeCertificateParser::reading(parsed_for(HOST, 60)),
            FakeTenantAuthorities::holding_everything(),
        );
        let issued = test_certificate(f.id, clock::now() + Duration::days(10));
        block_on(f.certificates.save(&test_ctx().tenant(), &issued)).unwrap();

        upload(&f, f.id).unwrap();

        let current = block_on(f.certificates.find_current(&test_ctx().tenant(), &f.id))
            .unwrap()
            .unwrap();
        assert!(matches!(current.source(), CertificateSource::Uploaded(_)));
        assert_eq!(f.certificates.count(), 1);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            vec!["tenant.domain_certificate_replaced"]
        );
    }

    /// Ann uploads a chain that cannot be read. It is refused and nothing
    /// is stored or recorded.
    #[test]
    fn an_unreadable_chain_is_refused() {
        let f = fixture_with(
            DomainSeed::verified(HOST),
            FakeCertificateParser::refusing(),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = upload(&f, f.id);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert!(nothing_changed(&f));
    }

    /// A certificate naming another hostname conflicts with Acme's domain;
    /// neither a certificate nor an upload event is stored.
    #[test]
    fn a_certificate_for_another_name_is_refused() {
        let f = fixture_reading(parsed_for("bank.test", 60));

        let result = upload(&f, f.id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(nothing_changed(&f));
    }

    /// Ann uploads a certificate that ran out yesterday. It is refused.
    #[test]
    fn an_expired_certificate_is_refused() {
        let mut parsed = parsed_for(HOST, 60);
        parsed.not_before = clock::now() - Duration::days(90);
        parsed.not_after = clock::now() - Duration::days(1);
        let f = fixture_reading(parsed);

        let result = upload(&f, f.id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(nothing_changed(&f));
    }

    /// A matching certificate cannot be uploaded before domain verification;
    /// the refusal leaves certificate storage and audit empty.
    #[test]
    fn an_unverified_domain_takes_no_certificate() {
        let f = fixture_with(
            DomainSeed::pending(HOST),
            FakeCertificateParser::reading(parsed_for(HOST, 60)),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = upload(&f, f.id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(nothing_changed(&f));
    }

    /// Ann names a domain Acme does not have. It is not found.
    #[test]
    fn an_unknown_domain_is_not_found() {
        let f = fixture();

        let result = upload(&f, DomainId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(nothing_changed(&f));
    }

    /// Domain-viewing rights cannot authorize an upload; the forbidden
    /// attempt stores no certificate or audit event.
    #[test]
    fn a_caller_who_may_only_view_domains_is_refused() {
        let f = fixture_with(
            DomainSeed::verified(HOST),
            FakeCertificateParser::reading(parsed_for(HOST, 60)),
            FakeTenantAuthorities::holding(&[SystemPermission::Domains(DomainAction::View)]),
        );

        let result = upload(&f, f.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(nothing_changed(&f));
    }

    /// A signed-out session cannot upload a certificate and leaves no
    /// certificate or audit record.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            DomainSeed::verified(HOST),
            FakeCertificateParser::reading(parsed_for(HOST, 60)),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = upload(&f, f.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(nothing_changed(&f));
    }
}
