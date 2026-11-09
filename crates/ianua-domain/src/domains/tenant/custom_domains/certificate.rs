use std::fmt;

use time::OffsetDateTime;

use crate::domains::tenant::control::{TenantArea, TenantControl};
use crate::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use crate::domains::tenant::custom_domains::uploaded_certificate::{
    CertificateUpload, UploadedDetails,
};
use crate::domains::tenant::custom_domains::verification_status::VerificationStatus;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::security::secret::Secret;
use crate::types::{CertificateId, CertificatePem, DomainId};

/// Where a certificate came from, which decides who renews it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateSource {
    /// An ACME authority issued it for the platform, which renews it.
    Acme,
    /// The tenant uploaded it, with what it says about itself. The tenant
    /// renews it, by uploading another.
    Uploaded(UploadedDetails),
}

/// Who renews a certificate before it runs out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renewal {
    /// The platform, through its ACME authority.
    ByPlatform,
    /// The tenant, who is warned as it nears its end.
    ByTenant,
}

/// A TLS certificate bundle for a custom domain.
///
/// It holds the certificate PEM and the private key PEM, decrypted in memory.
/// The adapters encrypt the private key at rest. The domain works with the
/// decrypted form.
///
/// # Lifecycle
///
/// 1. An ACME authority such as Let's Encrypt issues a certificate for the
///    domain, or the tenant uploads one of its own.
/// 2. The private key is encrypted and stored alongside the certificate.
/// 3. On load, the private key is decrypted before constructing this value.
/// 4. The proxy's dynamic cert resolver uses this to serve TLS.
///
/// `Debug` never shows the private key.
pub struct CertificateBundle {
    id: CertificateId,
    domain_id: DomainId,
    certificate_pem: CertificatePem,
    private_key_pem: Secret,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    source: CertificateSource,
}

impl fmt::Debug for CertificateBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateBundle")
            .field("id", &self.id)
            .field("domain_id", &self.domain_id)
            .field("private_key_pem", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("source", &self.source)
            .finish()
    }
}

/// A certificate as it came back from the issuer.
pub struct IssuedCertificate {
    /// The domain it was issued for.
    pub domain_id: DomainId,
    /// The certificate chain, PEM-encoded.
    pub certificate_pem: CertificatePem,
    /// Its private key, PEM-encoded.
    pub private_key_pem: Secret,
    /// When it was issued.
    pub issued_at: OffsetDateTime,
    /// When it stops being valid.
    pub expires_at: OffsetDateTime,
}

impl CertificateBundle {
    /// Creates a new certificate bundle, or `None` when it would expire no
    /// later than it was issued.
    #[must_use]
    pub fn new(issued: IssuedCertificate) -> Option<Self> {
        let IssuedCertificate {
            domain_id,
            certificate_pem,
            private_key_pem,
            issued_at,
            expires_at,
        } = issued;
        if issued_at >= expires_at {
            return None;
        }
        Some(Self {
            id: CertificateId::new(),
            domain_id,
            certificate_pem,
            private_key_pem,
            issued_at,
            expires_at,
            source: CertificateSource::Acme,
        })
    }

    /// Takes a certificate the tenant `scope` stands for uploaded for
    /// `domain`, once `by` may change its domains. It serves from when it
    /// starts being valid until it runs out, and the tenant renews it.
    ///
    /// Eve runs a tenant and uploads a certificate she holds for `bank.com`.
    /// Without these checks, the platform serves it on a name Eve never
    /// proved, or one meant for another name on hers.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` was worked out for another
    ///   tenant, or may not change its domains.
    /// - [`DomainError::Conflict`] when `domain` is not verified.
    /// - The cases [`UploadedDetails`] refuses: no names, none naming the
    ///   domain, or not valid now.
    pub fn upload<T: TenantScope>(
        upload: CertificateUpload,
        domain: &RegisteredDomain<T>,
        scope: &T,
        by: TenantControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(scope.tenant_id(), TenantArea::Domains)?;
        if domain.verification_status() != VerificationStatus::Verified {
            return Err(DomainError::conflict(message!(
                "tenant-must-be-verified-before-it-serves",
                format!(
                    "{} must be verified before it serves a certificate",
                    domain.domain()
                )
            )));
        }
        let CertificateUpload {
            certificate_pem,
            private_key_pem,
            parsed,
        } = upload;
        let issued_at = parsed.not_before;
        let details =
            UploadedDetails::accepted(parsed, domain.domain(), crate::shared::clock::now())?;
        Ok(Self {
            id: CertificateId::new(),
            domain_id: *domain.id(),
            certificate_pem,
            private_key_pem,
            issued_at,
            expires_at: details.not_after(),
            source: CertificateSource::Uploaded(details),
        })
    }

    /// Rebuilds a certificate bundle from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the certificate
    ///   expires no later than it was issued, or an uploaded one's recorded
    ///   end is not its expiry.
    pub fn reconstitute(row: CertificateBundleRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            domain_id: row.domain_id,
            certificate_pem: row.certificate_pem,
            private_key_pem: row.private_key_pem,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            source: row.source,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &CertificateBundleRow) -> Result<(), DomainError> {
        let recorded_end = match &row.source {
            CertificateSource::Acme => row.expires_at,
            CertificateSource::Uploaded(details) => details.not_after(),
        };
        RowCheck::of("certificate bundle")
            .holds(
                row.issued_at < row.expires_at,
                "expires before it was issued",
            )
            .holds(
                recorded_end == row.expires_at,
                "an uploaded certificate whose recorded end is not its expiry",
            )
            .finish()
    }

    /// Where it came from.
    #[must_use]
    pub fn source(&self) -> &CertificateSource {
        &self.source
    }

    /// Who renews it: the platform for one from ACME, the tenant for one it
    /// uploaded.
    #[must_use]
    pub fn renewal(&self) -> Renewal {
        match self.source {
            CertificateSource::Acme => Renewal::ByPlatform,
            CertificateSource::Uploaded(_) => Renewal::ByTenant,
        }
    }

    /// Unique certificate identifier.
    #[must_use]
    pub fn id(&self) -> &CertificateId {
        &self.id
    }

    /// The domain this certificate belongs to.
    #[must_use]
    pub fn domain_id(&self) -> &DomainId {
        &self.domain_id
    }

    /// PEM-encoded certificate chain.
    #[must_use]
    pub fn certificate_pem(&self) -> &CertificatePem {
        &self.certificate_pem
    }

    /// The decrypted private key, PEM-encoded.
    #[must_use]
    pub fn private_key_pem(&self) -> &Secret {
        &self.private_key_pem
    }

    /// When this certificate was issued.
    #[must_use]
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    /// When this certificate expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether the certificate has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        crate::shared::clock::now() >= self.expires_at
    }

    /// Whole days until expiry, or 0 once it has expired.
    #[must_use]
    pub fn days_until_expiry(&self) -> u32 {
        let days = crate::shared::clock::between(crate::shared::clock::now(), self.expires_at)
            .whole_days()
            .max(0);
        u32::try_from(days).unwrap_or(u32::MAX)
    }

    /// Whether the platform should renew the certificate now, within the
    /// given threshold. Never for one the tenant uploaded: asking an ACME
    /// authority would replace the tenant's own certificate behind its back.
    #[must_use]
    pub fn needs_renewal(&self, threshold_days: u32) -> bool {
        self.renewal() == Renewal::ByPlatform && self.runs_out_within(threshold_days)
    }

    /// Whether the certificate runs out within `threshold_days`, whoever
    /// renews it.
    #[must_use]
    pub fn runs_out_within(&self, threshold_days: u32) -> bool {
        self.days_until_expiry() <= threshold_days
    }
}

/// Stored fields of a [`CertificateBundle`], read back by repositories.
pub struct CertificateBundleRow {
    /// The certificate's id.
    pub id: CertificateId,
    /// The domain this certificate belongs to.
    pub domain_id: DomainId,
    /// PEM-encoded certificate chain.
    pub certificate_pem: CertificatePem,
    /// The decrypted private key, PEM-encoded.
    pub private_key_pem: Secret,
    /// When the certificate was issued.
    pub issued_at: OffsetDateTime,
    /// When the certificate expires.
    pub expires_at: OffsetDateTime,
    /// Where it came from.
    pub source: CertificateSource,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{SystemPermission, TenantSettingsAction};
    use crate::domains::tenant::custom_domains::registered_domain::{
        DomainConnection, DomainVerificationToken, NewDomain,
    };
    use crate::domains::tenant::custom_domains::uploaded_certificate::{
        CertificateIssuer, ParsedCertificate,
    };
    use crate::domains::tenant::fixtures::{ADMIN, active, holding, person};
    use crate::domains::tenant::lifecycle::Tenant;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::domain_name;

    fn pem() -> CertificatePem {
        CertificatePem::new("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----").unwrap()
    }
    use time::Duration;

    fn future_cert() -> CertificateBundle {
        let now = crate::shared::clock::now();
        CertificateBundle::new(IssuedCertificate {
            domain_id: DomainId::new(),
            certificate_pem: pem(),
            private_key_pem: Secret::new(concat!(
                "-----BEGIN PRIVATE ",
                "KEY-----\ntest\n-----END PRIVATE KEY-----"
            )),
            issued_at: now,
            expires_at: now + Duration::days(90),
        })
        .expect("valid cert")
    }

    /// An issuer hands back a certificate that expired a day before it was
    /// issued. No bundle is made.
    #[test]
    fn new_rejects_invalid_dates() {
        let now = crate::shared::clock::now();
        let result = CertificateBundle::new(IssuedCertificate {
            domain_id: DomainId::new(),
            certificate_pem: pem(),
            private_key_pem: Secret::new("key"),
            issued_at: now,
            expires_at: now - Duration::days(1),
        });
        assert!(result.is_none());
    }

    /// An issuer hands back a certificate that expires the instant it is
    /// issued. No bundle is made, since it would never be valid.
    #[test]
    fn new_rejects_equal_dates() {
        let now = crate::shared::clock::now();
        let result = CertificateBundle::new(IssuedCertificate {
            domain_id: DomainId::new(),
            certificate_pem: pem(),
            private_key_pem: Secret::new("key"),
            issued_at: now,
            expires_at: now,
        });
        assert!(result.is_none());
    }

    /// A 90-day certificate issued now is not expired and has days left.
    #[test]
    fn future_cert_is_not_expired() {
        let cert = future_cert();
        assert!(!cert.is_expired());
        assert!(cert.days_until_expiry() > 0);
    }

    /// A certificate expired ten days ago reads as expired with zero days
    /// left, not a negative count.
    #[test]
    fn expired_cert_returns_zero_days() {
        let now = crate::shared::clock::now();
        let cert = CertificateBundle::reconstitute(CertificateBundleRow {
            id: CertificateId::new(),
            domain_id: DomainId::new(),
            certificate_pem: pem(),
            private_key_pem: Secret::new("key"),
            issued_at: now - Duration::days(100),
            expires_at: now - Duration::days(10),
            source: CertificateSource::Acme,
        })
        .unwrap();
        assert!(cert.is_expired());
        assert_eq!(cert.days_until_expiry(), 0);
    }

    /// A certificate expires in 15 days. It needs renewal under a 30-day
    /// threshold but not under a 10-day one.
    #[test]
    fn needs_renewal_within_threshold() {
        let now = crate::shared::clock::now();
        let cert = CertificateBundle::reconstitute(CertificateBundleRow {
            id: CertificateId::new(),
            domain_id: DomainId::new(),
            certificate_pem: pem(),
            private_key_pem: Secret::new("key"),
            issued_at: now - Duration::days(60),
            expires_at: now + Duration::days(15),
            source: CertificateSource::Acme,
        })
        .unwrap();
        assert!(cert.needs_renewal(30));
        assert!(!cert.needs_renewal(10));
    }

    /// A stored certificate is read back. Its id, domain, chain, key and
    /// issue time come back as stored.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let id = CertificateId::new();
        let domain_id = DomainId::new();
        let now = crate::shared::clock::now();

        let cert = CertificateBundle::reconstitute(CertificateBundleRow {
            id,
            domain_id,
            certificate_pem: pem(),
            private_key_pem: Secret::new("key-pem"),
            issued_at: now,
            expires_at: now + Duration::days(90),
            source: CertificateSource::Acme,
        })
        .unwrap();

        assert_eq!(*cert.id(), id);
        assert_eq!(*cert.domain_id(), domain_id);
        assert_eq!(cert.certificate_pem(), &pem());
        assert_eq!(cert.private_key_pem().expose(), "key-pem");
        assert_eq!(cert.issued_at(), now);
    }

    /// A new bundle hands back a non-empty certificate chain and private
    /// key for the proxy to serve.
    #[test]
    fn accessors_return_correct_values() {
        let cert = future_cert();
        assert!(!cert.certificate_pem().as_str().is_empty());
        assert!(!cert.private_key_pem().is_empty());
    }

    /// A stored row says the certificate was issued at its expiry. It is
    /// refused as corrupt when read.
    #[test]
    fn a_stored_certificate_that_expires_before_it_was_issued_is_refused() {
        let cert = future_cert();
        let row = CertificateBundleRow {
            id: cert.id,
            domain_id: cert.domain_id,
            certificate_pem: cert.certificate_pem.clone(),
            private_key_pem: cert.private_key_pem.clone(),
            issued_at: cert.expires_at,
            expires_at: cert.expires_at,
            source: CertificateSource::Acme,
        };

        assert!(refused_as_corrupt(&CertificateBundle::reconstitute(row)));
    }

    /// Acme's tenant, a scope for it, and `auth.acme.com` registered there,
    /// verified when `proved` says so.
    fn acme_domain(proved: Proved) -> (Tenant, ResolvedTenant, RegisteredDomain<ResolvedTenant>) {
        let tenant = active();
        let scope = ResolvedTenant::new(*tenant.id(), tenant.slug().clone());
        let admin = person("admin@acme.test");
        let mut domain = RegisteredDomain::register(
            NewDomain {
                domain: domain_name("auth.acme.com"),
                connection: DomainConnection::SelfManaged,
                dns_challenge_token: DomainVerificationToken::new("challenge").unwrap(),
            },
            &scope,
            holding(&admin, &tenant, ADMIN),
        )
        .unwrap();
        if proved == Proved::Yes {
            domain.mark_verified().unwrap();
        }
        (tenant, scope, domain)
    }

    /// Whether a test domain was proved.
    #[derive(Clone, Copy, PartialEq)]
    enum Proved {
        Yes,
        No,
    }

    /// An upload of a certificate for `name`, valid for ninety days.
    fn upload_for(name: &str) -> CertificateUpload {
        let now = crate::shared::clock::now();
        CertificateUpload {
            certificate_pem: pem(),
            private_key_pem: Secret::new(
                "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
            ),
            parsed: ParsedCertificate {
                issuer: CertificateIssuer::new("CN=Acme Internal CA").unwrap(),
                subject_names: vec![domain_name(name)],
                not_before: now - Duration::days(1),
                not_after: now + Duration::days(20),
            },
        }
    }

    /// Acme's admin uploads its own certificate for the verified
    /// `auth.acme.com`. It is taken, recorded as uploaded, and serves until
    /// the end it carries.
    #[test]
    fn an_admin_uploads_a_certificate_for_a_verified_domain() {
        let (tenant, scope, domain) = acme_domain(Proved::Yes);
        let admin = person("admin@acme.test");

        let cert = CertificateBundle::upload(
            upload_for("auth.acme.com"),
            &domain,
            &scope,
            holding(&admin, &tenant, ADMIN),
        )
        .unwrap();

        assert_eq!(cert.renewal(), Renewal::ByTenant);
        assert!(matches!(cert.source(), CertificateSource::Uploaded(_)));
    }

    /// Viewing tenant settings does not authorize uploading a certificate for
    /// a verified domain.
    #[test]
    fn a_viewer_uploads_no_certificate() {
        let (tenant, scope, domain) = acme_domain(Proved::Yes);
        let sam = person("sam@acme.test");
        let view = [SystemPermission::TenantSettings(TenantSettingsAction::View)];

        let refused = CertificateBundle::upload(
            upload_for("auth.acme.com"),
            &domain,
            &scope,
            holding(&sam, &tenant, &view),
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Certificate upload rejects an unverified domain even for an administrator.
    #[test]
    fn an_unproved_domain_takes_no_certificate() {
        let (tenant, scope, domain) = acme_domain(Proved::No);
        let admin = person("admin@acme.test");

        let refused = CertificateBundle::upload(
            upload_for("auth.acme.com"),
            &domain,
            &scope,
            holding(&admin, &tenant, ADMIN),
        );

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// An uploaded certificate runs out in twenty days. ACME renewal skips
    /// it under a thirty-day threshold, though it does run out within it.
    #[test]
    fn acme_renewal_skips_an_uploaded_certificate() {
        let (tenant, scope, domain) = acme_domain(Proved::Yes);
        let admin = person("admin@acme.test");
        let cert = CertificateBundle::upload(
            upload_for("auth.acme.com"),
            &domain,
            &scope,
            holding(&admin, &tenant, ADMIN),
        )
        .unwrap();

        assert!(!cert.needs_renewal(30));
        assert!(cert.runs_out_within(30));
    }

    /// A certificate from ACME prints without its private key.
    #[test]
    fn a_bundle_never_prints_its_key() {
        let printed = format!("{:?}", future_cert());

        assert!(!printed.contains("PRIVATE KEY"));
    }
}
