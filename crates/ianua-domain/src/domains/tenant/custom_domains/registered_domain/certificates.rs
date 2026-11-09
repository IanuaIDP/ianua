//! How a registered domain gets, renews and loses its certificate, and the
//! records each step raises.

use crate::domains::tenant::control::{TenantArea, TenantControl};
use crate::domains::tenant::custom_domains::certificate::{
    CertificateBundle, CertificateSource, Renewal,
};
use crate::domains::tenant::custom_domains::registered_domain::{DomainProof, RegisteredDomain};
use crate::domains::tenant::custom_domains::uploaded_certificate::UploadedDetails;
use crate::domains::tenant::custom_domains::verification_status::TlsStatus;
use crate::domains::tenant::events::custom_domains::{
    TenantDomainCertificateExpiring, TenantDomainCertificateRemoved,
    TenantDomainCertificateReplaced, TenantDomainCertificateUploaded, TenantDomainTlsProvisioned,
    TenantDomainTlsRequested,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

impl<T: TenantScope> RegisteredDomain<T> {
    /// Asks for a certificate for this domain, which the worker then
    /// issues. Nothing stored changes until it is issued. Raises
    /// `tenant.domain_tls_requested`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] unless the domain is verified, or when
    ///   its certificate is already active.
    pub fn request_certificate(&mut self) -> Result<(), DomainError> {
        if !matches!(self.proof, DomainProof::Verified { .. }) {
            return Err(DomainError::conflict(message!(
                "tenant-must-be-verified-before-it-gets",
                format!(
                    "{} must be verified before it gets a certificate",
                    self.domain
                )
            )));
        }
        if self.tls_status == TlsStatus::Active {
            return Err(DomainError::conflict(message!(
                "tenant-the-certificate-of-is-already-active",
                format!("the certificate of {} is already active", self.domain)
            )));
        }
        self.raised.raise(TenantDomainTlsRequested {
            domain: self.domain.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Records that `cert` was issued and is serving. Raises
    /// `tenant.domain_tls_provisioned` with when it was issued and when it
    /// runs out.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] unless the domain is verified. A
    ///   certificate for a name nobody proved may be for someone else's name.
    /// - [`DomainError::InvalidTransition`] when a certificate is already
    ///   active.
    pub fn mark_tls_active(&mut self, cert: &CertificateBundle) -> Result<(), DomainError> {
        if !matches!(self.proof, DomainProof::Verified { .. }) {
            return Err(DomainError::conflict(message!(
                "tenant-must-be-verified-before-it-gets",
                format!(
                    "{} must be verified before it gets a certificate",
                    self.domain
                )
            )));
        }
        self.move_tls_to(TlsStatus::Active)?;
        self.raise_served(cert);
        Ok(())
    }

    /// Raises that `cert` now serves this domain.
    fn raise_served(&mut self, cert: &CertificateBundle) {
        self.raised.raise(TenantDomainTlsProvisioned {
            domain: self.domain.clone(),
            expires_at: cert.expires_at(),
            occurred_at: cert.issued_at(),
        });
    }

    /// Refuses renewing this domain's certificate.
    ///
    /// A renewal asks the authority for a name again. Only a domain proved
    /// now, that was given a certificate before, is renewed. Acme's proof
    /// for `auth.acme.com` is gone because the name was sold. Without this
    /// check, Acme keeps a certificate for the new owner's name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] unless the domain is verified.
    /// - [`DomainError::Conflict`] when it never asked for a certificate.
    pub fn ensure_renewable(&self) -> Result<(), DomainError> {
        if !matches!(self.proof, DomainProof::Verified { .. }) {
            return Err(DomainError::conflict(message!(
                "tenant-must-be-verified-for-its-certificate",
                format!(
                    "{} must be verified for its certificate to be renewed",
                    self.domain
                )
            )));
        }
        match self.tls_status {
            TlsStatus::NotRequired => Err(DomainError::conflict(message!(
                "tenant-never-asked-for-a-certificate-so",
                format!(
                    "{} never asked for a certificate, so there is none to renew",
                    self.domain
                )
            ))),
            TlsStatus::NoCertificate => Err(DomainError::conflict(message!(
                "tenant-had-its-certificate-removed-so-there",
                format!(
                    "{} had its certificate removed, so there is none to renew",
                    self.domain
                )
            ))),
            TlsStatus::Provisioning | TlsStatus::Active | TlsStatus::Expired => Ok(()),
        }
    }

    /// Records that the renewed `cert` is serving, including when the one
    /// before lapsed before it could be renewed. Raises
    /// `tenant.domain_tls_provisioned` with when it was issued and when it
    /// runs out.
    ///
    /// # Errors
    ///
    /// - As [`Self::ensure_renewable`].
    /// - [`DomainError::Conflict`] when `cert` is one the tenant uploaded.
    pub fn mark_tls_renewed(&mut self, cert: &CertificateBundle) -> Result<(), DomainError> {
        self.ensure_renewable()?;
        if cert.renewal() == Renewal::ByTenant {
            return Err(DomainError::conflict(message!(
                "tenant-a-certificate-the-tenant-uploaded-is",
                "a certificate the tenant uploaded is renewed by the tenant, never by ACME"
            )));
        }
        if self.tls_status != TlsStatus::Active {
            self.move_tls_to(TlsStatus::Active)?;
        }
        self.raise_served(cert);
        Ok(())
    }

    /// Records that the certificate lapsed without being renewed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] unless a certificate was active
    ///   or being provisioned.
    pub fn mark_tls_expired(&mut self) -> Result<(), DomainError> {
        self.move_tls_to(TlsStatus::Expired)
    }

    /// Serves `cert`, a certificate the tenant `scope` stands for uploaded,
    /// on this domain, as `by` decides. Raises
    /// `tenant.domain_certificate_uploaded`, or
    /// `tenant.domain_certificate_replaced` when a certificate was already
    /// serving.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the tenant's
    ///   domains, or `cert` was made for another domain.
    /// - [`DomainError::Conflict`] when `cert` came from ACME, or the domain
    ///   is not verified.
    pub fn serve_uploaded(
        &mut self,
        cert: &CertificateBundle,
        scope: &T,
        by: TenantControl<'_>,
    ) -> Result<(), DomainError> {
        let details = self.ensure_uploaded_here(cert, scope, by)?;
        if !matches!(self.proof, DomainProof::Verified { .. }) {
            return Err(DomainError::conflict(message!(
                "tenant-must-be-verified-before-it-serves",
                format!(
                    "{} must be verified before it serves a certificate",
                    self.domain
                )
            )));
        }
        let (issuer, expires_at) = (details.issuer().clone(), cert.expires_at());
        let occurred_at = crate::shared::clock::now();
        if self.tls_status == TlsStatus::Active {
            self.raised.raise(TenantDomainCertificateReplaced {
                domain: self.domain.clone(),
                issuer,
                expires_at,
                occurred_at,
            });
            return Ok(());
        }
        self.move_tls_to(TlsStatus::Active)?;
        self.raised.raise(TenantDomainCertificateUploaded {
            domain: self.domain.clone(),
            issuer,
            expires_at,
            occurred_at,
        });
        Ok(())
    }

    /// Stops serving `current`, the certificate the tenant uploaded for this
    /// domain, as `by` decides, whether it still serves or already lapsed.
    /// The domain then has no certificate until another is uploaded or
    /// issued, and nothing renews it on its own. Raises
    /// `tenant.domain_certificate_removed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the tenant's
    ///   domains, or `current` was made for another domain.
    /// - [`DomainError::Conflict`] when `current` came from ACME.
    /// - [`DomainError::InvalidTransition`] when no certificate is serving
    ///   or lapsed.
    pub fn remove_uploaded(
        &mut self,
        current: &CertificateBundle,
        scope: &T,
        by: TenantControl<'_>,
    ) -> Result<(), DomainError> {
        self.ensure_uploaded_here(current, scope, by)?;
        self.move_tls_to(TlsStatus::NoCertificate)?;
        self.raised.raise(TenantDomainCertificateRemoved {
            domain: self.domain.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Warns that `cert`, uploaded by the tenant for this domain, runs out
    /// within `threshold_days`. Nobody renews it for the tenant, so this is
    /// the only notice it gets. Raises `tenant.domain_certificate_expiring`
    /// when it does run out that soon, and nothing otherwise.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when `cert` came from ACME, which the
    ///   platform renews, or was made for another domain.
    pub fn report_expiring(
        &mut self,
        cert: &CertificateBundle,
        threshold_days: u32,
    ) -> Result<(), DomainError> {
        if cert.renewal() != Renewal::ByTenant || cert.domain_id() != &self.id {
            return Err(DomainError::conflict(message!(
                "tenant-only-a-certificate-the-tenant-uploaded",
                "only a certificate the tenant uploaded for this domain is reported"
            )));
        }
        if !cert.runs_out_within(threshold_days) {
            return Ok(());
        }
        self.raised.raise(TenantDomainCertificateExpiring {
            domain: self.domain.clone(),
            expires_at: cert.expires_at(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// The details of `cert`, once `by` may change the tenant's domains and
    /// `cert` is one the tenant uploaded for this domain.
    fn ensure_uploaded_here<'c>(
        &self,
        cert: &'c CertificateBundle,
        scope: &T,
        by: TenantControl<'_>,
    ) -> Result<&'c UploadedDetails, DomainError> {
        by.ensure_may(scope.tenant_id(), TenantArea::Domains)?;
        if cert.domain_id() != &self.id {
            return Err(DomainError::forbidden(message!(
                "tenant-the-certificate-was-uploaded-for-another",
                "the certificate was uploaded for another domain"
            )));
        }
        let CertificateSource::Uploaded(details) = cert.source() else {
            return Err(DomainError::conflict(message!(
                "tenant-the-certificate-came-from-acme-not",
                "the certificate came from ACME, not from the tenant"
            )));
        };
        Ok(details)
    }

    fn move_tls_to(&mut self, to: TlsStatus) -> Result<(), DomainError> {
        self.tls_status = self
            .tls_status
            .try_transition(to)
            .map_err(|refused| self.refused("TLS", refused.from, refused.to))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::tenant::custom_domains::certificate::IssuedCertificate;
    use crate::domains::tenant::custom_domains::registered_domain::{
        DomainConnection, DomainVerificationToken, NewDomain,
    };
    use crate::domains::tenant::custom_domains::uploaded_certificate::{
        CertificateIssuer, CertificateUpload, ParsedCertificate,
    };
    use crate::domains::tenant::fixtures::{ADMIN, active, holding, person};
    use crate::domains::tenant::lifecycle::Tenant;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::security::secret::Secret;
    use crate::test_support::builders::domain_name;
    use crate::test_support::events::raised_names;
    use crate::types::{CertificatePem, Human};

    /// Acme's tenant, its admin, and `name` registered and verified there.
    struct Setting {
        tenant: Tenant,
        scope: ResolvedTenant,
        admin: Human,
        domain: RegisteredDomain<ResolvedTenant>,
    }

    /// Acme with `name` verified.
    fn verified(name: &str) -> Setting {
        let tenant = active();
        let scope = ResolvedTenant::new(*tenant.id(), tenant.slug().clone());
        let admin = person("admin@acme.test");
        let mut domain = RegisteredDomain::register(
            NewDomain {
                domain: domain_name(name),
                connection: DomainConnection::SelfManaged,
                dns_challenge_token: DomainVerificationToken::new("challenge").unwrap(),
            },
            &scope,
            holding(&admin, &tenant, ADMIN),
        )
        .unwrap();
        domain.mark_verified().unwrap();
        raised_names(&mut domain);
        Setting {
            tenant,
            scope,
            admin,
            domain,
        }
    }

    /// A certificate the admin uploaded for `setting`'s domain, running out
    /// in `days`.
    fn uploaded(setting: &Setting, days: i64) -> CertificateBundle {
        let now = crate::shared::clock::now();
        CertificateBundle::upload(
            CertificateUpload {
                certificate_pem: chain(),
                private_key_pem: Secret::new("key"),
                parsed: ParsedCertificate {
                    issuer: CertificateIssuer::new("CN=Acme Internal CA").unwrap(),
                    subject_names: vec![setting.domain.domain().clone()],
                    not_before: now.saturating_sub(Duration::days(1)),
                    not_after: now.saturating_add(Duration::days(days)),
                },
            },
            &setting.domain,
            &setting.scope,
            holding(&setting.admin, &setting.tenant, ADMIN),
        )
        .unwrap()
    }

    /// A test chain.
    fn chain() -> CertificatePem {
        CertificatePem::new("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----").unwrap()
    }

    /// Acme uploads a certificate for `auth.acme.com`, then a newer one,
    /// then removes it. Each step is on record, and the name ends serving
    /// none.
    #[test]
    fn an_uploaded_certificate_is_served_replaced_and_removed() {
        let mut s = verified("auth.acme.com");
        let first = uploaded(&s, 60);
        let second = uploaded(&s, 90);

        s.domain
            .serve_uploaded(&first, &s.scope, holding(&s.admin, &s.tenant, ADMIN))
            .unwrap();
        s.domain
            .serve_uploaded(&second, &s.scope, holding(&s.admin, &s.tenant, ADMIN))
            .unwrap();
        s.domain
            .remove_uploaded(&second, &s.scope, holding(&s.admin, &s.tenant, ADMIN))
            .unwrap();

        assert_eq!(
            raised_names(&mut s.domain),
            [
                "tenant.domain_certificate_uploaded",
                "tenant.domain_certificate_replaced",
                "tenant.domain_certificate_removed",
            ]
        );
        assert_eq!(s.domain.tls_status(), TlsStatus::NoCertificate);
    }

    /// Acme's uploaded certificate for `auth.acme.com` lapsed, and Acme
    /// removes it. The removal goes through and the name has no
    /// certificate, rather than one that reads as lapsed.
    #[test]
    fn a_lapsed_uploaded_certificate_can_be_removed() {
        let mut s = verified("auth.acme.com");
        let cert = uploaded(&s, 60);
        s.domain
            .serve_uploaded(&cert, &s.scope, holding(&s.admin, &s.tenant, ADMIN))
            .unwrap();
        s.domain.mark_tls_expired().unwrap();

        s.domain
            .remove_uploaded(&cert, &s.scope, holding(&s.admin, &s.tenant, ADMIN))
            .unwrap();

        assert_eq!(s.domain.tls_status(), TlsStatus::NoCertificate);
    }

    /// A domain fails the renewal eligibility check after its uploaded
    /// certificate is removed.
    #[test]
    fn a_domain_whose_certificate_was_removed_is_not_renewed() {
        let mut s = verified("auth.acme.com");
        let cert = uploaded(&s, 60);
        s.domain
            .serve_uploaded(&cert, &s.scope, holding(&s.admin, &s.tenant, ADMIN))
            .unwrap();
        s.domain
            .remove_uploaded(&cert, &s.scope, holding(&s.admin, &s.tenant, ADMIN))
            .unwrap();

        let renewable = s.domain.ensure_renewable();

        assert!(matches!(renewable, Err(DomainError::Conflict(_))));
    }

    /// A certificate uploaded for one domain cannot be served on another.
    #[test]
    fn a_certificate_serves_only_the_domain_it_was_uploaded_for() {
        let auth = verified("auth.acme.com");
        let mut api = verified("api.acme.com");
        let cert = uploaded(&auth, 60);

        let refused =
            api.domain
                .serve_uploaded(&cert, &api.scope, holding(&api.admin, &api.tenant, ADMIN));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// ACME renewal rejects a tenant-uploaded certificate even when it is
    /// already serving the domain.
    #[test]
    fn acme_renewal_does_not_take_an_uploaded_certificate() {
        let mut s = verified("auth.acme.com");
        let cert = uploaded(&s, 60);
        s.domain
            .serve_uploaded(&cert, &s.scope, holding(&s.admin, &s.tenant, ADMIN))
            .unwrap();

        let refused = s.domain.mark_tls_renewed(&cert);

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
    }

    /// An uploaded certificate runs out in ten days. It is reported under a
    /// thirty-day threshold, and not under a five-day one.
    #[test]
    fn an_uploaded_certificate_nearing_its_end_is_reported() {
        let mut s = verified("auth.acme.com");
        let cert = uploaded(&s, 10);

        s.domain.report_expiring(&cert, 5).unwrap();
        let quiet = raised_names(&mut s.domain);
        s.domain.report_expiring(&cert, 30).unwrap();

        assert!(quiet.is_empty());
        assert_eq!(
            raised_names(&mut s.domain),
            ["tenant.domain_certificate_expiring"]
        );
    }

    /// A certificate from ACME is never reported as the tenant's to renew.
    #[test]
    fn an_acme_certificate_is_not_reported() {
        let mut s = verified("auth.acme.com");
        let now = crate::shared::clock::now();
        let acme = CertificateBundle::new(IssuedCertificate {
            domain_id: *s.domain.id(),
            certificate_pem: chain(),
            private_key_pem: Secret::new("key"),
            issued_at: now,
            expires_at: now.saturating_add(Duration::days(5)),
        })
        .unwrap();

        assert!(matches!(
            s.domain.report_expiring(&acme, 30),
            Err(DomainError::Conflict(_))
        ));
    }
}
