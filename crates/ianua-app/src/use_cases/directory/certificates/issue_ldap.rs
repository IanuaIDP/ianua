//! Issuing a directory client certificate to the person signed in, once they
//! prove who they are again.
//!
//! A certificate lets its holder bind to the directory for up to 397 days,
//! long after the session it was asked for ends. Mallory, holding Ann's
//! session, must not walk away with one, so Ann proves herself again first,
//! the way she signs in.

use std::sync::Arc;

use ianua_domain::domains::authentication::ldap_certificate::{
    CertificateValidity, IssueLdapCertificateParams, LdapClientCertificate,
};
use ianua_domain::domains::authentication::sessions::fresh_sign_in::FreshSignIn;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, CertificatePem, EventLabel, Label, LdapCertificateId};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::{LdapCertificateAuthority, LdapCertificateStore};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// A certificate signing request, the device it is for, and the person's
/// proof of who they are. It holds that proof, so it has no `Debug`.
pub struct IssueLdapRequest {
    /// The PEM-encoded signing request. The private key never leaves the
    /// device.
    pub csr_pem: String,
    /// The name the person gives the device, shown when listing.
    pub device_label: Label,
    /// What the person gives again to prove who they are.
    pub proof: ReenteredProof,
}

/// The signed certificate handed back to the person.
pub struct IssuedCertificate {
    /// The certificate record's id.
    pub certificate_id: LdapCertificateId,
    /// The signed certificate. The private key was never part of this
    /// exchange.
    pub certificate_pem: CertificatePem,
    /// When the certificate stops being valid.
    pub expires_at: OffsetDateTime,
}

/// The ports [`IssueLdapUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct IssueLdapPorts {
    /// Signs the request.
    pub certificate_authority: Arc<dyn LdapCertificateAuthority>,
    /// Keeps the issued certificate's record.
    pub certificate_store: Arc<dyn LdapCertificateStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the person gives again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
}

/// Issues the person signed in a directory client certificate for one of
/// their devices.
pub struct IssueLdapUseCase {
    ports: IssueLdapPorts,
    validity: CertificateValidity,
}

impl IssueLdapUseCase {
    /// A use case working through `ports`, issuing certificates valid for
    /// `validity`: short enough that a stolen or forgotten one matters less,
    /// since getting a new one is just another proof.
    #[must_use]
    pub fn new(ports: IssueLdapPorts, validity: CertificateValidity) -> Self {
        Self { ports, validity }
    }

    /// `csr_pem` signed for `account`, and the record of it issued for the
    /// device named `device_label`, on the strength of `fresh`.
    fn issued(
        &self,
        account: &User<ResolvedTenant>,
        csr_pem: &str,
        device_label: Label,
        fresh: &FreshSignIn,
    ) -> Result<(LdapClientCertificate<ResolvedTenant>, CertificatePem), AppError> {
        let signed = self
            .ports
            .certificate_authority
            .sign(csr_pem, account.id(), self.validity)
            .map_err(AppError::from_domain)?;
        let params = IssueLdapCertificateParams {
            user_id: *account.id(),
            holder_label: EventLabel::of(account.email().as_str()),
            fingerprint: signed.fingerprint,
            device_label,
            validity: self.validity,
        };
        let certificate =
            LdapClientCertificate::issue(params, fresh).map_err(AppError::from_domain)?;
        Ok((certificate, signed.certificate_pem))
    }

    /// Keeps `certificate` and records its issue through `auditor`, by the
    /// person it was issued to.
    async fn keep(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        certificate: &mut LdapClientCertificate<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.ports
            .certificate_store
            .save(tenant, certificate)
            .await
            .or_internal()?;
        let holder = ActorRef::User(*certificate.user_id());
        auditor
            .dispatch_by(&holder, certificate.take_events(tenant))
            .await
            .or_internal()
    }
}

impl Command for IssueLdapUseCase {
    type Caller = CallerContext;
    type Input = IssueLdapRequest;
    type Output = Result<IssuedCertificate, AppError>;

    /// Signs `request.csr_pem` for the person signed in to `ctx`'s session,
    /// once `request.proof` proves them again, keeps the record and records
    /// `authentication.ldap_certificate_issued`.
    ///
    /// A certificate always binds as the person who asked for it, never as
    /// anyone else.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::StepUpRequired` when the person has a second factor and
    ///   gave no code.
    /// - `AppError::Forbidden` when the proof is wrong, used before or
    ///   another account's, or the account is locked out.
    /// - `AppError::Domain` when the signing request is malformed.
    /// - `AppError::Internal` when the authority, storage or audit fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: IssueLdapRequest,
    ) -> Result<IssuedCertificate, AppError> {
        let IssueLdapRequest {
            csr_pem,
            device_label,
            proof,
        } = request;
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let tenant = ctx.tenant();
        let fresh = self
            .ports
            .fresh_proofs
            .prove(&tenant, &person.account, proof, ctx.origin())
            .await?;
        let (mut certificate, certificate_pem) =
            self.issued(&person.account, &csr_pem, device_label, &fresh)?;
        self.keep(&tenant, auditor, &mut certificate).await?;
        Ok(IssuedCertificate {
            certificate_id: *certificate.id(),
            certificate_pem,
            expires_at: certificate.expires_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakeLdapCertificateStore, MALFORMED_CSR, right_password, wrong_password,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        store: Arc<FakeLdapCertificateStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                store: Arc::new(FakeLdapCertificateStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn issue_as(
            &self,
            authorities: FakeTenantAuthorities,
            csr_pem: &str,
            proof: ReenteredProof,
        ) -> Result<IssuedCertificate, AppError> {
            let use_case = IssueLdapUseCase::new(
                IssueLdapPorts {
                    certificate_store: self.store.clone(),
                    tenant_authorities: Arc::new(authorities),
                    ..IssueLdapPorts::fakes()
                },
                CertificateValidity::days(90).unwrap(),
            );
            let request = IssueLdapRequest {
                csr_pem: csr_pem.to_owned(),
                device_label: Label::new("device_label", "MacBook").unwrap(),
                proof,
            };
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), request))
        }

        fn issue(&self, proof: ReenteredProof) -> Result<IssuedCertificate, AppError> {
            self.issue_as(FakeTenantAuthorities::holding(&[]), "valid-csr", proof)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann types her password again and asks for a certificate for her
    /// laptop. It is signed for 90 days, its record kept and the issue
    /// recorded.
    #[test]
    fn a_person_who_proves_herself_again_is_issued_a_certificate() {
        let fixture = Fixture::new();

        let issued = fixture.issue(right_password()).unwrap();

        let until = issued.expires_at - clock::now();
        assert_eq!(fixture.store.count(), 1);
        assert!(until > time::Duration::days(89) && until <= time::Duration::days(90));
        assert_eq!(
            fixture.recorded(),
            ["authentication.ldap_certificate_issued"]
        );
    }

    /// A wrong password prevents certificate issuance even with a valid
    /// session; no certificate record or audit event is saved.
    #[test]
    fn a_wrong_proof_is_refused_and_nothing_is_issued() {
        let fixture = Fixture::new();

        let result = fixture.issue(wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.store.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A malformed signing request fails validation despite a correct
    /// password, leaving the certificate store empty.
    #[test]
    fn a_malformed_signing_request_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.issue_as(
            FakeTenantAuthorities::holding(&[]),
            MALFORMED_CSR,
            right_password(),
        );

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(fixture.store.count(), 0);
    }

    /// A signed-out session cannot request a certificate even with the
    /// correct password; no certificate record is saved.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.issue_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            "valid-csr",
            right_password(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.store.count(), 0);
    }
}
