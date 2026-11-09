//! Revoking one of the directory client certificates of the person signed
//! in, so its device binds nothing any more.

use std::sync::Arc;

use ianua_domain::domains::authentication::ldap_certificate::LdapClientCertificate;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, EventLabel, LdapCertificateId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::LdapCertificateStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`RevokeLdapUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeLdapPorts {
    /// Loads and saves certificates.
    pub certificate_store: Arc<dyn LdapCertificateStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Revokes a certificate of the person signed in.
pub struct RevokeLdapUseCase {
    ports: RevokeLdapPorts,
}

impl RevokeLdapUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeLdapPorts) -> Self {
        Self { ports }
    }
}

impl Command for RevokeLdapUseCase {
    type Caller = CallerContext;
    type Input = LdapCertificateId;
    type Output = Result<(), AppError>;

    /// Revokes the certificate `certificate_id` of the person signed in to
    /// `ctx`'s session and records `authentication.ldap_certificate_revoked`.
    /// One already revoked keeps the time it was first revoked, and nothing
    /// more is recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::NotFound` when the person has no such certificate,
    ///   which is how another person's reads too.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        certificate_id: LdapCertificateId,
    ) -> Result<(), AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        let tenant = ctx.tenant();
        let store = self.ports.certificate_store.as_ref();
        let mut certificate =
            owned_certificate(store, &tenant, &certificate_id, person.account.id()).await?;
        let was_revoked = certificate.revoked_at().is_some();
        certificate
            .revoke(
                &person.signed_in,
                EventLabel::of(person.account.email().as_str()),
            )
            .map_err(AppError::from_domain)?;
        if was_revoked {
            return Ok(());
        }

        store.save(&tenant, &certificate).await.or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::User(*person.account.id()),
                certificate.take_events(&tenant),
            )
            .await
            .or_internal()
    }
}

/// The certificate `id` of `holder`. Another person's reads as missing, so
/// an id cannot be used to find out whose certificates exist.
async fn owned_certificate(
    store: &dyn LdapCertificateStore,
    tenant: &ScopedTenant,
    id: &LdapCertificateId,
    holder: &UserId,
) -> Result<LdapClientCertificate<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .filter(|certificate| certificate.user_id() == holder)
        .ok_or_else(|| {
            AppError::NotFound(message!(
                "directory-certificate-not-found",
                "certificate not found"
            ))
        })
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::CertificateFingerprint;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        CertificateStanding, FakeLdapCertificateStore, ldap_certificate,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann, the person every test caller is signed in as.
    fn ann() -> UserId {
        test_ctx().principal().unwrap().as_user().unwrap()
    }

    struct Fixture {
        certificate_id: LdapCertificateId,
        store: Arc<FakeLdapCertificateStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// A certificate of `holder`, standing as `standing` says.
        fn of(holder: UserId, standing: CertificateStanding) -> Self {
            let fingerprint = CertificateFingerprint::from_digest([7; 32]);
            let certificate = ldap_certificate(holder, fingerprint, standing);
            Self {
                certificate_id: *certificate.id(),
                store: Arc::new(FakeLdapCertificateStore::holding(
                    test_ctx().tenant_id(),
                    [certificate],
                )),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// Ann's laptop certificate, in force.
        fn anns() -> Self {
            Self::of(ann(), CertificateStanding::InForce)
        }

        fn revoke_as(
            &self,
            authorities: FakeTenantAuthorities,
            certificate_id: LdapCertificateId,
        ) -> Result<(), AppError> {
            let use_case = RevokeLdapUseCase::new(RevokeLdapPorts {
                certificate_store: self.store.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&test_ctx(), &auditor, certificate_id))
        }

        fn revoke(&self) -> Result<(), AppError> {
            self.revoke_as(FakeTenantAuthorities::holding(&[]), self.certificate_id)
        }

        fn revoked_at(&self) -> Option<time::OffsetDateTime> {
            self.store.revoked_at(&self.certificate_id)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann's laptop is stolen and she revokes its certificate. It stops
    /// binding at once and the revocation is recorded.
    #[test]
    fn a_person_revokes_their_own_certificate() {
        let fixture = Fixture::anns();

        fixture.revoke().unwrap();

        assert!(fixture.revoked_at().is_some());
        assert_eq!(
            fixture.recorded(),
            ["authentication.ldap_certificate_revoked"]
        );
    }

    /// Ann revokes a certificate she revoked an hour ago. It keeps the first
    /// time, so the record shows when access really ended, and nothing more
    /// is recorded.
    #[test]
    fn revoking_again_keeps_the_first_time_and_records_nothing() {
        let fixture = Fixture::of(ann(), CertificateStanding::Revoked);
        let first = fixture.revoked_at();

        fixture.revoke().unwrap();

        assert_eq!(fixture.revoked_at(), first);
        assert!(fixture.recorded().is_empty());
    }

    /// Another person's certificate appears missing to the caller and
    /// remains unrevoked after the attempted revocation.
    #[test]
    fn another_persons_certificate_is_not_found() {
        let fixture = Fixture::of(UserId::new(), CertificateStanding::InForce);

        let result = fixture.revoke();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.revoked_at().is_none());
    }

    /// An unknown certificate ID returns not found without recording a
    /// revocation event.
    #[test]
    fn an_unknown_certificate_is_not_found() {
        let fixture = Fixture::anns();

        let result = fixture.revoke_as(
            FakeTenantAuthorities::holding(&[]),
            LdapCertificateId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out session cannot revoke its holder's certificate, which
    /// remains unrevoked.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::anns();

        let result = fixture.revoke_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.certificate_id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(fixture.revoked_at().is_none());
    }
}
