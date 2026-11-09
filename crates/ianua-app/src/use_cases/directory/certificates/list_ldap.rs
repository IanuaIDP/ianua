//! Listing the directory client certificates of the person signed in.

use std::sync::Arc;

use ianua_domain::domains::authentication::ldap_certificate::LdapClientCertificate;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::directory::LdapCertificateStore;
use crate::use_case::Query;

/// The ports [`ListLdapUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListLdapPorts {
    /// Reads the person's certificates.
    pub certificate_store: Arc<dyn LdapCertificateStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the certificates of the person signed in, and no one else's.
pub struct ListLdapUseCase {
    ports: ListLdapPorts,
}

impl ListLdapUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListLdapPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListLdapUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<LdapClientCertificate<ResolvedTenant>>, AppError>;

    /// The certificates of the person signed in to `ctx`'s session, revoked
    /// and expired ones included.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<Vec<LdapClientCertificate<ResolvedTenant>>, AppError> {
        let person = self.ports.tenant_authorities.signed_in(ctx).await?;
        self.ports
            .certificate_store
            .list_by_user(&ctx.tenant(), person.account.id())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{CertificateFingerprint, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        CertificateStanding, FakeLdapCertificateStore, ldap_certificate,
    };
    use crate::test_support::{block_on, test_ctx};

    fn list_as(
        authorities: FakeTenantAuthorities,
        store: FakeLdapCertificateStore,
    ) -> Result<Vec<LdapClientCertificate<ResolvedTenant>>, AppError> {
        let use_case = ListLdapUseCase::new(ListLdapPorts {
            certificate_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    fn certificate_of(user: UserId, digest: u8) -> LdapClientCertificate<ResolvedTenant> {
        let fingerprint = CertificateFingerprint::from_digest([digest; 32]);
        ldap_certificate(user, fingerprint, CertificateStanding::InForce)
    }

    /// Ann has a certificate on her laptop, Bob one on his. Ann's list shows
    /// hers only.
    #[test]
    fn a_person_lists_only_their_own_certificates() {
        let ann = test_ctx().principal().unwrap().as_user().unwrap();
        let store = FakeLdapCertificateStore::holding(
            test_ctx().tenant_id(),
            [certificate_of(ann, 1), certificate_of(UserId::new(), 2)],
        );

        let listed = list_as(FakeTenantAuthorities::holding(&[]), store).unwrap();

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].user_id(), &ann);
    }

    /// Replaying a signed-out session returns an authentication error
    /// instead of a certificate listing.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = list_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            FakeLdapCertificateStore::empty(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
