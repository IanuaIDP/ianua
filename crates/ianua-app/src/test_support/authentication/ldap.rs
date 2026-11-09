//! Fakes for LDAP client certificates: the authority that signs them, the
//! store that keeps their records, and the records tests seed it with.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authentication::credentials::password::PasswordHasher;
use ianua_domain::domains::authentication::ldap_certificate::{
    CertificateValidity, DirectoryBind, LdapClientCertificate, LdapClientCertificateRow,
};
use ianua_domain::domains::authentication::risk_engine::rate_limit::LoginAttemptTracker;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::PasswordCheck;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::test_support::fakes::FakeHasher;
use ianua_domain::types::{
    CertificateFingerprint, CertificatePem, Label, LdapCertificateId, Revocation, TenantId, UserId,
};

use crate::context::DirectoryBound;
use crate::ports::TenantScoped;
use crate::ports::directory::{
    LdapCertificateAuthority, LdapCertificateStore, SignedLdapCertificate,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authentication::REENTERED_PASSWORD;

/// The CSR [`FakeLdapCertificateAuthority`] refuses as malformed.
pub const MALFORMED_CSR: &str = "malformed";

/// LDAP certificate authority that signs every CSR but [`MALFORMED_CSR`],
/// giving each certificate the same fingerprint.
pub struct FakeLdapCertificateAuthority {
    /// The fingerprint every signed certificate gets.
    pub next_fingerprint: CertificateFingerprint,
}

impl Default for FakeLdapCertificateAuthority {
    fn default() -> Self {
        Self {
            next_fingerprint: CertificateFingerprint::from_digest([7; 32]),
        }
    }
}

impl LdapCertificateAuthority for FakeLdapCertificateAuthority {
    fn sign(
        &self,
        csr_pem: &str,
        _user_id: &UserId,
        _validity: CertificateValidity,
    ) -> Result<SignedLdapCertificate, DomainError> {
        if csr_pem == MALFORMED_CSR {
            return Err(DomainError::invalid("bad CSR"));
        }
        Ok(SignedLdapCertificate {
            certificate_pem: CertificatePem::new(
                "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
            )?,
            fingerprint: self.next_fingerprint,
        })
    }
}

/// In-memory LDAP client certificate records, each kept in its tenant as it
/// was last saved.
#[derive(Default)]
pub struct FakeLdapCertificateStore {
    certs: Mutex<Vec<(TenantId, LdapClientCertificate<ResolvedTenant>)>>,
}

impl TenantScoped for FakeLdapCertificateStore {}

impl FakeLdapCertificateStore {
    /// Nothing held.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `certificates` in `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        certificates: impl IntoIterator<Item = LdapClientCertificate<ResolvedTenant>>,
    ) -> Self {
        let store = Self::default();
        store
            .certs
            .lock()
            .unwrap()
            .extend(certificates.into_iter().map(|cert| (tenant_id, cert)));
        store
    }

    /// How many certificates are held, across tenants.
    #[must_use]
    pub fn count(&self) -> usize {
        self.certs.lock().unwrap().len()
    }

    /// When the certificate `id` was revoked, if it is held and was.
    #[must_use]
    pub fn revoked_at(&self, id: &LdapCertificateId) -> Option<time::OffsetDateTime> {
        self.certs
            .lock()
            .unwrap()
            .iter()
            .find(|(_, cert)| cert.id() == id)
            .and_then(|(_, cert)| cert.revoked_at())
    }

    fn find(
        &self,
        tenant_id: &ScopedTenant,
        matches: impl Fn(&LdapClientCertificate<ResolvedTenant>) -> bool,
    ) -> Option<LdapClientCertificate<ResolvedTenant>> {
        self.certs
            .lock()
            .unwrap()
            .iter()
            .find(|(held_in, cert)| held_in == &**tenant_id && matches(cert))
            .map(|(_, cert)| clone_cert(cert))
    }
}

#[async_trait]
impl LdapCertificateStore for FakeLdapCertificateStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        certificate: &LdapClientCertificate<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut certs = self.certs.lock().unwrap();
        certs.retain(|(_, held)| held.id() != certificate.id());
        certs.push((**tenant_id, clone_cert(certificate)));
        Ok(())
    }

    async fn find_by_fingerprint(
        &self,
        tenant_id: &ScopedTenant,
        fingerprint: &CertificateFingerprint,
    ) -> Result<Option<LdapClientCertificate<ResolvedTenant>>, DomainError> {
        Ok(self.find(tenant_id, |cert| cert.fingerprint() == fingerprint))
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &LdapCertificateId,
    ) -> Result<Option<LdapClientCertificate<ResolvedTenant>>, DomainError> {
        Ok(self.find(tenant_id, |cert| cert.id() == id))
    }

    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<LdapClientCertificate<ResolvedTenant>>, DomainError> {
        Ok(self
            .certs
            .lock()
            .unwrap()
            .iter()
            .filter(|(held_in, cert)| held_in == &**tenant_id && cert.user_id() == user_id)
            .map(|(_, cert)| clone_cert(cert))
            .collect())
    }
}

/// Where a seeded certificate stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateStanding {
    /// Issued a day ago for 90 days, and not revoked.
    InForce,
    /// Issued 91 days ago for 90 days, so it ran out yesterday.
    Expired,
    /// Issued a day ago for 90 days, and revoked an hour ago.
    Revoked,
}

/// A certificate for `user_id` with `fingerprint`, standing as `standing`
/// says, as storage would hand it back.
///
/// # Panics
///
/// Never for the standings above, which all make consistent rows.
#[must_use]
pub fn ldap_certificate(
    user_id: UserId,
    fingerprint: CertificateFingerprint,
    standing: CertificateStanding,
) -> LdapClientCertificate<ResolvedTenant> {
    ldap_certificate_with_id(LdapCertificateId::new(), user_id, fingerprint, standing)
}

/// The certificate [`ldap_certificate`] makes, kept under the record `id`.
///
/// # Panics
///
/// Never for the standings above, which all make consistent rows.
#[must_use]
pub fn ldap_certificate_with_id(
    id: LdapCertificateId,
    user_id: UserId,
    fingerprint: CertificateFingerprint,
    standing: CertificateStanding,
) -> LdapClientCertificate<ResolvedTenant> {
    let now = clock::now();
    let issued_at = match standing {
        CertificateStanding::Expired => now - time::Duration::days(91),
        CertificateStanding::InForce | CertificateStanding::Revoked => now - time::Duration::DAY,
    };
    let revocation = match standing {
        CertificateStanding::Revoked => Revocation::Revoked {
            at: now - time::Duration::HOUR,
        },
        CertificateStanding::InForce | CertificateStanding::Expired => Revocation::InForce,
    };
    LdapClientCertificate::reconstitute(LdapClientCertificateRow {
        id,
        user_id,
        fingerprint,
        device_label: Label::new("device_label", "MacBook").expect("a valid label"),
        issued_at,
        expires_at: issued_at + time::Duration::days(90),
        revocation,
    })
    .expect("a seeded certificate is a consistent row")
}

/// `account`'s directory bind, made from their laptop with
/// [`REENTERED_PASSWORD`] over a certificate in force for them.
///
/// # Panics
///
/// Never: the certificate is in force for the account and the password is
/// the one it holds.
#[must_use]
pub fn directory_bound(account: &User<ResolvedTenant>) -> DirectoryBound {
    let laptop = CertificateFingerprint::from_digest([7; 32]);
    let certificate = ldap_certificate(*account.id(), laptop, CertificateStanding::InForce);
    let stored = FakeHasher
        .hash(REENTERED_PASSWORD)
        .expect("the fake hasher hashes anything");
    let check = PasswordCheck {
        raw: REENTERED_PASSWORD,
        stored: &stored,
        hasher: &FakeHasher,
        tracker: &mut LoginAttemptTracker::new(),
    };
    let bind = DirectoryBind::with_certificate(account, check, &certificate, &laptop)
        .expect("a bind with the right password over a certificate in force");
    DirectoryBound::new(bind)
}

/// A copy of `cert`, which does not implement `Clone`: aggregates are not
/// meant to be duplicated, but an in-memory store needs an owned copy.
///
/// # Panics
///
/// Panics if the certificate's own fields no longer make a valid row, which
/// a certificate the domain built never does.
#[must_use]
pub fn clone_cert(
    cert: &LdapClientCertificate<ResolvedTenant>,
) -> LdapClientCertificate<ResolvedTenant> {
    with_revocation(cert, Revocation::from_stored(cert.revoked_at()))
}

/// A copy of `cert` revoked just now, as storage would hand it back once
/// someone revoked it.
///
/// # Panics
///
/// Panics if the certificate's own fields no longer make a valid row, which
/// a certificate the domain built never does.
#[must_use]
pub fn revoked_now(
    cert: &LdapClientCertificate<ResolvedTenant>,
) -> LdapClientCertificate<ResolvedTenant> {
    with_revocation(cert, Revocation::Revoked { at: clock::now() })
}

fn with_revocation(
    cert: &LdapClientCertificate<ResolvedTenant>,
    revocation: Revocation,
) -> LdapClientCertificate<ResolvedTenant> {
    LdapClientCertificate::reconstitute(LdapClientCertificateRow {
        id: *cert.id(),
        user_id: *cert.user_id(),
        fingerprint: *cert.fingerprint(),
        device_label: cert.device_label().clone(),
        issued_at: cert.issued_at(),
        expires_at: cert.expires_at(),
        revocation,
    })
    .expect("a live certificate's own row rebuilds")
}

impl Fake for Arc<dyn LdapCertificateAuthority> {
    fn fake() -> Self {
        Arc::new(FakeLdapCertificateAuthority::default())
    }
}

impl Fake for Arc<dyn LdapCertificateStore> {
    fn fake() -> Self {
        Arc::new(FakeLdapCertificateStore::empty())
    }
}
