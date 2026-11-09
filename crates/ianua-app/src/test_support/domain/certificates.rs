//! Certificate fakes: a store of issued bundles and an issuer that signs
//! whatever it is asked for.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::certificate::{
    CertificateBundle, CertificateBundleRow,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateId, CertificatePem, DomainId, DomainName, TenantId};

use crate::ports::TenantScoped;
use crate::ports::domain::{CertificateStore, CrossTenantCertificateStore, TlsProvisioner};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// The certificate chain [`FakeTlsProvisioner`] issues.
pub const TEST_CERTIFICATE_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nTUlJQnRlc3RjZXJ0\n-----END CERTIFICATE-----\n";

/// The private key [`FakeTlsProvisioner`] issues.
pub const TEST_PRIVATE_KEY_PEM: &str =
    "-----BEGIN PRIVATE KEY-----\nTUlJRXRlc3RrZXk=\n-----END PRIVATE KEY-----\n";

struct CertEntry {
    tenant_id: TenantId,
    cert: CertificateBundle,
}

fn copy_of(cert: &CertificateBundle) -> CertificateBundle {
    CertificateBundle::reconstitute(CertificateBundleRow {
        id: *cert.id(),
        domain_id: *cert.domain_id(),
        certificate_pem: cert.certificate_pem().clone(),
        private_key_pem: cert.private_key_pem().clone(),
        issued_at: cert.issued_at(),
        expires_at: cert.expires_at(),
        source: cert.source().clone(),
    })
    .expect("a certificate bundle reads back as itself")
}

/// In-memory certificate store for use case tests. Keeps every bundle
/// saved, newest last, under the tenant it was saved for.
#[derive(Default)]
pub struct FakeCertificateStore {
    entries: Mutex<Vec<CertEntry>>,
}

impl TenantScoped for FakeCertificateStore {}

impl FakeCertificateStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns the number of stored certificates.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

#[async_trait]
impl CertificateStore for FakeCertificateStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        cert: &CertificateBundle,
    ) -> Result<(), DomainError> {
        self.entries.lock().unwrap().push(CertEntry {
            tenant_id: **tenant_id,
            cert: copy_of(cert),
        });
        Ok(())
    }

    async fn find_current(
        &self,
        tenant_id: &ScopedTenant,
        domain_id: &DomainId,
    ) -> Result<Option<CertificateBundle>, DomainError> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|entry| entry.tenant_id == **tenant_id && entry.cert.domain_id() == domain_id)
            .map(|entry| copy_of(&entry.cert)))
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &CertificateId,
    ) -> Result<bool, DomainError> {
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|entry| entry.tenant_id != **tenant_id || entry.cert.id() != id);
        Ok(entries.len() < before)
    }
}

#[async_trait]
impl CrossTenantCertificateStore for FakeCertificateStore {
    async fn find_by_domain_id(
        &self,
        domain_id: &DomainId,
    ) -> Result<Option<CertificateBundle>, DomainError> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|entry| entry.cert.domain_id() == domain_id)
            .map(|entry| copy_of(&entry.cert)))
    }

    async fn list_expiring(
        &self,
        within_days: u32,
    ) -> Result<Vec<(TenantId, CertificateBundle)>, DomainError> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| entry.cert.runs_out_within(within_days))
            .map(|entry| (entry.tenant_id, copy_of(&entry.cert)))
            .collect())
    }

    async fn cleanup(&self, domain_id: &DomainId) -> Result<u64, DomainError> {
        let mut entries = self.entries.lock().unwrap();
        let Some(latest) = entries
            .iter()
            .rposition(|entry| entry.cert.domain_id() == domain_id)
        else {
            return Ok(0);
        };
        let latest_id = *entries[latest].cert.id();
        let before = entries.len();
        entries
            .retain(|entry| entry.cert.domain_id() != domain_id || *entry.cert.id() == latest_id);
        Ok((before - entries.len()) as u64)
    }
}

/// TLS provisioner that issues [`TEST_CERTIFICATE_PEM`] with
/// [`TEST_PRIVATE_KEY_PEM`] for any domain.
pub struct FakeTlsProvisioner;

#[async_trait]
impl TlsProvisioner for FakeTlsProvisioner {
    async fn provision(
        &self,
        _domain: &DomainName,
    ) -> Result<(CertificatePem, Secret), DomainError> {
        let chain = CertificatePem::new(TEST_CERTIFICATE_PEM).expect("the test chain is PEM");
        Ok((chain, Secret::new(TEST_PRIVATE_KEY_PEM)))
    }
}

impl Fake for Arc<dyn CertificateStore> {
    fn fake() -> Self {
        Arc::new(FakeCertificateStore::empty())
    }
}

impl Fake for Arc<dyn CrossTenantCertificateStore> {
    fn fake() -> Self {
        Arc::new(FakeCertificateStore::empty())
    }
}

impl Fake for Arc<dyn TlsProvisioner> {
    fn fake() -> Self {
        Arc::new(FakeTlsProvisioner)
    }
}
