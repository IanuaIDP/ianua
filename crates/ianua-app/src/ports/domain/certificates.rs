//! Issued certificates and provisioning them.

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::certificate::CertificateBundle;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateId, CertificatePem, DomainId, DomainName, TenantId};

use crate::ports::TenantScoped;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor};
use crate::tenancy::ScopedTenant;

/// Where the certificate `id` keeps its private key sealed.
///
/// The platform owns it rather than a tenant: a handover moves the
/// certificate, under the same id, to the tenant the domain is handed to,
/// and its key must still open there.
#[must_use]
pub fn certificate_key_place(id: &CertificateId) -> SealedFor {
    SealedFor::new(SealOwner::Platform, SealedField::DomainCertificateKey, id)
}

/// Dyn-safe port for saving one tenant's TLS certificate bundles. The
/// cross-tenant questions are on [`CrossTenantCertificateStore`].
///
/// A bundle carries its private key as a redacted `Secret`; the adapter
/// seals it at rest and opens it on load.
#[async_trait]
pub trait CertificateStore: Send + Sync + TenantScoped {
    /// Saves a certificate bundle, sealing its private key at rest.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        cert: &CertificateBundle,
    ) -> Result<(), DomainError>;

    /// Loads the certificate the tenant's domain `domain_id` serves: the
    /// newest one saved for it, issued or uploaded. Its private key comes
    /// back opened.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_current(
        &self,
        tenant_id: &ScopedTenant,
        domain_id: &DomainId,
    ) -> Result<Option<CertificateBundle>, DomainError>;

    /// Deletes the tenant's certificate `id`, with its sealed key. Returns
    /// whether there was one to delete.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &CertificateId,
    ) -> Result<bool, DomainError>;
}

/// Dyn-safe port for the certificate questions the background sweeps ask
/// across every tenant.
///
/// Not [`TenantScoped`]: renewal runs without a caller to scope it, and a
/// certificate is known by its domain, whose id is unique across tenants.
/// What it lists carries the tenant whose domain each certificate serves,
/// so the sweep works on behalf of that tenant.
#[async_trait]
pub trait CrossTenantCertificateStore: Send + Sync {
    /// Loads the active certificate for a domain.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn find_by_domain_id(
        &self,
        domain_id: &DomainId,
    ) -> Result<Option<CertificateBundle>, DomainError>;

    /// Lists certificates expiring within the given number of days, each with
    /// the tenant whose domain it serves. Both kinds are listed: the ones the
    /// platform issued, which the sweep renews, and the ones tenants
    /// uploaded, which it reports.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list_expiring(
        &self,
        within_days: u32,
    ) -> Result<Vec<(TenantId, CertificateBundle)>, DomainError>;

    /// Deletes old certificates for a domain (keeps only the latest).
    /// Returns the number of deleted rows.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn cleanup(&self, domain_id: &DomainId) -> Result<u64, DomainError>;
}

/// Dyn-safe port for ACME-based TLS certificate provisioning.
///
/// Infrastructure implements the actual ACME flow (Let's Encrypt, proved over
/// HTTP-01 or DNS-01). For development, a self-signed provisioner generates
/// untrusted certificates.
///
/// An order can take minutes, waiting for a record to propagate or the
/// authority to validate, so it is placed only from the worker's
/// certificate job, never inside a request. The adapter gives every call to
/// the authority a timeout and the whole order a few minutes at most, and
/// reports one that runs out as `DomainError::Infrastructure`, so a stalled
/// authority never holds the job forever.
#[async_trait]
pub trait TlsProvisioner: Send + Sync {
    /// Issues one certificate covering a root and its direct-child wildcard
    /// through DNS-01. Provisioners without that capability refuse it.
    ///
    /// # Errors
    ///
    /// Returns `Infrastructure` when pair issuance is unsupported or fails.
    async fn provision_pair(
        &self,
        _root: &DomainName,
    ) -> Result<(CertificatePem, Secret), DomainError> {
        Err(DomainError::infra_msg(
            "this provisioner cannot issue platform certificate pairs",
        ))
    }

    /// Provisions a TLS certificate for the given domain via ACME.
    ///
    /// Returns the certificate chain and its private key.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if provisioning fails.
    async fn provision(&self, domain: &DomainName)
    -> Result<(CertificatePem, Secret), DomainError>;
}
