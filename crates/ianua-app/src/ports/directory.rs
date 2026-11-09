//! What the LDAP directory needs from the outside: the records of the
//! client certificates people bind with, the authority that signs them, the
//! accounts applications bind as and their secrets, and a throttle on
//! simple binds.

use async_trait::async_trait;
use ianua_domain::domains::authentication::directory_service::account::DirectoryServiceAccount;
use ianua_domain::domains::authentication::directory_service::scope::ServiceAccountName;
use ianua_domain::domains::authentication::ldap_certificate::{
    CertificateValidity, LdapClientCertificate,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificateFingerprint, CertificatePem, DirectoryServiceAccountId, LdapCertificateId, TenantId,
    TokenHash, UserId,
};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for LDAP client certificates, the possession factor an
/// LDAP simple bind can't carry. A bind proves the person only over a
/// connection that presented a certificate in force for them.
///
/// Every call names the tenant: a bind names its tenant in the DN, so a
/// certificate is looked for only among that tenant's records, and one
/// issued in another tenant is never found.
#[async_trait]
pub trait LdapCertificateStore: Send + Sync + TenantScoped {
    /// Saves a certificate record, new or changed, replacing the one with
    /// the same id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the record cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        certificate: &LdapClientCertificate<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Finds the tenant's certificate with `fingerprint`.
    ///
    /// The fingerprint is computed from a TLS-verified certificate. The
    /// certificate's own claimed Subject or SAN is never trusted for it.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the record cannot be read.
    async fn find_by_fingerprint(
        &self,
        tenant_id: &ScopedTenant,
        fingerprint: &CertificateFingerprint,
    ) -> Result<Option<LdapClientCertificate<ResolvedTenant>>, DomainError>;

    /// Finds the tenant's certificate with `id`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the record cannot be read.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &LdapCertificateId,
    ) -> Result<Option<LdapClientCertificate<ResolvedTenant>>, DomainError>;

    /// Lists a user's certificates.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the records cannot be read.
    async fn list_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<LdapClientCertificate<ResolvedTenant>>, DomainError>;
}

/// A certificate signed by the LDAP client certificate authority.
pub struct SignedLdapCertificate {
    /// The signed certificate, to hand back to the caller. The private key
    /// was never part of this exchange: the caller generated it locally and
    /// only ever sent us a CSR.
    pub certificate_pem: CertificatePem,
    /// SHA-256 fingerprint of the signed certificate's DER encoding, the
    /// value `LdapCertificateStore` looks up by.
    pub fingerprint: CertificateFingerprint,
}

/// Dyn-safe port for the LDAP client certificate authority.
///
/// Deliberately synchronous, like `PasswordHasher`: CA signing is CPU-bound
/// cryptography, not I/O.
pub trait LdapCertificateAuthority: Send + Sync {
    /// Signs a certificate signing request for `user_id`, valid for
    /// `validity`.
    ///
    /// The user id is written in as the common name for readability in
    /// client tooling only. Neither it nor the CSR's own claimed Subject or
    /// SAN is trusted for authorization. Identity is always resolved by
    /// looking up the returned fingerprint, never by parsing certificate
    /// content.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` if the CSR is malformed, or
    /// `DomainError::Infrastructure` if the CA itself can't be loaded.
    fn sign(
        &self,
        csr_pem: &str,
        user_id: &UserId,
        validity: CertificateValidity,
    ) -> Result<SignedLdapCertificate, DomainError>;
}

/// Dyn-safe port for the accounts applications bind to the directory as.
///
/// A name is unique within its tenant: the bind DN names the account by
/// it.
#[async_trait]
pub trait DirectoryServiceAccountStore: Send + Sync + TenantScoped {
    /// The account with `id`, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DirectoryServiceAccountId,
    ) -> Result<Option<DirectoryServiceAccount<ResolvedTenant>>, DomainError>;

    /// The account named `name`, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_name(
        &self,
        tenant_id: &ScopedTenant,
        name: &ServiceAccountName,
    ) -> Result<Option<DirectoryServiceAccount<ResolvedTenant>>, DomainError>;

    /// Every account of the tenant, by name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<DirectoryServiceAccount<ResolvedTenant>>, DomainError>;

    /// Saves a new or changed account.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` if another account of the tenant has
    /// the name, or `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        account: &DirectoryServiceAccount<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes the account with `id`. Removing one already gone succeeds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &DirectoryServiceAccountId,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port making service account secrets and hashing presented
/// ones.
#[async_trait]
pub trait ServiceAccountSecrets: Send + Sync {
    /// A new random secret and the hash it is kept by. The secret is shown
    /// once and never stored.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source
    /// fails.
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError>;

    /// The hash `presented` is kept by, compared by the account in constant
    /// time.
    fn hash(&self, presented: &Secret) -> TokenHash;
}

/// Dyn-safe port throttling per-tenant simple-bind attempts.
///
/// Kept distinct from [`crate::ports::limits::RateLimiter`]: that port
/// budgets general API traffic and is keyed purely by tenant, so sharing
/// its counter here would let a bind-guessing flood exhaust a tenant's API
/// quota, or a legitimate API burst lock out real binds.
#[async_trait]
pub trait BindThrottle: Send + Sync {
    /// Records a bind attempt and checks whether the tenant's rate is
    /// exceeded.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Forbidden` if the limit is exceeded.
    async fn check_and_record(&self, tenant_id: &TenantId) -> Result<(), DomainError>;
}
