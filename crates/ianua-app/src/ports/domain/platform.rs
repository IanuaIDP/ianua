//! Durable certificate orders for addresses owned by the platform itself.

use async_trait::async_trait;
use ianua_domain::domains::tenant::hosts::{PlatformCertificate, ReadableAddress};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificateId, DomainName, IpAddress, TenantId};

/// A tenant address and the consent required to serve it.
#[derive(Debug, Clone)]
pub struct PlatformCertificateTarget {
    /// The tenant holding the permanent label or readable name.
    pub tenant_id: TenantId,
    /// The root covered together with its wildcard.
    pub root: DomainName,
    /// `On` for the readable alias, `Off` for the always-private random name.
    pub readable: ReadableAddress,
}

/// The nameservers and gateway address platform zones answer with.
#[derive(Debug, Clone)]
pub struct PlatformZoneSettings {
    /// The deployment's authoritative nameservers.
    pub nameservers: Vec<DomainName>,
    /// The gateway's reachable address.
    pub address: IpAddress,
}

/// One leased order. Its identifier also binds the certificate's sealed key.
#[derive(Debug, Clone)]
pub struct PlatformCertificateOrder {
    /// Unique to this attempt; a stale worker cannot replace a later result.
    pub id: CertificateId,
    /// The address and owning tenant to issue for.
    pub target: PlatformCertificateTarget,
}

/// Platform certificate orders survive lost events and worker restarts.
/// Reads and writes are bounded; the gateway has read-only access and tenants
/// cannot mutate these through custom-domain endpoints.
#[async_trait]
pub trait PlatformCertificateStore: Send + Sync {
    /// Reconciles desired addresses in bulk, removing obsolete orders and
    /// keys. Rechecks live tenant status and consent before accepting targets.
    ///
    /// # Errors
    ///
    /// Returns `Infrastructure` on persistence failure.
    async fn synchronize(
        &self,
        targets: &[PlatformCertificateTarget],
        zones: Option<&PlatformZoneSettings>,
    ) -> Result<(), DomainError>;

    /// Leases the next missing or expiring certificate under `attempt`. A
    /// crashed worker's lease expires; failures have a persisted retry delay.
    ///
    /// # Errors
    ///
    /// Returns `Infrastructure` on persistence failure.
    async fn claim_next(
        &self,
        attempt: CertificateId,
    ) -> Result<Option<PlatformCertificateOrder>, DomainError>;

    /// Keeps the issued pair only while this attempt still owns its lease
    /// and the tenant still wants the address. Seals the key before writing.
    ///
    /// # Errors
    ///
    /// Returns `Infrastructure` on persistence or sealing failure.
    async fn save(&self, certificate: &PlatformCertificate) -> Result<(), DomainError>;

    /// Releases this attempt with a persisted delay, leaving a still-valid
    /// certificate usable during a renewal failure.
    ///
    /// # Errors
    ///
    /// Returns `Infrastructure` on persistence failure.
    async fn record_failure(&self, order: &PlatformCertificateOrder) -> Result<(), DomainError>;
}
