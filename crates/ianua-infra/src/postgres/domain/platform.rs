//! Durable platform certificate leases and sealed keys, separate from tenant registrations.

mod record;
mod zones;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::domain::{
    PlatformCertificateOrder, PlatformCertificateStore, PlatformCertificateTarget,
    PlatformZoneSettings, certificate_key_place,
};
use ianua_domain::domains::tenant::hosts::PlatformCertificate;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificateId, DomainName};
pub(crate) use record::CertificateRecord;
pub use zones::PgPlatformDnsChallenges;
pub(crate) use zones::served_zones;

use self::record::{OrderRecord, TargetColumns};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// Persists desired platform roots and renews them under expiring leases.
pub struct PgPlatformCertificateStore {
    databases: Arc<Databases>,
    encryptor: Arc<dyn SecretEncryptor>,
}

impl PgPlatformCertificateStore {
    /// Keeps platform certificates in `databases`, sealing every private key.
    #[must_use]
    pub fn new(databases: Arc<Databases>, encryptor: Arc<dyn SecretEncryptor>) -> Self {
        Self {
            databases,
            encryptor,
        }
    }
}

#[async_trait]
impl PlatformCertificateStore for PgPlatformCertificateStore {
    async fn synchronize(
        &self,
        targets: &[PlatformCertificateTarget],
        zones: Option<&PlatformZoneSettings>,
    ) -> Result<(), DomainError> {
        let columns = TargetColumns::of(targets);
        let nameservers: Vec<&str> = zones
            .map(|zone| zone.nameservers.iter().map(DomainName::as_str).collect())
            .unwrap_or_default();
        let address = zones.map(|zone| zone.address.as_str()).unwrap_or_default();
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/platform_certificates/prune.sql",
                &columns.roots as &[&str]
            )
            .execute(&mut *connection)
            .await?;
            sqlx::query_file!(
                "queries/platform_certificates/synchronize.sql",
                &columns.roots as &[&str],
                &columns.tenants,
                &columns.readable,
                &nameservers as &[&str],
                address
            )
            .execute(&mut *connection)
            .await?;
            sqlx::query_file!("queries/platform_certificates/purge_proofs.sql")
                .execute(connection)
                .await
                .map(|_| ())
        })
        .await
    }

    async fn claim_next(
        &self,
        attempt: CertificateId,
    ) -> Result<Option<PlatformCertificateOrder>, DomainError> {
        let record = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file_as!(
                OrderRecord,
                "queries/platform_certificates/claim.sql",
                attempt.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(|record| record.into_order(attempt)).transpose()
    }

    async fn save(&self, certificate: &PlatformCertificate) -> Result<(), DomainError> {
        let sealed = self
            .encryptor
            .encrypt(
                certificate.private_key_pem().expose().as_bytes(),
                &certificate_key_place(certificate.id()),
            )
            .await?;
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/platform_certificates/save.sql",
                certificate.id().as_uuid(),
                certificate.tenant_id().as_uuid(),
                certificate.root().as_str(),
                certificate.certificate_pem().as_str(),
                sealed.as_str(),
                certificate.issued_at(),
                certificate.expires_at()
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }

    async fn record_failure(&self, order: &PlatformCertificateOrder) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/platform_certificates/failed.sql",
                order.id.as_uuid(),
                order.target.tenant_id.as_uuid(),
                order.target.root.as_str()
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::proxy::CrossTenantServedCertificates as _;
    use ianua_domain::domains::tenant::hosts::ReadableAddress;

    use super::*;
    use crate::postgres::proxy::PgCrossTenantServedCertificates;
    use crate::test_support::certificates::Fixture;

    /// Claims an available root with a fresh certificate attempt identifier.
    async fn claim(f: &Fixture) -> PlatformCertificateOrder {
        f.store
            .claim_next(CertificateId::new())
            .await
            .unwrap()
            .unwrap()
    }

    /// Requires the store to withhold another lease until work becomes due.
    async fn assert_no_lease(f: &Fixture) {
        assert!(
            f.store
                .claim_next(CertificateId::new())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Checks both served names, tenant ownership and the opened private key.
    async fn assert_served_pair(f: &Fixture, certificate: &PlatformCertificate) {
        let reader =
            PgCrossTenantServedCertificates::new(f.db.gateway.clone(), f.encryptor.clone());
        let current = reader.current().await.unwrap();
        assert_eq!(current.len(), 2);
        assert!(
            current
                .iter()
                .any(|held| &held.domain == certificate.root())
        );
        assert!(
            current
                .iter()
                .any(|held| held.domain.as_str() == "*.k7f3q9.apps.example.com")
        );
        for held in current {
            assert_eq!(held.tenant_id, *f.tenant);
            assert_eq!(
                held.bundle.private_key_pem().expose(),
                certificate.private_key_pem().expose()
            );
        }
    }

    /// Two workers racing for one root receive one lease. The gateway reads
    /// the saved pair under its own role and opens the original sealed key.
    #[tokio::test]
    async fn one_worker_issues_a_pair_the_gateway_can_serve() {
        let f = Fixture::new().await;
        let target = f.target("k7f3q9.apps.example.com", ReadableAddress::Off);
        f.synchronize(std::slice::from_ref(&target)).await;
        let (first, second) = tokio::join!(
            f.store.claim_next(CertificateId::new()),
            f.store.claim_next(CertificateId::new())
        );
        let orders: Vec<_> = [first.unwrap(), second.unwrap()]
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(orders.len(), 1);
        let certificate = f.certificate(orders[0].id, &target.root);
        f.store.save(&certificate).await.unwrap();
        assert_served_pair(&f, &certificate).await;
        assert_no_lease(&f).await;
    }

    /// Saving an expired lease's certificate leaves the gateway's certificate
    /// list empty; saving the current attempt returns only that attempt's bundle.
    #[tokio::test]
    async fn a_stale_issuance_cannot_replace_the_current_attempt() {
        let f = Fixture::new().await;
        let target = f.target("k7f3q9.apps.example.com", ReadableAddress::Off);
        f.synchronize(std::slice::from_ref(&target)).await;
        let old = claim(&f).await;
        f.db.tamper("UPDATE platform_certificates SET lease_until = now() - interval '1 minute'")
            .await;
        let current = claim(&f).await;
        f.store
            .save(&f.certificate(old.id, &target.root))
            .await
            .unwrap();
        let reader =
            PgCrossTenantServedCertificates::new(f.db.gateway.clone(), f.encryptor.clone());
        assert!(reader.current().await.unwrap().is_empty());
        f.store
            .save(&f.certificate(current.id, &target.root))
            .await
            .unwrap();
        assert!(
            reader
                .current()
                .await
                .unwrap()
                .iter()
                .all(|held| held.bundle.id() == &current.id)
        );
    }

    /// A failed renewal leaves the existing certificate pair readable and
    /// prevents an immediate retry from claiming another lease.
    #[tokio::test]
    async fn a_failed_renewal_keeps_the_current_pair_and_delays_retry() {
        let f = Fixture::new().await;
        let target = f.target("k7f3q9.apps.example.com", ReadableAddress::Off);
        f.synchronize(std::slice::from_ref(&target)).await;
        let first = claim(&f).await;
        f.store
            .save(&f.certificate(first.id, &target.root))
            .await
            .unwrap();
        f.db.tamper("UPDATE platform_certificates SET expires_at = now() + interval '1 day', next_attempt = now() - interval '1 minute'").await;
        let renewal = claim(&f).await;
        f.store.record_failure(&renewal).await.unwrap();
        assert_no_lease(&f).await;
        let reader =
            PgCrossTenantServedCertificates::new(f.db.gateway.clone(), f.encryptor.clone());
        let current = reader.current().await.unwrap();
        assert_eq!(current.len(), 2);
        assert!(current.iter().all(|held| held.bundle.id() == &first.id));
    }

    /// Withdrawing consent after a readable root's lease is claimed keeps a
    /// late certificate save out of gateway reads. Removing the target then
    /// leaves no lease available to claim.
    #[tokio::test]
    async fn withdrawing_consent_stops_certificates_and_late_saves() {
        let f = Fixture::new().await;
        let target = f.target("main.acme.apps.example.com", ReadableAddress::On);
        f.synchronize(std::slice::from_ref(&target)).await;
        assert_no_lease(&f).await;
        f.consent(ReadableAddress::On).await;
        f.synchronize(std::slice::from_ref(&target)).await;
        let order = claim(&f).await;
        f.consent(ReadableAddress::Off).await;
        f.store
            .save(&f.certificate(order.id, &target.root))
            .await
            .unwrap();
        let reader =
            PgCrossTenantServedCertificates::new(f.db.gateway.clone(), f.encryptor.clone());
        assert!(reader.current().await.unwrap().is_empty());
        f.synchronize(&[]).await;
        assert_no_lease(&f).await;
    }
}
