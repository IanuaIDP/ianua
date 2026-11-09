//! Public platform DNS answers and temporary DNS-01 proofs.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::dns_zone::{HeldZone, TxtValue};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DomainName;

use self::record::ZoneRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::tls::AcmeDnsChallengeStore;

/// Publishes DNS-01 proofs only for currently leased platform roots.
pub struct PgPlatformDnsChallenges {
    databases: Arc<Databases>,
}

impl PgPlatformDnsChallenges {
    /// Uses the same platform database as the nameserver's public read.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AcmeDnsChallengeStore for PgPlatformDnsChallenges {
    async fn publish(&self, hostname: &DomainName, value: &TxtValue) -> Result<(), DomainError> {
        let root = hostname
            .as_str()
            .strip_prefix("*.")
            .unwrap_or(hostname.as_str());
        let written = scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/platform_certificates/publish_proof.sql",
                root,
                value.as_str()
            )
            .execute(connection)
            .await
        })
        .await?;
        if written.rows_affected() == 0 {
            return Err(DomainError::conflict(message!(
                "infra-the-platform-address-no-longer-has",
                "the platform address no longer has an active order"
            )));
        }
        Ok(())
    }

    async fn withdraw(&self, hostname: &DomainName, value: &TxtValue) -> Result<(), DomainError> {
        let root = hostname
            .as_str()
            .strip_prefix("*.")
            .unwrap_or(hostname.as_str());
        scoped(&self.databases, RowScope::Platform, async |connection| {
            sqlx::query_file!(
                "queries/platform_certificates/withdraw_proof.sql",
                root,
                value.as_str()
            )
            .execute(connection)
            .await
            .map(|_| ())
        })
        .await
    }
}

/// Reads live platform zones without reading any certificate material.
pub(crate) async fn served_zones(databases: &Databases) -> Result<Vec<HeldZone>, DomainError> {
    let records = scoped(databases, RowScope::Platform, async |connection| {
        sqlx::query_file_as!(ZoneRecord, "queries/platform_certificates/zones.sql")
            .fetch_all(connection)
            .await
    })
    .await?;
    records.into_iter().map(ZoneRecord::into_held).collect()
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::domain::PlatformCertificateStore as _;
    use ianua_domain::domains::tenant::custom_domains::dns_zone::{
        RecordKind, RecordSet, RecordValue,
    };
    use ianua_domain::domains::tenant::hosts::ReadableAddress;
    use ianua_domain::types::CertificateId;

    use super::*;
    use crate::test_support::certificates::Fixture;

    /// Public TXT answers as the nameserver's restricted role reads them.
    async fn proofs(f: &Fixture) -> Vec<String> {
        served_zones(&f.db.nameserver)
            .await
            .unwrap()
            .iter()
            .flat_map(|held| held.zone.sets())
            .filter(|set| set.kind() == RecordKind::Txt)
            .flat_map(RecordSet::values)
            .map(RecordValue::as_presentation)
            .collect()
    }

    /// Two proofs coexist under a leased root, and withdrawing one keeps
    /// the other. Unleased and unknown roots reject publication; expired
    /// proofs disappear from the nameserver's answers.
    #[tokio::test]
    async fn simultaneous_proofs_are_independent_and_expire() {
        let f = Fixture::new().await;
        let target = f.target("k7f3q9.apps.example.com", ReadableAddress::Off);
        f.synchronize(std::slice::from_ref(&target)).await;
        let store = PgPlatformDnsChallenges::new(f.db.databases.clone());
        let first = TxtValue::new("root-proof").unwrap();
        let second = TxtValue::new("wildcard-proof").unwrap();
        assert!(store.publish(&target.root, &first).await.is_err());
        f.store
            .claim_next(CertificateId::new())
            .await
            .unwrap()
            .unwrap();
        store.publish(&target.root, &first).await.unwrap();
        store.publish(&target.root, &second).await.unwrap();
        assert_eq!(proofs(&f).await.len(), 2);
        store.withdraw(&target.root, &first).await.unwrap();
        let remaining = proofs(&f).await;
        assert_eq!(remaining.len(), 1);
        assert!(remaining[0].contains("wildcard-proof"));
        let unknown = DomainName::new("unknown.apps.example.com").unwrap();
        assert!(store.publish(&unknown, &first).await.is_err());
        f.db.tamper("UPDATE platform_dns_proofs SET expires_at = now() - interval '1 minute'")
            .await;
        assert!(proofs(&f).await.is_empty());
    }

    /// A readable zone appears after consent and disappears as soon as
    /// consent is withdrawn, without another synchronization.
    #[tokio::test]
    async fn readable_dns_follows_current_consent() {
        let f = Fixture::new().await;
        let target = f.target("main.acme.apps.example.com", ReadableAddress::On);
        f.synchronize(std::slice::from_ref(&target)).await;
        assert!(served_zones(&f.db.nameserver).await.unwrap().is_empty());
        f.consent(ReadableAddress::On).await;
        f.synchronize(std::slice::from_ref(&target)).await;
        let zones = served_zones(&f.db.nameserver).await.unwrap();
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].zone.sets().len(), 2);
        f.consent(ReadableAddress::Off).await;
        assert!(served_zones(&f.db.nameserver).await.unwrap().is_empty());
    }
}
