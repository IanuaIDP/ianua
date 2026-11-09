//! The SAML assertions organizations' providers sent that were spent, kept
//! in the platform database until each would have expired anyway.
//!
//! Spending is one insert that does nothing for an id already kept, so of
//! two nodes racing the same replay exactly one is told it spent it. An
//! assertion is forgotten once its expiry passed, which the caller gives
//! with any clock skew it allows already added, so it is never taken again
//! while it could still be accepted.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgSamlAssertionLedger;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SamlAssertionId;
use time::OffsetDateTime;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres ledger of spent SAML assertions.
pub struct PgOrgSamlAssertionLedger {
    databases: Arc<Databases>,
}

impl PgOrgSamlAssertionLedger {
    /// A ledger keeping spent assertions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgSamlAssertionLedger for PgOrgSamlAssertionLedger {
    async fn spend(
        &self,
        assertion_id: &SamlAssertionId,
        expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let now = clock::now();
        let spent = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!("queries/org_saml_assertions/clear_expired.sql", now)
                .execute(&mut *connection)
                .await?;
            sqlx::query_file_scalar!(
                "queries/org_saml_assertions/spend.sql",
                assertion_id.as_str(),
                expires_at
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        Ok(spent.is_some())
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::test_support::TestDb;

    /// A fresh database, and the ledger on it.
    async fn fixture() -> (TestDb, PgOrgSamlAssertionLedger) {
        let db = TestDb::fresh().await;
        let ledger = PgOrgSamlAssertionLedger::new(Arc::clone(&db.databases));
        (db, ledger)
    }

    fn assertion(id: &str) -> SamlAssertionId {
        SamlAssertionId::new(id).unwrap()
    }

    fn in_five_minutes() -> OffsetDateTime {
        clock::now().saturating_add(Duration::minutes(5))
    }

    /// The first time an assertion is offered, this call spends it.
    #[tokio::test]
    async fn a_fresh_assertion_is_spent() {
        let (_db, ledger) = fixture().await;

        let spent = ledger
            .spend(&assertion("_fresh1"), in_five_minutes())
            .await
            .unwrap();

        assert!(spent);
    }

    /// Spending an assertion ID already in the ledger returns false while
    /// its expiry remains in the future.
    #[tokio::test]
    async fn a_replayed_assertion_is_refused() {
        let (_db, ledger) = fixture().await;
        let id = assertion("_replayed1");
        ledger.spend(&id, in_five_minutes()).await.unwrap();

        let again = ledger.spend(&id, in_five_minutes()).await.unwrap();

        assert!(!again);
    }

    /// Spending one assertion leaves every other one fresh.
    #[tokio::test]
    async fn another_assertion_is_still_fresh() {
        let (_db, ledger) = fixture().await;
        ledger
            .spend(&assertion("_first1"), in_five_minutes())
            .await
            .unwrap();

        let other = ledger
            .spend(&assertion("_second1"), in_five_minutes())
            .await
            .unwrap();

        assert!(other);
    }

    /// An assertion is forgotten once its expiry passed, when the next one
    /// is spent, so the ledger does not grow without end.
    #[tokio::test]
    async fn an_expired_assertion_is_forgotten() {
        let (db, ledger) = fixture().await;
        let id = assertion("_expired1");
        ledger.spend(&id, in_five_minutes()).await.unwrap();
        db.tamper("UPDATE org_saml_assertions SET expires_at = now() - interval '1 minute'")
            .await;

        let spent_again = ledger.spend(&id, in_five_minutes()).await.unwrap();

        assert!(spent_again);
    }
}
