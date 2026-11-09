//! The SAML assertions a tenant's connections sent that were spent, kept
//! until each would have expired anyway.
//!
//! Spending is one insert that does nothing for an id the tenant keeps
//! already, so of two nodes racing the same replay exactly one is told it
//! spent it. An assertion is forgotten once its expiry passed, which the
//! caller gives with any clock skew it allows already added, so it is never
//! taken again while it could still be accepted. The ledger reads no row
//! back, so it keeps no mapper.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::SamlAssertionLedger;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SamlAssertionId;
use time::OffsetDateTime;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres ledger of a tenant's spent SAML assertions.
pub struct PgSamlAssertionLedger {
    databases: Arc<Databases>,
}

impl PgSamlAssertionLedger {
    /// A ledger keeping spent assertions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSamlAssertionLedger {}

#[async_trait]
impl SamlAssertionLedger for PgSamlAssertionLedger {
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        assertion_id: &SamlAssertionId,
        expires_at: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let now = clock::now();
        let spent = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/saml_assertions/clear_expired.sql",
                    tenant_id.as_uuid(),
                    now
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query_file_scalar!(
                    "queries/saml_assertions/spend.sql",
                    tenant_id.as_uuid(),
                    assertion_id.as_str(),
                    expires_at
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        Ok(spent.is_some())
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;

    struct Fixture {
        db: TestDb,
        ledger: PgSamlAssertionLedger,
        tenant: ScopedTenant,
    }

    /// A fresh database, the ledger on it, and one tenant.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            ledger: PgSamlAssertionLedger::new(Arc::clone(&db.databases)),
            tenant: tenant(),
            db,
        }
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
        let fx = fixture().await;

        let spent = fx
            .ledger
            .spend(&fx.tenant, &assertion("_fresh1"), in_five_minutes())
            .await
            .unwrap();

        assert!(spent);
    }

    /// Spending the same unexpired SAML assertion a second time reports
    /// that it was not accepted again.
    #[tokio::test]
    async fn a_replayed_assertion_is_refused() {
        let fx = fixture().await;
        let id = assertion("_replayed1");
        fx.ledger
            .spend(&fx.tenant, &id, in_five_minutes())
            .await
            .unwrap();

        let again = fx
            .ledger
            .spend(&fx.tenant, &id, in_five_minutes())
            .await
            .unwrap();

        assert!(!again);
    }

    /// Two tenants' providers may issue the same id: spending it in one
    /// leaves it fresh in the other.
    #[tokio::test]
    async fn an_assertion_is_spent_per_tenant() {
        let fx = fixture().await;
        let id = assertion("_shared1");
        fx.ledger
            .spend(&fx.tenant, &id, in_five_minutes())
            .await
            .unwrap();

        let elsewhere = fx
            .ledger
            .spend(&tenant(), &id, in_five_minutes())
            .await
            .unwrap();

        assert!(elsewhere);
    }

    /// An assertion is forgotten once its expiry passed, when the tenant's
    /// next one is spent, so the ledger does not grow without end.
    #[tokio::test]
    async fn an_expired_assertion_is_forgotten() {
        let fx = fixture().await;
        let id = assertion("_expired1");
        fx.ledger
            .spend(&fx.tenant, &id, in_five_minutes())
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE saml_assertions SET expires_at = now() - interval '1 minute'")
            .await;

        let spent_again = fx
            .ledger
            .spend(&fx.tenant, &id, in_five_minutes())
            .await
            .unwrap();

        assert!(spent_again);
    }
}
