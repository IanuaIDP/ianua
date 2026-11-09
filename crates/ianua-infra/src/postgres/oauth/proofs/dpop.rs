//! The DPoP proofs each key already used in a tenant (RFC 9449 11.1), kept
//! until each would be refused as too old anyway, under row-level security.
//!
//! A use is one insert that does nothing for a proof its key sent before,
//! so of two requests racing one copied proof exactly one is told it was
//! the first. A proof is taken for a minute, so the tenant's expired ones
//! are forgotten as the next is spent, and the table holds about a minute
//! of them. The ledger reads no row back, so it has no mapping of its own.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::DpopReplayGuard;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TokenId;
use time::OffsetDateTime;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres ledger of DPoP proofs already used.
pub struct PgDpopReplayGuard {
    databases: Arc<Databases>,
}

impl TenantScoped for PgDpopReplayGuard {}

impl PgDpopReplayGuard {
    /// A ledger keeping used proofs in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl DpopReplayGuard for PgDpopReplayGuard {
    async fn first_use(
        &self,
        tenant_id: &ScopedTenant,
        thumbprint: &JwkThumbprint,
        jti: &TokenId,
        until: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let now = clock::now();
        let spent = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_dpop_proofs/clear_expired.sql",
                    tenant_id.as_uuid(),
                    now
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query_file_scalar!(
                    "queries/oauth_dpop_proofs/spend.sql",
                    tenant_id.as_uuid(),
                    thumbprint.as_str(),
                    jti.as_str(),
                    until
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

    /// A fresh database, and the ledger on it.
    async fn fixture() -> (TestDb, PgDpopReplayGuard) {
        let db = TestDb::fresh().await;
        let guard = PgDpopReplayGuard::new(Arc::clone(&db.databases));
        (db, guard)
    }

    fn key(last: char) -> JwkThumbprint {
        JwkThumbprint::new(format!("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9X{last}")).unwrap()
    }

    fn jti(value: &str) -> TokenId {
        TokenId::new(value).unwrap()
    }

    fn in_a_minute() -> OffsetDateTime {
        clock::now().saturating_add(Duration::minutes(1))
    }

    /// The first time a key sends a proof, this call records it.
    #[tokio::test]
    async fn a_fresh_proof_is_a_first_use() {
        let (_db, guard) = fixture().await;

        let first = guard
            .first_use(&tenant(), &key('s'), &jti("p-1"), in_a_minute())
            .await
            .unwrap();

        assert!(first);
    }

    /// Reusing a proof ID for the same key and tenant returns false.
    #[tokio::test]
    async fn a_replayed_proof_is_refused() {
        let (_db, guard) = fixture().await;
        let acme = tenant();
        guard
            .first_use(&acme, &key('s'), &jti("p-1"), in_a_minute())
            .await
            .unwrap();

        let again = guard
            .first_use(&acme, &key('s'), &jti("p-1"), in_a_minute())
            .await
            .unwrap();

        assert!(!again);
    }

    /// The same `jti` from another key, or in another tenant, is that one's
    /// own first use.
    #[tokio::test]
    async fn another_key_or_tenant_uses_its_own_ids() {
        let (_db, guard) = fixture().await;
        let acme = tenant();
        guard
            .first_use(&acme, &key('s'), &jti("p-1"), in_a_minute())
            .await
            .unwrap();

        let other_key = guard
            .first_use(&acme, &key('t'), &jti("p-1"), in_a_minute())
            .await
            .unwrap();
        let in_globex = guard
            .first_use(&tenant(), &key('s'), &jti("p-1"), in_a_minute())
            .await
            .unwrap();

        assert!(other_key);
        assert!(in_globex);
    }

    /// A proof is forgotten once its minute passed, when the next one is
    /// spent, so the ledger does not grow without end.
    #[tokio::test]
    async fn an_expired_proof_is_forgotten() {
        let (db, guard) = fixture().await;
        let acme = tenant();
        guard
            .first_use(&acme, &key('s'), &jti("p-1"), in_a_minute())
            .await
            .unwrap();
        db.tamper("UPDATE oauth_dpop_proofs SET expires_at = now() - interval '1 minute'")
            .await;

        let spent_again = guard
            .first_use(&acme, &key('s'), &jti("p-1"), in_a_minute())
            .await
            .unwrap();

        assert!(spent_again);
    }
}
