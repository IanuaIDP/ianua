//! The logout requests a tenant's peers sent that were taken, kept until
//! each would be refused as too old anyway.
//!
//! Taking one is one insert that does nothing for a request the tenant
//! keeps already, by its issuer and ID, so of two nodes racing the same
//! replay exactly one is told it took it. Taking one forgets the tenant's
//! requests that expired, so the ledger does not grow without end. The
//! ledger reads no row back, so it keeps no mapper.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::SamlLogoutLedger;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::federation::saml::logout::SamlLogoutRequest;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres ledger of the logout requests a tenant's peers sent.
pub struct PgSamlLogoutLedger {
    databases: Arc<Databases>,
}

impl PgSamlLogoutLedger {
    /// A ledger keeping taken requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSamlLogoutLedger {}

#[async_trait]
impl SamlLogoutLedger for PgSamlLogoutLedger {
    async fn spend(
        &self,
        tenant_id: &ScopedTenant,
        request: &SamlLogoutRequest,
    ) -> Result<bool, DomainError> {
        let now = clock::now();
        let taken = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/taken_logout_requests/clear_expired.sql",
                    tenant_id.as_uuid(),
                    now
                )
                .execute(&mut *connection)
                .await?;
                sqlx::query_file_scalar!(
                    "queries/taken_logout_requests/spend.sql",
                    tenant_id.as_uuid(),
                    request.issuer().as_str(),
                    request.id().as_str(),
                    request.taken_until()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        Ok(taken.is_some())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::saml::logout::LogoutRequestParts;
    use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
    use ianua_domain::types::{SamlEntityId, SamlRequestId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;

    /// A fresh database, the ledger on it, and one tenant.
    async fn fixture() -> (TestDb, PgSamlLogoutLedger, ScopedTenant) {
        let db = TestDb::fresh().await;
        let ledger = PgSamlLogoutLedger::new(Arc::clone(&db.databases));
        (db, ledger, tenant())
    }

    /// The request `id` from `issuer`, issued now.
    fn request(issuer: &str, id: &str) -> SamlLogoutRequest {
        SamlLogoutRequest::new(LogoutRequestParts {
            id: SamlRequestId::new(id).unwrap(),
            issuer: SamlEntityId::new(issuer).unwrap(),
            issued_at: clock::now(),
            name_id: SamlNameIdValue::new("00u1").unwrap(),
            session_indexes: Vec::new(),
        })
    }

    /// Two concurrent attempts to spend the same logout request yield one
    /// success; a later attempt is also refused.
    #[tokio::test]
    async fn a_request_is_taken_once() {
        let (_db, ledger, acme) = fixture().await;
        let logout = request("https://idp.acme.com", "_l1");

        let (one, two) = tokio::join!(ledger.spend(&acme, &logout), ledger.spend(&acme, &logout));
        let again = ledger.spend(&acme, &logout).await.unwrap();

        assert_ne!(one.unwrap(), two.unwrap());
        assert!(!again);
    }

    /// Two peers may use the same ID, and two tenants' peers too: taking it
    /// from one leaves it fresh for the others.
    #[tokio::test]
    async fn a_request_is_taken_per_tenant_and_issuer() {
        let (_db, ledger, acme) = fixture().await;
        ledger
            .spend(&acme, &request("https://idp.acme.com", "_l1"))
            .await
            .unwrap();

        let other_peer = ledger
            .spend(&acme, &request("https://app.acme.com", "_l1"))
            .await
            .unwrap();
        let other_tenant = ledger
            .spend(&tenant(), &request("https://idp.acme.com", "_l1"))
            .await
            .unwrap();

        assert!(other_peer);
        assert!(other_tenant);
    }

    /// A request is forgotten once it expired, when the tenant's next one
    /// is taken, so the ledger does not grow without end.
    #[tokio::test]
    async fn an_expired_request_is_forgotten() {
        let (db, ledger, acme) = fixture().await;
        let logout = request("https://idp.acme.com", "_l1");
        ledger.spend(&acme, &logout).await.unwrap();
        db.tamper("UPDATE taken_logout_requests SET expires_at = now() - interval '1 minute'")
            .await;

        let taken_again = ledger.spend(&acme, &logout).await.unwrap();

        assert!(taken_again);
    }
}
