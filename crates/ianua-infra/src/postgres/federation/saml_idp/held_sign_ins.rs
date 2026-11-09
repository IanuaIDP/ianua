//! The sign-in requests a tenant's SAML apps sent, held as they arrived
//! until the person they are for has signed in and they are answered.
//!
//! A request is answered within [`ANSWER_WITHIN`] of arriving: one held
//! longer is never handed out, and the tenant's lapsed ones are let go when
//! the next one arrives.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::{HeldSamlSignIn, HeldSamlSignInStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::SamlArrivalId;
use sqlx::PgConnection;
use time::{Duration, OffsetDateTime};

use self::record::{HeldColumns, HeldRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long a held request may wait for its answer.
const ANSWER_WITHIN: Duration = Duration::minutes(10);

/// The Postgres store of held SAML sign-in requests.
pub struct PgHeldSamlSignInStore {
    databases: Arc<Databases>,
}

impl PgHeldSamlSignInStore {
    /// A store holding requests in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgHeldSamlSignInStore {}

/// Removes this tenant's unanswered requests whose permitted waiting period has elapsed.
async fn clear_lapsed(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    before: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/held_saml_sign_ins/clear_lapsed.sql",
        tenant.as_uuid(),
        before
    )
    .execute(connection)
    .await
    .map(|_| ())
}

#[async_trait]
impl HeldSamlSignInStore for PgHeldSamlSignInStore {
    async fn hold(
        &self,
        tenant_id: &ScopedTenant,
        request: &HeldSamlSignIn,
    ) -> Result<(), DomainError> {
        let columns = HeldColumns::of(request);
        let lapsed_before = clock::now().saturating_sub(ANSWER_WITHIN);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                clear_lapsed(connection, tenant_id, lapsed_before).await?;
                sqlx::query_file!(
                    "queries/held_saml_sign_ins/hold.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.binding,
                    columns.signature_algorithm,
                    columns.signature,
                    columns.signed_query,
                    columns.message,
                    columns.relay_state,
                    columns.arrived_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlArrivalId,
    ) -> Result<Option<HeldSamlSignIn>, DomainError> {
        let lapsed_before = clock::now().saturating_sub(ANSWER_WITHIN);
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    HeldRecord,
                    "queries/held_saml_sign_ins/find.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid(),
                    lapsed_before
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(HeldRecord::into_held).transpose()
    }

    async fn release(
        &self,
        tenant_id: &ScopedTenant,
        id: &SamlArrivalId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/held_saml_sign_ins/release.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::federation::{InboundSamlMessage, RedirectSignature, SamlBinding};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::federation::held_sign_in;

    struct Fixture {
        db: TestDb,
        store: PgHeldSamlSignInStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgHeldSamlSignInStore::new(Arc::clone(&db.databases)),
            tenant: tenant(),
            db,
        }
    }

    /// A posted request is found as it arrived, until it is released.
    #[tokio::test]
    async fn a_held_request_is_found_until_it_is_released() {
        let fx = fixture().await;
        let held = held_sign_in("PHNhbWxwOkF1dGhuUmVxdWVzdC8+");
        fx.store.hold(&fx.tenant, &held).await.unwrap();

        let found = fx.store.find(&fx.tenant, &held.id).await.unwrap();
        fx.store.release(&fx.tenant, &held.id).await.unwrap();
        let after = fx.store.find(&fx.tenant, &held.id).await.unwrap();

        let found = found.unwrap();
        assert_eq!(found.message, held.message);
        assert_eq!(found.relay_state, held.relay_state);
        assert_eq!(
            found.arrived_at.unix_timestamp(),
            held.arrived_at.unix_timestamp()
        );
        assert!(after.is_none());
    }

    /// A request that came by redirect, signed on its query, keeps its
    /// signature exactly as it arrived.
    #[tokio::test]
    async fn a_redirected_request_keeps_its_signature() {
        let fx = fixture().await;
        let held = HeldSamlSignIn {
            message: InboundSamlMessage {
                binding: SamlBinding::Redirect(RedirectSignature::Present {
                    algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_owned(),
                    signature: "c2lnbmF0dXJl".to_owned(),
                    signed_query: "SAMLRequest=abc&SigAlg=rsa".to_owned(),
                }),
                message: "fZJNb9swDIb".to_owned(),
            },
            relay_state: None,
            ..held_sign_in("unused")
        };
        fx.store.hold(&fx.tenant, &held).await.unwrap();

        let found = fx.store.find(&fx.tenant, &held.id).await.unwrap().unwrap();

        assert_eq!(found.message, held.message);
        assert!(found.relay_state.is_none());
    }

    /// A sign-in request held for eleven minutes is absent from lookup.
    #[tokio::test]
    async fn a_lapsed_request_is_not_found() {
        let fx = fixture().await;
        let held = held_sign_in("PHNhbWxwOkF1dGhuUmVxdWVzdC8+");
        fx.store.hold(&fx.tenant, &held).await.unwrap();
        fx.db
            .tamper("UPDATE held_saml_sign_ins SET arrived_at = now() - interval '11 minutes'")
            .await;

        let found = fx.store.find(&fx.tenant, &held.id).await.unwrap();

        assert!(found.is_none());
    }

    /// Globex cannot find the sign-in request Acme holds by its ID.
    #[tokio::test]
    async fn another_tenants_request_is_not_found() {
        let fx = fixture().await;
        let held = held_sign_in("PHNhbWxwOkF1dGhuUmVxdWVzdC8+");
        fx.store.hold(&fx.tenant, &held).await.unwrap();

        let found = fx.store.find(&tenant(), &held.id).await.unwrap();

        assert!(found.is_none());
    }

    /// A stored POST message carrying a redirect signature fails to load
    /// as corrupt storage.
    #[tokio::test]
    async fn a_row_mixing_bindings_is_refused() {
        let fx = fixture().await;
        let held = held_sign_in("PHNhbWxwOkF1dGhuUmVxdWVzdC8+");
        fx.store.hold(&fx.tenant, &held).await.unwrap();
        fx.db
            .tamper(
                "ALTER TABLE held_saml_sign_ins DROP CONSTRAINT held_saml_sign_ins_signed_only_redirected; \
                 UPDATE held_saml_sign_ins \
                 SET signature_algorithm = 'rsa', signature = 'c2ln', signed_query = 'q'",
            )
            .await;

        let found = fx.store.find(&fx.tenant, &held.id).await;

        assert!(matches!(found, Err(DomainError::Infrastructure(_))));
    }
}
