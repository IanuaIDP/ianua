//! A tenant's SCIM endpoint, at most one, its bearer token kept as the
//! hash the domain hands over.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::federation::ScimStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;

use self::record::{EndpointColumns, EndpointRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of tenants' SCIM endpoints.
pub struct PgScimStore {
    databases: Arc<Databases>,
}

impl PgScimStore {
    /// A store keeping endpoints in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgScimStore {}

#[async_trait]
impl ScimStore for PgScimStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<ScimEndpoint<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    EndpointRecord,
                    "queries/scim_endpoints/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(EndpointRecord::into_endpoint).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        endpoint: &ScimEndpoint<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = EndpointColumns::of(endpoint);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/scim_endpoints/save.sql",
                    tenant_id.as_uuid(),
                    columns.bearer_token_hash,
                    columns.enabled,
                    columns.default_role_id,
                    columns.auto_activate,
                    columns.deactivate_on_remove,
                    columns.last_sync_at,
                    columns.created_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn save_last_sync(
        &self,
        tenant_id: &ScopedTenant,
        endpoint: &ScimEndpoint<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let synced_at = endpoint.last_sync_at();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/scim_endpoints/synced.sql",
                    tenant_id.as_uuid(),
                    synced_at
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
    use ianua_app::ports::authorization::RoleStore;
    use ianua_domain::domains::federation::scim::{ScimActivation, ScimEndpointRow, ScimRemoval};
    use ianua_domain::types::{Enablement, Setting, TokenHash};

    use super::*;
    use crate::postgres::authorization::PgRoleStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{role, tenant};
    use crate::test_support::rows::federation::scim_endpoint_row;

    struct Fixture {
        db: TestDb,
        store: PgScimStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgScimStore::new(Arc::clone(&db.databases)),
            tenant: tenant(),
            db,
        }
    }

    fn endpoint(row: ScimEndpointRow) -> ScimEndpoint<ResolvedTenant> {
        ScimEndpoint::reconstitute(row).unwrap()
    }

    /// Acme's endpoint, giving new people a role, waiting for their
    /// confirmation and deleting removed accounts, is found as it was saved.
    #[tokio::test]
    async fn an_endpoint_is_found_as_it_was_saved() {
        let fx = fixture().await;
        let member = role("member");
        PgRoleStore::new(Arc::clone(&fx.db.databases))
            .save(&fx.tenant, &member)
            .await
            .unwrap();
        let saved = endpoint(ScimEndpointRow {
            default_role_id: Setting::Set(*member.id()),
            auto_activate: ScimActivation::AfterConfirmation,
            deactivate_on_remove: ScimRemoval::Delete,
            last_sync_at: Some(at(10)),
            ..scim_endpoint_row("token-hash-1")
        });

        fx.store.save(&fx.tenant, &saved).await.unwrap();

        let found = fx.store.find(&fx.tenant).await.unwrap().unwrap();
        assert_eq!(found.bearer_token_hash(), saved.bearer_token_hash());
        assert!(found.enabled());
        assert_eq!(found.default_role_id(), Some(member.id()));
        assert_eq!(found.auto_activate(), ScimActivation::AfterConfirmation);
        assert_eq!(found.deactivate_on_remove(), ScimRemoval::Delete);
        assert_eq!(found.last_sync_at(), Some(at(10)));
        assert_eq!(found.created_at(), at(0));
    }

    /// A tenant without SCIM finds no endpoint, rather than failing.
    #[tokio::test]
    async fn a_tenant_without_scim_finds_none() {
        let fx = fixture().await;

        assert!(fx.store.find(&fx.tenant).await.unwrap().is_none());
    }

    /// An admin rotates the token and switches SCIM off: saving again
    /// keeps the new values, and when it was set up stays.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &endpoint(scim_endpoint_row("token-hash-1")))
            .await
            .unwrap();
        let rotated = endpoint(ScimEndpointRow {
            enabled: Enablement::Disabled,
            created_at: at(3),
            ..scim_endpoint_row("token-hash-2")
        });

        fx.store.save(&fx.tenant, &rotated).await.unwrap();

        let found = fx.store.find(&fx.tenant).await.unwrap().unwrap();
        assert_eq!(
            found.bearer_token_hash(),
            &TokenHash::from_stored("token-hash-2".to_owned())
        );
        assert!(!found.enabled());
        assert_eq!(found.created_at(), at(0));
    }

    /// Saving a sync time from a stale enabled endpoint updates the time
    /// while preserving the administrator's disabled setting.
    #[tokio::test]
    async fn a_sync_writes_only_its_time() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &endpoint(scim_endpoint_row("token-hash-1")))
            .await
            .unwrap();
        let switched_off = endpoint(ScimEndpointRow {
            enabled: Enablement::Disabled,
            ..scim_endpoint_row("token-hash-1")
        });
        fx.store.save(&fx.tenant, &switched_off).await.unwrap();
        let held_by_the_call = endpoint(ScimEndpointRow {
            last_sync_at: Some(at(20)),
            ..scim_endpoint_row("token-hash-1")
        });

        fx.store
            .save_last_sync(&fx.tenant, &held_by_the_call)
            .await
            .unwrap();

        let found = fx.store.find(&fx.tenant).await.unwrap().unwrap();
        assert!(!found.enabled());
        assert_eq!(found.last_sync_at(), Some(at(20)));
    }

    /// Looking up an endpoint in another tenant does not return Acme's.
    #[tokio::test]
    async fn another_tenants_endpoint_is_not_found() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &endpoint(scim_endpoint_row("token-hash-1")))
            .await
            .unwrap();

        assert!(fx.store.find(&tenant()).await.unwrap().is_none());
    }

    /// An endpoint whose stored sync time precedes its creation fails to
    /// load as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_endpoint_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &endpoint(scim_endpoint_row("token-hash-1")))
            .await
            .unwrap();
        fx.db
            .tamper(
                "ALTER TABLE scim_endpoints DROP CONSTRAINT scim_endpoints_synced_after_created; \
                 UPDATE scim_endpoints SET last_sync_at = created_at - interval '1 day'",
            )
            .await;

        let read = fx.store.find(&fx.tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
