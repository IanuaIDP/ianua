//! A tenant's model providers, each row under row-level security.
//!
//! A provider's API key arrives sealed: the app seals it with the
//! platform's secret sealer before the provider is built, so the store
//! writes the sealed form it is given and the database never holds the key
//! in clear. A deleted provider is gone for good; the runs that reasoned
//! with it keep its id.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::ModelProviderStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::execution::model_provider::ModelProvider;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ModelProviderId;
use sqlx::PgConnection;

use self::record::{ProviderColumns, ProviderRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres model provider store.
pub struct PgModelProviderStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgModelProviderStore {}

impl PgModelProviderStore {
    /// A store keeping model providers in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The providers `records` hold, each rebuilt through the domain's checks.
fn rebuilt_all(
    records: Vec<ProviderRecord>,
) -> Result<Vec<ModelProvider<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(ProviderRecord::into_provider)
        .collect()
}

/// Writes a provider's mapped columns on the tenant's scoped connection.
async fn write_provider(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    columns: &ProviderColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/agent_model_providers/save.sql",
        columns.id,
        tenant_id.as_uuid(),
        columns.name,
        columns.kind,
        columns.endpoint,
        columns.model,
        columns.input_price_micros,
        columns.output_price_micros,
        columns.api_key_sealed,
        columns.clearance,
        columns.status,
        columns.last_test_status,
        columns.last_tested_at,
        columns.last_test_reason,
        columns.created_at,
        columns.updated_at,
        columns.embedding_model,
    )
    .execute(connection)
    .await
    .map(|_| ())
}

#[async_trait]
impl ModelProviderStore for PgModelProviderStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ModelProviderId,
    ) -> Result<Option<ModelProvider<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ProviderRecord,
                    "queries/agent_model_providers/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids[..]
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(rebuilt_all(records)?.into_iter().next())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ModelProvider<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ProviderRecord,
                    "queries/agent_model_providers/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt_all(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        provider: &ModelProvider<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ProviderColumns::of(provider)?;
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_provider(connection, tenant_id, &columns).await,
        )
        .await
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &ModelProviderId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_model_providers/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::execution::model_provider::{
        LastTest, ModelName, ModelProviderRow, ModelProviderStatus, ModelProviderTestStatus,
        ProviderEmbeddings, ProviderKey,
    };
    use ianua_domain::domains::agents::execution::usage::ModelPricing;
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::{TenantId, UntrustedText};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::run::provider_row;
    use crate::test_support::rows::at;

    struct Fixture {
        db: TestDb,
        store: PgModelProviderStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep
    /// providers for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgModelProviderStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn provider(row: ModelProviderRow) -> ModelProvider<ResolvedTenant> {
        ModelProvider::reconstitute(row).unwrap()
    }

    impl Fixture {
        async fn saved(&self, row: ModelProviderRow) -> ModelProvider<ResolvedTenant> {
            let provider = provider(row);
            self.store.save(&self.tenant, &provider).await.unwrap();
            provider
        }

        async fn found(&self, id: &ModelProviderId) -> Option<ModelProvider<ResolvedTenant>> {
            self.found_in(&self.tenant, id).await
        }

        async fn found_in(
            &self,
            tenant: &ScopedTenant,
            id: &ModelProviderId,
        ) -> Option<ModelProvider<ResolvedTenant>> {
            self.store.find_by_id(tenant, id).await.unwrap()
        }

        async fn names_in(&self, tenant: &ScopedTenant) -> Vec<String> {
            let listed = self.store.list(tenant).await.unwrap();
            listed
                .iter()
                .map(|provider| provider.name().as_str().to_owned())
                .collect()
        }

        async fn names(&self) -> Vec<String> {
            self.names_in(&self.tenant).await
        }
    }

    /// Ann's OpenAI provider offering `text-embedding-3-small` is found
    /// again offering it.
    #[tokio::test]
    async fn a_provider_s_embedding_model_is_kept() {
        let fx = fixture().await;
        let saved = fx
            .saved(ModelProviderRow {
                embeddings: ProviderEmbeddings::Model(
                    ModelName::new("text-embedding-3-small").unwrap(),
                ),
                ..provider_row("prod-openai")
            })
            .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.embeddings(), saved.embeddings());
    }

    /// Ann's priced OpenAI provider, with its sealed key and a failed
    /// test, is found again as it was saved.
    #[tokio::test]
    async fn a_saved_provider_is_found_as_it_was_saved() {
        let fx = fixture().await;
        let saved = fx
            .saved(ModelProviderRow {
                last_test: LastTest::from_stored(
                    Some(ModelProviderTestStatus::Failed),
                    Some(at(5)),
                    Some("timed out".to_owned()),
                )
                .unwrap(),
                updated_at: at(5),
                ..provider_row("prod-openai")
            })
            .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.name(), saved.name());
        assert_eq!(found.kind(), saved.kind());
        assert_eq!(found.endpoint(), saved.endpoint());
        assert_eq!(found.model(), saved.model());
        assert_eq!(found.pricing(), saved.pricing());
        assert_eq!(found.clearance(), saved.clearance());
        assert_eq!(found.last_test(), saved.last_test());
        assert_eq!(found.updated_at(), at(5));
    }

    /// A provider's credential reads back in the sealed form supplied, and a
    /// keyless provider remains keyless.
    #[tokio::test]
    async fn the_key_is_kept_in_the_sealed_form_it_was_given() {
        let fx = fixture().await;
        let keyed = fx.saved(provider_row("prod-openai")).await;
        let keyless = fx
            .saved(ModelProviderRow {
                credential_ref: ProviderKey::Keyless,
                ..provider_row("in-cluster")
            })
            .await;

        let keyed_found = fx.found(keyed.id()).await.unwrap();
        let keyless_found = fx.found(keyless.id()).await.unwrap();

        assert_eq!(keyed_found.credential_ref(), keyed.credential_ref());
        assert_eq!(keyless_found.credential_ref(), &ProviderKey::Keyless);
    }

    /// An id the tenant has no provider for finds nothing, rather than
    /// failing.
    #[tokio::test]
    async fn an_unknown_provider_is_not_found() {
        let fx = fixture().await;

        assert!(fx.found(&ModelProviderId::new()).await.is_none());
    }

    /// The tenant's providers are listed oldest first.
    #[tokio::test]
    async fn the_providers_are_listed_oldest_first() {
        let fx = fixture().await;
        fx.saved(ModelProviderRow {
            created_at: at(2),
            updated_at: at(2),
            ..provider_row("later")
        })
        .await;
        fx.saved(provider_row("first")).await;

        assert_eq!(fx.names().await, ["first", "later"]);
    }

    /// Ann disables a provider and records a passing test: saving it again
    /// keeps both, and nothing else of it.
    #[tokio::test]
    async fn saving_again_keeps_the_new_standing() {
        let fx = fixture().await;
        let saved = fx.saved(provider_row("prod-openai")).await;
        fx.saved(ModelProviderRow {
            id: *saved.id(),
            status: ModelProviderStatus::Disabled,
            pricing: ModelPricing::Unpriced,
            last_test: LastTest::Passed { at: at(9) },
            updated_at: at(9),
            ..provider_row("prod-openai")
        })
        .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.status(), ModelProviderStatus::Disabled);
        assert_eq!(found.pricing(), ModelPricing::Unpriced);
        assert_eq!(found.last_tested_at(), Some(at(9)));
        assert_eq!(fx.names().await, ["prod-openai"]);
    }

    /// A deleted provider is gone, and deleting one the tenant does not
    /// have changes nothing.
    #[tokio::test]
    async fn a_deleted_provider_is_gone() {
        let fx = fixture().await;
        let kept = fx.saved(provider_row("kept")).await;
        let gone = fx.saved(provider_row("gone")).await;

        fx.store.delete(&fx.tenant, gone.id()).await.unwrap();
        let nobody = ModelProviderId::new();
        fx.store.delete(&fx.tenant, &nobody).await.unwrap();

        assert!(fx.found(gone.id()).await.is_none());
        assert!(fx.found(kept.id()).await.is_some());
    }

    /// Another tenant sees none of Acme's providers, by id or in its list,
    /// and cannot delete them.
    #[tokio::test]
    async fn another_tenants_providers_are_invisible() {
        let fx = fixture().await;
        let saved = fx.saved(provider_row("prod-openai")).await;
        let other = ScopedTenant::for_background(TenantId::new());

        fx.store.delete(&other, saved.id()).await.unwrap();

        assert!(fx.found_in(&other, saved.id()).await.is_none());
        assert!(fx.names_in(&other).await.is_empty());
        assert!(fx.found(saved.id()).await.is_some());
    }

    /// A dedicated tenant's provider is readable directly from its database
    /// and through tenant routing; the platform tenant's list remains empty.
    #[tokio::test]
    async fn a_tenant_with_its_own_database_keeps_its_providers_there() {
        let fx = fixture().await;
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let saved = provider(provider_row("apart"));

        fx.store.save(&apart, &saved).await.unwrap();

        let in_own = PgModelProviderStore::new(Arc::clone(&own.databases));
        let found = in_own.find_by_id(&apart, saved.id()).await.unwrap();
        assert!(found.is_some());
        assert!(fx.found_in(&apart, saved.id()).await.is_some());
        assert!(fx.names().await.is_empty());
    }

    /// A stored provider with an FTP endpoint is rejected as corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_provider_is_refused() {
        let fx = fixture().await;
        let saved = fx.saved(provider_row("prod-openai")).await;
        fx.db
            .tamper("UPDATE agent_model_providers SET endpoint = 'ftp://models'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A failure reason recorded from a provider's reply reads back as it
    /// was recorded.
    #[tokio::test]
    async fn a_failure_reason_reads_back_as_recorded() {
        let fx = fixture().await;
        let saved = fx
            .saved(ModelProviderRow {
                last_test: LastTest::Failed {
                    at: at(1),
                    reason: Some(UntrustedText::record("bad gateway")),
                },
                updated_at: at(1),
                ..provider_row("prod-openai")
            })
            .await;

        let found = fx.found(saved.id()).await.unwrap();

        assert_eq!(found.last_test_message(), Some("bad gateway"));
    }
}
