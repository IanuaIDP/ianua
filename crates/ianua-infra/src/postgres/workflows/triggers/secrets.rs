//! The secrets workflows' webhooks are called with, each table row under
//! row-level security, at most one per workflow.
//!
//! Only the secret's digest is kept: a keyed hash under a key the server
//! holds and the database does not, so a copied table cannot be searched
//! offline and a presented secret is checked by hashing it again. Being
//! already beyond use without that key, it is kept as other token digests
//! are, not sealed again. A unique constraint keeps one secret per
//! workflow, so two people issuing one at once cannot both keep theirs. A
//! secret goes with its workflow when an agent flow is deleted.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::workflows::WorkflowTriggerSecretStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::workflows::triggers::secret::WorkflowTriggerSecret;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{WorkflowId, WorkflowTriggerId};

use self::record::{TriggerSecretColumns, TriggerSecretRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps one secret per workflow.
const WORKFLOW_KEY: &str = "workflow_trigger_secrets_workflow_key";

/// The Postgres store of workflows' webhook secrets.
pub struct PgWorkflowTriggerSecretStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgWorkflowTriggerSecretStore {}

impl PgWorkflowTriggerSecretStore {
    /// A store keeping webhook secrets in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl WorkflowTriggerSecretStore for PgWorkflowTriggerSecretStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowTriggerId,
    ) -> Result<Option<WorkflowTriggerSecret<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TriggerSecretRecord,
                    "queries/workflow_trigger_secrets/by_id.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(TriggerSecretRecord::into_secret).transpose()
    }

    async fn find_for_workflow(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<Option<WorkflowTriggerSecret<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TriggerSecretRecord,
                    "queries/workflow_trigger_secrets/of_workflow.sql",
                    tenant_id.as_uuid(),
                    workflow_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(TriggerSecretRecord::into_secret).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        secret: &WorkflowTriggerSecret<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = TriggerSecretColumns::of(secret)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let attempt = sqlx::query_file!(
                    "queries/workflow_trigger_secrets/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.workflow_id,
                    columns.secret_hash,
                    columns.issued_by,
                    columns.created_at,
                    columns.secret_changed_at,
                )
                .execute(connection)
                .await;
                unique_on(attempt, WORKFLOW_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-workflow-already-has-a-webhook",
                "the workflow already has a webhook secret"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowTriggerId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/workflow_trigger_secrets/delete.sql",
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
    use ianua_app::ports::workflows::WorkflowStore;
    use ianua_domain::domains::workflows::design::workflow::Workflow;
    use ianua_domain::domains::workflows::triggers::secret::WorkflowTriggerSecretRow;
    use ianua_domain::types::{TenantId, TokenHash};

    use super::*;
    use crate::postgres::workflows::PgWorkflowStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::workflows::{flow_row, published_row, trigger_secret_row};

    struct Fixture {
        db: TestDb,
        store: PgWorkflowTriggerSecretStore,
        workflows: PgWorkflowStore,
        tenant: ScopedTenant,
        hooked: WorkflowId,
    }

    /// A fresh database, one tenant with a published workflow, and the
    /// store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let workflows = PgWorkflowStore::new(Arc::clone(&db.databases));
        let hooked = Workflow::reconstitute(published_row("hooked", 0)).unwrap();
        workflows.insert(&tenant, &hooked).await.unwrap();
        Fixture {
            store: PgWorkflowTriggerSecretStore::new(Arc::clone(&db.databases)),
            workflows,
            tenant,
            hooked: *hooked.id(),
            db,
        }
    }

    fn secret(row: WorkflowTriggerSecretRow) -> WorkflowTriggerSecret<ResolvedTenant> {
        WorkflowTriggerSecret::reconstitute(row).unwrap()
    }

    /// A saved secret is found by its id and by its workflow, its digest
    /// as it was saved.
    #[tokio::test]
    async fn a_saved_secret_is_found_by_id_and_by_workflow() {
        let fx = fixture().await;
        let saved = secret(trigger_secret_row(fx.hooked, "first"));

        fx.store.save(&fx.tenant, &saved).await.unwrap();

        let by_id = fx.store.find_by_id(&fx.tenant, saved.id()).await.unwrap();
        let by_workflow = fx
            .store
            .find_for_workflow(&fx.tenant, &fx.hooked)
            .await
            .unwrap();
        for found in [by_id.unwrap(), by_workflow.unwrap()] {
            assert_eq!(found.id(), saved.id());
            assert!(found.secret_hash() == saved.secret_hash());
            assert_eq!(found.issued_by(), saved.issued_by());
        }
    }

    /// A secret replaced keeps its id and when it was first issued, and
    /// takes the new digest.
    #[tokio::test]
    async fn a_replaced_secret_keeps_the_new_digest() {
        let fx = fixture().await;
        let saved = secret(trigger_secret_row(fx.hooked, "first"));
        fx.store.save(&fx.tenant, &saved).await.unwrap();
        let replaced = secret(WorkflowTriggerSecretRow {
            id: *saved.id(),
            secret_hash: TokenHash::from_stored("hash of second".to_owned()),
            secret_changed_at: at(5),
            ..trigger_secret_row(fx.hooked, "second")
        });

        fx.store.save(&fx.tenant, &replaced).await.unwrap();

        let found = fx
            .store
            .find_by_id(&fx.tenant, saved.id())
            .await
            .unwrap()
            .unwrap();
        assert!(found.secret_hash() == replaced.secret_hash());
        assert_eq!(found.secret_changed_at(), at(5));
    }

    /// Saving a second webhook secret for the same workflow returns a
    /// conflict.
    #[tokio::test]
    async fn a_second_secret_for_a_workflow_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.tenant, &secret(trigger_secret_row(fx.hooked, "first")))
            .await
            .unwrap();

        let second = fx
            .store
            .save(&fx.tenant, &secret(trigger_secret_row(fx.hooked, "second")))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Saving a secret for an unknown workflow returns an infrastructure
    /// error.
    #[tokio::test]
    async fn a_secret_of_an_unknown_workflow_is_refused() {
        let fx = fixture().await;

        let saved = fx
            .store
            .save(
                &fx.tenant,
                &secret(trigger_secret_row(WorkflowId::new(), "first")),
            )
            .await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A revoked secret is gone, and an agent flow's secret goes when the
    /// flow is deleted.
    #[tokio::test]
    async fn a_secret_is_deleted_alone_or_with_its_flow() {
        let fx = fixture().await;
        let revoked = secret(trigger_secret_row(fx.hooked, "first"));
        fx.store.save(&fx.tenant, &revoked).await.unwrap();
        let flow = Workflow::reconstitute(flow_row("digest", 0)).unwrap();
        fx.workflows.insert(&fx.tenant, &flow).await.unwrap();
        let of_flow = secret(trigger_secret_row(*flow.id(), "flow"));
        fx.store.save(&fx.tenant, &of_flow).await.unwrap();

        fx.store.delete(&fx.tenant, revoked.id()).await.unwrap();
        fx.workflows
            .delete_flow(&fx.tenant, flow.id())
            .await
            .unwrap();

        for gone in [revoked.id(), of_flow.id()] {
            assert!(
                fx.store
                    .find_by_id(&fx.tenant, gone)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    /// Another tenant finds none of Acme's secrets, and a tenant with a
    /// database of its own keeps its secrets there.
    #[tokio::test]
    async fn another_tenants_secrets_are_invisible() {
        let fx = fixture().await;
        let saved = secret(trigger_secret_row(fx.hooked, "first"));
        fx.store.save(&fx.tenant, &saved).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());
        let own = TestDb::fresh().await;
        let apart = ScopedTenant::for_background(TenantId::new());
        fx.db.databases.register(*apart, own.as_dedicated());
        let theirs = Workflow::reconstitute(published_row("theirs", 0)).unwrap();
        fx.workflows.insert(&apart, &theirs).await.unwrap();
        let apart_secret = secret(trigger_secret_row(*theirs.id(), "apart"));
        fx.store.save(&apart, &apart_secret).await.unwrap();

        let by_other = fx.store.find_by_id(&other, saved.id()).await.unwrap();
        let in_own = PgWorkflowTriggerSecretStore::new(Arc::clone(&own.databases))
            .find_for_workflow(&apart, theirs.id())
            .await
            .unwrap();

        assert!(by_other.is_none());
        assert_eq!(in_own.map(|kept| *kept.id()), Some(*apart_secret.id()));
    }

    /// Reading a secret with malformed stored issuer data returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_secret_is_refused() {
        let fx = fixture().await;
        let saved = secret(trigger_secret_row(fx.hooked, "first"));
        fx.store.save(&fx.tenant, &saved).await.unwrap();
        fx.db
            .tamper("UPDATE workflow_trigger_secrets SET issued_by = '{\"v\": 1, \"value\": 7}'")
            .await;

        let read = fx.store.find_by_id(&fx.tenant, saved.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
