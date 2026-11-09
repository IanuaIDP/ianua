//! Workflow webhook secrets kept in memory, per tenant, read back the way
//! storage reads them, and a maker of those secrets that counts them.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::triggers::secret::{
    WorkflowTriggerSecret, WorkflowTriggerSecretRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{TenantId, TokenHash, WorkflowId, WorkflowTriggerId};

use crate::ports::TenantScoped;
use crate::ports::workflows::{WorkflowTriggerSecretGenerator, WorkflowTriggerSecretStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::{Fake, test_ctx};

/// `secret` read back from its row, as storage reads it.
fn copy_of(
    secret: &WorkflowTriggerSecret<ResolvedTenant>,
) -> WorkflowTriggerSecret<ResolvedTenant> {
    WorkflowTriggerSecret::reconstitute(WorkflowTriggerSecretRow {
        id: *secret.id(),
        workflow_id: *secret.workflow_id(),
        secret_hash: secret.secret_hash().clone(),
        issued_by: secret.issued_by().clone(),
        created_at: Aggregate::created_at(secret),
        secret_changed_at: secret.secret_changed_at(),
    })
    .expect("a kept secret reads back as itself")
}

/// In-memory secret store: at most one secret per workflow, each kept under
/// its tenant.
#[derive(Default)]
pub struct FakeWorkflowTriggerSecretStore {
    secrets: Mutex<Vec<(TenantId, WorkflowTriggerSecret<ResolvedTenant>)>>,
}

impl TenantScoped for FakeWorkflowTriggerSecretStore {}

impl FakeWorkflowTriggerSecretStore {
    /// A store holding no secret.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `secret` in the test tenant.
    #[must_use]
    pub fn holding(secret: &WorkflowTriggerSecret<ResolvedTenant>) -> Self {
        Self {
            secrets: Mutex::new(vec![(test_ctx().tenant_id(), copy_of(secret))]),
        }
    }

    /// The secret of `workflow_id`'s webhook, as the test tenant keeps it
    /// now.
    #[must_use]
    pub fn stored_for(
        &self,
        workflow_id: &WorkflowId,
    ) -> Option<WorkflowTriggerSecret<ResolvedTenant>> {
        self.matching(test_ctx().tenant_id(), |kept| {
            kept.workflow_id() == workflow_id
        })
    }

    /// How many secrets are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.secrets.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant: TenantId,
        wanted: impl Fn(&WorkflowTriggerSecret<ResolvedTenant>) -> bool,
    ) -> Option<WorkflowTriggerSecret<ResolvedTenant>> {
        self.secrets
            .lock()
            .unwrap()
            .iter()
            .find(|(owner, kept)| *owner == tenant && wanted(kept))
            .map(|(_, kept)| copy_of(kept))
    }
}

#[async_trait]
impl WorkflowTriggerSecretStore for FakeWorkflowTriggerSecretStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowTriggerId,
    ) -> Result<Option<WorkflowTriggerSecret<ResolvedTenant>>, DomainError> {
        Ok(self.matching(**tenant_id, |kept| kept.id() == id))
    }

    async fn find_for_workflow(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<Option<WorkflowTriggerSecret<ResolvedTenant>>, DomainError> {
        Ok(self.matching(**tenant_id, |kept| kept.workflow_id() == workflow_id))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        secret: &WorkflowTriggerSecret<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let mut secrets = self.secrets.lock().unwrap();
        let another = secrets.iter().any(|(owner, kept)| {
            owner == &**tenant_id
                && kept.workflow_id() == secret.workflow_id()
                && kept.id() != secret.id()
        });
        if another {
            return Err(DomainError::conflict(
                "the workflow already has a webhook secret",
            ));
        }
        let held = secrets
            .iter()
            .position(|(owner, kept)| owner == &**tenant_id && kept.id() == secret.id());
        let entry = (**tenant_id, copy_of(secret));
        match held {
            Some(index) => secrets[index] = entry,
            None => secrets.push(entry),
        }
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowTriggerId,
    ) -> Result<(), DomainError> {
        self.secrets
            .lock()
            .unwrap()
            .retain(|(owner, kept)| owner != &**tenant_id || kept.id() != id);
        Ok(())
    }
}

impl Fake for Arc<dyn WorkflowTriggerSecretStore> {
    fn fake() -> Self {
        Arc::new(FakeWorkflowTriggerSecretStore::empty())
    }
}

/// A secret maker that counts the secrets it makes, `hook-secret-1` first,
/// and hashes each as `hash:` followed by the secret.
#[derive(Default)]
pub struct FakeWorkflowTriggerSecretGenerator {
    made: Mutex<u32>,
}

impl FakeWorkflowTriggerSecretGenerator {
    /// A maker that has made no secret yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WorkflowTriggerSecretGenerator for FakeWorkflowTriggerSecretGenerator {
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        let raw = Secret::new(format!("hook-secret-{made}"));
        let hash = self.hash_presented(&raw);
        Ok((raw, hash))
    }

    fn hash_presented(&self, presented: &Secret) -> TokenHash {
        trigger_secret_hash(presented.expose())
    }
}

impl Fake for Arc<dyn WorkflowTriggerSecretGenerator> {
    fn fake() -> Self {
        Arc::new(FakeWorkflowTriggerSecretGenerator::new())
    }
}

/// The hash the fake maker keeps for the secret `raw`.
#[must_use]
pub fn trigger_secret_hash(raw: &str) -> TokenHash {
    TokenHash::from_stored(format!("hash:{raw}"))
}
