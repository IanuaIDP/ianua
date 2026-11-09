//! The keys a tenant's agents sign in with, each table row under row-level
//! security.
//!
//! Only a key's public half is kept: an agent makes its own key pair, so
//! the platform never holds anything that could sign as the agent. A key
//! issued against an attestation keeps the subject attested, so one
//! workload identity is found if it tries to bootstrap a second agent. The
//! workload is also bound, once per tenant, to the agent it bootstrapped,
//! in the same transaction and before the key is written: two agents
//! bootstrapped for one workload at the same moment both pass that check,
//! and the second key is refused here. A key only moves on, active to
//! rotated to revoked, whatever an old copy saved over it says.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::AgentCredentialStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::identity::attestation::AttestedSubject;
use ianua_domain::domains::agents::identity::credential::AgentCredential;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentCredentialId, AgentId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{CredentialColumns, CredentialRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of agent credentials.
pub struct PgAgentCredentialStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAgentCredentialStore {}

impl PgAgentCredentialStore {
    /// A store keeping agent credentials in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

fn rebuilt(
    records: Vec<CredentialRecord>,
) -> Result<Vec<AgentCredential<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(CredentialRecord::into_credential)
        .collect()
}

#[async_trait]
impl AgentCredentialStore for PgAgentCredentialStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentCredentialId,
    ) -> Result<Option<AgentCredential<ResolvedTenant>>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CredentialRecord,
                    "queries/agent_credentials/by_ids.sql",
                    tenant_id.as_uuid(),
                    &ids
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        Ok(rebuilt(records)?.pop())
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<AgentCredential<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CredentialRecord,
                    "queries/agent_credentials/of_agent.sql",
                    tenant_id.as_uuid(),
                    agent.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        rebuilt(records)
    }

    async fn find_pinned_elsewhere(
        &self,
        tenant_id: &ScopedTenant,
        subject: &AttestedSubject,
        excluding: &AgentId,
    ) -> Result<Option<AgentCredential<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CredentialRecord,
                    "queries/agent_credentials/pinned_elsewhere.sql",
                    tenant_id.as_uuid(),
                    subject.as_str(),
                    excluding.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(CredentialRecord::into_credential).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        credential: &AgentCredential<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = CredentialColumns::of(credential);
        let saved = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| saved(connection, tenant_id.as_uuid(), &columns).await,
        )
        .await?;
        match saved {
            Saved::Written => Ok(()),
            Saved::BoundElsewhere => Err(DomainError::conflict(message!(
                "infra-the-workload-is-already-bound-to",
                "the workload is already bound to another agent"
            ))),
        }
    }
}

/// Whether a save kept the credential, or found the workload it was issued
/// to bound to another agent and wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Saved {
    /// The credential is written, and its workload bound to its agent.
    Written,
    /// Nothing is written: another agent holds the workload.
    BoundElsewhere,
}

/// Binds the workload `columns` was issued to, if any, to its agent, then
/// writes the credential; writes nothing when another agent holds the
/// workload.
async fn saved(
    connection: &mut PgConnection,
    tenant: &Uuid,
    columns: &CredentialColumns<'_>,
) -> Result<Saved, sqlx::Error> {
    if !workload_bound(&mut *connection, tenant, columns).await? {
        return Ok(Saved::BoundElsewhere);
    }
    write_credential(connection, tenant, columns).await?;
    Ok(Saved::Written)
}

/// Binds the workload `columns` was issued to, to the credential's agent.
/// Answers whether it is that agent's now: a key enrolled by hand binds
/// nothing and always is.
async fn workload_bound(
    connection: &mut PgConnection,
    tenant: &Uuid,
    columns: &CredentialColumns<'_>,
) -> Result<bool, sqlx::Error> {
    let Some(subject) = columns.attested_subject else {
        return Ok(true);
    };
    let bound = sqlx::query_file_scalar!(
        "queries/agent_workloads/bind.sql",
        tenant,
        subject,
        columns.agent_id
    )
    .fetch_optional(connection)
    .await?;
    Ok(bound.is_some())
}

/// Writes the credential `columns` describes.
async fn write_credential(
    connection: &mut PgConnection,
    tenant: &Uuid,
    columns: &CredentialColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/agent_credentials/save.sql",
        columns.id,
        tenant,
        columns.agent_id,
        columns.kid,
        columns.algorithm,
        columns.public_key,
        columns.status,
        columns.rotated_at,
        columns.attested_method,
        columns.attested_subject,
        columns.created_at,
        columns.expires_at,
        columns.updated_at,
    )
    .execute(connection)
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::credential::AgentCredentialRow;
    use ianua_domain::domains::crypto::key_status::{KeyState, KeyStatus};
    use ianua_domain::shared::model::aggregate::Aggregate as _;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::{attested, credential_row, saved_agent};
    use crate::test_support::rows::at;

    fn credential(row: AgentCredentialRow) -> AgentCredential<ResolvedTenant> {
        AgentCredential::reconstitute(row).unwrap()
    }

    /// A fresh database, the store on it, one tenant and an agent of it.
    async fn fixture() -> (TestDb, PgAgentCredentialStore, ScopedTenant, AgentId) {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let agent = saved_agent(&db.databases, &tenant, "ledger").await;
        let store = PgAgentCredentialStore::new(Arc::clone(&db.databases));
        (db, store, tenant, agent)
    }

    /// A rotated key issued against an attestation is found by its id and
    /// among its agent's keys as it was saved; an id nobody has finds
    /// nothing.
    #[tokio::test]
    async fn a_saved_credential_is_found_by_id_and_by_its_agent() {
        let (_db, store, tenant, agent) = fixture().await;
        let rotated = credential(AgentCredentialRow {
            state: KeyState::Rotated { at: at(30) },
            origin: attested("spiffe://acme/ns/agents/sa/ledger"),
            updated_at: at(30),
            ..credential_row(agent, "key-1")
        });
        let current = credential(credential_row(agent, "key-2"));
        store.save(&tenant, &rotated).await.unwrap();
        store.save(&tenant, &current).await.unwrap();

        let found = store
            .find_by_id(&tenant, rotated.id())
            .await
            .unwrap()
            .unwrap();
        let held = store.list_for_agent(&tenant, &agent).await.unwrap();
        let unknown = store
            .find_by_id(&tenant, &AgentCredentialId::new())
            .await
            .unwrap();

        assert_eq!(found.kid(), rotated.kid());
        assert_eq!(found.public_key(), rotated.public_key());
        assert_eq!(found.status(), KeyStatus::Rotated);
        assert_eq!(found.rotated_at(), Some(at(30)));
        assert_eq!(found.origin(), rotated.origin());
        assert_eq!(held.len(), 2);
        assert!(unknown.is_none());
    }

    /// A workload identity already pinned to one agent is found when it
    /// bootstraps another, and not when the same agent asks again.
    #[tokio::test]
    async fn a_subject_pinned_to_another_agent_is_found() {
        let (db, store, tenant, agent) = fixture().await;
        let other = saved_agent(&db.databases, &tenant, "other").await;
        let subject = "spiffe://acme/ns/agents/sa/ledger";
        let pinned = credential(AgentCredentialRow {
            origin: attested(subject),
            ..credential_row(agent, "key-1")
        });
        store.save(&tenant, &pinned).await.unwrap();
        let wanted = AttestedSubject::new(subject).unwrap();

        let for_other = store
            .find_pinned_elsewhere(&tenant, &wanted, &other)
            .await
            .unwrap();
        let for_itself = store
            .find_pinned_elsewhere(&tenant, &wanted, &agent)
            .await
            .unwrap();

        assert_eq!(for_other.unwrap().id(), pinned.id());
        assert!(for_itself.is_none());
    }

    /// Once a workload is bound to one agent, saving its key for another
    /// returns a conflict and leaves the other agent without credentials.
    #[tokio::test]
    async fn a_workload_bound_to_one_agent_cannot_key_another() {
        let (db, store, tenant, agent) = fixture().await;
        let other = saved_agent(&db.databases, &tenant, "other").await;
        let subject = "spiffe://acme/ns/agents/sa/ledger";
        let first = credential(AgentCredentialRow {
            origin: attested(subject),
            ..credential_row(agent, "key-1")
        });
        let second = credential(AgentCredentialRow {
            origin: attested(subject),
            ..credential_row(other, "key-2")
        });
        store.save(&tenant, &first).await.unwrap();

        let saved = store.save(&tenant, &second).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))), "{saved:?}");
        assert!(
            store
                .list_for_agent(&tenant, &other)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// The agent a workload is bound to bootstraps again and again: each
    /// fresh key from the same workload is kept.
    #[tokio::test]
    async fn the_bound_agent_keys_its_workload_again() {
        let (_db, store, tenant, agent) = fixture().await;
        let subject = "spiffe://acme/ns/agents/sa/ledger";
        let [first, again] = ["key-1", "key-2"].map(|kid| {
            credential(AgentCredentialRow {
                origin: attested(subject),
                ..credential_row(agent, kid)
            })
        });
        store.save(&tenant, &first).await.unwrap();

        let saved = store.save(&tenant, &again).await;

        assert!(saved.is_ok(), "{saved:?}");
        assert_eq!(
            store.list_for_agent(&tenant, &agent).await.unwrap().len(),
            2
        );
    }

    /// A key is revoked: saving it again keeps the new status, and the
    /// rotation it went through before.
    #[tokio::test]
    async fn saving_again_keeps_the_new_status() {
        let (_db, store, tenant, agent) = fixture().await;
        let key = credential(AgentCredentialRow {
            state: KeyState::Rotated { at: at(30) },
            ..credential_row(agent, "key-1")
        });
        store.save(&tenant, &key).await.unwrap();
        let revoked = credential(AgentCredentialRow {
            id: *key.id(),
            state: KeyState::Rotated { at: at(30) }.revoked(),
            updated_at: at(40),
            ..credential_row(agent, "key-1")
        });

        store.save(&tenant, &revoked).await.unwrap();

        let found = store.find_by_id(&tenant, key.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), KeyStatus::Revoked);
        assert_eq!(found.rotated_at(), Some(at(30)));
    }

    /// Saving an older rotation after revocation preserves the key's revoked
    /// status and the revocation's update time.
    #[tokio::test]
    async fn a_revoked_key_stays_revoked_when_an_old_rotation_is_saved() {
        let (_db, store, tenant, agent) = fixture().await;
        let key = credential(credential_row(agent, "key-1"));
        store.save(&tenant, &key).await.unwrap();
        let revoked = credential(AgentCredentialRow {
            id: *key.id(),
            state: KeyState::Active.revoked(),
            updated_at: at(40),
            ..credential_row(agent, "key-1")
        });
        store.save(&tenant, &revoked).await.unwrap();
        let rotated = credential(AgentCredentialRow {
            id: *key.id(),
            state: KeyState::Rotated { at: at(30) },
            updated_at: at(30),
            ..credential_row(agent, "key-1")
        });

        store.save(&tenant, &rotated).await.unwrap();

        let found = store.find_by_id(&tenant, key.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), KeyStatus::Revoked);
        assert_eq!(found.updated_at(), at(40));
    }

    /// Saving an old active copy preserves the key's rotated status and
    /// original rotation time.
    #[tokio::test]
    async fn a_rotated_key_is_not_made_active_by_an_old_copy() {
        let (_db, store, tenant, agent) = fixture().await;
        let active = credential(credential_row(agent, "key-1"));
        let rotated = credential(AgentCredentialRow {
            id: *active.id(),
            state: KeyState::Rotated { at: at(30) },
            updated_at: at(30),
            ..credential_row(agent, "key-1")
        });
        store.save(&tenant, &rotated).await.unwrap();

        store.save(&tenant, &active).await.unwrap();

        let found = store
            .find_by_id(&tenant, active.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), KeyStatus::Rotated);
        assert_eq!(found.rotated_at(), Some(at(30)));
    }

    /// Another tenant does not find this tenant's key, by id or by its
    /// agent.
    #[tokio::test]
    async fn a_credential_is_found_only_by_its_tenant() {
        let (_db, store, tenant, agent) = fixture().await;
        let key = credential(credential_row(agent, "key-1"));
        store.save(&tenant, &key).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let by_id = store.find_by_id(&other, key.id()).await.unwrap();
        let by_agent = store.list_for_agent(&other, &agent).await.unwrap();

        assert!(by_id.is_none());
        assert!(by_agent.is_empty());
    }

    /// Saving a credential for an unknown agent returns an infrastructure
    /// error.
    #[tokio::test]
    async fn a_credential_for_an_unknown_agent_is_refused() {
        let (_db, store, tenant, _) = fixture().await;
        let stray = credential(credential_row(AgentId::new(), "key-1"));

        let saved = store.save(&tenant, &stray).await;

        assert!(matches!(saved, Err(DomainError::Infrastructure(_))));
    }

    /// A stored credential with a hundred-year lifetime is rejected as corrupt.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_credential_is_refused() {
        let (db, store, tenant, agent) = fixture().await;
        let key = credential(credential_row(agent, "key-1"));
        store.save(&tenant, &key).await.unwrap();
        db.tamper(
            "UPDATE agent_credentials SET expires_at = created_at + interval '100 years', \
             updated_at = created_at",
        )
        .await;

        let read = store.find_by_id(&tenant, key.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
