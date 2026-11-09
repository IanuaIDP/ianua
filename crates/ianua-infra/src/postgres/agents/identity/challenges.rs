//! The single-use challenges a tenant's agents sign to prove where they
//! run, each table row under row-level security.
//!
//! Spending a challenge is one statement that marks it spent only while it
//! is unspent and valid, so two proofs racing for one nonce cannot both
//! get it, and a spent or lapsed one is never handed out.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::AttestationChallengeStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::identity::challenge::{AttestationChallenge, AttestationNonce};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::AgentId;

use self::record::{ChallengeColumns, ChallengeRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of attestation challenges.
pub struct PgAttestationChallengeStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAttestationChallengeStore {}

impl PgAttestationChallengeStore {
    /// A store keeping attestation challenges in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AttestationChallengeStore for PgAttestationChallengeStore {
    async fn issue(
        &self,
        tenant_id: &ScopedTenant,
        challenge: &AttestationChallenge<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ChallengeColumns::of(challenge);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/agent_attestation_challenges/issue.sql",
                    tenant_id.as_uuid(),
                    columns.nonce,
                    columns.agent_id,
                    columns.issued_at,
                    columns.expires_at,
                    columns.used_at,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn consume(
        &self,
        tenant_id: &ScopedTenant,
        agent_id: &AgentId,
        nonce: &AttestationNonce,
    ) -> Result<Option<AttestationChallenge<ResolvedTenant>>, DomainError> {
        let now = clock::now();
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChallengeRecord,
                    "queries/agent_attestation_challenges/consume.sql",
                    tenant_id.as_uuid(),
                    agent_id.as_uuid(),
                    nonce.as_str(),
                    now
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(ChallengeRecord::into_challenge).transpose()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::challenge::AttestationChallengeRow;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::{challenge_row, saved_agent};
    use crate::test_support::rows::identity::from_now;

    fn challenge(row: AttestationChallengeRow) -> AttestationChallenge<ResolvedTenant> {
        AttestationChallenge::reconstitute(row).unwrap()
    }

    /// A fresh database, the store on it, one tenant and an agent of it.
    async fn fixture() -> (TestDb, PgAttestationChallengeStore, ScopedTenant, AgentId) {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let agent = saved_agent(&db.databases, &tenant, "ledger").await;
        let store = PgAttestationChallengeStore::new(Arc::clone(&db.databases));
        (db, store, tenant, agent)
    }

    /// An issued challenge is spent once: the first proof gets it back
    /// spent, and a replay of the same nonce gets nothing.
    #[tokio::test]
    async fn a_challenge_is_spent_once() {
        let (_db, store, tenant, agent) = fixture().await;
        let issued = challenge(challenge_row(agent, "first"));
        store.issue(&tenant, &issued).await.unwrap();

        let spent = store
            .consume(&tenant, &agent, issued.nonce())
            .await
            .unwrap()
            .unwrap();
        let replayed = store
            .consume(&tenant, &agent, issued.nonce())
            .await
            .unwrap();

        assert_eq!(spent.nonce(), issued.nonce());
        assert!(spent.usage().used_at().is_some());
        assert!(replayed.is_none());
    }

    /// Another agent cannot consume the challenge; its intended agent can
    /// still consume it afterward.
    #[tokio::test]
    async fn a_challenge_is_spent_only_by_its_agent() {
        let (db, store, tenant, agent) = fixture().await;
        let other = saved_agent(&db.databases, &tenant, "other").await;
        let issued = challenge(challenge_row(agent, "first"));
        store.issue(&tenant, &issued).await.unwrap();

        let by_other = store
            .consume(&tenant, &other, issued.nonce())
            .await
            .unwrap();
        let by_its_agent = store
            .consume(&tenant, &agent, issued.nonce())
            .await
            .unwrap();

        assert!(by_other.is_none());
        assert!(by_its_agent.is_some());
    }

    /// Consuming an expired challenge returns no challenge.
    #[tokio::test]
    async fn a_lapsed_challenge_is_not_spent() {
        let (_db, store, tenant, agent) = fixture().await;
        let lapsed = challenge(AttestationChallengeRow {
            issued_at: from_now(-600),
            expires_at: from_now(-300),
            ..challenge_row(agent, "lapsed")
        });
        store.issue(&tenant, &lapsed).await.unwrap();

        let spent = store
            .consume(&tenant, &agent, lapsed.nonce())
            .await
            .unwrap();

        assert!(spent.is_none());
    }

    /// Issuing a consumed nonce again leaves it unavailable for consumption.
    #[tokio::test]
    async fn issuing_a_spent_nonce_again_does_not_revive_it() {
        let (_db, store, tenant, agent) = fixture().await;
        let issued = challenge(challenge_row(agent, "first"));
        store.issue(&tenant, &issued).await.unwrap();
        store
            .consume(&tenant, &agent, issued.nonce())
            .await
            .unwrap();

        store.issue(&tenant, &issued).await.unwrap();
        let replayed = store
            .consume(&tenant, &agent, issued.nonce())
            .await
            .unwrap();

        assert!(replayed.is_none());
    }

    /// Another tenant cannot spend this tenant's challenge.
    #[tokio::test]
    async fn a_challenge_is_spent_only_in_its_tenant() {
        let (_db, store, tenant, agent) = fixture().await;
        let issued = challenge(challenge_row(agent, "first"));
        store.issue(&tenant, &issued).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let elsewhere = store.consume(&other, &agent, issued.nonce()).await.unwrap();

        assert!(elsewhere.is_none());
    }

    /// Issuing a challenge for an unknown agent returns an infrastructure error.
    #[tokio::test]
    async fn a_challenge_for_an_unknown_agent_is_refused() {
        let (_db, store, tenant, _) = fixture().await;
        let stray = challenge(challenge_row(AgentId::new(), "stray"));

        let issued = store.issue(&tenant, &stray).await;

        assert!(matches!(issued, Err(DomainError::Infrastructure(_))));
    }
}
