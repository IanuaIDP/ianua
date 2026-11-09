//! The last verdict of the scheduled sweep on each tenant's audit chain,
//! one row per tenant, replaced by each sweep.
//!
//! The next sweep walks from the verdict's checkpoint, so a checkpoint
//! moved forward past records removed since would hide their removal, and
//! a standing rewritten would show a broken chain as intact. Each verdict
//! is sealed over its tenant and every column under the key the chain's
//! head is, and one whose seal does not hold is refused when read.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::audit::AuditChainVerdictStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::verdict::ChainVerdict;
use ianua_domain::shared::errors::DomainError;

use self::record::{VerdictColumns, VerdictRecord};
use crate::crypto::AuditChainSeals;
use crate::postgres::foundation::audit_chain;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of chain verdicts.
pub struct PgAuditChainVerdictStore {
    databases: Arc<Databases>,
    heads: AuditChainSeals,
}

impl PgAuditChainVerdictStore {
    /// A store keeping chain verdicts in `databases`, each sealed with
    /// `heads`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, heads: AuditChainSeals) -> Self {
        Self { databases, heads }
    }
}

impl TenantScoped for PgAuditChainVerdictStore {}

#[async_trait]
impl AuditChainVerdictStore for PgAuditChainVerdictStore {
    async fn find(&self, tenant_id: &ScopedTenant) -> Result<Option<ChainVerdict>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    VerdictRecord,
                    "queries/audit_chain_verdicts/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record
            .map(|held| held.into_sealed_verdict(*tenant_id.as_uuid(), &self.heads))
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        verdict: &ChainVerdict,
    ) -> Result<(), DomainError> {
        let columns = VerdictColumns::of(verdict);
        let seal =
            audit_chain::verdict_seal(&self.heads, *tenant_id.as_uuid(), &[&columns.sealed_over()]);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/audit_chain_verdicts/save.sql",
                    tenant_id.as_uuid(),
                    columns.verified_at,
                    columns.standing,
                    columns.broken_at_seq,
                    columns.checkpoint_seq,
                    columns.checkpoint_hash,
                    seal.as_slice(),
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
    use ianua_domain::domains::audit::checkpoint::{ChainCheckpoint, ChainHash, ChainStart};
    use ianua_domain::domains::audit::verdict::ChainVerdictRow;
    use ianua_domain::domains::audit::walk::ChainStanding;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::chain_heads;

    fn fixture_store(db: &TestDb) -> PgAuditChainVerdictStore {
        PgAuditChainVerdictStore::new(Arc::clone(&db.databases), chain_heads())
    }

    fn after(seq: i64) -> ChainStart {
        ChainStart::After(
            ChainCheckpoint::from_stored(seq, ChainHash::from_stored(&[4; 32]).unwrap()).unwrap(),
        )
    }

    fn verdict(standing: ChainStanding, checkpoint: ChainStart, seconds: i64) -> ChainVerdict {
        ChainVerdict::reconstitute(ChainVerdictRow {
            verified_at: at(seconds),
            standing,
            checkpoint,
        })
        .unwrap()
    }

    /// Before the first sweep a tenant has no verdict.
    #[tokio::test]
    async fn a_chain_never_swept_has_no_verdict() {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());

        let found = fixture_store(&db).find(&tenant).await.unwrap();

        assert!(found.is_none());
    }

    /// A sweep's verdict is kept, and the next sweep's replaces it, with
    /// where the chain broke and the last link verified.
    #[tokio::test]
    async fn the_last_verdict_replaces_the_one_before() {
        let db = TestDb::fresh().await;
        let store = fixture_store(&db);
        let tenant = ScopedTenant::for_background(TenantId::new());
        let first = verdict(ChainStanding::IntactSoFar, after(500), 1);
        let second = verdict(ChainStanding::BrokenAt(743), after(700), 2);

        store.save(&tenant, &first).await.unwrap();
        store.save(&tenant, &second).await.unwrap();

        assert_eq!(store.find(&tenant).await.unwrap(), Some(second));
    }

    /// A verdict of a walk from the start keeps no link.
    #[tokio::test]
    async fn a_verdict_from_the_start_keeps_no_link() {
        let db = TestDb::fresh().await;
        let store = fixture_store(&db);
        let tenant = ScopedTenant::for_background(TenantId::new());
        let intact = verdict(ChainStanding::Intact, ChainStart::Genesis, 1);

        store.save(&tenant, &intact).await.unwrap();

        assert_eq!(store.find(&tenant).await.unwrap(), Some(intact));
    }

    /// Another tenant finds no verdict for the saved chain.
    #[tokio::test]
    async fn a_verdict_is_read_by_its_tenant_alone() {
        let db = TestDb::fresh().await;
        let store = fixture_store(&db);
        let tenant = ScopedTenant::for_background(TenantId::new());
        let other = ScopedTenant::for_background(TenantId::new());
        store
            .save(&tenant, &verdict(ChainStanding::Intact, after(3), 1))
            .await
            .unwrap();

        assert!(store.find(&other).await.unwrap().is_none());
    }

    /// Reading a verdict whose stored break was moved before its checkpoint
    /// returns a corruption error.
    #[tokio::test]
    async fn a_verdict_breaking_before_its_checkpoint_is_refused() {
        let db = TestDb::fresh().await;
        let store = fixture_store(&db);
        let tenant = ScopedTenant::for_background(TenantId::new());
        store
            .save(
                &tenant,
                &verdict(ChainStanding::BrokenAt(743), after(700), 1),
            )
            .await
            .unwrap();
        db.tamper("UPDATE audit_chain_verdicts SET broken_at_seq = 400")
            .await;

        let read = store.find(&tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Advancing a stored checkpoint without updating its seal makes the
    /// verdict fail to read with a corruption error.
    #[tokio::test]
    async fn a_checkpoint_moved_past_the_store_is_refused() {
        let db = TestDb::fresh().await;
        let store = fixture_store(&db);
        let tenant = ScopedTenant::for_background(TenantId::new());
        store
            .save(&tenant, &verdict(ChainStanding::IntactSoFar, after(5), 1))
            .await
            .unwrap();
        db.tamper("UPDATE audit_chain_verdicts SET checkpoint_seq = 900")
            .await;

        let read = store.find(&tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Rewriting a broken verdict as intact without updating its seal makes
    /// the verdict fail to read with a corruption error.
    #[tokio::test]
    async fn a_broken_verdict_rewritten_as_intact_is_refused() {
        let db = TestDb::fresh().await;
        let store = fixture_store(&db);
        let tenant = ScopedTenant::for_background(TenantId::new());
        store
            .save(
                &tenant,
                &verdict(ChainStanding::BrokenAt(743), after(700), 1),
            )
            .await
            .unwrap();
        db.tamper("UPDATE audit_chain_verdicts SET standing = 'intact', broken_at_seq = NULL")
            .await;

        let read = store.find(&tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A sealed verdict copied to another tenant is rejected as corrupt when
    /// that tenant reads it.
    #[tokio::test]
    async fn a_verdict_copied_to_another_tenant_is_refused() {
        let db = TestDb::fresh().await;
        let store = fixture_store(&db);
        let tenant = ScopedTenant::for_background(TenantId::new());
        let other = ScopedTenant::for_background(TenantId::new());
        store
            .save(&tenant, &verdict(ChainStanding::Intact, after(3), 1))
            .await
            .unwrap();
        db.tamper(&format!(
            "INSERT INTO audit_chain_verdicts \
             SELECT '{}', verified_at, standing, broken_at_seq, checkpoint_seq, checkpoint_hash, seal \
             FROM audit_chain_verdicts",
            other.as_uuid()
        ))
        .await;

        let read = store.find(&other).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
