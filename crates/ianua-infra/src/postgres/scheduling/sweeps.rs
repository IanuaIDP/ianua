//! The claims that run each round of a sweep once across every worker, in
//! the platform database: the first worker to claim a round wins it, and
//! every later claim of the round finds it taken. Rounds older than a week
//! are removed as new ones are claimed; no worker asks for one that old.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::scheduling::SweepClaims;
use ianua_domain::domains::scheduling::sweep::{SweepName, SweepRound};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// How long a call may take before it fails.
const ANSWER_WITHIN: Duration = Duration::from_secs(5);

/// How long a claimed round is kept.
const KEPT: time::Duration = time::Duration::WEEK;

/// The claims on the rounds of every sweep.
pub struct PgSweepClaims {
    databases: Arc<Databases>,
}

impl PgSweepClaims {
    /// The claims kept in `databases`' platform database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl SweepClaims for PgSweepClaims {
    async fn claim(&self, sweep: &SweepName, round: SweepRound) -> Result<bool, DomainError> {
        let now = clock::now();
        let claimed = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/platform_sweep_claims/claim.sql",
                sweep.as_str(),
                round.number(),
                now,
                now.saturating_sub(KEPT),
            )
            .fetch_optional(connection)
            .await
        });
        let claimed = tokio::time::timeout(ANSWER_WITHIN, claimed)
            .await
            .map_err(|_| {
                DomainError::infra_msg("the sweep claims did not answer within five seconds")
            })??;
        Ok(claimed.is_some())
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;
    use crate::test_support::TestDb;

    fn sweep(name: &str) -> SweepName {
        SweepName::new(name).unwrap()
    }

    fn round(at: OffsetDateTime) -> SweepRound {
        SweepRound::at(
            at,
            ianua_domain::domains::scheduling::sweep::SweepPeriod::new(time::Duration::HOUR)
                .unwrap(),
        )
    }

    /// The first claim of an audit-retention round succeeds, and a second
    /// claim of that same round is refused.
    #[tokio::test]
    async fn a_round_is_won_once() {
        let db = TestDb::fresh().await;
        let claims = PgSweepClaims::new(Arc::clone(&db.databases));
        let now = round(clock::now());

        let first = claims.claim(&sweep("audit.retention"), now).await.unwrap();
        let second = claims.claim(&sweep("audit.retention"), now).await.unwrap();

        assert!(first);
        assert!(!second);
    }

    /// Each sweep and each round is claimed on its own.
    #[tokio::test]
    async fn sweeps_and_rounds_are_claimed_apart() {
        let db = TestDb::fresh().await;
        let claims = PgSweepClaims::new(Arc::clone(&db.databases));
        let now = clock::now();

        let retention = claims
            .claim(&sweep("audit.retention"), round(now))
            .await
            .unwrap();
        let reviews = claims
            .claim(&sweep("reviews.overdue"), round(now))
            .await
            .unwrap();
        let next_hour = claims
            .claim(&sweep("audit.retention"), round(now + time::Duration::HOUR))
            .await
            .unwrap();

        assert!(retention && reviews && next_hour);
    }
}
