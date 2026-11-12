//! The lease that lets one caller at a time exchange an account's grant,
//! across every worker and every API node.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ianua_app::ports::workflows::{GrantExchangeLease, GrantTurn, TurnHolder};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::IntegrationAccountId;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::workers::leases::{Leased, Leases};

/// How often a caller waiting for a turn asks again.
const ASK_EVERY: Duration = Duration::from_millis(100);

/// How long a caller waits for a turn before it is turned away.
const PATIENCE: Duration = Duration::from_secs(10);

/// How much longer than an exchange's limit a turn lasts, for the save
/// after it.
const SAVE_MARGIN: Duration = Duration::from_secs(60);

/// Turns on accounts' grants. Each turn has a holder of its own, so two
/// calls on one worker wait for each other as two workers do.
pub struct PgGrantExchangeLease {
    databases: Arc<Databases>,
    leases: Leases,
    patience: Duration,
}

impl PgGrantExchangeLease {
    /// Turns in `databases`, each lasting `lasting`, longer than any
    /// exchange and its save may take; a caller waits at most `patience`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, lasting: Duration, patience: Duration) -> Self {
        Self {
            databases,
            leases: Leases::of(Leased::AccountGrant, lasting),
            patience,
        }
    }

    /// Turns in `databases` for exchanges held to `limit`, lasting longer
    /// than the exchange and its save together.
    #[must_use]
    pub fn for_exchanges_within(databases: Arc<Databases>, limit: Duration) -> Self {
        Self::new(databases, limit.saturating_add(SAVE_MARGIN), PATIENCE)
    }
}

#[async_trait]
impl GrantExchangeLease for PgGrantExchangeLease {
    async fn claim_within(
        &self,
        account: &IntegrationAccountId,
    ) -> Result<Option<GrantTurn>, DomainError> {
        let holder = TurnHolder::new();
        let started = Instant::now();
        loop {
            if self
                .leases
                .claim_alone(&self.databases, account.as_uuid(), holder.as_uuid())
                .await?
            {
                return Ok(Some(GrantTurn {
                    account: *account,
                    holder,
                }));
            }
            if started.elapsed() >= self.patience {
                return Ok(None);
            }
            tokio::time::sleep(ASK_EVERY).await;
        }
    }

    async fn release(&self, turn: GrantTurn) {
        self.leases
            .release_alone(
                &self.databases,
                turn.account.as_uuid(),
                turn.holder.as_uuid(),
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDb;

    const A_MINUTE: Duration = Duration::from_secs(60);

    /// Pat's workflow holds the account's turn. A picker on the same
    /// worker waits its short while and gets none; once the turn is given
    /// back, the next caller has it.
    #[tokio::test]
    async fn a_turn_is_held_by_one_caller_even_on_one_worker() {
        let db = TestDb::fresh().await;
        let lease = PgGrantExchangeLease::new(
            Arc::clone(&db.databases),
            A_MINUTE,
            Duration::from_millis(250),
        );
        let account = IntegrationAccountId::new();
        let first = lease.claim_within(&account).await.unwrap().unwrap();

        let while_held = lease.claim_within(&account).await.unwrap();
        lease.release(first).await;
        let after = lease.claim_within(&account).await.unwrap();

        assert!(while_held.is_none());
        assert!(after.is_some());
    }

    /// A worker dies holding the turn. Its lease lapses by itself and
    /// another worker takes the turn over.
    #[tokio::test]
    async fn a_dead_holders_turn_lapses_by_itself() {
        let db = TestDb::fresh().await;
        let short = PgGrantExchangeLease::new(
            Arc::clone(&db.databases),
            Duration::from_millis(100),
            Duration::ZERO,
        );
        let waiting =
            PgGrantExchangeLease::new(Arc::clone(&db.databases), A_MINUTE, Duration::from_secs(5));
        let account = IntegrationAccountId::new();
        short.claim_within(&account).await.unwrap().unwrap();

        let taken_over = waiting.claim_within(&account).await.unwrap();

        assert!(taken_over.is_some());
    }

    /// Only the holder ends a turn: a caller whose turn lapsed cannot end
    /// the one taken over from it.
    #[tokio::test]
    async fn a_lapsed_turn_cannot_end_the_next_callers() {
        let db = TestDb::fresh().await;
        let short = PgGrantExchangeLease::new(
            Arc::clone(&db.databases),
            Duration::from_millis(100),
            Duration::ZERO,
        );
        let longer =
            PgGrantExchangeLease::new(Arc::clone(&db.databases), A_MINUTE, Duration::from_secs(5));
        let account = IntegrationAccountId::new();
        let lapsed = short.claim_within(&account).await.unwrap().unwrap();
        longer.claim_within(&account).await.unwrap().unwrap();

        short.release(lapsed).await;
        let third = PgGrantExchangeLease::new(
            Arc::clone(&db.databases),
            A_MINUTE,
            Duration::from_millis(250),
        );

        assert!(third.claim_within(&account).await.unwrap().is_none());
    }
}
