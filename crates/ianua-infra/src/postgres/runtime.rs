//! Whether the platform's database answers, for the process's readiness
//! check.
//!
//! The probe pings the platform's database the way every store reaches it,
//! in a short transaction of its own. A
//! tenant's database of its own is not asked: one tenant's database being
//! down stops that tenant, never the whole replica.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::runtime::{Readiness, ReadinessProbe, UnreadyReason};
use ianua_domain::shared::errors::DomainError;
use sqlx::Connection as _;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The longest the database is waited on before it counts as not ready.
const WAIT: Duration = Duration::from_secs(2);

/// Asks the platform's database whether it answers.
pub struct PgReadinessProbe {
    databases: Arc<Databases>,
}

impl PgReadinessProbe {
    /// A probe of the platform database of `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Pings the platform database through the unit of work.
    async fn ping(&self) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            connection.ping().await
        })
        .await
    }
}

#[async_trait]
impl ReadinessProbe for PgReadinessProbe {
    async fn check(&self) -> Readiness {
        match tokio::time::timeout(WAIT, self.ping()).await {
            Ok(Ok(())) => Readiness::Ready,
            Ok(Err(_)) => Readiness::NotReady(UnreadyReason::new("the database cannot be reached")),
            Err(_) => {
                Readiness::NotReady(UnreadyReason::new("the database did not answer in time"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::PgConnectOptions;

    use super::*;
    use crate::postgres::foundation::pool::PoolLimits;
    use crate::test_support::TestDb;

    /// A reachable platform database lets the replica's readiness probe pass.
    #[tokio::test]
    async fn a_database_that_answers_is_ready() {
        let db = TestDb::fresh().await;

        let readiness = PgReadinessProbe::new(Arc::clone(&db.databases))
            .check()
            .await;

        assert_eq!(readiness, Readiness::Ready);
    }

    /// An unreachable platform database makes the replica's readiness
    /// probe report that it is not ready.
    #[tokio::test]
    async fn a_database_that_cannot_be_reached_is_not_ready() {
        let nowhere = PgConnectOptions::new().host("127.0.0.1").port(1);
        let limits = PoolLimits {
            platform_connections: 1,
            dedicated_connections: 1,
            acquire_timeout: Duration::from_secs(5),
        };
        let databases = Arc::new(Databases::new(nowhere, limits));

        let readiness = PgReadinessProbe::new(databases).check().await;

        assert!(matches!(readiness, Readiness::NotReady(_)));
    }
}
