//! The leases that keep one worker driving an agent run or a workflow
//! execution, and one caller exchanging an account's grant, in the platform
//! database whichever database the run or account lives in.
//!
//! A worker holds a lease under its own id until a moment it names, and
//! extends it while it works. A lease that ran out was left by a worker
//! that stopped, and the next worker that asks takes it over in the same
//! statement, so two never both win it.

use std::time::Duration;

use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use uuid::Uuid;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::{scoped, scoped_alone};

/// What a lease is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Leased {
    /// Reserves one delegated task for its driving worker.
    AgentRun,
    /// Reserves one automation instance for its driving worker.
    WorkflowExecution,
    /// Reserves one account's grant for the one call exchanging it.
    AccountGrant,
}

impl Leased {
    fn word(self) -> &'static str {
        match self {
            Self::AgentRun => "agent_run",
            Self::WorkflowExecution => "workflow_execution",
            Self::AccountGrant => "account_grant",
        }
    }
}

/// One worker's leases of one kind.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Leases {
    leased: Leased,
    holder: Uuid,
    lasting: time::Duration,
}

impl Leases {
    /// The leases on `leased` this worker takes, each lasting `lasting`.
    pub(crate) fn of(leased: Leased, lasting: Duration) -> Self {
        Self {
            leased,
            holder: Uuid::now_v7(),
            lasting: time::Duration::try_from(lasting).unwrap_or(time::Duration::MAX),
        }
    }

    fn until(&self) -> time::OffsetDateTime {
        clock::now().saturating_add(self.lasting)
    }

    /// Whether this worker now holds the lease on `id`.
    pub(crate) async fn claim(
        &self,
        databases: &Databases,
        id: &Uuid,
    ) -> Result<bool, DomainError> {
        let taken = scoped(databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/platform_leases/claim.sql",
                self.leased.word(),
                id,
                self.holder,
                self.until(),
                clock::now(),
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        Ok(taken.is_some())
    }

    /// Whether `holder` now holds the lease on `id`, decided and kept
    /// outside any unit around it, so others see it at once.
    pub(crate) async fn claim_alone(
        &self,
        databases: &Databases,
        id: &Uuid,
        holder: Uuid,
    ) -> Result<bool, DomainError> {
        let taken = scoped_alone(databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/platform_leases/claim.sql",
                self.leased.word(),
                id,
                holder,
                self.until(),
                clock::now(),
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        Ok(taken.is_some())
    }

    /// Lets go of `holder`'s lease on `id`, outside any unit around it. A
    /// lease that cannot be let go runs out by itself.
    pub(crate) async fn release_alone(&self, databases: &Databases, id: &Uuid, holder: Uuid) {
        let released = scoped_alone(databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/platform_leases/release.sql",
                self.leased.word(),
                id,
                holder,
            )
            .execute(connection)
            .await
        })
        .await;
        if let Err(error) = released {
            tracing::warn!(%error, leased = self.leased.word(), "a lease could not be let go; it runs out by itself");
        }
    }

    /// Whether this worker still holds the lease on `id`, extended.
    pub(crate) async fn renew(
        &self,
        databases: &Databases,
        id: &Uuid,
    ) -> Result<bool, DomainError> {
        let renewed = scoped(databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/platform_leases/renew.sql",
                self.leased.word(),
                id,
                self.holder,
                self.until(),
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        Ok(renewed.is_some())
    }

    /// Lets go of the lease on `id`. A lease that cannot be let go runs out
    /// by itself, so a failure is logged, not answered.
    pub(crate) async fn release(&self, databases: &Databases, id: &Uuid) {
        let released = scoped(databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/platform_leases/release.sql",
                self.leased.word(),
                id,
                self.holder,
            )
            .execute(connection)
            .await
        })
        .await;
        if let Err(error) = released {
            tracing::warn!(%error, leased = self.leased.word(), "a lease could not be let go; it runs out by itself");
        }
    }
}
