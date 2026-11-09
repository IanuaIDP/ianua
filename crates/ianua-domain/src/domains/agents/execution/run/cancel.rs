//! A person's order to stop a run, and the proof that the run stopped on it.
//!
//! Stopping a running run is cooperative. The person asks, and the worker
//! driving the run stops it between steps, perhaps on another machine and a
//! few seconds later. So the person's say is checked once, when they ask,
//! and carried to the worker as a [`CancelOrder`]. The worker applies the
//! order without a person of its own. Applying it gives back a
//! [`RunCancelled`], and only that withdraws the approvals the run was
//! waiting on.

use time::OffsetDateTime;

use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::types::{AgentRunId, Human};

/// A person's order to stop one run, checked when they gave it.
///
/// Only [`AgentRun::order_cancel`](crate::domains::agents::execution::run::AgentRun::order_cancel) makes a
/// new one, after checking the person may stop the run, and a workflow
/// execution that ended, for a run of a step it abandoned
/// ([`WorkflowExecution::abandoned_run_orders`]). Storage carries it
/// to the worker and reads it back with [`reconstitute`](Self::reconstitute).
///
/// [`WorkflowExecution::abandoned_run_orders`]: crate::domains::workflows::execution::WorkflowExecution::abandoned_run_orders
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelOrder {
    run_id: AgentRunId,
    by: Human,
    at: OffsetDateTime,
}

/// A cancel order as storage keeps it.
pub struct CancelOrderRow {
    /// The run to stop.
    pub run_id: AgentRunId,
    /// The person who ordered it.
    pub by: Human,
    /// When they ordered it.
    pub at: OffsetDateTime,
}

impl CancelOrder {
    /// `by` orders `run_id` stopped, now.
    pub(super) fn new(run_id: AgentRunId, by: Human) -> Self {
        Self {
            run_id,
            by,
            at: clock::now(),
        }
    }

    /// The workflow engine's order to stop `run_id`, a run an ended workflow
    /// execution gave up, in the name of `acting_for`, the person the
    /// execution and its run acted for.
    ///
    /// Only an execution makes one, for a run it abandoned. Nobody's say is
    /// asked: the run was started for that execution's step, and the step
    /// no longer waits on it.
    pub(crate) fn for_abandoned_run(run_id: AgentRunId, acting_for: Human) -> Self {
        Self::new(run_id, acting_for)
    }

    /// Reads an order back from storage, after checking the row.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it was ordered
    ///   later than now.
    pub fn reconstitute(row: CancelOrderRow) -> Result<Self, DomainError> {
        RowCheck::of("cancel order")
            .holds(row.at <= clock::now(), "ordered later than now")
            .finish()?;
        Ok(Self {
            run_id: row.run_id,
            by: row.by,
            at: row.at,
        })
    }

    /// The run to stop.
    #[must_use]
    pub fn run_id(&self) -> &AgentRunId {
        &self.run_id
    }

    /// The person who ordered it.
    #[must_use]
    pub fn by(&self) -> &Human {
        &self.by
    }

    /// When they ordered it.
    #[must_use]
    pub fn at(&self) -> OffsetDateTime {
        self.at
    }
}

/// Proof that a run ended cancelled on a person's order.
///
/// Only [`AgentRun::cancel`](crate::domains::agents::execution::run::AgentRun::cancel) makes one. An approval
/// the run was waiting on is withdrawn with it, so nobody approves a call a
/// run will never make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCancelled {
    run_id: AgentRunId,
    by: Human,
}

impl RunCancelled {
    /// The cancellation `order` brought about.
    pub(super) fn of(order: &CancelOrder) -> Self {
        Self {
            run_id: order.run_id,
            by: order.by.clone(),
        }
    }

    /// The run that was cancelled.
    #[must_use]
    pub fn run_id(&self) -> &AgentRunId {
        &self.run_id
    }

    /// The person who ordered it.
    #[must_use]
    pub fn by(&self) -> &Human {
        &self.by
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{HumanAccount, PersonKey, UserId};

    fn ann() -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("ann@corp.test").unwrap(),
        )
    }

    /// An order stored a minute ago reads back as it was given.
    #[test]
    fn a_stored_order_reads_back() {
        let at = clock::now() - time::Duration::minutes(1);
        let run_id = AgentRunId::new();

        let order = CancelOrder::reconstitute(CancelOrderRow {
            run_id,
            by: ann(),
            at,
        })
        .unwrap();

        assert_eq!(order.run_id(), &run_id);
        assert_eq!(order.at(), at);
    }

    /// A stored order says it was given an hour from now. No order is given
    /// in the future, so it is refused as corrupt.
    #[test]
    fn an_order_from_the_future_is_refused() {
        let result = CancelOrder::reconstitute(CancelOrderRow {
            run_id: AgentRunId::new(),
            by: ann(),
            at: clock::now() + time::Duration::hours(1),
        });

        assert!(refused_as_corrupt(&result));
    }
}
