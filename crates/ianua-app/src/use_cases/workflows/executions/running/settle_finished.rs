//! Settle finished runs: every agent run the agents' worker announces as
//! finished, settled on the workflow step that started it.
//!
//! Settling is safe to hear twice: a step settled once no longer waits on
//! the run, and the second hearing finds nothing to settle.

use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::event_type::AgentsEvent;
use ianua_domain::types::{AgentRunId, EventType};
use uuid::Uuid;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::shared::PublishedEvent;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::workflows::executions::running::settle_agent_run::SettleAgentRunUseCase;

/// Settles each finished run heard on the bus on its workflow step.
///
/// The worker runs it for nobody, so its caller is `()`.
pub struct SettleFinishedRunUseCase {
    settle: Arc<SettleAgentRunUseCase>,
}

impl SettleFinishedRunUseCase {
    /// Hearing finished runs for `settle`.
    #[must_use]
    pub fn new(settle: Arc<SettleAgentRunUseCase>) -> Self {
        Self { settle }
    }
}

impl Command for SettleFinishedRunUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<Option<AgentRunId>, AppError>;

    /// Settles the run `event` says finished, and answers it; any other
    /// event is ignored and answers `None`.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` while a worker drives the execution; the
    ///   event is heard again.
    /// - `AppError::Domain` when the event names no run, or the execution
    ///   refuses the run's result.
    /// - `AppError::Internal` when a store, the lease or the audit trail
    ///   fails.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<Option<AgentRunId>, AppError> {
        let finished = event.event.event_type() == EventType::Agents(AgentsEvent::RunFinished);
        let Some(tenant_id) = event.event.tenant_id().copied().filter(|_| finished) else {
            return Ok(None);
        };
        let run_id = run_of(&event)?;
        let tenant = ScopedTenant::for_background(tenant_id);
        self.settle.execute(&tenant, auditor, run_id).await?;
        Ok(Some(run_id))
    }
}

/// The run a finished run's event names.
///
/// # Errors
///
/// `AppError::Domain` when it names none.
fn run_of(event: &PublishedEvent) -> Result<AgentRunId, AppError> {
    event
        .event
        .payload()
        .get("run")
        .and_then(|id| Uuid::parse_str(id).ok())
        .map(AgentRunId::from_uuid)
        .ok_or_else(|| {
            AppError::from_domain(DomainError::invalid(message!(
                "workflows-the-event-names-no-run",
                "the event names no run"
            )))
        })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::test_support::events::sample_tenant_event;
    use ianua_domain::types::{AuditRecordId, TenantId};

    use super::*;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::workflows::executions::running::settle_agent_run::SettleAgentRunPorts;

    /// An event that is no run's end is ignored, and nothing is settled.
    #[test]
    fn another_event_is_ignored() {
        let settle = SettleFinishedRunUseCase::new(Arc::new(SettleAgentRunUseCase::new(
            SettleAgentRunPorts::fakes(),
        )));
        let event = PublishedEvent {
            id: AuditRecordId::new(),
            event: sample_tenant_event(TenantId::new()),
            context: AuditContext::system(),
        };

        let settled = block_on(settle.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            event,
        ))
        .unwrap();

        assert_eq!(settled, None);
    }
}
