//! Hear convergence: every request the gateway allowed an agent, checked
//! once for meeting another agent at the same place.

use std::sync::Arc;

use ianua_domain::types::ActionClass;
use ianua_domain::types::event_type::AgentsEvent;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::shared::{EventReaction, PublishedEvent};
use crate::use_case::Command;
use crate::use_cases::agents::intent::heard::{Heard, HeardAction, HeardPorts, once};
use crate::use_cases::agents::intent::{DetectConvergenceRequest, DetectConvergenceUseCase};

/// The events meetings are looked for in: the requests allowed. A refused
/// request touched nothing.
const ALLOWED: [AgentsEvent; 1] = [AgentsEvent::ActionAuthorized];

/// Checks each allowed agent request heard on the bus for a meeting, once.
///
/// The worker runs it for nobody, so its caller is `()`.
pub struct HearConvergenceUseCase {
    detect: Arc<DetectConvergenceUseCase>,
    ports: HeardPorts,
}

impl HearConvergenceUseCase {
    /// Hearing requests for `detect`, through `ports`.
    #[must_use]
    pub fn new(detect: Arc<DetectConvergenceUseCase>, ports: HeardPorts) -> Self {
        Self { detect, ports }
    }
}

impl Command for HearConvergenceUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<Heard, AppError>;

    /// Checks the request `event` carries, at the moment the gateway allowed
    /// it, unless it was checked when the bus handed the event out before.
    /// Any other event is ignored.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the event does not read, or the monitor
    ///   may not suspend the agent.
    /// - `AppError::Internal` on persistence or audit failure; nothing is
    ///   kept, and the event is checked again.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<Heard, AppError> {
        let Some(action) = HeardAction::of(&event, &ALLOWED)? else {
            return Ok(Heard::Ignored);
        };
        let request = DetectConvergenceRequest {
            agent_id: action.agent_id,
            delegation_id: action.delegation_id,
            action: action.text("action")?.to_owned(),
            action_class: ActionClass::parse(action.text("action_class")?)
                .map_err(AppError::from_domain)?,
            at: action.at()?,
        };
        let checked = self.detect.execute(&action.tenant, auditor, request);
        once(
            &self.ports,
            &action.tenant,
            EventReaction::Convergence,
            event.id,
            checked,
        )
        .await
    }
}
