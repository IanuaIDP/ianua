//! Hear egress denials: every way out the egress gateway refused a service
//! while it handled an agent's request, held once against the agent.

use std::sync::Arc;

use ianua_domain::types::event_type::AgentsEvent;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::shared::{EventReaction, PublishedEvent};
use crate::use_case::Command;
use crate::use_cases::agents::intent::heard::{Heard, HeardAction, HeardPorts, once};
use crate::use_cases::agents::intent::{
    RespondToEgressDenialRequest, RespondToEgressDenialUseCase,
};

/// The events held against an agent: the ways out refused.
const REFUSED: [AgentsEvent; 1] = [AgentsEvent::EgressDenied];

/// Holds each refused way out heard on the bus against its agent, once.
///
/// The worker runs it for nobody, so its caller is `()`.
pub struct HearEgressDenialUseCase {
    respond: Arc<RespondToEgressDenialUseCase>,
    ports: HeardPorts,
}

impl HearEgressDenialUseCase {
    /// Hearing refused ways out for `respond`, through `ports`.
    #[must_use]
    pub fn new(respond: Arc<RespondToEgressDenialUseCase>, ports: HeardPorts) -> Self {
        Self { respond, ports }
    }
}

impl Command for HearEgressDenialUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<Heard, AppError>;

    /// Holds the refusal `event` carries against its agent, unless it was
    /// held when the bus handed the event out before. Any other event is
    /// ignored.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the event does not read, or the monitor
    ///   may not suspend the agent.
    /// - `AppError::Internal` on persistence or audit failure; nothing is
    ///   kept, and the event is held again.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<Heard, AppError> {
        let Some(action) = HeardAction::of(&event, &REFUSED)? else {
            return Ok(Heard::Ignored);
        };
        let request = RespondToEgressDenialRequest {
            agent_id: action.agent_id,
            delegation_id: action.delegation_id,
        };
        let held = self.respond.execute(&action.tenant, auditor, request);
        once(
            &self.ports,
            &action.tenant,
            EventReaction::EgressDenial,
            event.id,
            held,
        )
        .await
    }
}
