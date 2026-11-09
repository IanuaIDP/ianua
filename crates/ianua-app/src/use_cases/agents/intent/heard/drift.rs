//! Hear drift: every action the gateway allowed or refused an agent,
//! judged once against its delegation's intent.

use std::sync::Arc;

use ianua_domain::types::ActionClass;
use ianua_domain::types::event_type::AgentsEvent;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::shared::{EventReaction, PublishedEvent};
use crate::use_case::Command;
use crate::use_cases::agents::intent::heard::{Heard, HeardAction, HeardPorts, once};
use crate::use_cases::agents::intent::{EvaluateDriftRequest, EvaluateDriftUseCase};

/// The events drift is judged on: the actions allowed, and those refused,
/// so an agent probing past its intent is answered too.
const JUDGED: [AgentsEvent; 2] = [AgentsEvent::ActionAuthorized, AgentsEvent::ActionDenied];

/// Judges each agent action heard on the bus against its intent, once.
///
/// The worker runs it for nobody, so its caller is `()`.
pub struct HearDriftUseCase {
    drift: Arc<EvaluateDriftUseCase>,
    ports: HeardPorts,
}

impl HearDriftUseCase {
    /// Hearing actions for `drift`, through `ports`.
    #[must_use]
    pub fn new(drift: Arc<EvaluateDriftUseCase>, ports: HeardPorts) -> Self {
        Self { drift, ports }
    }
}

impl Command for HearDriftUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<Heard, AppError>;

    /// Judges the action `event` carries, unless it was judged when the bus
    /// handed the event out before. Any other event is ignored.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the event does not read, or the monitor
    ///   may not answer the drift.
    /// - `AppError::Internal` on persistence or audit failure; nothing is
    ///   kept, and the event is judged again.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<Heard, AppError> {
        let Some(action) = HeardAction::of(&event, &JUDGED)? else {
            return Ok(Heard::Ignored);
        };
        let request = EvaluateDriftRequest {
            agent_id: action.agent_id,
            delegation_id: action.delegation_id,
            action_class: ActionClass::parse(action.text("action_class")?)
                .map_err(AppError::from_domain)?,
        };
        let judged = self.drift.execute(&action.tenant, auditor, request);
        once(
            &self.ports,
            &action.tenant,
            EventReaction::Drift,
            event.id,
            judged,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::events::enforcement::{AgentActionAuthorized, AgentAtWork};
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::events::event::DomainEvent;
    use ianua_domain::test_support::events::sample_tenant_event;
    use ianua_domain::types::{AgentId, AuditRecordId, DelegationId, TenantId, UntrustedText};

    use super::*;
    use crate::test_support::{
        FakeEventDispatcher, FakeEventReactions, RecordingUnitOfWork, block_on, test_auditor,
    };
    use crate::use_cases::agents::intent::EvaluateDriftPorts;

    struct Fixture {
        heard: HearDriftUseCase,
        reactions: Arc<FakeEventReactions>,
    }

    fn fixture() -> Fixture {
        let reactions = Arc::new(FakeEventReactions::default());
        Fixture {
            heard: HearDriftUseCase::new(
                Arc::new(EvaluateDriftUseCase::new(EvaluateDriftPorts::fakes())),
                HeardPorts {
                    reactions: reactions.clone(),
                    unit_of_work: Arc::new(RecordingUnitOfWork::default()),
                },
            ),
            reactions,
        }
    }

    fn published(event: DomainEvent) -> PublishedEvent {
        PublishedEvent {
            id: AuditRecordId::new(),
            event,
            context: AuditContext::system(),
        }
    }

    fn allowed_read() -> PublishedEvent {
        let by = AgentAtWork::new(TenantId::new(), AgentId::new(), DelegationId::new());
        published(AgentActionAuthorized::observed(
            by,
            UntrustedText::record("GET /board/1"),
            ActionClass::Read,
            clock::now(),
        ))
    }

    fn heard(fx: &Fixture, event: PublishedEvent) -> Heard {
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(fx.heard.execute(&(), &auditor, event)).unwrap()
    }

    /// An allowed action heard on the bus is judged, and its event noted.
    #[test]
    fn an_action_heard_is_judged() {
        let fx = fixture();

        let outcome = heard(&fx, allowed_read());

        assert_eq!(outcome, Heard::Acted);
        assert_eq!(fx.reactions.count(), 1);
    }

    /// Redelivering an action event reports it as already heard and leaves
    /// only one recorded reaction.
    #[test]
    fn an_action_handed_out_again_is_not_judged_again() {
        let fx = fixture();
        let event = allowed_read();
        let again = PublishedEvent {
            id: event.id,
            event: event.event.recorded(),
            context: event.context.clone(),
        };

        heard(&fx, event);
        let outcome = heard(&fx, again);

        assert_eq!(outcome, Heard::Before);
        assert_eq!(fx.reactions.count(), 1);
    }

    /// An event that is no agent action is ignored, and nothing is noted.
    #[test]
    fn another_event_is_ignored() {
        let fx = fixture();

        let outcome = heard(&fx, published(sample_tenant_event(TenantId::new())));

        assert_eq!(outcome, Heard::Ignored);
        assert_eq!(fx.reactions.count(), 0);
    }
}
