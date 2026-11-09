//! Live: what happens in a workflow run, and changes to a draft, pushed to
//! whoever watches them, so the builder lights each step up as it starts
//! and ends and nobody keeps working on a stale draft.
//!
//! The event pipeline runs it once the event is recorded. A watcher is a
//! dashboard, not a record: a push that fails is logged and the event goes
//! on, as the audit trail already holds what happened.

use std::sync::Arc;

use ianua_domain::domains::workflows::events::{draft_changed, run_moment};

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::realtime::{
    DraftChange, NotificationPublisher, RealtimeMessage, draft_subject, run_subject,
};
use crate::ports::shared::PublishedEvent;
use crate::use_case::Command;

/// The ports [`PublishLiveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PublishLivePorts {
    /// Pushes to the subjects watchers listen on.
    pub publisher: Arc<dyn NotificationPublisher>,
}

/// Pushes runs' moments and drafts' changes to their watchers.
///
/// The event pipeline runs it, for nobody, so its caller is `()`.
pub struct PublishLiveUseCase {
    ports: PublishLivePorts,
}

impl PublishLiveUseCase {
    /// A publisher over `ports`.
    #[must_use]
    pub fn new(ports: PublishLivePorts) -> Self {
        Self { ports }
    }

    /// Pushes `message` on `subject`, logging a failure.
    async fn pushed(&self, subject: &str, message: &RealtimeMessage) -> u64 {
        match self
            .ports
            .publisher
            .publish_dashboard(subject, message)
            .await
        {
            Ok(()) => 1,
            Err(error) => {
                tracing::warn!(%error, "a live update was not pushed");
                0
            }
        }
    }
}

impl Command for PublishLiveUseCase {
    type Caller = ();
    type Input = PublishedEvent;
    type Output = Result<u64, AppError>;

    /// Pushes what `event` shows a run's or a draft's watchers, and says
    /// how many pushes went out. Any other event pushes nothing. Records
    /// nothing: the event it shows is recorded already.
    ///
    /// # Errors
    ///
    /// None today: a push that fails is logged, not returned.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        event: PublishedEvent,
    ) -> Result<u64, AppError> {
        if let Some(moment) = run_moment(&event.event) {
            let subject = run_subject(&moment.tenant_id, &moment.execution_id);
            return Ok(self
                .pushed(&subject, &RealtimeMessage::RunMoment(moment))
                .await);
        }
        let Some((tenant_id, workflow_id)) = draft_changed(&event.event) else {
            return Ok(0);
        };
        let change = DraftChange {
            tenant_id,
            workflow_id,
            event_type: event.event.event_type(),
        };
        let subject = draft_subject(&tenant_id, &workflow_id);
        Ok(self
            .pushed(&subject, &RealtimeMessage::DraftChanged(change))
            .await)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::AuditContext;
    use ianua_domain::shared::events::event::DomainEvent;
    use ianua_domain::shared::events::raised::Raises as _;
    use ianua_domain::types::{AuditRecordId, Label};

    use super::*;
    use crate::test_support::workflows::{draft_by, managing, person, tidy_step};
    use crate::test_support::{
        FakeEventDispatcher, RecordingPublisher, block_on, test_auditor, test_ctx,
    };

    fn published(event: DomainEvent) -> PublishedEvent {
        PublishedEvent {
            id: AuditRecordId::new(),
            event,
            context: AuditContext::system().with_tenant(test_ctx().tenant_id()),
        }
    }

    /// Ann renames her draft. Whoever has it open is pushed the change on
    /// that draft's own subject.
    #[test]
    fn a_change_to_a_draft_is_pushed_to_its_watchers() {
        let ann = person("ann@corp.test");
        let mut draft = draft_by(&ann, vec![tidy_step("tidy")], Vec::new());
        let _ = draft.take_events(&test_ctx().tenant());
        draft
            .rename(&managing(&ann), Label::new("name", "Monthly").unwrap())
            .unwrap();
        let event = draft.take_events(&test_ctx().tenant()).remove(0);
        let publisher = Arc::new(RecordingPublisher::default());
        let use_case = PublishLiveUseCase::new(PublishLivePorts {
            publisher: publisher.clone(),
        });

        let pushed = block_on(use_case.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            published(event),
        ))
        .unwrap();

        assert_eq!(pushed, 1);
        assert_eq!(
            publisher.subjects(),
            [draft_subject(&test_ctx().tenant_id(), draft.id())]
        );
    }
}
