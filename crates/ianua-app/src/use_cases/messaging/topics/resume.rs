//! Resume topic: let a paused topic take messages again.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::types::TopicId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::messaging::TopicStore;
use crate::use_case::Command;
use crate::use_cases::messaging::changes::MessagingChange;

/// The ports [`ResumeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResumePorts {
    /// Where topics are kept.
    pub topic_store: Arc<dyn TopicStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Resumes a paused topic.
pub struct ResumeUseCase {
    ports: ResumePorts,
}

impl ResumeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResumePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResumeUseCase {
    type Caller = CallerContext;
    type Input = TopicId;
    type Output = Result<(), AppError>;

    /// Resumes a paused topic, so it accepts messages again. Records
    /// `messaging.topic_resumed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the tenant has no such topic.
    /// - `AppError::Forbidden` when the caller does not manage messaging.
    /// - `AppError::Domain` unless the topic is paused.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        topic_id: TopicId,
    ) -> Result<(), AppError> {
        MessagingChange::by(caller, auditor, self.ports.tenant_authorities.as_ref())
            .topic(
                self.ports.topic_store.as_ref(),
                &topic_id,
                MessagingAction::Manage,
                Topic::resume,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::messaging::topic::{Topic, TopicStatus};
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{
        FakeTopicStore, archived_topic, paused_topic, stored_topic, topic_named,
        topics_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn resume(
        topic: Topic<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> (Result<(), AppError>, TopicStatus, Vec<String>) {
        let id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ResumeUseCase::new(ResumePorts {
            topic_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id));

        let records = audit.records.lock().unwrap().clone();
        (result, stored_topic(&store, &id).status(), records)
    }

    /// Ann paused `orders.created` for a migration and resumes it. It takes
    /// messages again, and that is on record.
    #[test]
    fn a_paused_topic_is_resumed_and_recorded() {
        let (result, status, records) = resume(
            paused_topic("orders.created"),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Manage)]),
        );

        result.unwrap();
        assert_eq!(status, TopicStatus::Active);
        assert_eq!(records, ["messaging.topic_resumed"]);
    }

    /// Resuming an already active topic returns a domain error without
    /// recording an event.
    #[test]
    fn an_active_topic_is_not_resumed() {
        let (result, _, records) = resume(
            topic_named("orders.created"),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(records.is_empty());
    }

    /// Resuming an archived topic returns a domain error and leaves it archived.
    #[test]
    fn an_archived_topic_is_not_resumed() {
        let (result, status, _) = resume(
            archived_topic("old.topic"),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(status, TopicStatus::Archived);
    }

    /// Publishing rights do not permit resuming a topic; the forbidden
    /// request leaves it paused.
    #[test]
    fn a_caller_who_does_not_manage_messaging_is_refused() {
        let (result, status, _) = resume(
            paused_topic("payments.settled"),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(
                MessagingAction::Publish,
            )]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status, TopicStatus::Paused);
    }

    /// A signed-out caller receives an unauthenticated error when resuming
    /// a topic, which stays paused.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (result, status, _) = resume(
            paused_topic("orders.created"),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status, TopicStatus::Paused);
    }

    /// Ann names a topic the tenant does not have. It is not found.
    #[test]
    fn an_unknown_topic_is_not_found() {
        let use_case = ResumeUseCase::new(ResumePorts {
            topic_store: Arc::new(FakeTopicStore::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit), TopicId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
