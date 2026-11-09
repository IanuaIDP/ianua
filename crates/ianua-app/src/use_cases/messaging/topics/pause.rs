//! Pause topic: stop a topic taking new messages, keeping its
//! subscriptions. A paused topic is one that may be deleted.

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

/// The ports [`PauseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PausePorts {
    /// Where topics are kept.
    pub topic_store: Arc<dyn TopicStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Pauses a topic.
pub struct PauseUseCase {
    ports: PausePorts,
}

impl PauseUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PausePorts) -> Self {
        Self { ports }
    }
}

impl Command for PauseUseCase {
    type Caller = CallerContext;
    type Input = TopicId;
    type Output = Result<(), AppError>;

    /// Pauses an active topic, so it refuses new messages until it is
    /// resumed. Records `messaging.topic_paused`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the tenant has no such topic.
    /// - `AppError::Forbidden` when the caller does not manage messaging.
    /// - `AppError::Domain` unless the topic is active.
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
                Topic::pause,
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
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn pause(
        topic: Topic<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> (Result<(), AppError>, TopicStatus, Vec<String>) {
        let id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = PauseUseCase::new(PausePorts {
            topic_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id));

        let records = audit.records.lock().unwrap().clone();
        (result, stored_topic(&store, &id).status(), records)
    }

    /// Ann pauses `orders.created` ahead of retiring it. It refuses new
    /// messages, and the pause is on record.
    #[test]
    fn an_active_topic_is_paused_and_recorded() {
        let (result, status, records) = pause(
            topic_named("orders.created"),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Manage)]),
        );

        result.unwrap();
        assert_eq!(status, TopicStatus::Paused);
        assert_eq!(records, ["messaging.topic_paused"]);
    }

    /// Pausing an already paused topic returns a domain error, leaves it
    /// paused and records no further event.
    #[test]
    fn a_paused_topic_is_not_paused_again() {
        let (result, status, records) = pause(
            paused_topic("orders.created"),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(status, TopicStatus::Paused);
        assert!(records.is_empty());
    }

    /// Pausing an archived topic returns a domain error and leaves it archived.
    #[test]
    fn an_archived_topic_is_not_paused() {
        let (result, status, _) = pause(
            archived_topic("old.topic"),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(status, TopicStatus::Archived);
    }

    /// Publishing rights do not permit pausing a topic; the forbidden
    /// request leaves it active.
    #[test]
    fn a_caller_who_does_not_manage_messaging_is_refused() {
        let (result, status, _) = pause(
            topic_named("payments.settled"),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(
                MessagingAction::Publish,
            )]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status, TopicStatus::Active);
    }

    /// A signed-out caller receives an unauthenticated error when pausing
    /// a topic, which stays active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (result, status, _) = pause(
            topic_named("orders.created"),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status, TopicStatus::Active);
    }

    /// Ann names a topic the tenant does not have. It is not found.
    #[test]
    fn an_unknown_topic_is_not_found() {
        let use_case = PauseUseCase::new(PausePorts {
            topic_store: Arc::new(FakeTopicStore::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit), TopicId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The pause cannot be recorded. Ann is told it failed rather than
    /// left thinking the record shows it.
    #[test]
    fn a_pause_that_cannot_be_recorded_fails() {
        let topic = topic_named("orders.created");
        let id = *topic.id();
        let use_case = PauseUseCase::new(PausePorts {
            topic_store: topics_of_test_tenant(topic),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            id,
        ));

        assert!(matches!(result, Err(AppError::Internal(_))));
    }
}
