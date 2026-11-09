//! Archive topic: retire a topic for good. It stays readable, takes no new
//! messages or subscriptions, and may then be deleted.

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

/// The ports [`ArchiveUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ArchivePorts {
    /// Where topics are kept.
    pub topic_store: Arc<dyn TopicStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Archives a topic.
pub struct ArchiveUseCase {
    ports: ArchivePorts,
}

impl ArchiveUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ArchivePorts) -> Self {
        Self { ports }
    }
}

impl Command for ArchiveUseCase {
    type Caller = CallerContext;
    type Input = TopicId;
    type Output = Result<(), AppError>;

    /// Archives an active or paused topic, read-only for good. Records
    /// `messaging.topic_archived`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the tenant has no such topic.
    /// - `AppError::Forbidden` when the caller may not delete in messaging.
    /// - `AppError::Domain` when the topic is already archived.
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
                MessagingAction::Delete,
                Topic::archive,
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

    fn archive(
        topic: Topic<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> (Result<(), AppError>, TopicStatus, Vec<String>) {
        let id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ArchiveUseCase::new(ArchivePorts {
            topic_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id));

        let records = audit.records.lock().unwrap().clone();
        (result, stored_topic(&store, &id).status(), records)
    }

    /// Ann may delete in messaging and retires `orders.v1`. It is archived,
    /// and that is on record.
    #[test]
    fn an_active_topic_is_archived_and_recorded() {
        let (result, status, records) = archive(
            topic_named("orders.v1"),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Delete)]),
        );

        result.unwrap();
        assert_eq!(status, TopicStatus::Archived);
        assert_eq!(records, ["messaging.topic_archived"]);
    }

    /// Ann paused `orders.v1` first, then retires it. A paused topic is
    /// archived too.
    #[test]
    fn a_paused_topic_is_archived() {
        let (result, status, _) = archive(
            paused_topic("orders.v1"),
            FakeTenantAuthorities::holding_everything(),
        );

        result.unwrap();
        assert_eq!(status, TopicStatus::Archived);
    }

    /// Archiving an already archived topic returns a domain error without
    /// recording another event.
    #[test]
    fn an_archived_topic_is_not_archived_again() {
        let (result, _, records) = archive(
            archived_topic("orders.v1"),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(records.is_empty());
    }

    /// A caller with topic creation rights cannot archive a topic; the
    /// forbidden request leaves it active.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let (result, status, _) = archive(
            topic_named("payments.settled"),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Create)]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status, TopicStatus::Active);
    }

    /// A signed-out caller receives an unauthenticated error when archiving
    /// a topic, which stays active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (result, status, _) = archive(
            topic_named("orders.v1"),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status, TopicStatus::Active);
    }

    /// Ann names a topic the tenant does not have. It is not found.
    #[test]
    fn an_unknown_topic_is_not_found() {
        let use_case = ArchiveUseCase::new(ArchivePorts {
            topic_store: Arc::new(FakeTopicStore::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit), TopicId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
