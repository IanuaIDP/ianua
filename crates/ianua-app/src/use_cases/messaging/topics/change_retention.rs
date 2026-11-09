//! Change topic retention: replace how long a topic keeps its messages.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::control::MessagingControl;
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::TopicId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{MessageConsumer, TopicStore};
use crate::use_case::Command;
use crate::use_cases::messaging::lookup::existing_topic;

/// Which topic keeps its messages how long.
pub struct ChangeRetentionRequest {
    /// The topic to change.
    pub topic_id: TopicId,
    /// The retention policy from now on.
    pub retention: RetentionPolicy,
}

/// The ports [`ChangeRetentionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeRetentionPorts {
    /// Where topics are kept.
    pub topic_store: Arc<dyn TopicStore>,
    /// The bus that drops what the old rule no longer keeps.
    pub message_consumer: Arc<dyn MessageConsumer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a topic's retention policy.
pub struct ChangeRetentionUseCase {
    ports: ChangeRetentionPorts,
}

impl ChangeRetentionUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeRetentionPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeRetentionUseCase {
    type Caller = CallerContext;
    type Input = ChangeRetentionRequest;
    type Output = Result<(), AppError>;

    /// Replaces the topic's retention policy. A shorter one drops messages
    /// subscribers have not read, so `messaging.topic_retention_changed`
    /// records the policy before and after.
    ///
    /// What the old rule no longer kept is removed from the bus first, so
    /// a longer limit cannot bring back a message already past it. A later
    /// failure leaves only those removed, which were past their limit
    /// anyway, and repeating the change removes nothing more.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the tenant has no such topic.
    /// - `AppError::Forbidden` when the caller does not manage messaging.
    /// - `AppError::Domain` when the topic is archived.
    /// - `AppError::Internal` on bus, storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: ChangeRetentionRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = MessagingControl::new(&authority);
        control
            .ensure_may(MessagingAction::Manage)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.topic_store.as_ref();
        let mut topic = existing_topic(store, &tenant, &req.topic_id).await?;
        let previous = topic.retention();
        topic
            .change_retention(req.retention, &control)
            .map_err(AppError::from_domain)?;

        self.ports
            .message_consumer
            .remove_lapsed(&tenant, topic.topic_name(), previous)
            .await
            .or_internal()?;
        store.save(&tenant, &topic).await.or_internal()?;

        auditor
            .dispatch_by(&caller.actor(), topic.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::messaging::topic::Topic;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{
        FakeMessageConsumer, FakeTopicStore, archived_topic, stored_topic, topic_named,
        topics_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Outcome {
        result: Result<(), AppError>,
        retention: RetentionPolicy,
        audit: Arc<FakeEventDispatcher>,
        bus: Arc<FakeMessageConsumer>,
    }

    fn an_hour() -> RetentionPolicy {
        RetentionPolicy::Duration(NonZeroU32::new(3600).unwrap())
    }

    fn change(topic: Topic<ResolvedTenant>, authorities: FakeTenantAuthorities) -> Outcome {
        let topic_id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let audit = Arc::new(FakeEventDispatcher::new());
        let bus = Arc::new(FakeMessageConsumer::empty());
        let use_case = ChangeRetentionUseCase::new(ChangeRetentionPorts {
            topic_store: store.clone(),
            message_consumer: bus.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let req = ChangeRetentionRequest {
            topic_id,
            retention: an_hour(),
        };

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), req));

        Outcome {
            result,
            retention: stored_topic(&store, &topic_id).retention(),
            audit,
            bus,
        }
    }

    /// Ann shortens `orders.created` from keeping everything to an hour.
    /// The topic keeps the new policy, and the record holds both, since
    /// the shorter one drops messages no subscriber has read.
    #[test]
    fn a_retention_change_is_kept_and_records_both_policies() {
        let outcome = change(
            topic_named("orders.created"),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Manage)]),
        );

        outcome.result.unwrap();
        assert_eq!(outcome.retention, an_hour());
        let payload = outcome
            .audit
            .payload_of("messaging.topic_retention_changed");
        let Some(FieldValue::Change(change)) = payload.value("retention") else {
            panic!("retention is not a change");
        };
        assert_eq!(
            (change.from(), change.to()),
            (Some("unlimited"), Some("3600s"))
        );
    }

    /// Ann changes `orders.created`. The bus is told to drop what the rule
    /// she replaces no longer keeps, the old rule and not the new one, so
    /// a longer limit cannot bring back a message already past the old.
    #[test]
    fn the_old_rule_is_applied_to_the_bus_first() {
        let outcome = change(
            topic_named("orders.created"),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Manage)]),
        );

        outcome.result.unwrap();
        assert_eq!(outcome.bus.removals(), [RetentionPolicy::Unlimited]);
    }

    /// An archived topic rejects a retention change with a domain error,
    /// keeps unlimited retention and records no event.
    #[test]
    fn an_archived_topic_keeps_its_retention() {
        let outcome = change(
            archived_topic("old.topic"),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(outcome.result, Err(AppError::Domain(_))));
        assert_eq!(outcome.retention, RetentionPolicy::Unlimited);
        assert!(outcome.audit.records.lock().unwrap().is_empty());
    }

    /// Publishing rights do not permit changing topic retention; the
    /// forbidden request leaves unlimited retention in place.
    #[test]
    fn a_caller_who_does_not_manage_messaging_is_refused() {
        let outcome = change(
            topic_named("payments.settled"),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(
                MessagingAction::Publish,
            )]),
        );

        assert!(matches!(outcome.result, Err(AppError::Forbidden(_))));
        assert_eq!(outcome.retention, RetentionPolicy::Unlimited);
    }

    /// A signed-out caller receives an unauthenticated error when changing
    /// topic retention.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let outcome = change(
            topic_named("orders.created"),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(outcome.result, Err(AppError::Unauthenticated)));
    }

    /// Ann names a topic the tenant does not have. It is not found.
    #[test]
    fn an_unknown_topic_is_not_found() {
        let use_case = ChangeRetentionUseCase::new(ChangeRetentionPorts {
            topic_store: Arc::new(FakeTopicStore::empty()),
            message_consumer: Arc::new(FakeMessageConsumer::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        let req = ChangeRetentionRequest {
            topic_id: TopicId::new(),
            retention: an_hour(),
        };
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit), req));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
