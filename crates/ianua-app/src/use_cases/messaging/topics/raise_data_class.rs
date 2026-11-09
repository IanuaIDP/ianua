//! Raise topic data class: declare that a topic may carry more sensitive
//! data. The class only ever rises; less sensitive traffic goes to a new
//! topic.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::types::TopicId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::messaging::TopicStore;
use crate::use_case::Command;
use crate::use_cases::messaging::changes::MessagingChange;

/// Which topic is raised to which class.
pub struct RaiseDataClassRequest {
    /// The topic to change.
    pub topic_id: TopicId,
    /// The most sensitive data the topic may carry from now on.
    pub data_class: DataClassLevel,
}

/// The ports [`RaiseDataClassUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RaiseDataClassPorts {
    /// Where topics are kept.
    pub topic_store: Arc<dyn TopicStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Raises a topic's data class.
pub struct RaiseDataClassUseCase {
    ports: RaiseDataClassPorts,
}

impl RaiseDataClassUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RaiseDataClassPorts) -> Self {
        Self { ports }
    }
}

impl Command for RaiseDataClassUseCase {
    type Caller = CallerContext;
    type Input = RaiseDataClassRequest;
    type Output = Result<(), AppError>;

    /// Raises the topic's data class. Subscribers cleared below the new
    /// class stop hearing it, so `messaging.topic_data_class_raised`
    /// records the class before and after.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the tenant has no such topic.
    /// - `AppError::Forbidden` when the caller does not manage messaging,
    ///   or the class asked for is below the current one.
    /// - `AppError::Domain` when the topic is archived.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: RaiseDataClassRequest,
    ) -> Result<(), AppError> {
        MessagingChange::by(caller, auditor, self.ports.tenant_authorities.as_ref())
            .topic(
                self.ports.topic_store.as_ref(),
                &req.topic_id,
                MessagingAction::Manage,
                |topic, control| topic.raise_data_class(req.data_class, control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::messaging::topic::Topic;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{
        FakeTopicStore, archived_topic, stored_topic, topic_named, topics_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Outcome {
        result: Result<(), AppError>,
        class: DataClassLevel,
        audit: Arc<FakeEventDispatcher>,
    }

    fn raise(
        topic: Topic<ResolvedTenant>,
        to: DataClassLevel,
        authorities: FakeTenantAuthorities,
    ) -> Outcome {
        let topic_id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = RaiseDataClassUseCase::new(RaiseDataClassPorts {
            topic_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let req = RaiseDataClassRequest {
            topic_id,
            data_class: to,
        };

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), req));

        Outcome {
            result,
            class: stored_topic(&store, &topic_id).data_class(),
            audit,
        }
    }

    /// Ann raises `orders.created` from internal to confidential once it
    /// carries card details. The topic keeps the new class, and the record
    /// holds both, since subscribers cleared below it stop hearing it.
    #[test]
    fn a_raised_class_is_kept_and_records_both_classes() {
        let outcome = raise(
            topic_named("orders.created"),
            DataClassLevel::Confidential,
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Manage)]),
        );

        outcome.result.unwrap();
        assert_eq!(outcome.class, DataClassLevel::Confidential);
        let payload = outcome
            .audit
            .payload_of("messaging.topic_data_class_raised");
        let Some(FieldValue::Change(change)) = payload.value("data_class") else {
            panic!("data_class is not a change");
        };
        assert_eq!(
            (change.from(), change.to()),
            (
                Some(DataClassLevel::Internal.as_str()),
                Some(DataClassLevel::Confidential.as_str())
            )
        );
    }

    /// Lowering a topic from internal to public is forbidden; its class
    /// stays internal and no event is recorded.
    #[test]
    fn a_data_class_is_not_lowered() {
        let outcome = raise(
            topic_named("orders.created"),
            DataClassLevel::Public,
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(outcome.result, Err(AppError::Forbidden(_))));
        assert_eq!(outcome.class, DataClassLevel::Internal);
        assert!(outcome.audit.records.lock().unwrap().is_empty());
    }

    /// Raising an archived topic's class returns a domain error and leaves
    /// its internal classification unchanged.
    #[test]
    fn an_archived_topic_keeps_its_class() {
        let outcome = raise(
            archived_topic("old.topic"),
            DataClassLevel::Restricted,
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(outcome.result, Err(AppError::Domain(_))));
        assert_eq!(outcome.class, DataClassLevel::Internal);
    }

    /// Publishing rights do not permit raising a topic's class; the
    /// forbidden request leaves its internal classification unchanged.
    #[test]
    fn a_caller_who_does_not_manage_messaging_is_refused() {
        let outcome = raise(
            topic_named("payments.settled"),
            DataClassLevel::Restricted,
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(
                MessagingAction::Publish,
            )]),
        );

        assert!(matches!(outcome.result, Err(AppError::Forbidden(_))));
        assert_eq!(outcome.class, DataClassLevel::Internal);
    }

    /// A signed-out caller receives an unauthenticated error when raising
    /// a topic's class.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let outcome = raise(
            topic_named("orders.created"),
            DataClassLevel::Confidential,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(outcome.result, Err(AppError::Unauthenticated)));
    }

    /// Ann names a topic the tenant does not have. It is not found.
    #[test]
    fn an_unknown_topic_is_not_found() {
        let use_case = RaiseDataClassUseCase::new(RaiseDataClassPorts {
            topic_store: Arc::new(FakeTopicStore::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        let req = RaiseDataClassRequest {
            topic_id: TopicId::new(),
            data_class: DataClassLevel::Confidential,
        };
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit), req));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
