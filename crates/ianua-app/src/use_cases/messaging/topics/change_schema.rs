//! Change topic schema: replace or clear the JSON schema a topic's messages
//! are checked against.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::schema::SchemaDefinition;
use ianua_domain::types::{Setting, TopicId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::messaging::TopicStore;
use crate::use_case::Command;
use crate::use_cases::messaging::changes::MessagingChange;

/// Which topic gets which schema.
pub struct ChangeSchemaRequest {
    /// The topic to change.
    pub topic_id: TopicId,
    /// The schema messages are checked against from now on, or unset for
    /// none.
    pub schema: Setting<SchemaDefinition>,
}

/// The ports [`ChangeSchemaUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeSchemaPorts {
    /// Where topics are kept.
    pub topic_store: Arc<dyn TopicStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a topic's schema.
pub struct ChangeSchemaUseCase {
    ports: ChangeSchemaPorts,
}

impl ChangeSchemaUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeSchemaPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeSchemaUseCase {
    type Caller = CallerContext;
    type Input = ChangeSchemaRequest;
    type Output = Result<(), AppError>;

    /// Replaces or clears the topic's schema. Records
    /// `messaging.topic_schema_changed`, naming the topic but not the
    /// schema.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the tenant has no such topic.
    /// - `AppError::Forbidden` when the caller does not manage messaging.
    /// - `AppError::Domain` when the topic is archived.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: ChangeSchemaRequest,
    ) -> Result<(), AppError> {
        MessagingChange::by(caller, auditor, self.ports.tenant_authorities.as_ref())
            .topic(
                self.ports.topic_store.as_ref(),
                &req.topic_id,
                MessagingAction::Manage,
                |topic, control| topic.change_schema(req.schema, control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::messaging::topic::Topic;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{
        FakeTopicStore, archived_topic, messaging_admin, stored_topic, topic_named,
        topics_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const ORDER: &str = r#"{"type":"object","required":["id"]}"#;

    struct Outcome {
        result: Result<(), AppError>,
        schema: Option<String>,
        records: Vec<String>,
    }

    fn order_schema() -> Setting<SchemaDefinition> {
        Setting::Set(SchemaDefinition::new(ORDER).unwrap())
    }

    fn change(
        topic: Topic<ResolvedTenant>,
        schema: Setting<SchemaDefinition>,
        authorities: FakeTenantAuthorities,
    ) -> Outcome {
        let topic_id = *topic.id();
        let store = topics_of_test_tenant(topic);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ChangeSchemaUseCase::new(ChangeSchemaPorts {
            topic_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        let req = ChangeSchemaRequest { topic_id, schema };

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), req));

        let kept = stored_topic(&store, &topic_id);
        Outcome {
            result,
            schema: kept.schema().map(|schema| schema.as_str().to_owned()),
            records: audit.records.lock().unwrap().clone(),
        }
    }

    /// Ann gives `orders.created` a schema requiring an `id`. The topic
    /// keeps it, and the change is on record.
    #[test]
    fn a_topic_takes_a_new_schema_and_it_is_recorded() {
        let outcome = change(
            topic_named("orders.created"),
            order_schema(),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Manage)]),
        );

        outcome.result.unwrap();
        assert_eq!(outcome.schema.as_deref(), Some(ORDER));
        assert_eq!(outcome.records, ["messaging.topic_schema_changed"]);
    }

    /// Ann clears the schema of `orders.created`. Its messages are checked
    /// against nothing from now on.
    #[test]
    fn a_topic_schema_is_cleared() {
        let mut topic = topic_named("orders.created");
        topic
            .change_schema(order_schema(), &messaging_admin())
            .unwrap();

        let outcome = change(
            topic,
            Setting::Unset,
            FakeTenantAuthorities::holding_everything(),
        );

        outcome.result.unwrap();
        assert_eq!(outcome.schema, None);
    }

    /// Adding a schema to an archived topic returns a domain error, leaves
    /// it without a schema and records no event.
    #[test]
    fn an_archived_topic_keeps_its_schema() {
        let outcome = change(
            archived_topic("old.topic"),
            order_schema(),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(outcome.result, Err(AppError::Domain(_))));
        assert_eq!(outcome.schema, None);
        assert!(outcome.records.is_empty());
    }

    /// Topic creation rights do not permit adding a schema to an existing
    /// topic; the forbidden request leaves it without a schema.
    #[test]
    fn a_caller_who_does_not_manage_messaging_is_refused() {
        let outcome = change(
            topic_named("payments.settled"),
            order_schema(),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Create)]),
        );

        assert!(matches!(outcome.result, Err(AppError::Forbidden(_))));
        assert_eq!(outcome.schema, None);
    }

    /// A signed-out caller receives an unauthenticated error when changing
    /// a topic's schema.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let outcome = change(
            topic_named("orders.created"),
            order_schema(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(outcome.result, Err(AppError::Unauthenticated)));
    }

    /// Ann names a topic the tenant does not have. It is not found.
    #[test]
    fn an_unknown_topic_is_not_found() {
        let use_case = ChangeSchemaUseCase::new(ChangeSchemaPorts {
            topic_store: Arc::new(FakeTopicStore::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        let req = ChangeSchemaRequest {
            topic_id: TopicId::new(),
            schema: order_schema(),
        };
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit), req));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
