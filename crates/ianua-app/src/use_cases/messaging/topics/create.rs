//! Create topic: register a new messaging topic within a tenant.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::messaging::schema::SchemaDefinition;
use ianua_domain::domains::messaging::topic::{CreateTopicParams, RetentionPolicy, Topic};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, Setting, TopicId};

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::TopicStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};

/// Request to create a new topic.
pub struct CreateRequest {
    /// Human-readable display name.
    pub name: Label,
    /// Machine-readable topic name.
    pub topic_name: TopicName,
    /// Optional description.
    pub description: Option<Label>,
    /// The JSON schema messages are checked against, if any.
    pub schema: Setting<SchemaDefinition>,
    /// Message retention policy.
    pub retention: RetentionPolicy,
    /// The most sensitive data the topic may carry.
    pub data_class: DataClassLevel,
}

/// Ports needed by the create topic use case.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Port for topic persistence.
    pub topic_store: Arc<dyn TopicStore>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// What a consumer's roles give it, once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
}

/// Registers a named message destination within the caller's tenant.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// Refuses a topic name the tenant already uses.
    ///
    /// # Errors
    ///
    /// - `AppError::Conflict` if the name is taken.
    /// - `AppError::Internal` on storage failure.
    async fn ensure_name_free(
        &self,
        tenant: &ScopedTenant,
        topic_name: &TopicName,
    ) -> Result<(), AppError> {
        let existing = self
            .ports
            .topic_store
            .find_by_name(tenant, topic_name)
            .await
            .or_internal()?;
        if existing.is_some() {
            return Err(AppError::Conflict(message!(
                "messaging-topic-already-exists",
                format!("topic '{topic_name}' already exists")
            )));
        }
        Ok(())
    }
}

impl Command for CreateUseCase {
    type Caller = MessagingCaller;
    type Input = CreateRequest;
    type Output = Result<TopicId, AppError>;

    /// Creates a topic within the tenant, recording the person or consumer
    /// who made it. Records `messaging.topic_created`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or consumer
    ///   credential no longer counts.
    /// - `AppError::Forbidden` when the person, or the consumer's roles, do
    ///   not give the right to create in messaging.
    /// - `AppError::Conflict` if a topic with the same name already exists.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        auditor: &RequestAuditor,
        req: CreateRequest,
    ) -> Result<TopicId, AppError> {
        let tenant = caller.tenant();
        let actor = MessagingActor::of(
            caller,
            self.ports.tenant_authorities.as_ref(),
            self.ports.consumers.as_ref(),
        )
        .await?;
        actor.ensure_holds(SystemPermission::Messaging(MessagingAction::Create))?;
        self.ensure_name_free(&tenant, &req.topic_name).await?;
        let mut topic = actor.creating(|creator| Topic::create(topic_params(req), creator))?;

        self.ports
            .topic_store
            .save(&tenant, &topic)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&topic.created_by().actor(), topic.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(*topic.id())
    }
}

fn topic_params(req: CreateRequest) -> CreateTopicParams {
    CreateTopicParams {
        name: req.name,
        topic_name: req.topic_name,
        description: req.description,
        schema: req.schema,
        retention: req.retention,
        data_class: req.data_class,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::messaging::control::CreatedBy;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::TokenHash;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{billing_sync, key_caller, sign_in_of, test_key_digest};
    use crate::test_support::messaging::{FakeTopicStore, topic_named, topics_of_test_tenant};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const CREATE: SystemPermission = SystemPermission::Messaging(MessagingAction::Create);
    const PUBLISH: SystemPermission = SystemPermission::Messaging(MessagingAction::Publish);

    fn request() -> CreateRequest {
        CreateRequest {
            name: Label::new("name", "Order Events").unwrap(),
            topic_name: TopicName::new("orders.created").unwrap(),
            description: None,
            schema: Setting::Unset,
            retention: RetentionPolicy::Unlimited,
            data_class: DataClassLevel::Internal,
        }
    }

    fn person() -> MessagingCaller {
        MessagingCaller::Person(test_ctx())
    }

    fn billing_sync_with(digest: TokenHash) -> MessagingCaller {
        MessagingCaller::Consumer(key_caller(digest))
    }

    fn use_case_over(store: Arc<FakeTopicStore>) -> CreateUseCase {
        CreateUseCase::new(CreatePorts {
            topic_store: store,
            ..CreatePorts::fakes()
        })
    }

    fn consumer_holding(store: Arc<FakeTopicStore>, held: &[SystemPermission]) -> CreateUseCase {
        CreateUseCase::new(CreatePorts {
            topic_store: store,
            consumers: sign_in_of(billing_sync(), held),
            ..CreatePorts::fakes()
        })
    }

    fn run(
        use_case: &CreateUseCase,
        caller: &MessagingCaller,
        req: CreateRequest,
    ) -> (Result<TopicId, AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(caller, &test_auditor(audit.clone()), req));
        (result, audit)
    }

    fn stored(store: &FakeTopicStore, id: &TopicId) -> Topic<ResolvedTenant> {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
    }

    /// Ann creates `orders.created`. It is kept, names her as its creator,
    /// and the creation is on record.
    #[test]
    fn a_person_creates_a_topic_and_it_is_recorded() {
        let store = Arc::new(FakeTopicStore::empty());

        let (result, audit) = run(&use_case_over(store.clone()), &person(), request());

        let topic = stored(&store, &result.unwrap());
        assert!(matches!(topic.created_by(), CreatedBy::Person(_)));
        assert_eq!(audit.records.lock().unwrap()[0], "messaging.topic_created");
    }

    /// "billing-sync" holds a role that may create in messaging. It creates
    /// a topic with its own key, and the topic names it as its creator.
    #[test]
    fn a_consumer_creates_a_topic_of_its_own() {
        let store = Arc::new(FakeTopicStore::empty());
        let consumer = billing_sync();
        let id = *consumer.id();
        let use_case = CreateUseCase::new(CreatePorts {
            topic_store: store.clone(),
            consumers: sign_in_of(consumer, &[CREATE]),
            ..CreatePorts::fakes()
        });

        let (result, _) = run(&use_case, &billing_sync_with(test_key_digest()), request());

        let topic = stored(&store, &result.unwrap());
        assert_eq!(topic.created_by(), &CreatedBy::Consumer(id));
    }

    /// A consumer with publishing rights cannot create a topic; the
    /// forbidden request saves no topic and records no event.
    #[test]
    fn a_consumer_whose_roles_only_publish_is_refused() {
        let store = Arc::new(FakeTopicStore::empty());

        let (result, audit) = run(
            &consumer_holding(store.clone(), &[PUBLISH]),
            &billing_sync_with(test_key_digest()),
            request(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A consumer presenting the wrong key receives an unauthenticated
    /// error when creating a topic, and no topic is saved.
    #[test]
    fn a_consumer_with_a_wrong_key_is_signed_out() {
        let store = Arc::new(FakeTopicStore::empty());
        let guessed = TokenHash::from_stored("guessed".to_owned());

        let (result, _) = run(
            &consumer_holding(store.clone(), &[CREATE]),
            &billing_sync_with(guessed),
            request(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 0);
    }

    /// A person with messaging view rights cannot create a topic; the
    /// forbidden request saves no topic.
    #[test]
    fn a_person_without_the_create_right_is_refused() {
        let store = Arc::new(FakeTopicStore::empty());
        let use_case = CreateUseCase::new(CreatePorts {
            topic_store: store.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Messaging(MessagingAction::View),
            ])),
            ..CreatePorts::fakes()
        });

        let (result, _) = run(&use_case, &person(), request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// A signed-out person receives an unauthenticated error when creating
    /// a topic, and no topic is saved.
    #[test]
    fn a_signed_out_person_is_refused() {
        let store = Arc::new(FakeTopicStore::empty());
        let use_case = CreateUseCase::new(CreatePorts {
            topic_store: store.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..CreatePorts::fakes()
        });

        let (result, _) = run(&use_case, &person(), request());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 0);
    }

    /// The tenant already has `orders.created`. A person who may only view
    /// messaging, naming it too, is refused for lacking the right and is
    /// not told the name is taken.
    #[test]
    fn a_taken_name_is_not_told_to_someone_without_the_create_right() {
        let store = topics_of_test_tenant(topic_named("orders.created"));
        let use_case = CreateUseCase::new(CreatePorts {
            topic_store: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Messaging(MessagingAction::View),
            ])),
            ..CreatePorts::fakes()
        });

        let (result, _) = run(&use_case, &person(), request());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// The tenant already has `orders.created`. A second topic by that name
    /// is refused as a conflict.
    #[test]
    fn a_taken_topic_name_is_a_conflict() {
        let store = topics_of_test_tenant(topic_named("orders.created"));

        let (result, _) = run(&use_case_over(store.clone()), &person(), request());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(store.count(), 1);
    }

    /// Ann creates a topic for restricted data. It keeps that class.
    #[test]
    fn a_topic_keeps_the_data_class_it_was_created_with() {
        let store = Arc::new(FakeTopicStore::empty());
        let restricted = CreateRequest {
            data_class: DataClassLevel::Restricted,
            ..request()
        };

        let (result, _) = run(&use_case_over(store.clone()), &person(), restricted);

        let topic = stored(&store, &result.unwrap());
        assert_eq!(topic.data_class(), DataClassLevel::Restricted);
    }
}
