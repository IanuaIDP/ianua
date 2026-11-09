//! The messaging use cases the API serves: a tenant's topics, schemas and
//! subscriptions, publishing, pulling and settling what was pulled, dead
//! letters, push secrets, and watching a topic live.

use std::sync::Arc;

use ianua_app::ports::realtime::NotificationSubscriber;
use ianua_app::use_cases::messaging::{broker, schemas, subscriptions, topics};

use crate::deps::Adapters;

/// The messaging use cases, and what a live topic stream listens through.
#[derive(Clone)]
pub struct MessagingState {
    pub create_topic: Arc<topics::CreateUseCase>,
    pub list_topics: Arc<topics::ListUseCase>,
    pub get_topic: Arc<topics::GetUseCase>,
    pub delete_topic: Arc<topics::DeleteUseCase>,
    pub pause_topic: Arc<topics::PauseUseCase>,
    pub resume_topic: Arc<topics::ResumeUseCase>,
    pub archive_topic: Arc<topics::ArchiveUseCase>,
    pub change_topic_schema: Arc<topics::ChangeSchemaUseCase>,
    pub change_topic_retention: Arc<topics::ChangeRetentionUseCase>,
    pub raise_topic_data_class: Arc<topics::RaiseDataClassUseCase>,
    pub publish_message: Arc<broker::PublishMessageUseCase>,
    pub pull_messages: Arc<broker::PullMessagesUseCase>,
    pub ack_message: Arc<broker::AckMessageUseCase>,
    pub nack_message: Arc<broker::NackMessageUseCase>,
    pub list_dead_letters: Arc<broker::ListDeadLettersUseCase>,
    pub replay_dead_letter: Arc<broker::ReplayDeadLetterUseCase>,
    pub stream_topic: Arc<broker::StreamTopicUseCase>,
    pub create_subscription: Arc<subscriptions::CreateUseCase>,
    pub list_subscriptions: Arc<subscriptions::ListUseCase>,
    pub delete_subscription: Arc<subscriptions::DeleteUseCase>,
    pub pause_subscription: Arc<subscriptions::PauseUseCase>,
    pub resume_subscription: Arc<subscriptions::ResumeUseCase>,
    pub rotate_push_secret: Arc<subscriptions::RotatePushSecretUseCase>,
    pub register_schema: Arc<schemas::RegisterUseCase>,
    pub list_schemas: Arc<schemas::ListUseCase>,
    pub get_schema: Arc<schemas::GetUseCase>,
    pub evolve_schema: Arc<schemas::EvolveUseCase>,
    pub delete_schema: Arc<schemas::DeleteUseCase>,
    /// Hands a live topic stream the messages broadcast on its subject.
    pub live: Arc<dyn NotificationSubscriber>,
}

/// Builds the messaging use cases over `a`.
/// The exhaustive public state has 29 fields; construction stays in the helpers below.
#[allow(clippy::too_many_lines)]
pub fn build(a: &Adapters) -> MessagingState {
    MessagingState {
        create_topic: Arc::new(create_topic(a)),
        list_topics: Arc::new(list_topics(a)),
        get_topic: Arc::new(get_topic(a)),
        delete_topic: Arc::new(delete_topic(a)),
        pause_topic: Arc::new(pause_topic(a)),
        resume_topic: Arc::new(resume_topic(a)),
        archive_topic: Arc::new(archive_topic(a)),
        change_topic_schema: Arc::new(change_topic_schema(a)),
        change_topic_retention: Arc::new(change_topic_retention(a)),
        raise_topic_data_class: Arc::new(raise_topic_data_class(a)),
        publish_message: Arc::new(publish_message(a)),
        pull_messages: Arc::new(pull_messages(a)),
        ack_message: Arc::new(ack_message(a)),
        nack_message: Arc::new(nack_message(a)),
        list_dead_letters: Arc::new(list_dead_letters(a)),
        replay_dead_letter: Arc::new(replay_dead_letter(a)),
        stream_topic: Arc::new(stream_topic(a)),
        create_subscription: Arc::new(create_subscription(a)),
        list_subscriptions: Arc::new(list_subscriptions(a)),
        delete_subscription: Arc::new(delete_subscription(a)),
        pause_subscription: Arc::new(pause_subscription(a)),
        resume_subscription: Arc::new(resume_subscription(a)),
        rotate_push_secret: Arc::new(rotate_push_secret(a)),
        register_schema: Arc::new(register_schema(a)),
        list_schemas: Arc::new(list_schemas(a)),
        get_schema: Arc::new(get_schema(a)),
        evolve_schema: Arc::new(evolve_schema(a)),
        delete_schema: Arc::new(delete_schema(a)),
        live: a.notification_subscriber.clone(),
    }
}

/// Creates topics under tenant or consumer authority.
fn create_topic(a: &Adapters) -> topics::CreateUseCase {
    topics::CreateUseCase::new(topics::CreatePorts {
        topic_store: a.topic_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumers: a.consumer_authorities.clone(),
    })
}

/// Lists the topics visible through the caller's tenant authority.
fn list_topics(a: &Adapters) -> topics::ListUseCase {
    topics::ListUseCase::new(topics::ListPorts {
        topic_store: a.topic_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Reads a topic under tenant authority.
fn get_topic(a: &Adapters) -> topics::GetUseCase {
    topics::GetUseCase::new(topics::GetPorts {
        topic_store: a.topic_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Deletes topics with access to their subscriptions and broker consumers.
fn delete_topic(a: &Adapters) -> topics::DeleteUseCase {
    topics::DeleteUseCase::new(topics::DeletePorts {
        topic_store: a.topic_store.clone(),
        subscription_store: a.subscription_store.clone(),
        message_consumer: a.message_consumer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Pauses a topic through tenant authority checks.
fn pause_topic(a: &Adapters) -> topics::PauseUseCase {
    topics::PauseUseCase::new(topics::PausePorts {
        topic_store: a.topic_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Resumes a topic through tenant authority checks.
fn resume_topic(a: &Adapters) -> topics::ResumeUseCase {
    topics::ResumeUseCase::new(topics::ResumePorts {
        topic_store: a.topic_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Archives a topic through tenant authority checks.
fn archive_topic(a: &Adapters) -> topics::ArchiveUseCase {
    topics::ArchiveUseCase::new(topics::ArchivePorts {
        topic_store: a.topic_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes a topic's schema under tenant authority.
fn change_topic_schema(a: &Adapters) -> topics::ChangeSchemaUseCase {
    topics::ChangeSchemaUseCase::new(topics::ChangeSchemaPorts {
        topic_store: a.topic_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Changes a topic's retention policy under tenant authority.
fn change_topic_retention(a: &Adapters) -> topics::ChangeRetentionUseCase {
    topics::ChangeRetentionUseCase::new(topics::ChangeRetentionPorts {
        topic_store: a.topic_store.clone(),
        message_consumer: a.message_consumer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Raises a topic's classification under tenant authority.
fn raise_topic_data_class(a: &Adapters) -> topics::RaiseDataClassUseCase {
    topics::RaiseDataClassUseCase::new(topics::RaiseDataClassPorts {
        topic_store: a.topic_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Publishes authorized messages to the broker and live subscribers.
fn publish_message(a: &Adapters) -> broker::PublishMessageUseCase {
    broker::PublishMessageUseCase::new(broker::PublishMessagePorts {
        topic_store: a.topic_store.clone(),
        message_publisher: a.message_publisher.clone(),
        broadcaster: a.notification_publisher.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumers: a.consumer_authorities.clone(),
    })
}

/// Pulls subscription messages after tenant or consumer authorization.
fn pull_messages(a: &Adapters) -> broker::PullMessagesUseCase {
    broker::PullMessagesUseCase::new(broker::PullMessagesPorts {
        subscription_store: a.subscription_store.clone(),
        topic_store: a.topic_store.clone(),
        message_consumer: a.message_consumer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumers: a.consumer_authorities.clone(),
    })
}

/// Acknowledges deliveries through their subscription and broker consumer.
fn ack_message(a: &Adapters) -> broker::AckMessageUseCase {
    broker::AckMessageUseCase::new(broker::AckMessagePorts {
        subscription_store: a.subscription_store.clone(),
        message_consumer: a.message_consumer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumers: a.consumer_authorities.clone(),
    })
}

/// Rejects deliveries through their subscription and broker consumer.
fn nack_message(a: &Adapters) -> broker::NackMessageUseCase {
    broker::NackMessageUseCase::new(broker::NackMessagePorts {
        subscription_store: a.subscription_store.clone(),
        message_consumer: a.message_consumer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumers: a.consumer_authorities.clone(),
    })
}

/// Reads failed deliveries with their subscription and topic authority checks.
fn list_dead_letters(a: &Adapters) -> broker::ListDeadLettersUseCase {
    broker::ListDeadLettersUseCase::new(broker::ListDeadLettersPorts {
        subscription_store: a.subscription_store.clone(),
        topic_store: a.topic_store.clone(),
        dead_letters: a.dead_letters.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumers: a.consumer_authorities.clone(),
    })
}

/// Replays failed deliveries through the authorized subscription.
fn replay_dead_letter(a: &Adapters) -> broker::ReplayDeadLetterUseCase {
    broker::ReplayDeadLetterUseCase::new(broker::ReplayDeadLetterPorts {
        subscription_store: a.subscription_store.clone(),
        topic_store: a.topic_store.clone(),
        dead_letters: a.dead_letters.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumers: a.consumer_authorities.clone(),
    })
}

/// Authorizes live topic streaming for tenants and consumers.
fn stream_topic(a: &Adapters) -> broker::StreamTopicUseCase {
    broker::StreamTopicUseCase::new(broker::StreamTopicPorts {
        topic_store: a.topic_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumers: a.consumer_authorities.clone(),
    })
}

/// Creates subscriptions with broker consumers, encrypted secrets and plan limits.
fn create_subscription(a: &Adapters) -> subscriptions::CreateUseCase {
    subscriptions::CreateUseCase::new(subscriptions::CreatePorts {
        topic_store: a.topic_store.clone(),
        subscription_store: a.subscription_store.clone(),
        message_consumer: a.message_consumer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumer_store: a.consumer_store.clone(),
        consumers: a.consumer_authorities.clone(),
        push_secrets: a.push_secret_generator.clone(),
        encryptor: a.secret_encryptor.clone(),
        plan_limits: a.plan_limits_source.clone(),
        limit_enforcer: a.limit_enforcer.clone(),
    })
}

/// Lists subscriptions under tenant authority.
fn list_subscriptions(a: &Adapters) -> subscriptions::ListUseCase {
    subscriptions::ListUseCase::new(subscriptions::ListPorts {
        subscription_store: a.subscription_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Deletes subscriptions with access to their broker consumers.
fn delete_subscription(a: &Adapters) -> subscriptions::DeleteUseCase {
    subscriptions::DeleteUseCase::new(subscriptions::DeletePorts {
        subscription_store: a.subscription_store.clone(),
        message_consumer: a.message_consumer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Pauses subscription delivery under tenant authority.
fn pause_subscription(a: &Adapters) -> subscriptions::PauseUseCase {
    subscriptions::PauseUseCase::new(subscriptions::PausePorts {
        subscription_store: a.subscription_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Resumes subscription delivery under tenant authority.
fn resume_subscription(a: &Adapters) -> subscriptions::ResumeUseCase {
    subscriptions::ResumeUseCase::new(subscriptions::ResumePorts {
        subscription_store: a.subscription_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Generates and encrypts replacement push secrets under tenant authority.
fn rotate_push_secret(a: &Adapters) -> subscriptions::RotatePushSecretUseCase {
    subscriptions::RotatePushSecretUseCase::new(subscriptions::RotatePushSecretPorts {
        subscription_store: a.subscription_store.clone(),
        push_secrets: a.push_secret_generator.clone(),
        encryptor: a.secret_encryptor.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Registers schemas under tenant or consumer authority.
fn register_schema(a: &Adapters) -> schemas::RegisterUseCase {
    schemas::RegisterUseCase::new(schemas::RegisterPorts {
        schema_store: a.schema_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        consumers: a.consumer_authorities.clone(),
    })
}

/// Lists schemas under tenant authority.
fn list_schemas(a: &Adapters) -> schemas::ListUseCase {
    schemas::ListUseCase::new(schemas::ListPorts {
        schema_store: a.schema_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Reads a schema under tenant authority.
fn get_schema(a: &Adapters) -> schemas::GetUseCase {
    schemas::GetUseCase::new(schemas::GetPorts {
        schema_store: a.schema_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Evolves a schema under tenant authority.
fn evolve_schema(a: &Adapters) -> schemas::EvolveUseCase {
    schemas::EvolveUseCase::new(schemas::EvolvePorts {
        schema_store: a.schema_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Deletes a schema under tenant authority.
fn delete_schema(a: &Adapters) -> schemas::DeleteUseCase {
    schemas::DeleteUseCase::new(schemas::DeletePorts {
        schema_store: a.schema_store.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}
