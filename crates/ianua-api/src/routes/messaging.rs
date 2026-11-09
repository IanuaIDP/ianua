//! Messaging endpoints: a tenant's topics, subscriptions and schemas, and
//! publishing, pulling and watching messages.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::messaging::{
    ChangeTopicRetentionBody, ChangeTopicSchemaBody, CreateSubscriptionBody,
    CreateSubscriptionResponse, CreateTopicBody, CreateTopicResponse, DeadLetterResponse,
    EvolveSchemaBody, EvolveSchemaResponse, HeaderPair, MessageResponse, NackResponse,
    PublishMessageBody, RaiseTopicDataClassBody, ReceiptBody, RegisterSchemaBody,
    RegisterSchemaResponse, RotatePushSecretBody, RotatePushSecretResponse, SchemaResponse,
    SchemaVersionResponse, SubscriptionResponse, TopicResponse,
};
use crate::handlers::messaging::{broker, schemas, subscriptions, topics};
use crate::method::{delete, get, post, put, shared};
use crate::state::ApiState;

/// The messaging endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let base = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging";
    topic_routes(base)
        .merge(topic_settings_routes(base))
        .merge(subscription_routes(base))
        .merge(delivery_routes(base))
        .merge(schema_routes(base))
}

/// Registers topic creation, inspection and lifecycle changes.
fn topic_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/topics"),
            post(topics::create_topic).get(shared(topics::list_topics)),
        )
        .route(
            &format!("{base}/topics/{{id}}"),
            get(topics::get_topic).delete(shared(topics::delete_topic)),
        )
        .route(
            &format!("{base}/topics/{{id}}/pause"),
            post(topics::pause_topic),
        )
        .route(
            &format!("{base}/topics/{{id}}/resume"),
            post(topics::resume_topic),
        )
        .route(
            &format!("{base}/topics/{{id}}/archive"),
            post(topics::archive_topic),
        )
}

/// Registers topic settings and producer operations.
fn topic_settings_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/topics/{{id}}/schema"),
            put(topics::change_topic_schema),
        )
        .route(
            &format!("{base}/topics/{{id}}/retention"),
            put(topics::change_topic_retention),
        )
        .route(
            &format!("{base}/topics/{{id}}/data-class"),
            put(topics::raise_topic_data_class),
        )
        .route(
            &format!("{base}/topics/{{name}}/publish"),
            post(broker::publish_message),
        )
        .route(
            &format!("{base}/topics/{{name}}/stream"),
            get(broker::stream_topic),
        )
}

/// Registers subscription lifecycle and push credentials.
fn subscription_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/subscriptions"),
            post(subscriptions::create_subscription).get(shared(subscriptions::list_subscriptions)),
        )
        .route(
            &format!("{base}/subscriptions/{{id}}"),
            delete(subscriptions::delete_subscription),
        )
        .route(
            &format!("{base}/subscriptions/{{id}}/pause"),
            post(subscriptions::pause_subscription),
        )
        .route(
            &format!("{base}/subscriptions/{{id}}/resume"),
            post(subscriptions::resume_subscription),
        )
        .route(
            &format!("{base}/subscriptions/{{id}}/rotate-push-secret"),
            post(subscriptions::rotate_push_secret),
        )
}

/// Registers pull acknowledgements and dead-letter recovery.
fn delivery_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/subscriptions/{{id}}/messages"),
            get(broker::pull_messages),
        )
        .route(
            &format!("{base}/subscriptions/{{id}}/messages/ack"),
            post(broker::ack_message),
        )
        .route(
            &format!("{base}/subscriptions/{{id}}/messages/nack"),
            post(broker::nack_message),
        )
        .route(
            &format!("{base}/subscriptions/{{id}}/dead-letters"),
            get(broker::list_dead_letters),
        )
        .route(
            &format!("{base}/subscriptions/{{id}}/dead-letters/{{dead_letter_id}}/replay"),
            post(broker::replay_dead_letter),
        )
}

/// Registers schema declarations and versions used by topics.
fn schema_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/schemas"),
            post(schemas::register_schema).get(shared(schemas::list_schemas)),
        )
        .route(
            &format!("{base}/schemas/{{id}}"),
            get(schemas::get_schema).delete(shared(schemas::delete_schema)),
        )
        .route(
            &format!("{base}/schemas/{{id}}/versions"),
            post(schemas::evolve_schema),
        )
}

/// The messaging part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        topics::create_topic,
        topics::list_topics,
        topics::get_topic,
        topics::delete_topic,
        topics::pause_topic,
        topics::resume_topic,
        topics::archive_topic,
        topics::change_topic_schema,
        topics::change_topic_retention,
        topics::raise_topic_data_class,
        broker::publish_message,
        broker::pull_messages,
        broker::ack_message,
        broker::nack_message,
        broker::list_dead_letters,
        broker::replay_dead_letter,
        broker::stream_topic,
        subscriptions::create_subscription,
        subscriptions::list_subscriptions,
        subscriptions::delete_subscription,
        subscriptions::pause_subscription,
        subscriptions::resume_subscription,
        subscriptions::rotate_push_secret,
        schemas::register_schema,
        schemas::list_schemas,
        schemas::get_schema,
        schemas::evolve_schema,
        schemas::delete_schema,
    ),
    components(schemas(
        CreateTopicBody,
        CreateTopicResponse,
        TopicResponse,
        ChangeTopicSchemaBody,
        ChangeTopicRetentionBody,
        RaiseTopicDataClassBody,
        PublishMessageBody,
        HeaderPair,
        MessageResponse,
        ReceiptBody,
        NackResponse,
        DeadLetterResponse,
        CreateSubscriptionBody,
        CreateSubscriptionResponse,
        SubscriptionResponse,
        RotatePushSecretBody,
        RotatePushSecretResponse,
        RegisterSchemaBody,
        RegisterSchemaResponse,
        EvolveSchemaBody,
        EvolveSchemaResponse,
        SchemaResponse,
        SchemaVersionResponse,
    ))
)]
pub(crate) struct Document;
