//! Broker handlers: publishing a message to a topic, pulling from a
//! subscription and settling what was pulled, the dead letters set aside
//! and replaying them, and watching a topic live.

use axum::extract::{Path, State};
use axum::response::Response;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::messaging::broker::{
    ListDeadLettersRequest, PullMessagesRequest, StreamTopicRequest,
};
use ianua_assembly::messaging::MessagingState;

use crate::dto::messaging::{
    DeadLetterResponse, MessageResponse, NackResponse, PublishMessageBody, PullMessagesParams,
    ReceiptBody, replay_of,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::json::Json;
use crate::extractors::messaging::TenantMessenger;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::messaging::{DeadLetterPath, SubscriptionPath, TopicNamePath};
use crate::extractors::query::Query;
use crate::extractors::realtime::Handshake;
use crate::response::{NoContent, PageResponse};
use crate::state::streams::MessagingStreamState;
use crate::ws::{Admission, SubjectSubscription, TopicWatch, stream_subject};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{name}/publish",
    tag = "Messaging",
    request_body = PublishMessageBody,
    responses(
        (status = 204, description = "Published"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the topic is not active", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Publish a message to a topic
///
/// Publishes one message to the topic named by `topic_name` in the URL.
/// `payload` is base64-encoded (so any bytes travel over JSON) and decoded
/// before delivery; `headers` is an optional list of `{ key, value }` pairs
/// delivered with the message. The message fans out to every active
/// subscription (or is shared among the members of each consumer group) and
/// reaches every open live stream on the topic. Records
/// `messaging.message_published` with the payload's size, never the
/// payload.
///
/// `204` on success; the answer carries no message id. `404` if the topic
/// does not exist, `403` if it is not `Active` (paused or archived), `422`
/// for an invalid topic name, a payload that is not base64 or is larger
/// than the bus accepts, or a header the platform reserves. Requires the
/// right to publish in messaging.
pub(crate) async fn publish_message(
    State(messaging): State<MessagingState>,
    messenger: TenantMessenger,
    Path(path): Path<TopicNamePath>,
    Json(body): Json<PublishMessageBody>,
) -> Result<NoContent, ApiError> {
    let request = body.publication_to(path.topic_name()?)?;
    messaging
        .publish_message
        .execute(&messenger.caller, &messenger.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions/{id}/messages",
    tag = "Messaging",
    params(PullMessagesParams),
    responses(
        (status = 200, description = "Success", body = Vec<MessageResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the subscription is paused", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Pull messages from a subscription
///
/// Polls a `Pull` subscription for waiting messages and returns up to
/// `max_messages` of them (default `10`, at most `100`), each with its
/// base64-encoded `payload`, its `headers`, the `receipt` that settles it
/// and how often it was `delivered`. `Push` subscriptions deliver to the
/// service instead and are not read here.
///
/// Nothing is taken until it is acknowledged: hand each `receipt` to `ack`
/// once it is handled, or to `nack` to have it delivered again at once. A
/// message not acknowledged within the subscription's deadline comes round
/// again, and one whose deliveries ran out is set aside as a dead letter
/// instead of handed out.
///
/// Pulling hands out the service's messages, so it needs the right to
/// consume, not only to view. The topic's class is checked against the
/// caller's clearance on every pull (`403` when above it, or while the
/// subscription is paused). `404` if the subscription does not exist.
pub(crate) async fn pull_messages(
    State(messaging): State<MessagingState>,
    messenger: TenantMessenger,
    Path(path): Path<SubscriptionPath>,
    Query(params): Query<PullMessagesParams>,
) -> Result<Json<Vec<MessageResponse>>, ApiError> {
    let request = PullMessagesRequest {
        subscription_id: path.subscription(),
        max_messages: params.max(),
    };
    let messages = messaging
        .pull_messages
        .execute(&messenger.caller, request)
        .await?;
    Ok(Json(
        messages.into_iter().map(MessageResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions/{id}/messages/ack",
    tag = "Messaging",
    request_body = ReceiptBody,
    responses(
        (status = 204, description = "Acknowledged"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such subscription, or the delivery no longer waits", body = ErrorBody)
    )
)]
/// Acknowledge a pulled message
///
/// Hands back the `receipt` a pull gave out with a message, once the
/// service handled it: the message is taken and never delivered again.
/// `404` when the delivery no longer waits: already settled, past its
/// deadline (it comes round again), or never this subscription's. Nothing
/// is recorded: acknowledging is the message flow itself. Requires the
/// right to consume in messaging.
pub(crate) async fn ack_message(
    State(messaging): State<MessagingState>,
    messenger: TenantMessenger,
    Path(path): Path<SubscriptionPath>,
    Json(body): Json<ReceiptBody>,
) -> Result<NoContent, ApiError> {
    messaging
        .ack_message
        .execute(&messenger.caller, body.ack_of(path.subscription()))
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions/{id}/messages/nack",
    tag = "Messaging",
    request_body = ReceiptBody,
    responses(
        (status = 200, description = "Refused; what became of the message", body = NackResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such subscription, or the delivery no longer waits", body = ErrorBody)
    )
)]
/// Refuse a pulled message
///
/// Hands back the `receipt` of a message the service could not handle.
/// The subscription's `max_deliveries` decides what becomes of it: the
/// answer's `fate` is `Redeliver` when it comes round again at once, or
/// `DeadLetter` when its deliveries ran out and it was set aside. `404`
/// when the delivery no longer waits. Nothing is recorded. Requires the
/// right to consume in messaging.
pub(crate) async fn nack_message(
    State(messaging): State<MessagingState>,
    messenger: TenantMessenger,
    Path(path): Path<SubscriptionPath>,
    Json(body): Json<ReceiptBody>,
) -> Result<Json<NackResponse>, ApiError> {
    let fate = messaging
        .nack_message
        .execute(&messenger.caller, body.nack_of(path.subscription()))
        .await?;
    Ok(Json(NackResponse::from(fate)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions/{id}/dead-letters",
    tag = "Messaging",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<DeadLetterResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// List a subscription's dead letters
///
/// Returns, oldest first and paginated, the messages the subscription set
/// aside once their deliveries ran out, each with its `id`, base64-encoded
/// `payload`, `headers`, how often it was `delivered` and when it was set
/// aside. They are the topic's messages, so this asks what pulling does:
/// the right to consume and clearance for the topic's class as it stands
/// now (`403` otherwise). Read-only.
pub(crate) async fn list_dead_letters(
    State(messaging): State<MessagingState>,
    messenger: TenantMessenger,
    Path(path): Path<SubscriptionPath>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<DeadLetterResponse>>, ApiError> {
    let request = ListDeadLettersRequest {
        subscription_id: path.subscription(),
        page: pagination,
    };
    let page = messaging
        .list_dead_letters
        .execute(&messenger.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        DeadLetterResponse::from,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/subscriptions/{id}/dead-letters/{dead_letter_id}/replay",
    tag = "Messaging",
    responses(
        (status = 204, description = "Put back on the subscription"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such subscription or dead letter", body = ErrorBody)
    )
)]
/// Replay a dead letter
///
/// Puts a dead letter back on this subscription alone, with a fresh count
/// of deliveries, and removes it from the dead letters; no other
/// subscription of the topic sees it twice. Records
/// `messaging.dead_letter_replayed`, since it hands the service a message
/// it once gave up on. `404` when the subscription holds no such dead
/// letter. Requires the right to consume in messaging.
pub(crate) async fn replay_dead_letter(
    State(messaging): State<MessagingState>,
    messenger: TenantMessenger,
    Path(path): Path<DeadLetterPath>,
) -> Result<NoContent, ApiError> {
    messaging
        .replay_dead_letter
        .execute(
            &messenger.caller,
            &messenger.auditor,
            replay_of(path.subscription(), path.dead_letter()),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{name}/stream",
    tag = "Messaging",
    responses(
        (status = 101, description = "WebSocket upgrade: the topic's messages as they are published"),
        (status = 400, description = "Not a WebSocket handshake"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the topic is not active", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 429, description = "Too many open streams", body = ErrorBody)
    )
)]
/// Stream a topic over WebSocket
///
/// Upgrades to a WebSocket and streams the messages published to the topic
/// named by `topic_name` in the URL as they arrive. On connect the server
/// sends a `{ "type": "connected", "subject" }` frame, then one JSON frame
/// per message. `Pull` subscriptions are the polling way to the same data.
///
/// A live stream hands over what pulling would, so it takes what pulling
/// takes: the right to consume, an `Active` topic (`403` otherwise) and
/// clearance for the topic's class. The app is asked again every little
/// while, and the stream closes on the first refusal: a raised class, a
/// paused topic or a session that stopped counting ends it. The stream also
/// ends after its lifetime, and the client connects again. `404` if the
/// topic does not exist.
pub(crate) async fn stream_topic(
    State(MessagingStreamState { messaging, gates }): State<MessagingStreamState>,
    messenger: TenantMessenger,
    Path(path): Path<TopicNamePath>,
    handshake: Handshake,
) -> Result<Response, ApiError> {
    let topic_name = path.topic_name()?;
    let request = StreamTopicRequest {
        topic_name: topic_name.clone(),
    };
    let stream = messaging
        .stream_topic
        .execute(&messenger.caller, request)
        .await?;
    let permit = gates.streams.claim(messenger.stream_owner)?;
    let subject = stream.subject().to_owned();
    let watch = TopicWatch::new(messaging.stream_topic, messenger.caller, topic_name);
    let (live, timing) = (messaging.live, gates.timing);
    Ok(handshake.accept(move |socket| async move {
        let _permit = permit;
        let subscription = SubjectSubscription::new(live, subject);
        stream_subject(socket, subscription, Admission::everything(watch), timing).await;
    }))
}
