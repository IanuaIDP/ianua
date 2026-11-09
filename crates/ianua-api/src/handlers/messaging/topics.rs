//! Topic handlers: a tenant's named message channels and how each works.

use axum::extract::{Path, State};
use ianua_app::ports::messaging::TopicSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::messaging::topics::{CreateRequest, ListRequest};
use ianua_assembly::messaging::MessagingState;

use crate::dto::messaging::{
    ChangeTopicRetentionBody, ChangeTopicSchemaBody, CreateTopicBody, CreateTopicResponse,
    RaiseTopicDataClassBody, TopicResponse,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::messaging::TenantMessenger;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::messaging::TopicPath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics",
    tag = "Messaging",
    request_body = CreateTopicBody,
    responses(
        (status = 201, description = "Created", body = CreateTopicResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 409, description = "Conflict", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a messaging topic
///
/// Creates a named message channel of the tenant in `Active` status, which
/// services publish to and subscribe to. `topic_name` is the
/// machine-readable routing key (such as `orders.created`); `retention`
/// says how long messages are kept (`{"Duration": seconds}`,
/// `{"MessageCount": n}` or `"Unlimited"`, never zero); `data_class` is the
/// most sensitive data it may carry (`Internal` when left out). An optional
/// JSON `schema` documents the expected message shape. The creator is the
/// person calling. Returns the new topic's `id`. Records
/// `messaging.topic_created`.
///
/// `409` if the topic name is taken, `422` for an invalid name, topic name,
/// description, schema or retention. Requires the right to create in
/// messaging.
pub(crate) async fn create_topic(
    State(messaging): State<MessagingState>,
    messenger: TenantMessenger,
    Json(body): Json<CreateTopicBody>,
) -> Result<Created<CreateTopicResponse>, ApiError> {
    let request = CreateRequest::try_from(body)?;
    let id = messaging
        .create_topic
        .execute(&messenger.caller, &messenger.auditor, request)
        .await?;
    Ok(Created(CreateTopicResponse { id: *id.as_uuid() }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics",
    tag = "Messaging",
    params(SortQuery<TopicSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<TopicResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List messaging topics
///
/// Returns every topic the tenant owns, sortable (see the `sort`
/// parameter) and paginated. Each entry carries the human-readable `name`,
/// the machine `topic_name` the publish and stream endpoints address it by,
/// the `retention` policy, an optional JSON `schema`, its `data_class` and
/// the lifecycle `status` (`Active`, `Paused` or `Archived`). Read-only.
/// Requires the right to view messaging.
pub(crate) async fn list_topics(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<TopicSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<TopicResponse>>, ApiError> {
    let request = ListRequest {
        sort,
        page: pagination,
    };
    let page = messaging
        .list_topics
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(page, TopicResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{id}",
    tag = "Messaging",
    responses(
        (status = 200, description = "Success", body = TopicResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
/// Get a messaging topic
///
/// Returns a single topic by `id`, with its `topic_name`, `retention`,
/// optional `schema`, `data_class`, lifecycle `status`, creator and
/// timestamps. The `status` says what the topic accepts: only an `Active`
/// topic takes messages and live streams. `404` if the tenant has no such
/// topic. Read-only. Requires the right to view messaging.
pub(crate) async fn get_topic(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<TopicPath>,
) -> Result<Json<TopicResponse>, ApiError> {
    let topic = messaging
        .get_topic
        .execute(&tenant.caller, path.topic())
        .await?;
    Ok(Json(TopicResponse::from(topic)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{id}",
    tag = "Messaging",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Still active", body = ErrorBody)
    )
)]
/// Delete a topic
///
/// Removes a topic for good, with every subscription to it and the bus
/// consumers they read through. The topic must not be `Active`: pause or
/// archive it first (`409` while it is). Records `messaging.topic_deleted`.
/// `404` if it does not exist. Requires the right to delete in messaging.
pub(crate) async fn delete_topic(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<TopicPath>,
) -> Result<NoContent, ApiError> {
    messaging
        .delete_topic
        .execute(&tenant.caller, &tenant.auditor, path.topic())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{id}/pause",
    tag = "Messaging",
    responses(
        (status = 204, description = "Paused"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not active", body = ErrorBody)
    )
)]
/// Pause a topic
///
/// Pauses an `Active` topic: it refuses new messages until it is resumed,
/// and its subscriptions are kept. Records `messaging.topic_paused`. `404`
/// if it does not exist, `422` unless it is active. Requires the right to
/// manage messaging.
pub(crate) async fn pause_topic(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<TopicPath>,
) -> Result<NoContent, ApiError> {
    messaging
        .pause_topic
        .execute(&tenant.caller, &tenant.auditor, path.topic())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{id}/resume",
    tag = "Messaging",
    responses(
        (status = 204, description = "Resumed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Not paused", body = ErrorBody)
    )
)]
/// Resume a topic
///
/// Resumes a `Paused` topic, so it takes messages again. Records
/// `messaging.topic_resumed`. `404` if it does not exist, `422` unless it
/// is paused. Requires the right to manage messaging.
pub(crate) async fn resume_topic(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<TopicPath>,
) -> Result<NoContent, ApiError> {
    messaging
        .resume_topic
        .execute(&tenant.caller, &tenant.auditor, path.topic())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{id}/archive",
    tag = "Messaging",
    responses(
        (status = 204, description = "Archived"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already archived", body = ErrorBody)
    )
)]
/// Archive a topic
///
/// Archives an active or paused topic: it is read-only for good, takes no
/// new messages or subscriptions, and can then be deleted. Records
/// `messaging.topic_archived`. `404` if it does not exist, `422` if it is
/// already archived. Requires the right to delete in messaging.
pub(crate) async fn archive_topic(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<TopicPath>,
) -> Result<NoContent, ApiError> {
    messaging
        .archive_topic
        .execute(&tenant.caller, &tenant.auditor, path.topic())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{id}/schema",
    tag = "Messaging",
    request_body = ChangeTopicSchemaBody,
    responses(
        (status = 204, description = "Changed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Archived, or an invalid schema", body = ErrorBody)
    )
)]
/// Change a topic's schema
///
/// Replaces the JSON `schema` messages on the topic are checked against, or
/// clears it with `null`. Records `messaging.topic_schema_changed`, naming
/// the topic but not the schema. `404` if the topic does not exist, `422`
/// when it is archived or the schema is blank or too large. Requires the
/// right to manage messaging.
pub(crate) async fn change_topic_schema(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<TopicPath>,
    Json(body): Json<ChangeTopicSchemaBody>,
) -> Result<NoContent, ApiError> {
    messaging
        .change_topic_schema
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.topic())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{id}/retention",
    tag = "Messaging",
    request_body = ChangeTopicRetentionBody,
    responses(
        (status = 204, description = "Changed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Archived, or an invalid policy", body = ErrorBody)
    )
)]
/// Change a topic's retention
///
/// Replaces how long the topic keeps messages (`{"Duration": seconds}`,
/// `{"MessageCount": n}` or `"Unlimited"`, never zero). A shorter policy
/// drops messages subscribers have not read, so
/// `messaging.topic_retention_changed` records the policy before and after.
/// `404` if the topic does not exist, `422` when it is archived or the
/// policy is invalid. Requires the right to manage messaging.
pub(crate) async fn change_topic_retention(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<TopicPath>,
    Json(body): Json<ChangeTopicRetentionBody>,
) -> Result<NoContent, ApiError> {
    messaging
        .change_topic_retention
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.topic()),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/messaging/topics/{id}/data-class",
    tag = "Messaging",
    request_body = RaiseTopicDataClassBody,
    responses(
        (status = 204, description = "Raised"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or below the current class", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Archived", body = ErrorBody)
    )
)]
/// Raise a topic's data class
///
/// Raises the most sensitive data the topic may carry. A class only goes
/// up: one below the current class is refused (`403`). Subscribers cleared
/// below the new class stop hearing it, so
/// `messaging.topic_data_class_raised` records the class before and after.
/// `404` if the topic does not exist, `422` when it is archived. Requires
/// the right to manage messaging.
pub(crate) async fn raise_topic_data_class(
    State(messaging): State<MessagingState>,
    tenant: TenantCaller,
    Path(path): Path<TopicPath>,
    Json(body): Json<RaiseTopicDataClassBody>,
) -> Result<NoContent, ApiError> {
    messaging
        .raise_topic_data_class
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.change_of(path.topic()),
        )
        .await?;
    Ok(NoContent)
}
