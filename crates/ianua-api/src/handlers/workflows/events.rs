//! Service event handlers: what integrations' services send the workflows
//! registered for their events, at a registration's own address or at the
//! one address an integration's app receives every event at.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::workflows::executions::DeliveredTo;
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::events::{answered, delivered};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::paths::workflows::{ChannelPath, IntegrationEventsPath, SubscriptionPath};
use crate::extractors::workflows::ServiceDelivery;

#[utoipa::path(
    post,
    path = "/api/v1/integrations/events/{subscription_id}",
    tag = "Workflows",
    request_body(content = String, description = "The service's delivery, byte for byte, signed the way the service signs", content_type = "application/json"),
    responses(
        (status = 200, description = "The proof the service asked for, to show the platform holds the address"),
        (status = 204, description = "Taken, or the service's secret kept"),
        (status = 401, description = "No such registration, or the signature does not check out", body = ErrorBody),
        (status = 409, description = "The registration is no longer in service", body = ErrorBody)
    )
)]
/// Receive a service's event
///
/// Where a service sends the events a workflow is registered for, at the
/// address its registration was given when the workflow was published.
/// Nobody signs in: the service's signature with the registration's
/// secret is checked before anything else is read. A delivery that is the
/// trigger's event, and passes its filters, starts the version in service
/// for its publisher; a delivery the service sends again starts nothing
/// twice; anything else is taken and starts nothing. `401` alike for an
/// unknown registration and a forged or unsigned delivery, and `409` once
/// the registration is no longer in service, so the service stops. Records
/// `workflows.execution_started`, or `workflows.start_refused` when the
/// publisher may not have it start now. Public.
pub(crate) async fn receive_event(
    State(workflows): State<WorkflowState>,
    Path(path): Path<SubscriptionPath>,
    delivery: ServiceDelivery,
) -> Result<Response, ApiError> {
    let (request, auditor) = delivered(DeliveredTo::Registration(path.subscription()), delivery);
    let answer = workflows
        .start_on_service_event
        .execute(&(), &auditor, request)
        .await?;
    Ok(answered(answer))
}

#[utoipa::path(
    post,
    path = "/api/v1/integrations/events/channels/{channel_id}",
    tag = "Workflows",
    request_body(content = String, description = "The service's delivery, byte for byte, signed the way the service signs", content_type = "application/json"),
    responses(
        (status = 200, description = "The proof the service asked for, to show the platform holds the address"),
        (status = 204, description = "Taken, or the service's token kept"),
        (status = 401, description = "No such channel, it is not live, or the delivery is not proven", body = ErrorBody),
        (status = 502, description = "What the delivery announced could not be read from the service, so it should be sent again", body = ErrorBody)
    )
)]
/// Receive a service's event for one account
///
/// Where a service with one address per account sends its events. Nobody
/// signs in. The delivery is proven once, with what the channel holds,
/// then read for every workflow waiting on that account, each started as
/// at a registration's own address. Until the channel is live nothing is
/// read, apart from the service's own check of the address. Public.
pub(crate) async fn receive_channel_event(
    State(workflows): State<WorkflowState>,
    Path(path): Path<ChannelPath>,
    delivery: ServiceDelivery,
) -> Result<Response, ApiError> {
    let (request, auditor) = delivered(DeliveredTo::Channel(path.channel()), delivery);
    let answer = workflows
        .start_on_service_event
        .execute(&(), &auditor, request)
        .await?;
    Ok(answered(answer))
}

#[utoipa::path(
    head,
    path = "/api/v1/integrations/events/{subscription_id}",
    tag = "Workflows",
    responses(
        (status = 200, description = "The address is served")
    )
)]
/// Check a service's event address
///
/// Answers that the address takes events, as Trello asks with a `HEAD`
/// request before it takes a webhook, which arrives while the
/// registration is still being made. It answers the same for every
/// address, so it says nothing of which registrations exist, and reads
/// and starts nothing. Public.
pub(crate) async fn address_served() -> StatusCode {
    StatusCode::OK
}

#[utoipa::path(
    post,
    path = "/api/v1/integrations/{integration}/events",
    tag = "Workflows",
    request_body(content = String, description = "The service's delivery, byte for byte, signed with the deployment's app secret", content_type = "application/json"),
    responses(
        (status = 200, description = "The proof the service asked for, to show the platform holds the address"),
        (status = 204, description = "Taken"),
        (status = 401, description = "Not signed with the deployment's app secret, or not an integration", body = ErrorBody)
    )
)]
/// Receive a service's event for the deployment's app
///
/// Where a service that sends every event of the deployment's app to one
/// address sends them, such as Slack's Events API. The signature with the
/// app's secret is checked first, then the event goes to each registration
/// for the workspace or site it names, each checked and started as at a
/// registration's own address. A service's request to prove the platform
/// holds the address is answered. Public.
pub(crate) async fn receive_app_event(
    State(workflows): State<WorkflowState>,
    Path(path): Path<IntegrationEventsPath>,
    delivery: ServiceDelivery,
) -> Result<Response, ApiError> {
    let (request, auditor) = delivered(DeliveredTo::Integration(path.integration()?), delivery);
    let answer = workflows
        .start_on_service_event
        .execute(&(), &auditor, request)
        .await?;
    Ok(answered(answer))
}
