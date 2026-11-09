//! Signal endpoints: a tenant's security signal streams and their
//! deliveries, the endpoints a stream's receiver calls (confirming its
//! endpoint, polling, verification and subjects), and the transmitter's
//! configuration.

use std::time::Duration;

use axum::Router;
use utoipa::OpenApi;

use crate::dto::signals::{
    AuthorizationScheme, ConfirmEndpointBody, DefaultSubjectsBody, PollBody, PollResponse,
    RegisterStreamBody, RegisterStreamResponse, StreamDeliveryResponse, StreamResponse,
    StreamStatusResponse, SubjectBody, SubjectIdentifierBody, SubjectKindBody,
    TransmitterConfigurationResponse, UpdateStreamBody, VerifyStreamBody,
};
use crate::handlers::signals::{delivery, streams, subjects, verification};
use crate::method::{get, post, shared};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The tenant part of every signal path.
const TENANT: &str = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";

/// The endpoints a stream's receiver calls, with no session or with its
/// stream's key, and the transmitter's configuration, read by anyone:
/// limited per client address.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let stream = format!("{TENANT}/streams/{{id}}");
    let limiter = per_address(
        state,
        state.http.rate.api_default_per_minute,
        Duration::from_secs(60),
    );
    Router::new()
        .route(
            &format!("{TENANT}/.well-known/ssf-configuration"),
            get(streams::transmitter_configuration),
        )
        .route(
            &format!("{stream}/confirm"),
            post(streams::confirm_endpoint),
        )
        .route(&format!("{stream}/poll"), post(delivery::poll_events))
        .route(
            &format!("{stream}/verify"),
            post(verification::request_verification),
        )
        .route(
            &format!("{stream}/subjects/add"),
            post(subjects::add_subject),
        )
        .route(
            &format!("{stream}/subjects/remove"),
            post(subjects::remove_subject),
        )
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The signal endpoints for a person of the tenant.
pub(crate) fn routes() -> Router<ApiState> {
    let base = format!("{TENANT}/streams");
    Router::new()
        .route(
            &base,
            post(streams::register_stream).get(shared(streams::list_streams)),
        )
        .route(
            &format!("{base}/{{id}}"),
            get(streams::get_stream)
                .patch(shared(streams::update_stream))
                .delete(shared(streams::delete_stream)),
        )
        .route(
            &format!("{base}/{{id}}/status"),
            get(streams::get_stream_status),
        )
        .route(&format!("{base}/{{id}}/pause"), post(streams::pause_stream))
        .route(
            &format!("{base}/{{id}}/resume"),
            post(streams::resume_stream),
        )
        .route(
            &format!("{base}/{{id}}/disable"),
            post(streams::disable_stream),
        )
        .route(
            &format!("{base}/{{id}}/deliveries"),
            get(delivery::list_stream_deliveries),
        )
}

/// The signal part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        streams::register_stream,
        streams::list_streams,
        streams::get_stream,
        streams::get_stream_status,
        streams::update_stream,
        streams::pause_stream,
        streams::resume_stream,
        streams::disable_stream,
        streams::delete_stream,
        streams::confirm_endpoint,
        streams::transmitter_configuration,
        subjects::add_subject,
        subjects::remove_subject,
        verification::request_verification,
        delivery::list_stream_deliveries,
        delivery::poll_events,
    ),
    components(schemas(
        RegisterStreamBody,
        DefaultSubjectsBody,
        RegisterStreamResponse,
        UpdateStreamBody,
        StreamResponse,
        StreamStatusResponse,
        ConfirmEndpointBody,
        SubjectBody,
        SubjectIdentifierBody,
        SubjectKindBody,
        VerifyStreamBody,
        PollBody,
        PollResponse,
        StreamDeliveryResponse,
        TransmitterConfigurationResponse,
        AuthorizationScheme,
    ))
)]
pub(crate) struct Document;
