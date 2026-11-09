//! Webhook endpoints: a tenant's subscriptions, the events they may
//! receive, and their deliveries.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::webhooks::{
    CreateSubscriptionBody, CreateSubscriptionResponse, DeliveryAttemptResponse, EventTypeResponse,
    RotateSecretBody, RotateSecretResponse, SendTestEventBody, SubscriptionResponse,
    UpdateSubscriptionBody,
};
use crate::handlers::webhooks::{delivery, subscriptions};
use crate::method::{get, post, shared};
use crate::state::ApiState;

/// The webhook endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let base = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/webhooks";
    Router::new()
        .route(
            base,
            post(subscriptions::create_subscription).get(shared(subscriptions::list_subscriptions)),
        )
        .route(
            &format!("{base}/event-types"),
            get(subscriptions::list_event_types),
        )
        .route(
            &format!("{base}/{{id}}"),
            get(subscriptions::get_subscription)
                .patch(shared(subscriptions::update_subscription))
                .delete(shared(subscriptions::delete_subscription)),
        )
        .route(
            &format!("{base}/{{id}}/pause"),
            post(subscriptions::pause_subscription),
        )
        .route(
            &format!("{base}/{{id}}/resume"),
            post(subscriptions::resume_subscription),
        )
        .route(
            &format!("{base}/{{id}}/rotate-secret"),
            post(subscriptions::rotate_secret),
        )
        .merge(delivery_routes(base))
}

/// Registers delivery history, retries and test events for a subscription.
fn delivery_routes(base: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{base}/{{id}}/deliveries"),
            get(delivery::list_delivery_attempts),
        )
        .route(
            &format!("{base}/{{id}}/deliveries/{{delivery_id}}/resend"),
            post(delivery::resend_delivery),
        )
        .route(
            &format!("{base}/{{id}}/test"),
            post(delivery::send_test_event),
        )
}

/// The webhook part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        subscriptions::create_subscription,
        subscriptions::list_subscriptions,
        subscriptions::list_event_types,
        subscriptions::get_subscription,
        subscriptions::update_subscription,
        subscriptions::pause_subscription,
        subscriptions::resume_subscription,
        subscriptions::delete_subscription,
        subscriptions::rotate_secret,
        delivery::list_delivery_attempts,
        delivery::resend_delivery,
        delivery::send_test_event,
    ),
    components(schemas(
        CreateSubscriptionBody,
        CreateSubscriptionResponse,
        UpdateSubscriptionBody,
        SubscriptionResponse,
        RotateSecretBody,
        RotateSecretResponse,
        EventTypeResponse,
        SendTestEventBody,
        DeliveryAttemptResponse,
    ))
)]
pub(crate) struct Document;
