//! Onboarding endpoints: whether signups are taken, public signup, and a
//! member founding another organization.
//!
//! Signup is unauthenticated: it keeps a sign-up and mails a link, and
//! confirming it founds an organization, so those sit behind a per-address
//! limiter like the sign-in endpoints. Asking answers no sooner than a
//! floor, so its timing says nothing about the address.

use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn;
use utoipa::OpenApi;

use crate::dto::onboarding::{
    AnotherOrganizationBody, ConfirmSignupBody, SignupAcceptedResponse, SignupBody,
    SignupOpenResponse, SignupResponse,
};
use crate::handlers::onboarding as handlers;
use crate::method::{get, post, shared};
use crate::middleware::answer_floor::link_request_floor;
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The onboarding endpoints for a member the auth middleware identified.
pub(crate) fn routes() -> Router<ApiState> {
    Router::new().route(
        "/api/v1/organizations",
        post(handlers::found_another_organization),
    )
}

/// The unauthenticated onboarding endpoints, limited per client address.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let limiter = per_address(
        state,
        state.http.rate.login_per_minute,
        Duration::from_secs(60),
    );
    Router::new()
        .route(
            "/api/v1/signup",
            get(handlers::signup_open)
                .post(shared(handlers::signup))
                .layer(from_fn(link_request_floor)),
        )
        .route("/api/v1/signup/confirm", post(handlers::confirm_signup))
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The onboarding part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::signup_open,
        handlers::signup,
        handlers::confirm_signup,
        handlers::found_another_organization,
    ),
    components(schemas(
        AnotherOrganizationBody,
        SignupBody,
        SignupOpenResponse,
        SignupAcceptedResponse,
        ConfirmSignupBody,
        SignupResponse
    ))
)]
pub(crate) struct Document;
