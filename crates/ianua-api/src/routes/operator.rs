//! Operator endpoints: operator accounts, an operator's own keys and their
//! impersonation grants, and the jobs the platform gave up on, listed and
//! retried.
//! Platform-level, not scoped to any organization or tenant.

use std::time::Duration;

use axum::Router;
use utoipa::OpenApi;

use crate::dto::operator::{
    ChangeOperatorEmailBody, CreateOperatorBody, CreateOperatorKeyBody, CreateOperatorKeyResponse,
    CreateOperatorResponse, DeadJobResponse, GrantImpersonationBody, GrantImpersonationResponse,
    OperatorResponse, OperatorSignInBody, RevokeAllKeysResponse,
};
use crate::handlers::operator::{accounts, impersonation, jobs, keys};
use crate::method::{delete, get, post, shared};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::middleware::sign_in_admission::sign_in_admission;
use crate::state::ApiState;

/// The operator endpoint reached before anyone is identified: signing in
/// for a key, limited per client address like every other sign-in.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let limiter = per_address(
        state,
        state.http.rate.login_per_minute,
        Duration::from_secs(60),
    );
    Router::new()
        .route("/api/v1/operators/sign-in", post(keys::sign_in_operator))
        .layer(axum::middleware::from_fn_with_state(
            state.http.sign_ins.clone(),
            sign_in_admission,
        ))
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The operator endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let operators = "/api/v1/operators";
    Router::new()
        .route(
            operators,
            post(accounts::create_operator).get(shared(accounts::list_operators)),
        )
        .route(&format!("{operators}/{{id}}"), get(accounts::get_operator))
        .route(
            &format!("{operators}/{{id}}/enable"),
            post(accounts::enable_operator),
        )
        .route(
            &format!("{operators}/{{id}}/disable"),
            post(accounts::disable_operator),
        )
        .route(
            &format!("{operators}/{{id}}/email"),
            post(accounts::change_operator_email),
        )
        .merge(access_routes(operators))
        .route(&format!("{operators}/dead-jobs"), get(jobs::list_dead_jobs))
        .route(
            &format!("{operators}/dead-jobs/{{id}}/retry"),
            post(jobs::retry_dead_job),
        )
}

/// Operator keys and temporary impersonation grants.
fn access_routes(operators: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{operators}/{{id}}/keys"),
            post(keys::create_operator_key),
        )
        .route(
            &format!("{operators}/{{id}}/keys/revoke-all"),
            post(keys::revoke_all_operator_keys),
        )
        .route(
            &format!("{operators}/{{id}}/keys/{{key_prefix}}/revoke"),
            post(keys::revoke_operator_key),
        )
        .route(
            &format!("{operators}/{{id}}/grants"),
            post(impersonation::grant_impersonation),
        )
        .route(
            &format!("{operators}/grants/{{id}}"),
            delete(impersonation::revoke_impersonation),
        )
}

/// The operator part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        keys::sign_in_operator,
        accounts::create_operator,
        accounts::list_operators,
        accounts::get_operator,
        accounts::enable_operator,
        accounts::disable_operator,
        accounts::change_operator_email,
        keys::create_operator_key,
        keys::revoke_operator_key,
        keys::revoke_all_operator_keys,
        impersonation::grant_impersonation,
        impersonation::revoke_impersonation,
        jobs::list_dead_jobs,
        jobs::retry_dead_job,
    ),
    components(schemas(
        DeadJobResponse,
        CreateOperatorBody,
        CreateOperatorResponse,
        OperatorResponse,
        ChangeOperatorEmailBody,
        CreateOperatorKeyBody,
        CreateOperatorKeyResponse,
        OperatorSignInBody,
        RevokeAllKeysResponse,
        GrantImpersonationBody,
        GrantImpersonationResponse,
    ))
)]
pub(crate) struct Document;
