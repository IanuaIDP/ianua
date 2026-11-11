//! The API's router: the shared endpoints, every context's routes, and the
//! middleware every request passes through.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{from_fn, from_fn_with_state};
use ianua_domain::message;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use utoipa_scalar::{Scalar, Servable as _};
use utoipa_swagger_ui::SwaggerUi;

use crate::middleware::unit_of_work::RequestUnit;
use crate::middleware::unread_body::BodyDraining;
use crate::state::{ApiState, Deps};

/// The whole API, built from what the server plugged in: every context's
/// routes, the shared endpoints, the documentation and the middleware every
/// request passes through.
pub fn build(deps: &Deps) -> Router {
    let state = crate::state::build(deps);
    let app = documentation(public_routes(&state), &state);
    let app = request_context(app.fallback(no_such_address), &state, deps);
    let app = response_policy(app, &state, deps);
    observed(app, deps)
}

/// Combines context endpoints with the public flows and their address limits.
fn public_routes(state: &ApiState) -> Router<ApiState> {
    Router::new()
        .merge(crate::routes::all())
        .merge(crate::routes::authentication::limited_routes(state))
        .merge(crate::routes::organization::public_routes(state))
        .merge(crate::routes::operator::public_routes(state))
        .merge(crate::routes::onboarding::public_routes(state))
        .merge(crate::routes::identity::public_routes(state))
        .merge(crate::routes::oauth::public_routes(state))
        .merge(crate::routes::crypto::public_routes(state))
        .merge(crate::routes::federation::public_routes(state))
        .merge(crate::routes::scim::public_routes(state))
        .merge(crate::routes::signals::public_routes(state))
        .merge(crate::routes::workflows::public_routes(state))
        .merge(crate::routes::routing::public_routes(state))
        .merge(crate::routes::files::routes(state))
        .merge(agent_routes(state))
}

/// Applies separate per-address budgets to agent signatures and relay messages.
fn agent_routes(state: &ApiState) -> Router<ApiState> {
    crate::routes::agents::agent_signed_routes()
        .layer(from_fn_with_state(
            crate::middleware::ip_rate_limit::per_address(
                state,
                state.http.rate.login_per_minute,
                Duration::from_secs(60),
            ),
            crate::middleware::ip_rate_limit::ip_rate_limit,
        ))
        .merge(
            crate::routes::agents::relay_routes().layer(from_fn_with_state(
                crate::middleware::ip_rate_limit::per_address(
                    state,
                    state.http.rate.agent_relay_per_minute,
                    Duration::from_secs(60),
                ),
                crate::middleware::ip_rate_limit::ip_rate_limit,
            )),
        )
}

/// Mounts both documentation views only when this deployment serves them.
fn documentation(app: Router<ApiState>, state: &ApiState) -> Router<ApiState> {
    if state.http.api_docs != crate::state::http::ApiDocs::Served {
        return app;
    }
    let document = crate::openapi::document();
    app.merge(SwaggerUi::new("/api/v1/docs").url("/api/v1/docs/openapi.json", document.clone()))
        .merge(Scalar::with_url("/api/v1/reference", document))
}

/// Resolves callers before rate limits and wraps each accepted mutation in a unit.
fn request_context(app: Router<ApiState>, state: &ApiState, deps: &Deps) -> Router {
    app.layer(from_fn_with_state(
        RequestUnit::new(
            state.unit_of_work.clone(),
            state.http.public_listener.timeout,
        ),
        crate::middleware::unit_of_work::unit_of_work,
    ))
    .layer(crate::middleware::rate_limit::RateLimitLayer::new(
        deps.adapters.rate_limiter.clone(),
        Arc::new(crate::middleware::rate_limit::PlanLimitCache::new(
            state.org_store.clone(),
            state.http.rate.api_default_per_minute,
            state.http.rate.limit_cache_ttl,
        )),
    ))
    .layer(crate::middleware::auth::AuthLayer::new(
        deps.adapters.token_resolver.clone(),
    ))
    .with_state(state.clone())
}

/// Bounds public requests, applies wording, browser and cache response
/// policies, and reads what is left of a body answered early.
fn response_policy(app: Router, state: &ApiState, deps: &Deps) -> Router {
    let listener = state.http.public_listener;
    app.layer(ConcurrencyLimitLayer::new(listener.max_concurrency))
        .layer(DefaultBodyLimit::max(listener.max_body_bytes))
        .layer(from_fn_with_state(
            deps.adapters.refusal_wording.clone(),
            crate::middleware::wording::wording,
        ))
        .layer(build_cors_layer(state.http.cors_origin.as_deref()))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::PRAGMA,
            HeaderValue::from_static("no-cache"),
        ))
        .layer(CatchPanicLayer::new())
        .layer(from_fn(
            crate::middleware::security_headers::security_headers,
        ))
        .layer(from_fn_with_state(
            BodyDraining {
                most: DRAIN_MOST,
                within: DRAIN_WITHIN,
            },
            crate::middleware::unread_body::drain_unread_body,
        ))
}

/// The most of a body nothing read that an early answer reads and throws
/// away: well past the body limit, so a body refused for its size is read
/// to its end too, as a proxy's lingering close does.
const DRAIN_MOST: usize = 16 * 1024 * 1024;

/// The longest an early answer waits for the rest of a body nothing read.
const DRAIN_WITHIN: Duration = Duration::from_secs(2);

/// Observes every public request, including refusals from the inner middleware.
fn observed(app: Router, deps: &Deps) -> Router {
    app.layer(
        TraceLayer::new_for_http().make_span_with(crate::middleware::access_log::request_span),
    )
    .layer(from_fn_with_state(
        deps.adapters.served_request_observer.clone(),
        crate::middleware::request_metrics::request_metrics,
    ))
    .layer(from_fn(crate::middleware::access_log::access_log))
}

/// The answer to an address the API does not serve: the problem body every
/// refusal carries, so nothing a client sent in the address comes back,
/// and a browser shown it reads JSON, never a page.
async fn no_such_address() -> crate::error::ApiError {
    crate::error::ApiError(ianua_app::error::AppError::NotFound(message!(
        "api-no-such-address",
        "no such address"
    )))
}

/// The internal listener's API on an API node: the probes and the metrics
/// scrape, never routed by the public ingress.
pub fn build_internal(deps: &Deps) -> Router {
    let state = crate::state::build(deps);
    let listener = state.http.internal_listener;
    bounded(runtime_routes(state.runtime, listener), listener)
}

/// The relay listener's API: the gateway's app sign-in relay and its
/// questions about agent approvals, apart from the probes so the listener
/// can ask a certificate of every caller, never routed by the public
/// ingress.
pub fn build_relay(deps: &Deps) -> Router {
    let state = crate::state::build(deps);
    let listener = state.http.internal_listener;
    let relay = crate::routes::authentication::internal_routes(&state)
        .merge(crate::routes::agents::internal_routes())
        .layer(from_fn_with_state(
            RequestUnit::new(state.unit_of_work.clone(), listener.timeout),
            crate::middleware::unit_of_work::unit_of_work,
        ))
        .with_state(state);
    bounded(relay, listener)
}

/// The internal listener of a node serving no API, such as a worker: the
/// probes and the metrics scrape over `ports`, bounded as `listener` says.
pub fn build_runtime(
    ports: ianua_assembly::runtime::RuntimePorts,
    listener: crate::state::http::ListenerLimits,
) -> Router {
    bounded(
        runtime_routes(ianua_assembly::runtime::of(ports), listener),
        listener,
    )
}

/// The probes and the scrape over `state`, each answered within the
/// listener's time.
fn runtime_routes(
    state: ianua_assembly::runtime::RuntimeState,
    listener: crate::state::http::ListenerLimits,
) -> Router {
    crate::routes::runtime::internal_routes()
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            listener.timeout,
        ))
        .with_state(state)
}

/// `router` taking on what `listener` allows: so many requests at once,
/// bodies so large, and a panic answered rather than dropping the
/// connection.
fn bounded(router: Router, listener: crate::state::http::ListenerLimits) -> Router {
    router
        .layer(ConcurrencyLimitLayer::new(listener.max_concurrency))
        .layer(DefaultBodyLimit::max(listener.max_body_bytes))
        .layer(CatchPanicLayer::new())
}

/// The CORS rules for the configured origin: no cross-origin browser calls
/// when unset, any origin without credentials for `*`, and that one origin
/// with credentials otherwise. Panics on an origin that is not a valid
/// header value.
// Configuration parses a URL and supplies its ASCII origin before building the router.
#[allow(clippy::expect_used)]
fn build_cors_layer(origin: Option<&str>) -> tower_http::cors::CorsLayer {
    let cors = cors_methods_and_headers();
    let Some(origin) = origin else {
        tracing::warn!(
            "CORS_ORIGIN is unset; cross-origin browser requests will be denied. \
             Set CORS_ORIGIN to enable a specific origin."
        );
        return cors;
    };

    if origin == "*" {
        tracing::warn!("CORS_ORIGIN is a wildcard; allowing any origin without credentials");
        return cors.allow_origin(Any);
    }

    let value = origin
        .parse::<HeaderValue>()
        .expect("configuration serializes CORS_ORIGIN as an ASCII HTTP origin");
    cors.allow_origin(value).allow_credentials(true)
}

/// The methods and request headers accepted by every configured CORS mode.
fn cors_methods_and_headers() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
}
