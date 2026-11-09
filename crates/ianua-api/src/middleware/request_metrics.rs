//! Request metrics: every answered request reported to the process's
//! metrics, by the route template that answered it, its method, its status
//! and how long it took.
//!
//! The route is the template the router matched, such as
//! `/api/v1/organizations/{org_slug}/tenants`, never the path as sent: a
//! path carries slugs, ids and whatever a client typed, and a series per
//! path would both fill the metrics store and write tenants' names into
//! it. A request no route matched is reported as unmatched. Narrowing the
//! method and status, and capping the combinations, is the observer's
//! work, the same for the API as for the proxy.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use ianua_app::ports::runtime::{ServedRequest, ServedRequestObserver, ServedRoute};

/// Reports the request once it is answered, whatever answered it.
pub async fn request_metrics(
    State(observer): State<Arc<dyn ServedRequestObserver>>,
    request: Request,
    next: Next,
) -> Response {
    let route = request.extensions().get::<MatchedPath>().cloned();
    let method = request.method().clone();
    let started = Instant::now();

    let response = next.run(request).await;

    observer.observe(&ServedRequest {
        route: route.as_ref().map_or(ServedRoute::Unmatched, |matched| {
            ServedRoute::Template(matched.as_str())
        }),
        method: method.as_str(),
        status: response.status().as_u16(),
        latency: started.elapsed(),
    });
    response
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;
    use ianua_app::test_support::RecordingServedRequests;
    use ianua_assembly::deps::Adapters;

    use super::*;
    use crate::test_support::{adapters, router};

    /// A handler that answers `ok`.
    async fn ok() -> &'static str {
        "ok"
    }

    /// One route with a path parameter, behind the metrics middleware.
    fn app(observer: Arc<RecordingServedRequests>) -> Router {
        Router::new()
            .route("/tenants/{tenant_slug}/users", get(ok))
            .layer(axum::middleware::from_fn_with_state(
                observer as Arc<dyn ServedRequestObserver>,
                request_metrics,
            ))
    }

    /// Metrics record the route template, method and status without the
    /// organization's slug from the request path.
    #[tokio::test]
    async fn a_request_is_reported_by_its_template_not_its_path() {
        let observer = Arc::new(RecordingServedRequests::default());
        let server = axum_test::TestServer::new(app(observer.clone())).unwrap();

        let response = server.get("/tenants/acme-secret-project/users").await;

        response.assert_status_ok();

        let heard = observer.heard();
        assert_eq!(heard.len(), 1);
        assert_eq!(
            heard[0].route.as_deref(),
            Some("/tenants/{tenant_slug}/users")
        );
        assert_eq!(heard[0].method, "GET");
        assert_eq!(heard[0].status, 200);
        assert!(!format!("{heard:?}").contains("acme-secret-project"));
    }

    /// A nonexistent path produces one unmatched-route metric with status 404.
    #[tokio::test]
    async fn a_request_no_route_matched_is_reported_as_unmatched() {
        let observer = Arc::new(RecordingServedRequests::default());
        let server = axum_test::TestServer::new(app(observer.clone())).unwrap();

        let response = server.get("/wp-admin/setup.php").await;

        response.assert_status(StatusCode::NOT_FOUND);
        let heard = observer.heard();
        assert_eq!(heard.len(), 1);
        assert_eq!(heard[0].route, None);
        assert_eq!(heard[0].status, 404);
    }

    /// The whole API reports to the observer it was given: a tenant
    /// listing asked for without a token is reported under its template,
    /// and the organization's slug is nowhere in it.
    #[tokio::test]
    async fn the_api_reports_every_request_to_its_observer() {
        let observer = Arc::new(RecordingServedRequests::default());
        let server = axum_test::TestServer::new(router(Adapters {
            served_request_observer: observer.clone(),
            ..adapters()
        }))
        .unwrap();

        let _answered = server
            .get("/api/v1/organizations/globex-hidden/tenants")
            .await;

        let heard = observer.heard();
        assert_eq!(heard.len(), 1);
        assert_eq!(
            heard[0].route.as_deref(),
            Some("/api/v1/organizations/{org_slug}/tenants")
        );
        assert!(!format!("{heard:?}").contains("globex-hidden"));
    }
}
