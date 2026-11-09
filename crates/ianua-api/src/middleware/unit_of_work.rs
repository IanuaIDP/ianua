//! One unit of work per state-changing request, with the handler's deadline
//! inside it.
//!
//! Every write a `POST`, `PUT`, `PATCH` or `DELETE` makes, and every audit
//! record it dispatches, is committed together unless ianua itself failed
//! the request (500), in which case all of it is dropped. Anything else is
//! committed: a failed sign-in keeps the attempt it counted and the audit
//! record of it, and a failed test of a model provider keeps the result it
//! recorded although the provider's failure is answered with 502. Reads run
//! outside any unit, so a long-lived read such as an event stream never holds
//! a transaction open.
//!
//! The deadline bounds the handler alone. A handler that runs past it is
//! answered `504` and its writes are dropped. One that finishes in time is
//! committed and answered whatever the commit takes: a deadline around the
//! commit could answer `504` for work that was kept, and the client would
//! retry a change already made.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ianua_app::error::AppError;
use ianua_app::ports::runtime::{Settlement, UnitOfWork, atomically};

use crate::error::ApiError;

/// What a request runs under: the unit its writes are kept in, and how long
/// its handler may take.
#[derive(Clone)]
pub(crate) struct RequestUnit {
    unit_of_work: Arc<dyn UnitOfWork>,
    handler_limit: Duration,
}

impl RequestUnit {
    /// Requests kept in `unit_of_work`, each handler given `handler_limit`.
    #[must_use]
    pub(crate) fn new(unit_of_work: Arc<dyn UnitOfWork>, handler_limit: Duration) -> Self {
        Self {
            unit_of_work,
            handler_limit,
        }
    }
}

/// Marks the answer to a handler that ran past its deadline, so its writes
/// are dropped although it is no server error.
#[derive(Debug, Clone, Copy)]
struct DeadlinePassed;

/// Runs a request's handler within its deadline, and a state-changing
/// request as one unit of work around it.
pub(crate) async fn unit_of_work(
    State(unit): State<RequestUnit>,
    request: Request,
    next: Next,
) -> Response {
    let reads_only = request.method().is_safe();
    let handled = answered_within(unit.handler_limit, next.run(request));
    if reads_only {
        return handled.await;
    }
    atomically(unit.unit_of_work.as_ref(), handled, settlement_for)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "a request's writes could not be committed");
            ApiError::from(AppError::internal(error)).into_response()
        })
}

/// What `handler` answers, or `504` once `limit` has passed.
async fn answered_within(
    limit: Duration,
    handler: impl Future<Output = Response> + Send,
) -> Response {
    let Ok(response) = tokio::time::timeout(limit, handler).await else {
        return deadline_passed();
    };
    response
}

/// The `504` a handler past its deadline is answered.
fn deadline_passed() -> Response {
    let mut response = StatusCode::GATEWAY_TIMEOUT.into_response();
    response.extensions_mut().insert(DeadlinePassed);
    response
}

/// Keeps a request's writes unless ianua itself failed it or its handler
/// ran out of time.
fn settlement_for(response: &Response) -> Settlement {
    let unfinished = response.extensions().get::<DeadlinePassed>().is_some();
    if unfinished || response.status() == StatusCode::INTERNAL_SERVER_ERROR {
        return Settlement::Rollback;
    }
    Settlement::Commit
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty response with this status.
    fn response(status: StatusCode) -> Response {
        status.into_response()
    }

    /// Ann creates something and it is kept.
    #[test]
    fn a_successful_request_keeps_its_writes() {
        assert_eq!(
            settlement_for(&response(StatusCode::CREATED)),
            Settlement::Commit
        );
    }

    /// Mallory's sign-in is refused, and the failed attempt it counted is
    /// still kept.
    #[test]
    fn a_refused_request_keeps_its_writes() {
        assert_eq!(
            settlement_for(&response(StatusCode::UNAUTHORIZED)),
            Settlement::Commit
        );
    }

    /// A provider that fails its test is answered with `502`, and the result
    /// recorded about it is kept.
    #[test]
    fn an_upstream_failure_keeps_what_was_recorded_about_it() {
        assert_eq!(
            settlement_for(&response(StatusCode::BAD_GATEWAY)),
            Settlement::Commit
        );
    }

    /// When ianua itself fails the request, everything it wrote is dropped.
    #[test]
    fn a_server_error_drops_its_writes() {
        assert_eq!(
            settlement_for(&response(StatusCode::INTERNAL_SERVER_ERROR)),
            Settlement::Rollback
        );
    }

    /// A handler runs past its deadline part way through its writes. It is
    /// answered `504`, and what it wrote is dropped rather than half kept.
    #[test]
    fn a_handler_past_its_deadline_drops_its_writes() {
        let answer = deadline_passed();

        assert_eq!(answer.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(settlement_for(&answer), Settlement::Rollback);
    }
}
