//! What integrations' services send, on the wire: a delivery handed to the
//! use case as it arrived, and the answer the service gets back.
//!
//! The service is told only whether its delivery was taken, never what it
//! started, so nothing about the tenant's runs reaches it.

use axum::http::StatusCode;
use axum::http::header::{CONTENT_TYPE, HeaderName, HeaderValue, X_CONTENT_TYPE_OPTIONS};
use axum::response::{IntoResponse, Response};
use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::workflows::{CheckBody, CheckReply};
use ianua_app::use_cases::workflows::executions::{
    DeliveredTo, ServiceEventAnswer, ServiceEventRequest,
};

use crate::extractors::workflows::ServiceDelivery;

/// `delivery`, sent `to`, as the use case reads it, and its auditor.
#[must_use]
pub(crate) fn delivered(
    to: DeliveredTo,
    delivery: ServiceDelivery,
) -> (ServiceEventRequest, RequestAuditor) {
    let request = ServiceEventRequest {
        to,
        address: delivery.address,
        headers: delivery.headers,
        body: delivery.body,
    };
    (request, delivery.auditor)
}

/// The answer the service gets: the proof it asked for as plain text, or
/// `204` once taken.
#[must_use]
pub fn answered(answer: ServiceEventAnswer) -> Response {
    match answer {
        ServiceEventAnswer::Proof(body) => {
            (StatusCode::OK, [(CONTENT_TYPE, "text/plain")], body).into_response()
        }
        ServiceEventAnswer::Checked(reply) => checked(reply),
        ServiceEventAnswer::Taken(_) => StatusCode::NO_CONTENT.into_response(),
    }
}

/// The answer to a service checking the address. Text a service sent to be
/// echoed is marked so no browser reads it as anything but text.
fn checked(reply: CheckReply) -> Response {
    let mut response = match reply.body {
        CheckBody::Empty => StatusCode::NO_CONTENT.into_response(),
        CheckBody::PlainText(body) => (
            StatusCode::OK,
            [
                (CONTENT_TYPE, "text/plain"),
                (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            body,
        )
            .into_response(),
    };
    let Some((name, value)) = reply.header else {
        return response;
    };
    let (Ok(name), Ok(value)) = (HeaderName::try_from(name), HeaderValue::try_from(value)) else {
        return response;
    };
    response.headers_mut().insert(name, value);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Slack asks the platform to prove it holds the address, and is
    /// answered its challenge as plain text.
    #[test]
    fn a_proof_is_answered_as_plain_text() {
        let response = answered(ServiceEventAnswer::Proof(b"challenge".to_vec()));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/plain");
    }

    /// Microsoft Graph checks the address and is sent its token back as
    /// text no browser will read as anything else.
    #[test]
    fn a_check_with_a_body_is_answered_as_plain_text() {
        let response = answered(ServiceEventAnswer::Checked(CheckReply {
            body: CheckBody::PlainText(b"validation token".to_vec()),
            header: None,
        }));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/plain");
        assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    /// Asana hands over a secret and is sent it back in its own header,
    /// with no body.
    #[test]
    fn a_check_with_a_header_echoes_it() {
        let response = answered(ServiceEventAnswer::Checked(CheckReply {
            body: CheckBody::Empty,
            header: Some(("x-hook-secret", "secret words".to_owned())),
        }));

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["x-hook-secret"], "secret words");
    }

    /// GitHub sends an issue that started Ann's workflow, and is told only
    /// that it was taken.
    #[test]
    fn a_taken_delivery_answers_no_content() {
        let response = answered(ServiceEventAnswer::Taken(Vec::new()));

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
