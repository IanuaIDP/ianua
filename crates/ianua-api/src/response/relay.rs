//! The API's answers to what the gateway relays on the internal listener,
//! sealed so the gateway can tell them from anyone else's.

use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use ianua_app::ports::authentication::SEAL_HEADER;
use ianua_app::services::gateway_relay::AnswerSeal;
use serde::Serialize;

/// A JSON answer to a request the gateway relayed, with the seal binding it
/// to that request in [`SEAL_HEADER`], over the exact bytes sent.
///
/// A request that never opened has no seal to answer with, so its answer
/// goes bare and the gateway takes it for none.
pub(crate) struct SealedAnswer<T: Serialize> {
    answer: T,
    seal: Option<AnswerSeal>,
}

impl<T: Serialize> SealedAnswer<T> {
    /// `answer`, sealed through `seal` when the request opened.
    #[must_use]
    pub(crate) fn new(answer: T, seal: Option<AnswerSeal>) -> Self {
        Self { answer, seal }
    }
}

impl<T: Serialize> IntoResponse for SealedAnswer<T> {
    /// `200` with the answer as JSON and its seal. An answer that does not
    /// write is a `500` with no body, which the gateway refuses on.
    fn into_response(self) -> Response {
        let Ok(body) = serde_json::to_vec(&self.answer) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let seal = self.seal.map(|seal| seal.seal(&body));
        let mut response = ([(CONTENT_TYPE, "application/json")], body).into_response();
        let Some(seal) = seal else {
            return response;
        };
        let Ok(value) = HeaderValue::from_str(&seal) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        response.headers_mut().insert(SEAL_HEADER, value);
        response
    }
}
