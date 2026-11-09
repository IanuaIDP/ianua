//! The model's two endpoints over HTTP/1.1: each request checked for its
//! key and its shape as the provider checks it, then answered from the
//! desk.

use std::convert::Infallible;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, Method, Request, Response};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::desk::Desk;
use super::script::Reply;
use super::{Format, Received, Usage, anthropic, openai};
use crate::wire::Status;

/// The largest request taken: far more than any conversation a test holds.
const LARGEST_REQUEST: usize = 4 * 1024 * 1024;

/// The provider every connection reaches: the desk and the key it takes.
#[derive(Clone)]
struct Provider {
    desk: Desk,
    api_key: String,
}

/// Takes connections on `listener`, each served as a task of its own,
/// until the answer is aborted.
pub(super) fn serve(listener: TcpListener, desk: Desk, api_key: String) -> JoinHandle<()> {
    let provider = Provider { desk, api_key };
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let provider = provider.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| answered(request, provider.clone()));
                let served = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                if let Err(error) = served {
                    tracing::debug!(%error, "a connection to the scripted model ended early");
                }
            });
        }
    })
}

/// An answer: its status, its content type and its body.
struct Answer {
    status: Status,
    content_type: &'static str,
    body: String,
}

impl Answer {
    /// `body` as JSON with `status`.
    fn json(status: Status, body: &Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.to_string(),
        }
    }

    /// `body` as a stream of server-sent events.
    fn events(body: String) -> Self {
        Self {
            status: Status::OK,
            content_type: "text/event-stream",
            body,
        }
    }

    /// The HTTP response.
    fn response(self) -> Response<Full<Bytes>> {
        let mut response = Response::new(Full::new(Bytes::from(self.body)));
        *response.status_mut() = self.status;
        response.headers_mut().insert(
            CONTENT_TYPE,
            http::HeaderValue::from_static(self.content_type),
        );
        response
    }
}

/// The answer to one request.
async fn answered(
    request: Request<Incoming>,
    provider: Provider,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(answer_to(request, &provider).await.response())
}

/// The answer to `request`: the provider's refusal of a wrong path, key or
/// body, or the script's reply.
async fn answer_to(request: Request<Incoming>, provider: &Provider) -> Answer {
    let Some(format) = format_of(&request) else {
        return Answer::json(Status::NOT_FOUND, &not_found(request.uri().path()));
    };
    if let Err(refusal) = authenticate(format, request.headers(), &provider.api_key) {
        return refusal;
    }
    let path = request.uri().path().to_owned();
    let headers = lowercased(request.headers());
    let Some(body) = json_body(request).await else {
        return refused_body(format, "the body is not JSON");
    };
    if let Err(refusal) = ensure_shape(format, &body) {
        return refusal;
    }
    let received = Received::new(format, path, headers, body);
    reply(format, received, &provider.desk).await
}

/// The script's reply to `received`, written in `format`, or the refusal
/// of a request no turn answers.
async fn reply(format: Format, received: Received, desk: &Desk) -> Answer {
    let asked = received.text().len();
    let streaming = received.is_streaming();
    let Some(reply) = desk.reply_to(received.clone()).await else {
        return refused_body(format, "the script has no turn for this request");
    };
    let usage = Usage::counted(asked, reply_length(&reply));
    match (format, streaming) {
        (Format::Anthropic, false) => {
            Answer::json(Status::OK, &anthropic::message(&reply, &received, usage))
        }
        (Format::Anthropic, true) => Answer::events(anthropic::events(&reply, &received, usage)),
        (Format::OpenAi, false) => {
            Answer::json(Status::OK, &openai::completion(&reply, &received, usage))
        }
        (Format::OpenAi, true) => Answer::events(openai::chunks(&reply, &received, usage)),
    }
}

/// How many characters `reply` writes.
fn reply_length(reply: &Reply) -> usize {
    match reply {
        Reply::Text(text) | Reply::MaxTokens(text) => text.len(),
        Reply::Call { name, input } => name.len().saturating_add(input.to_string().len()),
        Reply::EndTurn => 0,
    }
}

/// The format a `POST` to one of the two endpoints speaks.
fn format_of(request: &Request<Incoming>) -> Option<Format> {
    if request.method() != Method::POST {
        return None;
    }
    match request.uri().path() {
        anthropic::PATH => Some(Format::Anthropic),
        openai::PATH => Some(Format::OpenAi),
        _ => None,
    }
}

/// Refuses a request without the key where its provider takes it.
fn authenticate(format: Format, headers: &HeaderMap, api_key: &str) -> Result<(), Answer> {
    match format {
        Format::Anthropic => anthropic_signed_in(headers, api_key),
        Format::OpenAi => openai_signed_in(headers, api_key),
    }
}

/// Refuses an Anthropic request without the key in `x-api-key`, or
/// without the API version every request names.
fn anthropic_signed_in(headers: &HeaderMap, api_key: &str) -> Result<(), Answer> {
    if text_header(headers, anthropic::KEY_HEADER) != Some(api_key) {
        return Err(Answer::json(
            Status::UNAUTHORIZED,
            &anthropic::error("authentication_error", "invalid x-api-key"),
        ));
    }
    if text_header(headers, anthropic::VERSION_HEADER).is_none() {
        return Err(Answer::json(
            Status::BAD_REQUEST,
            &anthropic::error(
                "invalid_request_error",
                "anthropic-version: header is required",
            ),
        ));
    }
    Ok(())
}

/// Refuses an OpenAI request without the key as `Authorization: Bearer`.
fn openai_signed_in(headers: &HeaderMap, api_key: &str) -> Result<(), Answer> {
    let expected = format!("Bearer {api_key}");
    if text_header(headers, AUTHORIZATION.as_str()) == Some(expected.as_str()) {
        return Ok(());
    }
    Err(Answer::json(
        Status::UNAUTHORIZED,
        &openai::error(
            "invalid_request_error",
            "invalid_api_key",
            "Incorrect API key provided.",
        ),
    ))
}

/// The header `name` of `headers`, when it is text.
fn text_header<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Refuses a body missing what its provider requires: a model and the
/// messages, and for Anthropic `max_tokens`.
fn ensure_shape(format: Format, body: &Value) -> Result<(), Answer> {
    let has = |field: &str| body.get(field).is_some_and(|value| !value.is_null());
    let missing = ["model", "messages"].into_iter().find(|field| !has(field));
    if let Some(field) = missing {
        return Err(refused_body(format, &format!("{field}: Field required")));
    }
    if format == Format::Anthropic && !has("max_tokens") {
        return Err(refused_body(format, "max_tokens: Field required"));
    }
    Ok(())
}

/// The provider's refusal of a request it cannot take, for `why`.
fn refused_body(format: Format, why: &str) -> Answer {
    let body = match format {
        Format::Anthropic => anthropic::error("invalid_request_error", why),
        Format::OpenAi => openai::error("invalid_request_error", "invalid_request", why),
    };
    Answer::json(Status::BAD_REQUEST, &body)
}

/// The refusal of a path neither provider serves.
fn not_found(path: &str) -> Value {
    serde_json::json!({"type": "error", "error": {"type": "not_found_error", "message": format!("no endpoint at {path}")}})
}

/// The headers, their names in lowercase, those that are not text left
/// out.
fn lowercased(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|text| (name.as_str().to_ascii_lowercase(), text.to_owned()))
        })
        .collect()
}

/// The request's body read as JSON, up to the largest taken.
async fn json_body(request: Request<Incoming>) -> Option<Value> {
    let collected = Limited::new(request.into_body(), LARGEST_REQUEST)
        .collect()
        .await
        .ok()?;
    serde_json::from_slice(&collected.to_bytes()).ok()
}
