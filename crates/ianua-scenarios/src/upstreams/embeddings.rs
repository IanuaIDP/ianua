//! An embedding server speaking OpenAI's embeddings API, as a provider or
//! the platform's own server would: `POST {base}/embeddings` with a model
//! and an input, answered with one vector counting each letter of the
//! input, so texts sharing words come out alike. It keeps each request's
//! model and whether it carried a bearer key.

use std::convert::Infallible;
use std::io;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde_json::{Value, json};

use super::serving::{Listening, Record};

/// How many numbers each of its vectors holds: one per letter.
pub const LETTER_VECTOR_SIZE: usize = 26;

/// One request it answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Embedded {
    /// The model asked for.
    pub model: String,
    /// The bearer key it carried, if any.
    pub bearer: Option<String>,
}

/// An embedding server on a port of loopback, stopped when dropped.
pub struct LetterEmbeddings {
    listening: Listening,
    asked: Record<Embedded>,
}

impl LetterEmbeddings {
    /// The server, listening.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub async fn start() -> io::Result<Self> {
        let asked = Record::default();
        let kept = asked.clone();
        let listening = Listening::open(move |stream| {
            let kept = kept.clone();
            async move {
                let service = service_fn(move |request| answered(request, kept.clone()));
                let builder = auto::Builder::new(TokioExecutor::new());
                if let Err(error) = builder
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::debug!(%error, "a connection to the embedding server ended early");
                }
            }
        })
        .await?;
        Ok(Self { listening, asked })
    }

    /// Its OpenAI-compatible base, `http://127.0.0.1:<port>/v1`.
    #[must_use]
    pub fn base(&self) -> String {
        format!("{}/v1", self.listening.url())
    }

    /// Every request it answered, oldest first.
    #[must_use]
    pub fn asked(&self) -> Vec<Embedded> {
        self.asked.all()
    }
}

/// The vector of `request`'s input, or a refusal of anything else.
async fn answered(
    request: Request<Incoming>,
    kept: Record<Embedded>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let bearer = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned);
    let asked: Value = body
        .collect()
        .await
        .ok()
        .and_then(|collected| serde_json::from_slice(&collected.to_bytes()).ok())
        .unwrap_or(Value::Null);
    let (Some(model), Some(input)) = (asked["model"].as_str(), asked["input"].as_str()) else {
        return Ok(status(StatusCode::BAD_REQUEST));
    };
    if !parts.uri.path().ends_with("/embeddings") {
        return Ok(status(StatusCode::NOT_FOUND));
    }
    kept.keep(Embedded {
        model: model.to_owned(),
        bearer,
    });
    let answer = json!({ "data": [{ "embedding": letter_counts(input) }], "model": model });
    Ok(json_answer(&answer))
}

/// Encodes a successful embedding answer with its JSON content type.
fn json_answer(answer: &Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(answer.to_string())));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// An empty answer with `status`.
fn status(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

/// One number per letter of the alphabet: how often it appears in `text`.
fn letter_counts(text: &str) -> Vec<f32> {
    let mut counts = vec![0.0_f32; LETTER_VECTOR_SIZE];
    for letter in text
        .to_ascii_lowercase()
        .bytes()
        .filter(u8::is_ascii_lowercase)
    {
        counts[usize::from(letter - b'a')] += 1.0;
    }
    counts
}
