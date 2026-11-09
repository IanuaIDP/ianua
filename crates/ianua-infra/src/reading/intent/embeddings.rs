//! Turning text into embedding vectors, for the semantic intent compiler.
//!
//! [`Embedder`] is a seam inside this adapter, not an app port: nothing in
//! the app asks for vectors. [`HttpEmbedder`] fills it from an
//! OpenAI-compatible `POST {endpoint}/embeddings`, such as OpenAI, Voyage
//! or a self-hosted text-embeddings server. The endpoint is one the
//! platform configured, so the call goes through the
//! [`fixed`](crate::http::client::fixed) client: held to a few seconds,
//! never following a redirect, its answer read only up to a bound.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::http::client::{body_within, fixed};

/// How long one embedding call may take.
const CALL_LIMIT: Duration = Duration::from_secs(4);

/// The longest answer read, in bytes: enough for a few dozen vectors of
/// several thousand dimensions written out as JSON.
const MOST_ANSWER_BYTES: usize = 4_194_304;

/// The most dimensions a vector may have before the answer is refused.
const MOST_DIMENSIONS: usize = 8192;

/// Turns texts into embedding vectors.
///
/// An implementation answers exactly one vector per text, in the order the
/// texts were given, every vector of the same length, none of them empty
/// and every value finite. Anything else is an error. It answers within a
/// few seconds or fails.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// The vector of each of `texts`, in their order.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the backend cannot be
    /// reached, does not answer in time, or answers with anything but one
    /// well-formed vector per text.
    async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, DomainError>;
}

/// Where the embeddings come from, as the deployment configures it.
pub struct EmbeddingSettings {
    /// The API's base address, such as `https://api.openai.com/v1`.
    pub endpoint: Url,
    /// The model asked for, such as `text-embedding-3-small`.
    pub model: String,
    /// The API key sent as a bearer token, or none for an endpoint that
    /// takes none.
    pub api_key: Option<Secret>,
}

impl fmt::Debug for EmbeddingSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddingSettings")
            .field("endpoint", &self.endpoint.as_str())
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// An [`Embedder`] calling an OpenAI-compatible embeddings endpoint.
pub struct HttpEmbedder {
    client: reqwest::Client,
    address: Url,
    model: String,
    api_key: Option<Secret>,
}

impl fmt::Debug for HttpEmbedder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpEmbedder")
            .field("address", &self.address.as_str())
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl HttpEmbedder {
    /// An embedder asking `settings.endpoint` for `settings.model`'s
    /// vectors, each call held to a few seconds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the endpoint is not an
    /// `http` or `https` address a path can be added to, and
    /// `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(settings: EmbeddingSettings) -> Result<Self, DomainError> {
        Ok(Self {
            client: fixed(CALL_LIMIT)?,
            address: embeddings_address(settings.endpoint)?,
            model: settings.model,
            api_key: settings.api_key,
        })
    }

    async fn asked(&self, texts: &[&str]) -> Result<reqwest::Response, DomainError> {
        let request = self
            .client
            .post(self.address.clone())
            .json(&EmbeddingRequest {
                model: &self.model,
                input: texts,
            });
        let request = match &self.api_key {
            Some(key) => request.bearer_auth(key.expose()),
            None => request,
        };
        request.send().await.map_err(DomainError::infra)
    }
}

#[async_trait]
impl Embedder for HttpEmbedder {
    async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, DomainError> {
        let response = self.asked(texts).await?;
        let status = response.status();
        if !status.is_success() {
            return Err(DomainError::infra_msg(format!(
                "the embedding endpoint answered {}",
                status.as_u16()
            )));
        }
        let body = body_within(response, MOST_ANSWER_BYTES).await?;
        let answer: EmbeddingAnswer = serde_json::from_slice(&body).map_err(DomainError::infra)?;
        in_order(answer, texts.len())
    }
}

/// `endpoint` with `/embeddings` added to its path.
fn embeddings_address(mut endpoint: Url) -> Result<Url, DomainError> {
    if !matches!(endpoint.scheme(), "http" | "https") {
        return Err(DomainError::invalid(message!(
            "infra-the-embeddings-endpoint-must-be-an",
            "the embeddings endpoint must be an http or https address"
        )));
    }
    endpoint
        .path_segments_mut()
        .map_err(|()| {
            DomainError::invalid(message!(
                "infra-the-embeddings-endpoint-takes-no-path",
                "the embeddings endpoint takes no path"
            ))
        })?
        .pop_if_empty()
        .push("embeddings");
    Ok(endpoint)
}

/// The request body of an embeddings call.
#[derive(Serialize)]
struct EmbeddingRequest<'a> {
    model: &'a str,
    input: &'a [&'a str],
}

/// The answer of an embeddings call, as far as it is read.
#[derive(Deserialize)]
struct EmbeddingAnswer {
    data: Vec<EmbeddingDatum>,
}

/// One vector of the answer, with the position of the text it is for.
#[derive(Deserialize)]
struct EmbeddingDatum {
    index: usize,
    embedding: Vec<f32>,
}

/// The vectors of `answer` in the order of the `asked` texts, when it holds
/// exactly one well-formed vector for each.
fn in_order(answer: EmbeddingAnswer, asked: usize) -> Result<Vec<Vec<f32>>, DomainError> {
    let mut data = answer.data;
    if data.len() != asked {
        return Err(DomainError::infra_msg(
            "the embedding endpoint answered another number of vectors than it was asked for",
        ));
    }
    data.sort_by_key(|datum| datum.index);
    let placed = data
        .iter()
        .enumerate()
        .all(|(position, datum)| datum.index == position);
    if !placed {
        return Err(DomainError::infra_msg(
            "the embedding endpoint answered vectors for texts it was not asked about",
        ));
    }
    let vectors: Vec<Vec<f32>> = data.into_iter().map(|datum| datum.embedding).collect();
    ensure_well_formed(&vectors)?;
    Ok(vectors)
}

/// Refuses vectors that are empty, too long, of different lengths, or hold
/// a value that is not finite.
fn ensure_well_formed(vectors: &[Vec<f32>]) -> Result<(), DomainError> {
    let Some(dimensions) = vectors.first().map(Vec::len) else {
        return Ok(());
    };
    let shaped = (1..=MOST_DIMENSIONS).contains(&dimensions)
        && vectors.iter().all(|vector| vector.len() == dimensions);
    let finite = vectors.iter().flatten().all(|value| value.is_finite());
    if !(shaped && finite) {
        return Err(DomainError::infra_msg(
            "the embedding endpoint answered vectors that are not well formed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn embedder_at(server: &MockServer, api_key: Option<&str>) -> HttpEmbedder {
        HttpEmbedder::new(EmbeddingSettings {
            endpoint: Url::parse(&format!("{}/v1", server.uri())).unwrap(),
            model: "text-embedding-3-small".to_owned(),
            api_key: api_key.map(Secret::new),
        })
        .unwrap()
    }

    async fn answering(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    /// The vectors come back in the order the texts were asked in, whatever
    /// order the endpoint lists them in, and the key and model are sent.
    #[tokio::test]
    async fn vectors_come_back_in_the_order_asked() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .and(header("authorization", "Bearer sk-embed"))
            .and(body_partial_json(
                json!({"model": "text-embedding-3-small", "input": ["a", "b"]}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [
                    {"index": 1, "embedding": [0.0, 1.0]},
                    {"index": 0, "embedding": [1.0, 0.0]}
                ]
            })))
            .mount(&server)
            .await;

        let vectors = embedder_at(&server, Some("sk-embed"))
            .embed(&["a", "b"])
            .await
            .unwrap();

        assert_eq!(vectors, vec![vec![1.0, 0.0], vec![0.0, 1.0]]);
    }

    /// An endpoint returning one vector for two input texts produces an
    /// infrastructure error.
    #[tokio::test]
    async fn a_short_answer_is_refused() {
        let server = answering(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"index": 0, "embedding": [1.0]}]
        })))
        .await;

        let result = embedder_at(&server, None).embed(&["a", "b"]).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// An endpoint returning vectors of different lengths produces an
    /// infrastructure error.
    #[tokio::test]
    async fn vectors_that_cannot_be_compared_are_refused() {
        let server = answering(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"index": 0, "embedding": [1.0, 0.0]},
                {"index": 1, "embedding": [1.0]}
            ]
        })))
        .await;

        let result = embedder_at(&server, None).embed(&["a", "b"]).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// An endpoint that fails answers an error, never vectors.
    #[tokio::test]
    async fn a_failing_endpoint_is_an_error() {
        let server = answering(ResponseTemplate::new(503)).await;

        let result = embedder_at(&server, Some("sk-embed")).embed(&["a"]).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// An endpoint delaying its answer for ten seconds makes the embedding call
    /// fail within eight seconds.
    #[tokio::test]
    async fn a_hung_endpoint_is_given_up_on() {
        let server = answering(ResponseTemplate::new(200).set_delay(Duration::from_secs(10))).await;

        let started = std::time::Instant::now();
        let result = embedder_at(&server, None).embed(&["a"]).await;

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(8));
    }

    /// A response body one byte larger than the bound fails the embedding call.
    #[tokio::test]
    async fn an_answer_past_its_bound_is_refused() {
        let server =
            answering(ResponseTemplate::new(200).set_body_bytes(vec![b' '; MOST_ANSWER_BYTES + 1]))
                .await;

        let result = embedder_at(&server, None).embed(&["a"]).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// The embedder's debug output replaces the API key with a redaction marker.
    #[tokio::test]
    async fn the_api_key_never_shows_in_debug() {
        let server = answering(ResponseTemplate::new(200)).await;
        let embedder = embedder_at(&server, Some("sk-distinctive-key"));

        let rendered = format!("{embedder:?}");

        assert!(!rendered.contains("sk-distinctive-key"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    /// Configuring the embedder with a file URL fails validation.
    #[test]
    fn an_endpoint_that_is_not_http_is_refused() {
        let result = HttpEmbedder::new(EmbeddingSettings {
            endpoint: Url::parse("file:///etc/passwd").unwrap(),
            model: "m".to_owned(),
            api_key: None,
        });

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
