//! Turning a text into a vector through OpenAI's embeddings API,
//! `POST {base}/embeddings` with `{"model": …, "input": …}`, which OpenAI,
//! Azure OpenAI, Mistral, Ollama, vLLM and Hugging Face's
//! text-embeddings-inference server all speak.
//!
//! Two kinds of endpoint are reached. A tenant's model provider is its own
//! address, so it goes through the [`screened`] client as a model call
//! does: checked before the call, screened as its name resolves, no
//! redirect followed, a private address reached only when the deployment
//! lists the network, and its key sent only as `Authorization: Bearer`. The
//! platform's own embedding server is an address the operator set
//! (`EMBEDDING_URL`), reached with the [`fixed`] client and no key.
//!
//! Every call is held to its timeout and the answer read within a bound.
//! An answer is one vector of finite numbers or it is refused; a provider's
//! error body is never handed on, and the key never reaches an error.

use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::workflows::{Embedder, EmbeddingTarget};
use ianua_domain::domains::agents::execution::model_provider::{ModelEndpoint, ModelName};
use ianua_domain::domains::workflows::memory::entry::MemoryText;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::http::calls::{Sent, sent};
use crate::http::client::{body_within, ensure_reachable, fixed, screened};

/// The most an embeddings answer may hold: a vector of 4,096 numbers
/// written out fits many times over.
const MOST_ANSWER_BYTES: usize = 1024 * 1024;

/// The platform's own embedding server: where it answers and the model it
/// serves.
#[derive(Debug, Clone)]
pub struct PlatformEmbeddings {
    /// Its OpenAI-compatible base, such as `http://embeddings:8080/v1`.
    pub url: Url,
    /// The model it serves, such as `BAAI/bge-small-en-v1.5`.
    pub model: ModelName,
}

/// Turns texts into vectors at a tenant's provider or the platform's own
/// embedding server.
#[derive(Debug)]
pub struct HttpEmbedder {
    tenants: reqwest::Client,
    networks: UpstreamNetworks,
    platform: Option<(PlatformEmbeddings, reqwest::Client)>,
}

impl HttpEmbedder {
    /// A client reaching tenants' providers only where `networks` permits
    /// and the platform's server `platform` where the deployment runs one,
    /// each call held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a client cannot be built.
    pub fn new(
        networks: UpstreamNetworks,
        platform: Option<PlatformEmbeddings>,
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        let platform = platform
            .map(|server| fixed(timeout).map(|client| (server, client)))
            .transpose()?;
        Ok(Self {
            tenants: screened(timeout, networks.clone())?,
            networks,
            platform,
        })
    }

    /// The request for `text` at `target`.
    fn request(
        &self,
        target: &EmbeddingTarget,
        text: &MemoryText,
    ) -> Result<reqwest::RequestBuilder, DomainError> {
        match target {
            EmbeddingTarget::Platform(model) => {
                let Some((server, client)) = &self.platform else {
                    return Err(DomainError::infra_msg(
                        "this deployment runs no embedding server",
                    ));
                };
                let address = joined(&server.url, "embeddings");
                Ok(client.post(address).json(&body(model, text)))
            }
            EmbeddingTarget::Provider {
                endpoint,
                model,
                api_key,
            } => {
                let address = provider_address(endpoint, &self.networks)?;
                let request = self.tenants.post(address).json(&body(model, text));
                with_key(request, api_key.as_ref())
            }
        }
    }
}

#[async_trait]
impl Embedder for HttpEmbedder {
    fn platform_model(&self) -> Option<ModelName> {
        self.platform
            .as_ref()
            .map(|(server, _)| server.model.clone())
    }

    async fn embed(
        &self,
        target: &EmbeddingTarget,
        text: &MemoryText,
    ) -> Result<Vec<f32>, DomainError> {
        let response = answered(self.request(target, text)?.send().await)?;
        let body = body_within(response, MOST_ANSWER_BYTES).await?;
        vector_of(&body)
    }
}

/// The request body asking `model` for the vector of `text`.
fn body(model: &ModelName, text: &MemoryText) -> serde_json::Value {
    json!({ "model": model.as_str(), "input": text.as_str() })
}

/// `request` carrying `key` as a bearer token, marked sensitive, when there
/// is one.
fn with_key(
    request: reqwest::RequestBuilder,
    key: Option<&Secret>,
) -> Result<reqwest::RequestBuilder, DomainError> {
    let Some(key) = key.filter(|key| !key.is_empty()) else {
        return Ok(request);
    };
    let mut value = HeaderValue::from_str(&format!("Bearer {}", key.expose()))
        .map_err(|_| DomainError::infra_msg("the provider's key cannot be sent"))?;
    value.set_sensitive(true);
    Ok(request.header(AUTHORIZATION, value))
}

/// The embeddings address under a provider's `endpoint`, refused when it
/// is not a plain address or names one the deployment may not reach.
fn provider_address(
    endpoint: &ModelEndpoint,
    networks: &UpstreamNetworks,
) -> Result<Url, DomainError> {
    let base = Url::parse(endpoint.as_str())
        .map_err(|_| DomainError::infra_msg("the provider's endpoint is not a URL"))?;
    let plain = matches!(base.scheme(), "http" | "https")
        && base.query().is_none()
        && base.fragment().is_none()
        && base.username().is_empty()
        && base.password().is_none();
    if !plain {
        return Err(DomainError::infra_msg(
            "the provider's endpoint is not a plain address",
        ));
    }
    let address = joined(&base, "embeddings");
    ensure_reachable(&address, networks)?;
    Ok(address)
}

/// `path` under `base`'s own path.
fn joined(base: &Url, path: &str) -> Url {
    let mut address = base.clone();
    let joined = format!("{}/{path}", base.path().trim_end_matches('/'));
    address.set_path(&joined);
    address
}

/// The answer, when the endpoint answered with success; a status, a time
/// out or an unreachable endpoint otherwise, never the error body.
fn answered(
    result: Result<reqwest::Response, reqwest::Error>,
) -> Result<reqwest::Response, DomainError> {
    match sent(result)? {
        Sent::Answered(response) if response.status().is_success() => Ok(response),
        Sent::Answered(response) => Err(DomainError::infra_msg(format!(
            "the embedding endpoint answered {}",
            response.status().as_u16()
        ))),
        Sent::TimedOut => Err(DomainError::infra_msg(
            "the embedding endpoint did not answer in time",
        )),
        Sent::Unreachable(error) => Err(DomainError::infra(error)),
    }
}

/// An embeddings answer: one item with its vector.
#[derive(Deserialize)]
struct EmbeddingsAnswer {
    data: Vec<EmbeddingItem>,
}

/// One vector of an answer.
#[derive(Deserialize)]
struct EmbeddingItem {
    embedding: Vec<f32>,
}

/// The one vector `body` holds.
fn vector_of(body: &[u8]) -> Result<Vec<f32>, DomainError> {
    let answer: EmbeddingsAnswer = serde_json::from_slice(body)
        .map_err(|_| DomainError::infra_msg("the embedding endpoint's answer does not read"))?;
    let mut items = answer.data.into_iter();
    let (Some(item), None) = (items.next(), items.next()) else {
        return Err(DomainError::infra_msg(
            "the embedding endpoint did not answer with one vector",
        ));
    };
    Ok(item.embedding)
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::calls::tests::loopback;

    fn ticket() -> MemoryText {
        MemoryText::new("I want my money back").unwrap()
    }

    fn model(name: &str) -> ModelName {
        ModelName::new(name).unwrap()
    }

    fn answer(vectors: &serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({ "data": vectors }))
    }

    fn embedder(platform: Option<PlatformEmbeddings>) -> HttpEmbedder {
        HttpEmbedder::new(loopback(), platform, Duration::from_secs(5)).unwrap()
    }

    /// The platform's embedding server is asked for the ticket's vector
    /// with its model and no key, and its one vector comes back.
    #[tokio::test]
    async fn the_platform_server_answers_with_the_ticket_s_vector() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .and(body_json(
                json!({"model": "bge-small", "input": "I want my money back"}),
            ))
            .respond_with(answer(&json!([{ "embedding": [0.5, -0.25, 1.0] }])))
            .expect(1)
            .mount(&server)
            .await;
        let platform = PlatformEmbeddings {
            url: Url::parse(&format!("{}/v1", server.uri())).unwrap(),
            model: model("bge-small"),
        };

        let vector = embedder(Some(platform))
            .embed(&EmbeddingTarget::Platform(model("bge-small")), &ticket())
            .await
            .unwrap();

        assert_eq!(vector, [0.5, -0.25, 1.0]);
    }

    /// A tenant's OpenAI-style provider is sent its key as a bearer token.
    #[tokio::test]
    async fn a_provider_is_sent_its_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .and(header("authorization", "Bearer provider key"))
            .respond_with(answer(&json!([{ "embedding": [1.0] }])))
            .expect(1)
            .mount(&server)
            .await;
        let target = EmbeddingTarget::Provider {
            endpoint: ModelEndpoint::new(format!("{}/v1", server.uri())).unwrap(),
            model: model("text-embedding-3-small"),
            api_key: Some(Secret::new("provider key")),
        };

        let vector = embedder(None).embed(&target, &ticket()).await.unwrap();

        assert_eq!(vector, [1.0]);
    }

    /// Requesting embeddings from an unlisted private endpoint returns an error.
    #[tokio::test]
    async fn a_private_provider_endpoint_is_refused() {
        let embedder = HttpEmbedder::new(
            UpstreamNetworks::public_only(),
            None,
            Duration::from_secs(5),
        )
        .unwrap();
        let target = EmbeddingTarget::Provider {
            endpoint: ModelEndpoint::new("http://10.0.0.5:8000/v1").unwrap(),
            model: model("nomic-embed-text"),
            api_key: None,
        };

        assert!(embedder.embed(&target, &ticket()).await.is_err());
    }

    /// HTTP 401 and an answer containing two vectors each return an error;
    /// the refusal's debug output excludes the provider's response text.
    #[tokio::test]
    async fn an_error_or_two_vectors_give_no_vector() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bad/embeddings"))
            .respond_with(ResponseTemplate::new(401).set_body_string("secret detail"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/two/embeddings"))
            .respond_with(answer(
                &json!([{ "embedding": [1.0] }, { "embedding": [2.0] }]),
            ))
            .mount(&server)
            .await;
        let at = |base: &str| EmbeddingTarget::Provider {
            endpoint: ModelEndpoint::new(format!("{}/{base}", server.uri())).unwrap(),
            model: model("m"),
            api_key: None,
        };
        let embedder = embedder(None);

        let refused = embedder.embed(&at("bad"), &ticket()).await;
        let two = embedder.embed(&at("two"), &ticket()).await;

        assert!(
            !format!("{refused:?}").contains("secret detail"),
            "{refused:?}"
        );
        assert!(refused.is_err());
        assert!(two.is_err());
    }

    /// Without a platform embedding server, no model is advertised and a
    /// platform embedding request returns an error.
    #[tokio::test]
    async fn no_platform_server_gives_no_vector() {
        let embedder = embedder(None);

        let vector = embedder
            .embed(&EmbeddingTarget::Platform(model("bge-small")), &ticket())
            .await;

        assert!(embedder.platform_model().is_none());
        assert!(vector.is_err());
    }
}
