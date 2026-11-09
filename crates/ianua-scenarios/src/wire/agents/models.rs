//! The model providers a tenant connects for its runs.

use serde::{Deserialize, Serialize};

/// `POST …/model-providers`: a provider at an endpoint, with its key.
/// Holds the key, so it has no `Debug`.
#[derive(Clone, Serialize)]
pub struct ConnectProvider {
    /// A name people know it by.
    pub name: String,
    /// `anthropic`, `openai` or `self_hosted`.
    pub kind: String,
    /// The API's base, such as `https://api.anthropic.com`.
    pub endpoint: String,
    /// The model asked for.
    pub model: String,
    /// The key the provider takes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// The most sensitive data runs may send it, such as `Internal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clearance: Option<String>,
    /// What it charges, or none when nobody set a price.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pricing: Option<Pricing>,
}

/// What a provider charges, in millionths of the tenant's billing
/// currency per million tokens.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Pricing {
    /// The price of a million tokens sent to the model.
    pub input_micros_per_million: u64,
    /// The price of a million tokens the model wrote.
    pub output_micros_per_million: u64,
}

/// A connected provider as its readers see it. The key never comes back.
#[derive(Debug, Clone, Deserialize)]
pub struct Provider {
    /// Handle supplied when starting a run with this provider.
    pub id: String,
    /// Protocol family used to call the configured provider.
    pub kind: String,
    /// Base URL used for model requests.
    pub endpoint: String,
    /// Provider-specific model identifier sent with inference requests.
    pub model: String,
    /// The embedding model it offers, if any.
    pub embedding_model: Option<String>,
    /// Whether a key is kept for it.
    pub has_credential: bool,
    /// `active` or `disabled`.
    pub status: String,
}

/// What a provider's test answered.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderTest {
    /// Whether the model answered.
    pub ok: bool,
    /// The start of its answer.
    pub sample: String,
}

/// `PUT …/model-providers/{id}/embeddings`.
#[derive(Debug, Clone, Serialize)]
pub struct EmbeddingModel {
    /// The embedding model, such as `text-embedding-3-small`; `None` for
    /// none.
    pub embedding_model: Option<String>,
}
