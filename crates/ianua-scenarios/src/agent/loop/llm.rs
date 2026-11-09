//! The agent's model client, as a provider's SDK makes the call: the key
//! where the provider documents it, the conversation in its shape, the
//! answer read whole or as it streams.

use std::fmt;
use std::time::Duration;

use super::answer::{self, ModelTurn, UnreadableAnswer};
use super::conversation::{ANTHROPIC_VERSION, Asking};
use crate::agent::model::Format;
use crate::wire::Status;

/// The longest one model call may take.
const CALL_WAIT: Duration = Duration::from_secs(60);

/// Whether answers come whole or as server-sent events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Streaming {
    /// Whole, once the model finished.
    Off,
    /// As it is written.
    On,
}

/// How a model is asked to sample its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sampling {
    /// As the provider does when asked nothing.
    ProviderDefault,
    /// At temperature zero, with `seed` where the provider's API takes
    /// one, so a real model answers the same way run after run.
    Fixed {
        /// The seed, for an API that takes one.
        seed: Option<u64>,
    },
}

/// Which model the agent reasons with, and where. Holds the key, so
/// `Debug` leaves it out.
#[derive(Clone)]
pub struct ModelAccess {
    /// The provider's wire format.
    pub format: Format,
    /// The provider's endpoint: Anthropic's API host, or OpenAI's base.
    pub endpoint: String,
    /// The key it takes.
    pub api_key: String,
    /// The model asked for.
    pub model: String,
    /// Whether answers stream.
    pub streaming: Streaming,
    /// How the model is asked to sample.
    pub sampling: Sampling,
}

impl fmt::Debug for ModelAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModelAccess")
            .field("format", &self.format)
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("streaming", &self.streaming)
            .field("sampling", &self.sampling)
            .finish_non_exhaustive()
    }
}

/// Why a model call gave no answer.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    /// The client could not be built or the call not made.
    #[error("the model could not be reached")]
    Unreachable(#[source] reqwest::Error),
    /// The provider refused the call, with this status.
    #[error("the model provider refused the call with {status}")]
    Refused {
        /// HTTP outcome returned by the provider for the rejected request.
        status: Status,
    },
    /// The answer is not in the provider's shape.
    #[error(transparent)]
    Unreadable(#[from] UnreadableAnswer),
}

/// The model's turn, and the body it was asked with.
pub(super) struct Answered {
    /// Parsed prose, tool requests and stopping reason returned by the model.
    pub(super) turn: ModelTurn,
    /// What was sent to the model.
    pub(super) sent: serde_json::Value,
}

/// A client calling one model.
pub(super) struct ModelClient {
    access: ModelAccess,
    http: reqwest::Client,
}

impl ModelClient {
    /// A client for `access`.
    ///
    /// # Errors
    ///
    /// [`ModelError::Unreachable`] when the client cannot be built.
    pub(super) fn new(access: ModelAccess) -> Result<Self, ModelError> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(CALL_WAIT)
            .build()
            .map_err(ModelError::Unreachable)?;
        Ok(Self { access, http })
    }

    /// The model asked for.
    pub(super) fn model(&self) -> &str {
        &self.access.model
    }

    /// Whether answers stream.
    pub(super) fn streams(&self) -> bool {
        self.access.streaming == Streaming::On
    }

    /// How the model is asked to sample.
    pub(super) fn sampling(&self) -> Sampling {
        self.access.sampling
    }

    /// The model's next turn in the conversation `asking` holds.
    ///
    /// # Errors
    ///
    /// [`ModelError`] when no answer came or it cannot be read.
    pub(super) async fn next_turn(&self, asking: &Asking<'_>) -> Result<Answered, ModelError> {
        let format = self.access.format;
        let sent = super::conversation::body(format, asking);
        let response = self
            .request(format)
            .json(&sent)
            .send()
            .await
            .map_err(ModelError::Unreachable)?;
        let status = response.status();
        if !status.is_success() {
            return Err(ModelError::Refused { status });
        }
        let text = response.text().await.map_err(ModelError::Unreachable)?;
        let turn = answer::read(format, asking.streaming, &text)?;
        Ok(Answered { turn, sent })
    }

    /// The call to make in `format`, the key in its documented header.
    fn request(&self, format: Format) -> reqwest::RequestBuilder {
        let base = self.access.endpoint.trim_end_matches('/');
        match format {
            Format::Anthropic => self
                .http
                .post(format!("{base}/v1/messages"))
                .header("x-api-key", &self.access.api_key)
                .header("anthropic-version", ANTHROPIC_VERSION),
            Format::OpenAi if self.access.api_key.is_empty() => {
                self.http.post(format!("{base}/chat/completions"))
            }
            Format::OpenAi => self
                .http
                .post(format!("{base}/chat/completions"))
                .bearer_auth(&self.access.api_key),
        }
    }
}
