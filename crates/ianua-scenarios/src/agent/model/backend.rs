//! Which model an agent reasons with, chosen once per stack by
//! `IANUA_SCENARIO_MODEL`, and the one way both an agent's own loop and a
//! platform-run agent's provider reach it.
//!
//! - `scripted`, the default and what CI runs: the [`ModelServer`],
//!   answering from a script. It needs no network.
//! - `local`: a small open model behind an OpenAI-compatible server, at
//!   `IANUA_SCENARIO_LOCAL_MODEL_URL` (its `/v1` base, on loopback), named
//!   by `IANUA_SCENARIO_LOCAL_MODEL`.
//! - `claude`: Anthropic's API, with the key in `ANTHROPIC_API_KEY` and the
//!   model `claude-haiku-4-5-20251001` unless `IANUA_SCENARIO_CLAUDE_MODEL`
//!   names another.
//!
//! A scenario says how it is steered. [`Steering::Scripted`] scenarios force
//! exact moves, such as following a planted instruction, which no real
//! model can be made to do, so they always run against the scripted model,
//! whatever the setting says. [`Steering::Free`] scenarios run against the
//! chosen backend and check only rules that hold whatever the model does.
//!
//! A chosen backend that cannot be reached, or `claude` without its key,
//! fails at once naming the setting. Nothing falls back in silence.

use std::fmt;
use std::time::Duration;

use super::{Format, ModelServer, Script};
use crate::agent::r#loop::{ModelAccess, Sampling, Streaming, ToolSpec};
use crate::net::redaction;
use crate::wire::agents::models::ConnectProvider;

/// The setting naming the backend.
pub(crate) const MODEL_SETTING: &str = "IANUA_SCENARIO_MODEL";

/// The setting naming a local model server's OpenAI-compatible base.
pub(crate) const LOCAL_URL_SETTING: &str = "IANUA_SCENARIO_LOCAL_MODEL_URL";

/// The setting naming the local model.
pub(crate) const LOCAL_MODEL_SETTING: &str = "IANUA_SCENARIO_LOCAL_MODEL";

/// The setting holding Anthropic's key.
pub(crate) const CLAUDE_KEY_SETTING: &str = "ANTHROPIC_API_KEY";

/// The setting naming the Claude model, when not the default.
pub(crate) const CLAUDE_MODEL_SETTING: &str = "IANUA_SCENARIO_CLAUDE_MODEL";

/// The Claude model asked for unless another is named.
pub(crate) const DEFAULT_CLAUDE_MODEL: &str = "claude-haiku-4-5-20251001";

/// Anthropic's API host.
const ANTHROPIC_ENDPOINT: &str = "https://api.anthropic.com";

/// The model the scripted server is asked for: it answers any.
const SCRIPTED_MODEL: &str = "scenario-scripted";

/// The seed a local model is asked to sample with.
const LOCAL_SEED: u64 = 4821;

/// The networks a model on loopback lies in, for
/// `ALLOW_PRIVATE_MODEL_ENDPOINTS`.
const LOOPBACK: &str = "127.0.0.0/8";

/// How long a chosen backend has to answer that it is there.
const PROBE_WAIT: Duration = Duration::from_secs(10);

/// Which backend `IANUA_SCENARIO_MODEL` chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// The scripted model server.
    Scripted,
    /// A local open model behind an OpenAI-compatible server.
    Local,
    /// Anthropic's API.
    Claude,
}

impl BackendKind {
    /// The backend the environment chooses, `scripted` when it names none.
    ///
    /// # Errors
    ///
    /// [`BackendError::Unknown`] for a name that is none of the three.
    pub fn chosen() -> Result<Self, BackendError> {
        let named = std::env::var(MODEL_SETTING).unwrap_or_default();
        match named.trim().to_ascii_lowercase().as_str() {
            "" | "scripted" => Ok(Self::Scripted),
            "local" => Ok(Self::Local),
            "claude" => Ok(Self::Claude),
            _ => Err(BackendError::Unknown(named)),
        }
    }
}

/// How a scenario steers its model.
#[derive(Debug, Clone)]
pub enum Steering {
    /// Exact steps: always the scripted model, whatever the setting says.
    Scripted(Script),
    /// A goal and the tools offered, under the chosen backend; the scenario
    /// checks only what holds whatever the model does.
    Free {
        /// The goal, as vague as a person would put it.
        goal: String,
        /// The tools offered, allowed and forbidden alike.
        tools: Vec<ToolSpec>,
        /// What the scripted model answers when it is the chosen backend:
        /// a script that wanders, trying wrong tools, retrying, reaching
        /// outside the grant, so the scenario still runs in CI.
        wandering: Script,
    },
}

/// Why the chosen backend cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// `IANUA_SCENARIO_MODEL` names no backend.
    #[error("IANUA_SCENARIO_MODEL={0:?} names no backend; use scripted, local or claude")]
    Unknown(String),
    /// A setting the backend needs is not set.
    #[error("IANUA_SCENARIO_MODEL chooses {kind}, which needs {setting} set")]
    Missing {
        /// The backend.
        kind: &'static str,
        /// The setting missing.
        setting: &'static str,
    },
    /// The backend did not answer.
    #[error(
        "IANUA_SCENARIO_MODEL chooses {kind}, but it does not answer through {setting} ({status})"
    )]
    Unreachable {
        /// The backend.
        kind: &'static str,
        /// The setting it was reached through.
        setting: &'static str,
        /// What came back, in words.
        status: String,
    },
    /// The scripted model could not listen.
    #[error("the scripted model could not listen")]
    Listen(#[source] std::io::Error),
    /// The HTTP client used to probe the configured model could not be built.
    #[error("the model probe client could not be built")]
    Client(#[source] reqwest::Error),
}

/// Where a backend is and how it is asked. Holds a key, so `Debug` leaves
/// it out.
#[derive(Clone)]
struct Reach {
    format: Format,
    endpoint: String,
    api_key: Option<String>,
    model: String,
}

/// The model one scenario reasons with.
pub struct ModelBackend {
    kind: BackendKind,
    reach: Reach,
    server: Option<ModelServer>,
}

impl fmt::Debug for ModelBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModelBackend")
            .field("kind", &self.kind)
            .field("endpoint", &self.reach.endpoint)
            .field("model", &self.reach.model)
            .finish_non_exhaustive()
    }
}

impl ModelBackend {
    /// The backend `steering` runs against: the scripted model for a
    /// scripted scenario, the chosen backend for a free one, its script the
    /// wandering one.
    ///
    /// # Errors
    ///
    /// [`BackendError`] when the chosen backend is unknown, lacks a setting
    /// or does not answer.
    pub async fn for_steering(steering: &Steering) -> Result<Self, BackendError> {
        match steering {
            Steering::Scripted(script) => Self::scripted(script.clone()).await,
            Steering::Free { wandering, .. } => match BackendKind::chosen()? {
                BackendKind::Scripted => Self::scripted(wandering.clone()).await,
                BackendKind::Local => Self::local().await,
                BackendKind::Claude => Self::claude().await,
            },
        }
    }

    /// The scripted model answering from `script`.
    async fn scripted(script: Script) -> Result<Self, BackendError> {
        let server = ModelServer::start(script)
            .await
            .map_err(BackendError::Listen)?;
        let reach = Reach {
            format: Format::Anthropic,
            endpoint: server.endpoint(Format::Anthropic),
            api_key: Some(server.api_key().to_owned()),
            model: SCRIPTED_MODEL.to_owned(),
        };
        Ok(Self {
            kind: BackendKind::Scripted,
            reach,
            server: Some(server),
        })
    }

    /// The local model the settings name, once it answers.
    async fn local() -> Result<Self, BackendError> {
        let endpoint = required("local", LOCAL_URL_SETTING)?;
        let model = required("local", LOCAL_MODEL_SETTING)?;
        let probe = probe_client()?.get(format!("{}/models", endpoint.trim_end_matches('/')));
        ensure_answers(probe, "local", LOCAL_URL_SETTING).await?;
        let reach = Reach {
            format: Format::OpenAi,
            endpoint,
            api_key: None,
            model,
        };
        Ok(Self {
            kind: BackendKind::Local,
            reach,
            server: None,
        })
    }

    /// Anthropic's API, with the key from the environment, once it takes
    /// the key.
    async fn claude() -> Result<Self, BackendError> {
        let api_key = required("claude", CLAUDE_KEY_SETTING)?;
        redaction::secret_value(&api_key);
        let model = std::env::var(CLAUDE_MODEL_SETTING)
            .ok()
            .filter(|named| !named.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_CLAUDE_MODEL.to_owned());
        let probe = probe_client()?
            .get(format!("{ANTHROPIC_ENDPOINT}/v1/models"))
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01");
        ensure_answers(probe, "claude", CLAUDE_KEY_SETTING).await?;
        let reach = Reach {
            format: Format::Anthropic,
            endpoint: ANTHROPIC_ENDPOINT.to_owned(),
            api_key: Some(api_key),
            model,
        };
        Ok(Self {
            kind: BackendKind::Claude,
            reach,
            server: None,
        })
    }

    /// Which backend this is.
    #[must_use]
    pub fn kind(&self) -> BackendKind {
        self.kind
    }

    /// The scripted server, when this is it: what it was asked can be
    /// read back.
    #[must_use]
    pub fn server(&self) -> Option<&ModelServer> {
        self.server.as_ref()
    }

    /// The key it takes, when it takes one, to look for where it must not
    /// be.
    #[must_use]
    pub fn api_key(&self) -> Option<&str> {
        self.reach.api_key.as_deref()
    }

    /// How an agent's own loop reaches it, answers streaming as `streaming`
    /// says; a real model is asked to sample at temperature zero, with a
    /// fixed seed where its API takes one.
    #[must_use]
    pub fn access(&self, streaming: Streaming) -> ModelAccess {
        let sampling = match self.kind {
            BackendKind::Scripted => Sampling::ProviderDefault,
            BackendKind::Local => Sampling::Fixed {
                seed: Some(LOCAL_SEED),
            },
            BackendKind::Claude => Sampling::Fixed { seed: None },
        };
        ModelAccess {
            format: self.reach.format,
            endpoint: self.reach.endpoint.clone(),
            api_key: self.reach.api_key.clone().unwrap_or_default(),
            model: self.reach.model.clone(),
            streaming,
            sampling,
        }
    }

    /// The provider a tenant connects for its runs to reason with it,
    /// named `name` and cleared for internal data.
    #[must_use]
    pub fn provider(&self, name: &str) -> ConnectProvider {
        let kind = match self.kind {
            BackendKind::Local => "self_hosted",
            BackendKind::Scripted | BackendKind::Claude => self.reach.format.kind(),
        };
        ConnectProvider {
            name: name.to_owned(),
            kind: kind.to_owned(),
            endpoint: self.reach.endpoint.clone(),
            model: self.reach.model.clone(),
            api_key: self.reach.api_key.clone(),
            clearance: Some("Internal".to_owned()),
            pricing: None,
        }
    }

    /// The private networks the platform must let a model endpoint into to
    /// reach it, for `ALLOW_PRIVATE_MODEL_ENDPOINTS`: loopback, where the
    /// scripted and the local model listen; none for Anthropic's API.
    #[must_use]
    pub fn private_networks(&self) -> Option<&'static str> {
        match self.kind {
            BackendKind::Scripted | BackendKind::Local => Some(LOOPBACK),
            BackendKind::Claude => None,
        }
    }
}

/// The setting `setting`, which the backend `kind` needs.
fn required(kind: &'static str, setting: &'static str) -> Result<String, BackendError> {
    std::env::var(setting)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(BackendError::Missing { kind, setting })
}

/// A client for asking a backend whether it is there.
///
/// Returns the construction error when the HTTP client cannot be built.
fn probe_client() -> Result<reqwest::Client, BackendError> {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(PROBE_WAIT)
        .build()
        .map_err(BackendError::Client)
}

/// Refuses a backend whose `probe` is not answered with a success.
async fn ensure_answers(
    probe: reqwest::RequestBuilder,
    kind: &'static str,
    setting: &'static str,
) -> Result<(), BackendError> {
    let unreachable = |status: String| BackendError::Unreachable {
        kind,
        setting,
        status,
    };
    let answer = probe
        .send()
        .await
        .map_err(|_| unreachable("no answer".to_owned()))?;
    let status = answer.status();
    if status.is_success() {
        return Ok(());
    }
    Err(unreachable(format!("status {status}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::model::{Reply, Turn};

    /// A scripted scenario runs against the scripted model whatever the
    /// setting says, and its provider points at it.
    #[tokio::test]
    async fn a_scripted_scenario_always_gets_the_scripted_model() {
        let steering = Steering::Scripted(Script::new().then(Turn::answer(Reply::text("pong"))));

        let backend = ModelBackend::for_steering(&steering).await.unwrap();

        assert_eq!(backend.kind(), BackendKind::Scripted);
        assert!(backend.server().is_some());
        let provider = backend.provider("scripted");
        assert_eq!(provider.kind, "anthropic");
        assert_eq!(provider.api_key.as_deref(), backend.api_key());
        assert_eq!(backend.private_networks(), Some(LOOPBACK));
    }

    /// The error naming a missing key names the setting, not a value.
    #[test]
    fn a_missing_setting_is_named() {
        let error = BackendError::Missing {
            kind: "claude",
            setting: CLAUDE_KEY_SETTING,
        };

        assert!(error.to_string().contains("ANTHROPIC_API_KEY"));
    }
}
