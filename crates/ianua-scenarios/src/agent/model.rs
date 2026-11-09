//! The scripted model: an HTTP server speaking Anthropic's Messages API
//! (`POST /v1/messages`) and OpenAI's Chat Completions
//! (`POST /v1/chat/completions`), answering from a [`Script`].
//!
//! To whoever calls it, the platform or an agent's own loop, it is the
//! provider: it takes the key where each provider documents it, refuses a
//! call without it the way the provider does, answers with `tool_use`
//! blocks or `tool_calls` when tools were offered natively and with the
//! JSON a prompt asks for when they were only described, reports `usage`,
//! ends with `stop_reason` or `finish_reason`, and streams server-sent
//! events when `stream` is set.
//!
//! Every request is kept, as it came, so a test can say what the caller
//! sent: the tools it offered, its system prompt, and no secret that does
//! not belong.
//!
//! It is one of three backends a scenario's model may be, chosen by
//! `IANUA_SCENARIO_MODEL` ([`backend`]): the others are a local open model
//! and Anthropic's API.

mod anthropic;
pub mod backend;
mod desk;
mod http;
mod openai;
mod received;
pub mod script;

use std::fmt;
use std::net::SocketAddr;

pub use backend::{BackendError, BackendKind, ModelBackend, Steering};
use desk::Desk;
pub use received::Received;
pub use script::{Reply, Script, Turn, When};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::stack::secrets;

/// Which provider's wire format a request came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Anthropic's Messages API.
    Anthropic,
    /// OpenAI's Chat Completions.
    OpenAi,
}

impl Format {
    /// The provider kind the platform names it by, for a provider's
    /// `kind`.
    #[must_use]
    pub fn kind(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }
}

/// The tokens one answer is counted at: a quarter of the characters each
/// way, as a rough tokenizer counts, never zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Usage {
    input: u64,
    output: u64,
}

impl Usage {
    /// The usage of an answer of `output` characters to a request of
    /// `input` characters.
    fn counted(input: usize, output: usize) -> Self {
        let tokens = |characters: usize| u64::try_from(characters / 4).unwrap_or(u64::MAX).max(1);
        Self {
            input: tokens(input),
            output: tokens(output),
        }
    }
}

/// The scripted model, listening on a port of loopback until dropped.
pub struct ModelServer {
    address: SocketAddr,
    api_key: String,
    desk: Desk,
    accepting: JoinHandle<()>,
}

impl fmt::Debug for ModelServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModelServer")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl ModelServer {
    /// A model answering from `script`, taking calls made with a key of
    /// its own.
    ///
    /// # Errors
    ///
    /// When no port can be listened on.
    pub async fn start(script: Script) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let api_key = format!("scenario-model-{}", secrets::hex(8));
        let desk = Desk::open(script);
        let accepting = http::serve(listener, desk.clone(), api_key.clone());
        Ok(Self {
            address,
            api_key,
            desk,
            accepting,
        })
    }

    /// Where a provider of `format` is reached, as its `endpoint` is
    /// written: Anthropic's API host, or OpenAI's API base under `/v1`.
    #[must_use]
    pub fn endpoint(&self, format: Format) -> String {
        match format {
            Format::Anthropic => format!("http://{}", self.address),
            Format::OpenAi => format!("http://{}/v1", self.address),
        }
    }

    /// The key it takes, as a provider's key is pasted in.
    #[must_use]
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Every request it received, in order.
    pub async fn received(&self) -> Vec<Received> {
        self.desk.received().await
    }

    /// How many requests no turn of the script answered.
    pub async fn unanswered(&self) -> usize {
        self.desk.unanswered().await
    }

    /// How many turns of the script were not given yet.
    pub async fn turns_left(&self) -> usize {
        self.desk.turns_left().await
    }
}

impl Drop for ModelServer {
    /// Stops taking connections.
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// How many characters one streamed piece carries.
const PIECE: usize = 16;

/// `text` in pieces of a few characters, cut on character boundaries, as
/// a stream delivers it.
fn pieces(text: &str) -> Vec<String> {
    let characters: Vec<char> = text.chars().collect();
    characters
        .chunks(PIECE)
        .map(|piece| piece.iter().collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pieces put back together are the text, cut on character
    /// boundaries.
    #[test]
    fn pieces_put_together_are_the_text() {
        let text = "Ünïcödé text that is longer than one piece";

        let cut = pieces(text);

        assert!(cut.len() > 1);
        assert_eq!(cut.concat(), text);
    }

    /// Usage is never zero, so a provider never reports an empty bill.
    #[test]
    fn usage_is_never_zero() {
        assert_eq!(
            Usage::counted(0, 2),
            Usage {
                input: 1,
                output: 1
            }
        );
        assert_eq!(
            Usage::counted(400, 40),
            Usage {
                input: 100,
                output: 10
            }
        );
    }
}
