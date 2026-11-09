//! Reading what an agent's declared purpose allows.
//!
//! A person states what a delegation or token is for, such as "read the
//! orders ledger and email a summary". A compiler turns that statement into
//! the action classes it implies (read, write, delete, ...), narrows the
//! requested capabilities to what those classes can use, and fingerprints
//! the statement so a drift monitor can tell a reworded purpose from a new
//! one. It runs once, when the grant or token is made, never per request.
//!
//! Two compilers sit behind the one port:
//!
//! - [`SemanticIntentCompiler`] asks an [`Embedder`] for vectors of the
//!   statement and of example phrasings of each class, and takes the classes
//!   whose examples sit close to the statement. Wording that shares no
//!   keyword still lands in the right class. A backend that fails or does
//!   not answer within a few seconds is an error; it never falls back to a
//!   wider reading.
//! - [`KeywordIntentCompiler`] reads the classes from keywords, for a
//!   deployment with no embeddings endpoint.
//!
//! Either way a statement that matches no class gets the read-only floor,
//! and the scope handed back is only ever narrower than the one asked for.

mod digest;
mod embeddings;
mod keywords;
mod semantic;

pub use embeddings::{Embedder, EmbeddingSettings, HttpEmbedder};
use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::agents::authority::intent::{
    CompiledIntent, IntentEnvelope, IntentStatement,
};
pub use keywords::KeywordIntentCompiler;
pub use semantic::SemanticIntentCompiler;

use crate::reading::intent::digest::fingerprint;

/// What `intent` compiles to once its classes are read as `envelope`: the
/// requested scope narrowed to them, the statement's fingerprint and the
/// classes themselves.
fn compiled(
    intent: &IntentStatement,
    requested: &CapabilitySet,
    envelope: IntentEnvelope,
) -> CompiledIntent {
    CompiledIntent::new(envelope.narrow(requested), fingerprint(intent), envelope)
}
