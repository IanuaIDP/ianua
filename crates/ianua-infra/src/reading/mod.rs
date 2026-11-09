//! Reading what a caller sent, before anything acts on it: the cost of a
//! GraphQL request, the shape of an agent's message, what an agent's
//! declared purpose allows, and how deep an XML document nests.
//!
//! Each reads a tenant's or a caller's input, so each is bounded: a body
//! past its size, a query nested past what the parser may recurse, a
//! schema reaching outside itself or a purpose the embeddings service does
//! not read in time is refused, never passed through unread.

mod graphql;
mod intent;
mod messages;
pub(crate) mod xml;

pub use graphql::DocumentGraphQlAnalyzer;
pub use intent::{
    Embedder, EmbeddingSettings, HttpEmbedder, KeywordIntentCompiler, SemanticIntentCompiler,
};
pub use messages::JsonSchemaMessageShape;
