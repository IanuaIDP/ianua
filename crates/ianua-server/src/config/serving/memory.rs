//! Memory: the platform's own embedding server, which fills the memories of
//! a tenant without an embedding model of its own, and where the memories'
//! texts and vectors are kept, pgvector inside the platform's Postgres or
//! a vector server.

use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_domain::domains::agents::execution::model_provider::ModelName;
use ianua_infra::http::PlatformEmbeddings;
use ianua_infra::vectors::VectorServer;

/// Where the memories' texts and vectors are kept.
#[derive(Debug, Clone)]
pub(crate) enum VectorStore {
    /// In pgvector, inside the platform's own Postgres.
    Postgres,
    /// In a server speaking Qdrant's REST API.
    Server(VectorServer),
}

/// The memory settings.
#[derive(Debug, Clone)]
pub(crate) struct MemoryConfig {
    /// `EMBEDDING_URL`, the platform's embedding server's OpenAI-compatible
    /// base, such as `http://embeddings:8080/v1`, and `EMBEDDING_MODEL`,
    /// the model it serves: both or neither. With neither, a memory is
    /// filled only through a tenant's provider.
    pub platform: Option<PlatformEmbeddings>,
    /// `EMBEDDING_TIMEOUT_SECONDS` (30): the longest one embedding call may
    /// take, at the platform's server or a tenant's provider.
    pub timeout: Duration,
    /// `VECTOR_STORE_URL`, a vector server, and `VECTOR_STORE_API_KEY` (or
    /// `_FILE`), the key it takes, if any; pgvector when the address is
    /// unset.
    pub vectors: VectorStore,
}

impl MemoryConfig {
    /// The memory settings `vars` names.
    ///
    /// # Errors
    ///
    /// An address that is no URL, a model name that is not one, only one
    /// of `EMBEDDING_URL` and `EMBEDDING_MODEL`, or a vector server's key
    /// with no vector server.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            platform: platform(vars)?,
            timeout: vars.seconds("EMBEDDING_TIMEOUT_SECONDS", Duration::from_secs(30))?,
            vectors: vectors(vars)?,
        })
    }
}

/// The platform's embedding server `vars` names, both its address and its
/// model, or neither.
fn platform(vars: &Env) -> Read<Option<PlatformEmbeddings>> {
    let url = vars.url("EMBEDDING_URL")?;
    let model = vars.optional("EMBEDDING_MODEL")?;
    match (url, model) {
        (None, None) => Ok(None),
        (Some(url), Some(model)) => Ok(Some(PlatformEmbeddings {
            url,
            model: ModelName::new(model)
                .map_err(|_| ConfigError::invalid("EMBEDDING_MODEL", "a model name"))?,
        })),
        (Some(_), None) => Err(ConfigError::missing("EMBEDDING_MODEL")),
        (None, Some(_)) => Err(ConfigError::missing("EMBEDDING_URL")),
    }
}

/// Where `vars` keeps the memories' vectors.
fn vectors(vars: &Env) -> Read<VectorStore> {
    let url = vars.url("VECTOR_STORE_URL")?;
    let api_key = vars.secret("VECTOR_STORE_API_KEY")?;
    match (url, api_key) {
        (Some(url), api_key) => Ok(VectorStore::Server(VectorServer { url, api_key })),
        (None, None) => Ok(VectorStore::Postgres),
        (None, Some(_)) => Err(ConfigError::missing("VECTOR_STORE_URL")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing set, memories keep their vectors in pgvector and only
    /// tenants' providers fill them.
    #[test]
    fn unset_means_pgvector_and_no_platform_server() {
        let config = MemoryConfig::read(&Env::of([])).unwrap();

        assert!(config.platform.is_none());
        assert!(matches!(config.vectors, VectorStore::Postgres));
    }

    /// The platform's server needs both its address and its model.
    #[test]
    fn the_platform_server_needs_its_address_and_model() {
        let both = MemoryConfig::read(&Env::of([
            ("EMBEDDING_URL", "http://embeddings:8080/v1"),
            ("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5"),
        ]))
        .unwrap();
        let half = MemoryConfig::read(&Env::of([("EMBEDDING_URL", "http://embeddings:8080/v1")]));

        assert_eq!(
            both.platform.map(|server| server.model.as_str().to_owned()),
            Some("BAAI/bge-small-en-v1.5".to_owned())
        );
        assert!(half.is_err());
    }

    /// A vector server's key with no vector server is refused, rather than
    /// keeping the vectors in pgvector unasked.
    #[test]
    fn a_vector_key_needs_its_server() {
        let keyless =
            MemoryConfig::read(&Env::of([("VECTOR_STORE_URL", "http://vectors:6333")])).unwrap();
        let orphan = MemoryConfig::read(&Env::of([("VECTOR_STORE_API_KEY", "words not a key")]));

        assert!(matches!(keyless.vectors, VectorStore::Server(_)));
        assert!(orphan.is_err());
    }
}
