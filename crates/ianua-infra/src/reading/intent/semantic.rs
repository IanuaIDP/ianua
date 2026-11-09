//! The intent compiler that reads a statement by meaning.
//!
//! It asks the [`Embedder`] for vectors of the statement and of a few
//! example phrasings of each action class, in one call, and takes every
//! class whose closest example reaches the threshold by cosine similarity.
//! A statement no class reaches gets the read-only floor. The whole
//! compile is held to a few seconds; a backend that fails or is slower is
//! an error, never a wider reading.

use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::agents::IntentCompiler;
use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::agents::authority::intent::{
    CompiledIntent, IntentEnvelope, IntentStatement,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ActionClass;

use crate::reading::intent::compiled;
use crate::reading::intent::embeddings::Embedder;

/// How long one compile may take, the embedding call included.
const COMPILE_LIMIT: Duration = Duration::from_secs(5);

/// Every action class, each scored against the statement.
const CLASSES: [ActionClass; 7] = [
    ActionClass::Read,
    ActionClass::Write,
    ActionClass::Delete,
    ActionClass::Configure,
    ActionClass::Communicate,
    ActionClass::Financial,
    ActionClass::Admin,
];

/// Example phrasings of each class, which a statement is compared with.
const EXAMPLES: &[(ActionClass, &str)] = &[
    (ActionClass::Read, "read data and view information"),
    (ActionClass::Read, "list records and fetch a report"),
    (ActionClass::Read, "look up, analyze and summarize"),
    (ActionClass::Write, "create or update a record"),
    (ActionClass::Write, "modify and save changes"),
    (ActionClass::Write, "book, schedule or submit"),
    (ActionClass::Delete, "delete or remove records"),
    (ActionClass::Delete, "purge, shred and clean up old data"),
    (ActionClass::Delete, "archive then destroy stale files"),
    (ActionClass::Configure, "change configuration and settings"),
    (
        ActionClass::Configure,
        "enable or disable a feature and rotate keys",
    ),
    (ActionClass::Communicate, "send an email or notification"),
    (
        ActionClass::Communicate,
        "message, alert and reply to someone",
    ),
    (ActionClass::Financial, "process a payment or refund"),
    (ActionClass::Financial, "charge, invoice and transfer funds"),
    (ActionClass::Admin, "manage roles and permissions"),
    (
        ActionClass::Admin,
        "grant access and administer the access policy",
    ),
];

/// Reads an intent's classes by how close its meaning is to each class's
/// examples.
#[derive(Debug)]
pub struct SemanticIntentCompiler<E> {
    embedder: E,
    threshold: f32,
}

impl<E: Embedder> SemanticIntentCompiler<E> {
    /// A compiler over `embedder`, taking a class when one of its examples
    /// reaches `threshold` cosine similarity to the statement.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when `threshold` is not between 0
    /// and 1.
    pub fn new(embedder: E, threshold: f32) -> Result<Self, DomainError> {
        if !(0.0..=1.0).contains(&threshold) {
            return Err(DomainError::invalid(message!(
                "infra-the-similarity-threshold-must-be-between",
                "the similarity threshold must be between 0 and 1"
            )));
        }
        Ok(Self {
            embedder,
            threshold,
        })
    }

    /// The classes `intent` is close to.
    async fn classes_of(&self, intent: &IntentStatement) -> Result<IntentEnvelope, DomainError> {
        let texts: Vec<&str> = std::iter::once(intent.as_str())
            .chain(EXAMPLES.iter().map(|(_, text)| *text))
            .collect();
        let vectors = self.embedder.embed(&texts).await?;
        let Some((statement, examples)) = vectors.split_first() else {
            return Err(DomainError::infra_msg("the embedder answered no vector"));
        };
        if examples.len() != EXAMPLES.len() {
            return Err(DomainError::infra_msg(
                "the embedder answered another number of vectors than it was asked for",
            ));
        }
        Ok(nearest(statement, examples, self.threshold))
    }
}

#[async_trait]
impl<E: Embedder> IntentCompiler for SemanticIntentCompiler<E> {
    async fn compile(
        &self,
        intent: &IntentStatement,
        requested: &CapabilitySet,
    ) -> Result<CompiledIntent, DomainError> {
        let envelope = tokio::time::timeout(COMPILE_LIMIT, self.classes_of(intent))
            .await
            .map_err(DomainError::infra)??;
        Ok(compiled(intent, requested, envelope))
    }
}

/// The classes whose closest example reaches `threshold`, or reading alone
/// when none does.
fn nearest(statement: &[f32], examples: &[Vec<f32>], threshold: f32) -> IntentEnvelope {
    let reached: Vec<ActionClass> = CLASSES
        .iter()
        .copied()
        .filter(|class| closest(*class, statement, examples) >= threshold)
        .collect();
    if reached.is_empty() {
        return IntentEnvelope::new([ActionClass::Read]);
    }
    IntentEnvelope::new(reached)
}

/// How close `statement` comes to the nearest example of `class`.
fn closest(class: ActionClass, statement: &[f32], examples: &[Vec<f32>]) -> f32 {
    EXAMPLES
        .iter()
        .zip(examples)
        .filter(|((of, _), _)| *of == class)
        .map(|(_, example)| cosine(statement, example))
        .fold(f32::MIN, f32::max)
}

/// The cosine similarity of two vectors, or zero when either has no
/// length.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let lengths = length(a) * length(b);
    if lengths <= 0.0 {
        return 0.0;
    }
    dot / lengths
}

/// The Euclidean length of a vector.
fn length(vector: &[f32]) -> f32 {
    vector.iter().map(|x| x * x).sum::<f32>().sqrt()
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::HttpMethod;
    use serde_json::{Value, json};
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use crate::reading::intent::embeddings::{EmbeddingSettings, HttpEmbedder};

    /// The words that pull a text towards each axis, one axis a class, in
    /// the order of [`CLASSES`]. The stand-in model places a text by how
    /// many of each axis's words it holds, so related phrasings cluster
    /// without sharing a keyword with the class's name.
    const AXES: [&[&str]; 7] = [
        &[
            "read", "view", "list", "fetch", "look", "analyz", "summar", "review", "report",
        ],
        &[
            "create", "update", "modif", "save", "book", "schedul", "submit", "edit",
        ],
        &[
            "delete", "remove", "purge", "shred", "destroy", "archive", "clean", "obsolete",
            "stale",
        ],
        &["config", "setting", "enable", "disable", "rotate"],
        &["send", "email", "notif", "message", "alert", "reply"],
        &[
            "payment", "refund", "charge", "invoice", "transfer", "funds",
        ],
        &[
            "role",
            "permission",
            "grant",
            "access",
            "administer",
            "policy",
        ],
    ];

    fn placed(text: &str) -> Vec<f32> {
        let lower = text.to_lowercase();
        AXES.iter()
            .map(|words| words.iter().filter(|word| lower.contains(**word)).count() as f32)
            .collect()
    }

    /// An embeddings endpoint that answers every text with its place on
    /// the axes, in the API's own shape.
    fn concept_model(request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let data: Vec<Value> = body["input"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, text)| json!({"index": index, "embedding": placed(text.as_str().unwrap())}))
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({ "data": data }))
    }

    async fn model(response: impl wiremock::Respond + 'static) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/embeddings"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    fn compiler(server: &MockServer) -> SemanticIntentCompiler<HttpEmbedder> {
        let embedder = HttpEmbedder::new(EmbeddingSettings {
            endpoint: Url::parse(&server.uri()).unwrap(),
            model: "concepts".to_owned(),
            api_key: None,
        })
        .unwrap();
        SemanticIntentCompiler::new(embedder, 0.4).unwrap()
    }

    async fn compile(server: &MockServer, intent: &str) -> Result<CompiledIntent, DomainError> {
        compiler(server)
            .compile(
                &IntentStatement::new(intent).unwrap(),
                &CapabilitySet::empty(),
            )
            .await
    }

    /// Wording no keyword list holds still lands in its class: shredding
    /// obsolete paperwork is a delete, not a read.
    #[tokio::test]
    async fn novel_phrasing_lands_in_its_class() {
        let server = model(concept_model).await;

        let compiled = compile(&server, "shred obsolete paperwork").await.unwrap();

        let envelope = compiled.envelope();
        assert!(envelope.permits_action(HttpMethod::Delete, "/papers/1"));
        assert!(!envelope.permits_action(HttpMethod::Get, "/papers/1"));
    }

    /// A purpose naming two things reaches both, and nothing more.
    #[tokio::test]
    async fn a_purpose_spanning_two_classes_reaches_both() {
        let server = model(concept_model).await;

        let compiled = compile(&server, "read the ledger and email a summary")
            .await
            .unwrap();

        let envelope = compiled.envelope();
        assert!(envelope.permits(ActionClass::Read));
        assert!(envelope.permits(ActionClass::Communicate));
        assert!(!envelope.permits(ActionClass::Delete));
    }

    /// A statement matching none of the stand-in model's concepts compiles to
    /// reading alone.
    #[tokio::test]
    async fn an_unplaceable_statement_gets_the_read_only_floor() {
        let server = model(concept_model).await;

        let compiled = compile(&server, "xyzzy plugh").await.unwrap();

        assert_eq!(compiled.envelope().allowed(), &[ActionClass::Read]);
    }

    /// An embedding endpoint's 500 response fails intent compilation.
    #[tokio::test]
    async fn a_failing_backend_fails_the_compile() {
        let server = model(ResponseTemplate::new(500)).await;

        let result = compile(&server, "read the ledger").await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A backend delaying its answer for twenty seconds makes intent compilation
    /// fail within ten seconds.
    #[tokio::test]
    async fn a_slow_backend_fails_the_compile_in_time() {
        let server = model(ResponseTemplate::new(200).set_delay(Duration::from_secs(20))).await;

        let started = std::time::Instant::now();
        let result = compile(&server, "read the ledger").await;

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// An embedding answer containing no vectors fails intent compilation.
    #[tokio::test]
    async fn an_empty_answer_fails_the_compile() {
        let server = model(ResponseTemplate::new(200).set_body_json(json!({"data": []}))).await;

        let result = compile(&server, "read the ledger").await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A NaN similarity threshold fails compiler configuration validation.
    #[tokio::test]
    async fn a_threshold_outside_zero_and_one_is_refused() {
        let server = model(concept_model).await;
        let embedder = HttpEmbedder::new(EmbeddingSettings {
            endpoint: Url::parse(&server.uri()).unwrap(),
            model: "concepts".to_owned(),
            api_key: None,
        })
        .unwrap();

        let result = SemanticIntentCompiler::new(embedder, f32::NAN);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
