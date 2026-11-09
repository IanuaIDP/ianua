//! Write code: a person says in words what a sandbox's code should do, and
//! the tenant's own model provider writes it in the sandbox's language,
//! using only the packages named. A failure from trying it goes back to
//! the model to fix.
//!
//! The model is told the names of the step's inputs, never their values,
//! and its answer is read as untrusted text held to the shape of a
//! version's code. Nothing is saved or run: the person reads the code and
//! its explanation, saves it as a version and tries it, and what a workflow
//! runs is only ever a version someone saved and published.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::chat::{ChatMessage, CompletionRequest};
use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::FieldName;
use ianua_domain::domains::workflows::sandbox::package::{MAX_PACKAGES, PackageName};
use ianua_domain::domains::workflows::sandbox::recipe::SandboxCode;
use ianua_domain::domains::workflows::sandbox::runtime::Language;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ModelProviderId, SandboxId, Text, UntrustedText};
use serde::Deserialize;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::agents::{ModelClient, ModelProviderStore, ModelTarget};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::SandboxStore;
use crate::services::model_targets::active_model;
use crate::use_case::Query;
use crate::use_cases::workflows::sandboxes::code::no_code;
use crate::use_cases::workflows::sandboxes::lookup::existing_sandbox;

/// The most tokens the model may answer with.
const ANSWER_TOKENS: u32 = 8_000;

/// The longest explanation kept, in characters.
const EXPLANATION_CHARS: usize = 600;

/// What a person asks the model to write.
pub struct WriteRequest {
    /// The sandbox the code is for, which sets its language.
    pub sandbox_id: SandboxId,
    /// The tenant's model provider the request goes to.
    pub provider_id: ModelProviderId,
    /// What the code should do, in up to 500 characters.
    pub words: Text,
    /// The names of the fields the code is handed.
    pub inputs: Vec<FieldName>,
    /// The packages it may import, by name as the sandbox's language's
    /// registry names them, at most 50.
    pub packages: Vec<String>,
    /// Whether it is written afresh or fixes earlier code.
    pub writing: Writing,
}

/// Whether code is written afresh or fixed.
pub enum Writing {
    /// Written from the words alone.
    Fresh,
    /// `code` failed as `failure` says, when tried; the model fixes it.
    Fix {
        /// The code that failed.
        code: SandboxCode,
        /// What its trial said, the end of its error.
        failure: UntrustedText,
    },
}

/// Code the model wrote, with what it says the code does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenCode {
    /// The code, held to a version's rules.
    pub code: SandboxCode,
    /// What it does, as the model says, in at most 600 characters.
    pub explanation: String,
}

/// The ports [`WriteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct WritePorts {
    /// Keeps the sandboxes.
    pub sandboxes: Arc<dyn SandboxStore>,
    /// The tenant's model providers.
    pub providers: Arc<dyn ModelProviderStore>,
    /// Opens a provider's key for one call.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Asks the model.
    pub model_client: Arc<dyn ModelClient>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Writes sandbox code with the tenant's model.
pub struct WriteUseCase {
    ports: WritePorts,
}

impl WriteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: WritePorts) -> Self {
        Self { ports }
    }

    /// The whole answer `target` gives to `prompt`.
    async fn answer(
        &self,
        target: &ModelTarget,
        prompt: &CompletionRequest,
    ) -> Result<String, AppError> {
        let completion = self
            .ports
            .model_client
            .complete(target, prompt)
            .await
            .map_err(|failure| AppError::upstream(failure.error))?;
        completion.finished().ok_or_else(|| {
            AppError::upstream(UnusableAnswer("the answer was cut off before it finished"))
        })
    }
}

impl Query for WriteUseCase {
    type Caller = CallerContext;
    type Input = WriteRequest;
    type Output = Result<WrittenCode, AppError>;

    /// The code the tenant's model writes for `request`, for the person
    /// `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without workflow-change rights.
    /// - `AppError::NotFound` for a missing tenant sandbox/active provider; `Domain` for invalid package names or more than 50 packages.
    /// - `AppError::Upstream` for an unreachable model or code violating version rules; `Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: WriteRequest,
    ) -> Result<WrittenCode, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let sandbox =
            existing_sandbox(self.ports.sandboxes.as_ref(), &tenant, &request.sandbox_id).await?;
        let target = active_model(
            self.ports.providers.as_ref(),
            self.ports.encryptor.as_ref(),
            &tenant,
            &request.provider_id,
        )
        .await?;
        let Some(language) = sandbox.kind().language() else {
            return Err(no_code());
        };
        let packages = package_names(language, &request.packages)?;
        let answer = self
            .answer(&target, &prompt(language, &request, &packages))
            .await?;
        written_from(&answer)
    }
}

/// An answer the model gave that holds no code a version keeps.
#[derive(Debug, thiserror::Error)]
#[error("the model gave no code to use: {0}")]
struct UnusableAnswer(&'static str);

/// The answer's shape.
#[derive(Deserialize)]
struct Answer {
    code: String,
    #[serde(default)]
    explanation: String,
}

/// The packages `written` names, read as `language`'s registry names them.
///
/// # Errors
///
/// - `AppError::Domain` when a name is not one the registry takes, or more
///   are named than a version may pin.
fn package_names(language: Language, written: &[String]) -> Result<Vec<PackageName>, AppError> {
    if written.len() > MAX_PACKAGES {
        return Err(AppError::from_domain(DomainError::invalid(message!(
            "workflows-too-many-packages-to-write-with",
            format!("name at most {MAX_PACKAGES} packages for the code to use")
        ))));
    }
    written
        .iter()
        .map(|name| {
            PackageName::new(language, name.as_str())
                .map_err(|error| AppError::from_domain(error.into()))
        })
        .collect()
}

/// What the model is asked for `request`, in `language`, using `packages`.
fn prompt(
    language: Language,
    request: &WriteRequest,
    packages: &[PackageName],
) -> CompletionRequest {
    let inputs: Vec<&str> = request.inputs.iter().map(FieldName::as_str).collect();
    let packages: Vec<&str> = packages.iter().map(PackageName::as_str).collect();
    let contract = contract_of(language);
    let fixing = fixing_of(&request.writing);
    let system = format!(
        "You write code for a sandbox with no network unless allowed and no files. Language: {contract}\n\
The input has these fields: {}. You are never shown their values.\n\
Import only these packages, besides the standard library: {}.\n\
Answer with one JSON object and nothing else: {{\"code\": \"...\", \"explanation\": \"one or two plain sentences\"}}.{fixing}",
        inputs.join(", "),
        packages.join(", ")
    );
    CompletionRequest {
        messages: vec![
            ChatMessage::system(&system),
            ChatMessage::user(request.words.as_str()),
        ],
        max_tokens: Some(ANSWER_TOKENS),
    }
}

/// What code in `language` must look like for the sandbox to run it.
fn contract_of(language: Language) -> &'static str {
    match language {
        Language::Python => {
            "Python. Define `def main(input):` taking a dict and returning a JSON-serialisable value."
        }
        Language::JavaScript => {
            "JavaScript (Node). Export one function: `module.exports = (input) => ...`, taking an object and returning a JSON-serialisable value, possibly async."
        }
    }
}

/// What the model is told of code it is asked to fix, or nothing for code
/// written fresh.
fn fixing_of(writing: &Writing) -> String {
    match writing {
        Writing::Fresh => String::new(),
        Writing::Fix { code, failure } => format!(
            "\nThis code failed when tried:\n{}\nIt said:\n{failure}\nFix it.",
            code.as_str()
        ),
    }
}

/// The code and explanation in `answer`, held to a version's rules.
fn written_from(answer: &str) -> Result<WrittenCode, AppError> {
    let start = answer.find('{');
    let end = answer.rfind('}');
    let (Some(start), Some(end)) = (start, end) else {
        return Err(AppError::upstream(UnusableAnswer("no JSON object")));
    };
    let parsed: Answer = answer
        .get(start..=end)
        .and_then(|object| serde_json::from_str(object).ok())
        .ok_or_else(|| AppError::upstream(UnusableAnswer("not the asked shape")))?;
    let code = SandboxCode::new(parsed.code)
        .map_err(|_| AppError::upstream(UnusableAnswer("code a version does not keep")))?;
    Ok(WrittenCode {
        code,
        explanation: parsed.explanation.chars().take(EXPLANATION_CHARS).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The model answers with its code and explanation around some words.
    /// The code is kept as a version's code would be.
    #[test]
    fn code_in_the_answer_is_kept() {
        let answer = "Here you go: {\"code\": \"def main(input):\\n\\treturn input\\n\", \"explanation\": \"Hands the input back.\"}";

        let written = written_from(answer).unwrap();

        assert!(written.code.as_str().starts_with("def main"));
        assert_eq!(written.explanation, "Hands the input back.");
    }

    /// Blank model code and code containing an escape control character are both
    /// rejected as upstream failures.
    #[test]
    fn an_answer_without_usable_code_is_refused() {
        let blank = written_from("{\"code\": \"   \"}");
        let escaping = written_from("{\"code\": \"print(1)\\u001b[2J\"}");

        assert!(matches!(blank, Err(AppError::Upstream(_))));
        assert!(matches!(escaping, Err(AppError::Upstream(_))));
    }
}
