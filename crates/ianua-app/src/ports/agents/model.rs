//! What an agent's run reaches out to: the model it asks and the tools it
//! calls.

use async_trait::async_trait;
use ianua_domain::domains::agents::execution::chat::{Completion, CompletionRequest};
use ianua_domain::domains::agents::execution::model_provider::{
    ModelEndpoint, ModelName, ModelProvider, ModelProviderKind,
};
use ianua_domain::domains::agents::execution::run::ToolArguments;
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::execution::usage::ModelUsage;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentRunId, AgentToolId, ModelProviderId};

use crate::ports::TenantScoped;
use crate::ports::agents::TaskToken;
use crate::tenancy::ScopedTenant;

/// A resolved, ready-to-call model target: the provider's endpoint and model
/// plus the **decrypted** API key.
///
/// The application resolves a [`ModelProvider`] into this by decrypting the
/// stored credential reference. The key is held transiently for the duration of
/// one call and is never persisted, logged, or included in `Debug`.
pub struct ModelTarget {
    /// The backend kind (selects the wire format).
    pub kind: ModelProviderKind,
    /// The base endpoint URL.
    pub endpoint: ModelEndpoint,
    /// The model to request.
    pub model: ModelName,
    /// The decrypted API key, or `None` for a keyless endpoint.
    pub api_key: Option<Secret>,
}

impl std::fmt::Debug for ModelTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelTarget")
            .field("kind", &self.kind)
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Dyn-safe port for calling a bring-your-own LLM.
///
/// The adapter speaks the wire format the target's kind names: Anthropic's
/// Messages API, or Chat Completions for OpenAI and self-hosted endpoints.
/// The orchestration loop reasons through this; the model's requested
/// actions are still gated by the proxy, so a compromised model cannot
/// exceed the agent's authority.
#[async_trait]
pub trait ModelClient: Send + Sync {
    /// Requests a completion from the target model.
    ///
    /// The completion carries the tokens the provider reported the call
    /// used, or `ModelUsage::Unreported` when it reported none; a run under
    /// a spend limit stops on an unreported call, so the adapter never
    /// guesses. It says too whether the model finished its answer. The
    /// adapter times the call out, so a hung provider does not hold a run's
    /// worker.
    ///
    /// # Errors
    ///
    /// Returns a [`ModelFailure`] when there is no answer to use: the
    /// backend is unreachable, errors, or answers with something that
    /// cannot be read, or the model declined. A provider that answered and
    /// billed the call still has its usage carried in the failure.
    async fn complete(
        &self,
        target: &ModelTarget,
        request: &CompletionRequest,
    ) -> Result<Completion, ModelFailure>;
}

/// A model call that gave no answer to use, and what it cost.
///
/// A provider can answer, bill the call and still give nothing a run can
/// use: an answer in a shape it cannot read, or the model declining. The
/// tokens were spent all the same, so a run under a spend limit counts
/// them. Without that, a model that keeps declining spends without end.
#[derive(Debug)]
pub struct ModelFailure {
    /// What the provider billed for the call.
    pub charge: ModelCharge,
    /// Why there is no answer.
    pub error: DomainError,
}

impl ModelFailure {
    /// A call the provider never answered with a bill: it could not be
    /// reached, did not answer in time, or refused the request.
    #[must_use]
    pub fn unbilled(error: DomainError) -> Self {
        Self {
            charge: ModelCharge::Unbilled,
            error,
        }
    }

    /// A call the provider answered and billed, reporting `usage`, whose
    /// answer cannot be used.
    #[must_use]
    pub fn billed(usage: ModelUsage, error: DomainError) -> Self {
        Self {
            charge: ModelCharge::Billed(usage),
            error,
        }
    }
}

impl From<DomainError> for ModelFailure {
    fn from(error: DomainError) -> Self {
        Self::unbilled(error)
    }
}

/// What a failed model call cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelCharge {
    /// The provider gave no answer it bills for.
    Unbilled,
    /// The provider answered and billed the call, with the usage it
    /// reported, or that it reported none.
    Billed(ModelUsage),
}

/// Dyn-safe port for persisting a tenant's model providers.
#[async_trait]
pub trait ModelProviderStore: Send + Sync + TenantScoped {
    /// Finds a provider by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ModelProviderId,
    ) -> Result<Option<ModelProvider<ResolvedTenant>>, DomainError>;

    /// Lists the tenant's providers.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ModelProvider<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated provider.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        provider: &ModelProvider<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a provider.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &ModelProviderId,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for persisting a tenant's registered agent tools.
#[async_trait]
pub trait ToolStore: Send + Sync + TenantScoped {
    /// Finds a tool by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentToolId,
    ) -> Result<Option<AgentTool<ResolvedTenant>>, DomainError>;

    /// Lists the tenant's tools.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AgentTool<ResolvedTenant>>, DomainError>;

    /// Saves a new or updated tool.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        tool: &AgentTool<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes a tool.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &AgentToolId) -> Result<(), DomainError>;
}

/// Identifies one tool invocation within a run, so the adapter can derive a
/// stable idempotency key and present the run's task token to the proxy. The
/// same `(run_id, step)` re-driven after a crash with the same tool and
/// arguments yields the same key, letting the upstream dedupe a side effect
/// that fired but wasn't persisted before the reclaim.
#[derive(Debug, Clone)]
pub struct ToolInvocationContext {
    /// The run the call belongs to.
    pub run_id: AgentRunId,
    /// The 1-based step position of the call within the run.
    pub step: u32,
    /// The run's task token. Every call carries one: a call the proxy cannot
    /// authorize is a call that does not happen.
    pub authorization: TaskToken,
}

/// Dyn-safe port for invoking a tool call the loop has already permitted.
///
/// The adapter performs the HTTP call the tool binds to (its method + path),
/// with `arguments` (a JSON string) shaping the query/body, and returns the
/// response body. It sends every call through the zero-trust proxy bearing the
/// run's task token, so the proxy authorizes the call as actually made. The
/// loop's own gate decided only which tool, not which URL.
#[async_trait]
pub trait ToolInvoker: Send + Sync {
    /// Invokes a permitted tool and returns its response body.
    ///
    /// `context` identifies the invocation so the adapter can attach a stable
    /// idempotency key for at-most-once side effects under run reclaim.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] when the call fails, when no
    /// proxy is configured to carry it, or when the arguments would fill a
    /// path placeholder with anything but a single path segment.
    async fn invoke(
        &self,
        tool: &AgentTool<ResolvedTenant>,
        arguments: &ToolArguments,
        context: &ToolInvocationContext,
    ) -> Result<String, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decrypted key is held for one call; a log line of the target must
    /// still say which endpoint was called, and never with what key.
    #[test]
    fn debug_names_the_model_target_but_not_its_api_key() {
        let target = ModelTarget {
            kind: ModelProviderKind::OpenAi,
            endpoint: ModelEndpoint::new("https://api.openai.com/v1").unwrap(),
            model: ModelName::new("gpt-4o").unwrap(),
            api_key: Some(Secret::new("sk-distinctivesecret")),
        };

        let rendered = format!("{target:?}");

        assert!(!rendered.contains("sk-distinctivesecret"), "{rendered}");
        assert!(rendered.contains("https://api.openai.com/v1"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
