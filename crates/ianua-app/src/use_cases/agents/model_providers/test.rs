//! Test model provider: check that a provider answers.
//!
//! Opens the provider's sealed API key, sends a trivial completion, and
//! returns the model's reply. This is how someone confirms a self-hosted
//! endpoint is reachable before runs depend on it. The outcome is kept on
//! the provider, so it still shows after the page reloads.
//!
//! A probe spends the provider's key and changes its record, so only
//! someone allowed to manage agents sends one, and they are refused before
//! the key is spent.

use std::error::Error as _;
use std::sync::Arc;

use ianua_domain::domains::agents::execution::chat::{ChatMessage, Completion, CompletionRequest};
use ianua_domain::domains::agents::execution::model_provider::{
    ModelProvider, ModelProviderTestStatus,
};
use ianua_domain::domains::agents::identity::control::AgentControl;
use ianua_domain::domains::authorization::permission::{AgentAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::ModelProviderId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{ModelClient, ModelProviderStore, ModelTarget};
use crate::ports::authentication::SecretEncryptor;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::lookup::existing_model_provider;
use crate::use_cases::agents::model_providers::connect::opened_key;

/// What the probe asks the model.
const PROBE_PROMPT: &str = "Reply with the single word: OK";

/// The most tokens the probe's answer may take.
const PROBE_MAX_TOKENS: u32 = 16;

/// The ports [`TestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct TestPorts {
    /// Loads and saves the provider.
    pub provider_store: Arc<dyn ModelProviderStore>,
    /// Opens the sealed API key.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Calls the model.
    pub model_client: Arc<dyn ModelClient>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Probes a model provider of the caller's tenant.
pub struct TestUseCase {
    ports: TestPorts,
}

impl TestUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: TestPorts) -> Self {
        Self { ports }
    }

    /// The answer of `tenant`'s `provider` to the probe, once its key is
    /// open. A key that cannot be opened is ianua's failure, not the
    /// provider's, so it is an error rather than an answer.
    async fn probed(
        &self,
        tenant: &ScopedTenant,
        provider: &ModelProvider<ResolvedTenant>,
    ) -> Result<Result<Completion, DomainError>, AppError> {
        let api_key = opened_key(self.ports.encryptor.as_ref(), tenant, provider)
            .await
            .or_internal()?;
        Ok(probe(self.ports.model_client.as_ref(), provider, api_key).await)
    }
}

impl Command for TestUseCase {
    type Caller = CallerContext;
    type Input = ModelProviderId;
    type Output = Result<String, AppError>;

    /// Sends a trivial completion to the provider and returns the model's
    /// reply. The outcome is kept on the provider and recorded, whether the
    /// provider answered or not.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such provider.
    /// - `AppError::Forbidden` when the caller may not manage agents.
    /// - `AppError::Upstream` when the backend is unreachable or answers
    ///   with an error. The failure is kept all the same.
    /// - `AppError::Internal` when the provider's key cannot be opened,
    ///   which is ianua's failure and not the provider's, so nothing is
    ///   kept; or on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        provider_id: ModelProviderId,
    ) -> Result<String, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Agents(AgentAction::Manage))
            .map_err(AppError::from_domain)?;
        let mut provider =
            existing_model_provider(self.ports.provider_store.as_ref(), &tenant, &provider_id)
                .await?;
        let outcome = self.probed(&tenant, &provider).await?;
        let result = test_status(&outcome);
        let message = outcome.as_ref().err().map(failure_message);
        provider
            .record_test_result(&AgentControl::new(&authority), result, message.as_deref())
            .map_err(AppError::from_domain)?;
        self.ports
            .provider_store
            .save(&tenant, &provider)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), provider.take_events(&tenant))
            .await
            .or_internal()?;
        outcome
            .map(|completion| completion.content)
            .map_err(AppError::upstream)
    }
}

/// The model's answer to the probe, through `provider` with its opened
/// `api_key`. An answer cut off at the probe's small cap still shows the
/// provider answers, so it passes; a failure is reported by its reason,
/// since a probe is no run and keeps no spend.
async fn probe(
    client: &dyn ModelClient,
    provider: &ModelProvider<ResolvedTenant>,
    api_key: Option<Secret>,
) -> Result<Completion, DomainError> {
    let target = ModelTarget {
        kind: provider.kind(),
        endpoint: provider.endpoint().clone(),
        model: provider.model().clone(),
        api_key,
    };
    let request =
        CompletionRequest::single(ChatMessage::user(PROBE_PROMPT), Some(PROBE_MAX_TOKENS));
    client
        .complete(&target, &request)
        .await
        .map_err(|failure| failure.error)
}

/// Whether the probe passed.
fn test_status(outcome: &Result<Completion, DomainError>) -> ModelProviderTestStatus {
    match outcome {
        Ok(_) => ModelProviderTestStatus::Passed,
        Err(_) => ModelProviderTestStatus::Failed,
    }
}

/// Why the probe failed, in words a person can act on.
///
/// An infrastructure error's own text is a fixed "infrastructure error";
/// the reason (connection refused, timeout, an error status) is its source.
fn failure_message(err: &DomainError) -> String {
    err.source()
        .map_or_else(|| err.to_string(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::agents::execution::model_provider::{
        CreateModelProviderParams, ModelEndpoint, ModelName, ModelProviderKind, ProviderKey,
    };
    use ianua_domain::domains::agents::execution::usage::ModelPricing;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::types::{Label, SealedSecret};

    use super::*;
    use crate::ports::authentication::SealedFor;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::agents::{
        FakeModelClient, FakeModelProviderStore, agent_manager, connected_provider,
        providers_holding, someone_else,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An encryptor whose keys cannot be reached.
    struct LockedVault;

    #[async_trait]
    impl SecretEncryptor for LockedVault {
        async fn encrypt(&self, _: &[u8], _: &SealedFor) -> Result<SealedSecret, DomainError> {
            Err(DomainError::infra_msg("the key vault is unreachable"))
        }

        async fn decrypt(&self, _: &SealedSecret, _: &SealedFor) -> Result<Vec<u8>, DomainError> {
            Err(DomainError::infra_msg("the key vault is unreachable"))
        }
    }

    /// The active self-hosted provider `name`, whose API key is kept
    /// sealed.
    fn keyed_provider(name: &str) -> ModelProvider<ResolvedTenant> {
        let manager = agent_manager(someone_else());
        ModelProvider::create(
            &AgentControl::new(&manager),
            CreateModelProviderParams {
                id: ModelProviderId::new(),
                name: Label::new("name", name).unwrap(),
                kind: ModelProviderKind::SelfHosted,
                endpoint: ModelEndpoint::new("http://openai.models.svc:8000/v1").unwrap(),
                model: ModelName::new("gpt-4o").unwrap(),
                pricing: ModelPricing::Unpriced,
                credential_ref: ProviderKey::Sealed(SealedSecret::new("enc_1,2,3").unwrap()),
                clearance: DataClassLevel::Internal,
            },
        )
        .unwrap()
    }

    /// A tenant with `prod-deepseek` connected, and its id.
    fn deepseek() -> (Arc<FakeModelProviderStore>, ModelProviderId) {
        let provider = connected_provider("prod-deepseek");
        let id = *provider.id();
        (Arc::new(providers_holding([provider])), id)
    }

    fn answering(store: &Arc<FakeModelProviderStore>, client: FakeModelClient) -> TestPorts {
        TestPorts {
            provider_store: store.clone(),
            model_client: Arc::new(client),
            ..TestPorts::fakes()
        }
    }

    fn probe_with(
        ports: TestPorts,
        sink: &Arc<FakeEventDispatcher>,
        id: ModelProviderId,
    ) -> Result<String, AppError> {
        block_on(TestUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    fn reloaded(
        store: &FakeModelProviderStore,
        id: &ModelProviderId,
    ) -> ModelProvider<ResolvedTenant> {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
    }

    /// Ann probes `prod-deepseek` and the model answers "OK". She gets the
    /// reply back.
    #[test]
    fn probes_the_model_and_returns_its_reply() {
        let (store, id) = deepseek();

        let reply = probe_with(
            answering(&store, FakeModelClient::replying("OK")),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        )
        .unwrap();

        assert_eq!(reply, "OK");
    }

    /// Ann's probe passes. The pass is kept on the provider, so it still
    /// shows after a reload, with no failure reason.
    #[test]
    fn a_passing_test_is_kept() {
        let (store, id) = deepseek();

        probe_with(
            answering(&store, FakeModelClient::replying("OK")),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        )
        .unwrap();

        let provider = reloaded(&store, &id);
        assert_eq!(
            provider.last_test_status(),
            Some(ModelProviderTestStatus::Passed)
        );
        assert_eq!(provider.last_test_message(), None);
        assert!(provider.last_tested_at().is_some());
    }

    /// The endpoint refuses the connection. Ann is told it failed, and the
    /// failure is kept with its reason.
    #[test]
    fn a_failing_test_is_kept_with_its_reason() {
        let (store, id) = deepseek();

        let result = probe_with(
            answering(&store, FakeModelClient::failing("connection refused")),
            &Arc::new(FakeEventDispatcher::new()),
            id,
        );

        assert!(matches!(result, Err(AppError::Upstream(_))));
        let provider = reloaded(&store, &id);
        assert_eq!(
            provider.last_test_status(),
            Some(ModelProviderTestStatus::Failed)
        );
        assert_eq!(provider.last_test_message(), Some("connection refused"));
    }

    /// A probe fails, then a later one passes. The old failure reason goes.
    #[test]
    fn a_later_pass_clears_a_previous_failure_message() {
        let (store, id) = deepseek();
        let sink = Arc::new(FakeEventDispatcher::new());
        let failing = answering(&store, FakeModelClient::failing("connection refused"));
        probe_with(failing, &sink, id).unwrap_err();

        probe_with(
            answering(&store, FakeModelClient::replying("OK")),
            &sink,
            id,
        )
        .unwrap();

        let provider = reloaded(&store, &id);
        assert_eq!(
            provider.last_test_status(),
            Some(ModelProviderTestStatus::Passed)
        );
        assert_eq!(provider.last_test_message(), None);
    }

    /// Ann probes a provider with a key, and ianua's own encryption keys
    /// cannot be reached to open it. That is ianua's failure, not the
    /// provider's: it is answered as one, and the provider keeps no failed
    /// test.
    #[test]
    fn a_key_ianua_cannot_open_fails_as_an_error_and_keeps_nothing() {
        let provider = keyed_provider("prod-openai");
        let id = *provider.id();
        let store = Arc::new(providers_holding([provider]));
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = TestPorts {
            encryptor: Arc::new(LockedVault),
            ..answering(&store, FakeModelClient::replying("OK"))
        };

        let result = probe_with(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(reloaded(&store, &id).last_test_status(), None);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann probes a provider the tenant does not have. It is not found.
    #[test]
    fn an_unknown_provider_is_not_found() {
        let (store, _) = deepseek();

        let result = probe_with(
            answering(&store, FakeModelClient::replying("OK")),
            &Arc::new(FakeEventDispatcher::new()),
            ModelProviderId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// The probe is recorded with its result only, never the model's
    /// reply, which is text from outside the platform.
    #[test]
    fn a_test_is_recorded_with_its_result_not_the_reply() {
        let (store, id) = deepseek();
        let sink = Arc::new(FakeEventDispatcher::new());

        probe_with(
            answering(&store, FakeModelClient::replying("OK")),
            &sink,
            id,
        )
        .unwrap();

        let payload = sink.payload_of("agents.model_provider_tested");
        let fields: Vec<&str> = payload.fields().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(fields, vec!["provider", "result"]);
    }

    /// The update right alone cannot probe a provider; the attempt is
    /// refused without a stored test result or audit record.
    #[test]
    fn a_caller_who_may_not_manage_agents_is_refused() {
        let (store, id) = deepseek();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = TestPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Agents(AgentAction::Update),
            ])),
            ..answering(&store, FakeModelClient::replying("OK"))
        };

        let result = probe_with(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(reloaded(&store, &id).last_test_status(), None);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot probe a model provider.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = deepseek();
        let ports = TestPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..answering(&store, FakeModelClient::replying("OK"))
        };

        let result = probe_with(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
