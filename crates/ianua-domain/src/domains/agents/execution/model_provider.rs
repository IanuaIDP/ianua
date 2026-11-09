//! The language model a tenant brings for its agents' runs.
//!
//! Ianua ships no model. A tenant registers the model its runs use. That is a
//! self-hosted OpenAI-compatible endpoint, OpenAI, or Anthropic. A self-hosted
//! endpoint might be DeepSeek, Kimi or vLLM in the tenant's own Kubernetes.
//! The proxy still checks every action the model asks for. So a hijacked
//! model can never go beyond the agent's delegated authority.
//!
//! A provider has a clearance: the most sensitive data it may be sent. A run
//! that has read restricted HR data may not ask a model cleared only for
//! internal data. Only someone allowed to manage agents connects a provider,
//! changes it or records its tests.
//!
//! The API key is kept only as a [`SealedSecret`](crate::types::SealedSecret)
//! the infrastructure encrypted. The domain never sees it in plain text. A
//! self-hosted endpoint may take no key.

mod backend;
mod embeddings;
mod status;

use std::marker::PhantomData;

pub use backend::*;
pub use embeddings::ProviderEmbeddings;
use embeddings::ensure_kind_embeds;
pub use status::*;
use time::OffsetDateTime;

use crate::domains::agents::events::execution::{
    AgentModelProviderConnected, AgentModelProviderDeleted, AgentModelProviderStatusChanged,
    AgentModelProviderTested,
};
use crate::domains::agents::events::setup::{
    AgentModelProviderClearanceChanged, AgentModelProviderEmbeddingsChanged,
    AgentModelProviderKeyRotated, AgentModelProviderModelChanged,
};
use crate::domains::agents::execution::usage::ModelPricing;
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::clock;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::{EventLabel, Label, ModelProviderId, UntrustedText};

/// Parameters for registering a model provider.
pub struct CreateModelProviderParams {
    /// The id it is kept under, chosen before it is connected so its API
    /// key can be sealed for it.
    pub id: ModelProviderId,
    /// Display name, such as `prod-deepseek`.
    pub name: Label,
    /// The backend kind.
    pub kind: ModelProviderKind,
    /// The base endpoint URL.
    pub endpoint: ModelEndpoint,
    /// The model to request.
    pub model: ModelName,
    /// What the model charges, or that its price is unknown.
    pub pricing: ModelPricing,
    /// The encrypted API key, or that the endpoint takes none.
    pub credential_ref: ProviderKey,
    /// The most sensitive data the provider may be sent.
    pub clearance: DataClassLevel,
}

/// The model a provider is switched to, with its price.
pub struct ModelChange {
    /// The model to request from now on.
    pub model: ModelName,
    /// What it charges, or that its price is unknown.
    pub pricing: ModelPricing,
}

/// Persisted state for reconstitution.
pub struct ModelProviderRow {
    /// Unique identifier.
    pub id: ModelProviderId,
    /// Human-readable name.
    pub name: Label,
    /// Backend kind.
    pub kind: ModelProviderKind,
    /// Base endpoint URL.
    pub endpoint: ModelEndpoint,
    /// Model name.
    pub model: ModelName,
    /// What the model charges, or that its price is unknown.
    pub pricing: ModelPricing,
    /// The encrypted API key, or that the endpoint takes none.
    pub credential_ref: ProviderKey,
    /// The most sensitive data the provider may be sent. Storage reads it
    /// with [`DataClassLevel::from_stored`], which refuses an unknown level.
    pub clearance: DataClassLevel,
    /// The embedding model it offers beside its chat model, if any.
    pub embeddings: ProviderEmbeddings,
    /// Whether runs may use it.
    pub status: ModelProviderStatus,
    /// The last test of whether it answers. See [`LastTest::from_stored`].
    pub last_test: LastTest,
    /// When created.
    pub created_at: OffsetDateTime,
    /// When last modified.
    pub updated_at: OffsetDateTime,
}

/// A tenant's registered model backend.
#[derive(Clone)]
pub struct ModelProvider<T: TenantScope> {
    id: ModelProviderId,
    name: Label,
    kind: ModelProviderKind,
    endpoint: ModelEndpoint,
    model: ModelName,
    pricing: ModelPricing,
    credential_ref: ProviderKey,
    clearance: DataClassLevel,
    embeddings: ProviderEmbeddings,
    status: ModelProviderStatus,
    last_test: LastTest,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> ModelProvider<T> {
    /// Registers a new, active model provider. Raises
    /// `agents.model_provider_connected`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person connecting it may not
    ///   manage agents.
    pub fn create(
        control: &AgentControl<'_>,
        params: CreateModelProviderParams,
    ) -> Result<Self, DomainError> {
        ensure_manages(control)?;
        let now = clock::now();
        let mut provider = Self {
            id: params.id,
            name: params.name,
            kind: params.kind,
            endpoint: params.endpoint,
            model: params.model,
            pricing: params.pricing,
            credential_ref: params.credential_ref,
            clearance: params.clearance,
            embeddings: ProviderEmbeddings::Off,
            status: ModelProviderStatus::Active,
            last_test: LastTest::NotYet,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        provider.raised.raise(AgentModelProviderConnected {
            provider_id: provider.id,
            provider_label: provider.label(),
            kind: provider.kind,
            occurred_at: now,
        });
        Ok(provider)
    }

    /// Rebuilds a model provider from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the provider changed
    ///   or was tested before it was created, or an Anthropic provider offers
    ///   an embedding model.
    pub fn reconstitute(row: ModelProviderRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            name: row.name,
            kind: row.kind,
            endpoint: row.endpoint,
            model: row.model,
            pricing: row.pricing,
            credential_ref: row.credential_ref,
            clearance: row.clearance,
            embeddings: row.embeddings,
            status: row.status,
            last_test: row.last_test,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ModelProviderRow) -> Result<(), DomainError> {
        RowCheck::of("model provider")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .in_order_if(
                row.created_at,
                row.last_test.at(),
                "tested before it was created",
            )
            .holds(
                embeddings::kind_embeds(row.kind, &row.embeddings),
                "an Anthropic provider offers an embedding model",
            )
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &ModelProviderId {
        &self.id
    }

    /// Human-readable name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Backend kind.
    #[must_use]
    pub fn kind(&self) -> ModelProviderKind {
        self.kind
    }

    /// Base endpoint URL.
    #[must_use]
    pub fn endpoint(&self) -> &ModelEndpoint {
        &self.endpoint
    }

    /// Model name.
    #[must_use]
    pub fn model(&self) -> &ModelName {
        &self.model
    }

    /// The encrypted API key, or that the endpoint takes none.
    #[must_use]
    pub fn credential_ref(&self) -> &ProviderKey {
        &self.credential_ref
    }

    /// The most sensitive data this provider may be sent. A run whose
    /// exposure is above it may not ask this provider.
    #[must_use]
    pub fn clearance(&self) -> DataClassLevel {
        self.clearance
    }

    /// Whether runs may use it.
    #[must_use]
    pub fn status(&self) -> ModelProviderStatus {
        self.status
    }

    /// Whether the provider is active, so runs may pick it.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.status, ModelProviderStatus::Active)
    }

    /// The outcome of the last test of whether it answers, if one has run.
    #[must_use]
    pub fn last_test_status(&self) -> Option<ModelProviderTestStatus> {
        self.last_test.status()
    }

    /// When the last test ran, if one has.
    #[must_use]
    pub fn last_tested_at(&self) -> Option<OffsetDateTime> {
        self.last_test.at()
    }

    /// Why the last test failed, if it failed and the provider said why.
    #[must_use]
    pub fn last_test_message(&self) -> Option<&str> {
        self.last_test.reason()
    }

    /// The last test of whether it answers.
    #[must_use]
    pub fn last_test(&self) -> &LastTest {
        &self.last_test
    }

    /// Changes the most sensitive data the provider may be sent.
    ///
    /// Raising it lets runs that read restricted HR data reason with the
    /// provider, so the change is recorded with both levels. Raises
    /// `agents.model_provider_clearance_changed` when the clearance moves;
    /// clearing it for what it already has raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person acting may not manage
    ///   agents.
    pub fn change_clearance(
        &mut self,
        control: &AgentControl<'_>,
        clearance: DataClassLevel,
    ) -> Result<(), DomainError> {
        ensure_manages(control)?;
        let from = std::mem::replace(&mut self.clearance, clearance);
        if from == clearance {
            return Ok(());
        }
        self.touch();
        self.raised.raise(AgentModelProviderClearanceChanged {
            provider_id: self.id,
            provider_label: self.label(),
            from,
            to: clearance,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// What the model charges, or that its price is unknown.
    #[must_use]
    pub fn pricing(&self) -> ModelPricing {
        self.pricing
    }

    /// Calls the provider with `key` from now on.
    ///
    /// OpenAI and Anthropic always take a key, so only a self-hosted
    /// endpoint may go keyless. The last test was of the old key, so it no
    /// longer says whether the provider answers.
    ///
    /// Raises `agents.model_provider_key_rotated`, never naming the key.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person acting may not manage
    ///   agents.
    /// - [`DomainError::Validation`] when a provider that takes a key is
    ///   given none.
    /// - [`DomainError::Conflict`] when `key` is the key it holds.
    pub fn rotate_key(
        &mut self,
        control: &AgentControl<'_>,
        key: ProviderKey,
    ) -> Result<(), DomainError> {
        ensure_manages(control)?;
        if self.kind.requires_key() && key == ProviderKey::Keyless {
            return Err(DomainError::invalid(message!(
                "agents-this-provider-always-takes-a-key",
                "this provider always takes a key"
            )));
        }
        if key == self.credential_ref {
            return Err(DomainError::conflict(message!(
                "agents-the-provider-holds-this-key-already",
                "the provider holds this key already"
            )));
        }
        self.credential_ref = key;
        self.last_test = LastTest::NotYet;
        self.touch();
        self.raised.raise(AgentModelProviderKeyRotated {
            provider_id: self.id,
            provider_label: self.label(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Asks for the model and price `change` names from now on.
    ///
    /// A new model has not been tested, so the last test is cleared. A
    /// price change alone keeps it.
    ///
    /// Raises `agents.model_provider_model_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person acting may not manage
    ///   agents.
    /// - [`DomainError::Conflict`] when it names the model and price the
    ///   provider has.
    pub fn change_model(
        &mut self,
        control: &AgentControl<'_>,
        change: ModelChange,
    ) -> Result<(), DomainError> {
        ensure_manages(control)?;
        if change.model == self.model && change.pricing == self.pricing {
            return Err(DomainError::conflict(message!(
                "agents-the-provider-asks-for-this-model",
                "the provider asks for this model at this price already"
            )));
        }
        if change.model != self.model {
            self.last_test = LastTest::NotYet;
        }
        let from = std::mem::replace(&mut self.model, change.model);
        self.pricing = change.pricing;
        self.touch();
        self.raised.raise(AgentModelProviderModelChanged {
            provider_id: self.id,
            provider_label: self.label(),
            from,
            to: self.model.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Disables the provider. It is kept, but new runs may not pick it.
    /// Raises `agents.model_provider_status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person acting may not manage
    ///   agents.
    /// - [`DomainError::InvalidTransition`] when it is already disabled.
    pub fn disable(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        ensure_manages(control)?;
        self.move_to(ModelProviderStatus::Disabled)
    }

    /// Re-enables a disabled provider. Raises
    /// `agents.model_provider_status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person acting may not manage
    ///   agents.
    /// - [`DomainError::InvalidTransition`] when it is already active.
    pub fn enable(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        ensure_manages(control)?;
        self.move_to(ModelProviderStatus::Active)
    }

    /// Deletes this provider, which only someone who may manage agents does,
    /// and only once the provider is disabled. Raises
    /// `agents.model_provider_deleted`, taken once the provider is removed
    /// from storage.
    ///
    /// A provider is disabled first, so no new run picks it while it goes.
    /// Sam may only view agents. Without this check, he deletes the model
    /// every run of the tenant reasons with.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person acting may not manage
    ///   agents.
    /// - [`DomainError::InvalidTransition`] while the provider is active.
    pub fn delete(&mut self, control: &AgentControl<'_>) -> Result<(), DomainError> {
        ensure_manages(control)?;
        if self.is_active() {
            return Err(DomainError::invalid_transition(message!(
                "agents-a-model-provider-is-disabled-before",
                "a model provider is disabled before it is deleted"
            )));
        }
        self.raised.raise(AgentModelProviderDeleted {
            provider_id: self.id,
            provider_label: self.label(),
            occurred_at: clock::now(),
        });
        Ok(())
    }

    fn move_to(&mut self, to: ModelProviderStatus) -> Result<(), DomainError> {
        self.status = self.status.try_transition(to)?;
        self.touch();
        self.raised.raise(AgentModelProviderStatusChanged {
            provider_id: self.id,
            provider_label: self.label(),
            status: self.status,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// The name the provider is recorded under.
    fn label(&self) -> EventLabel {
        EventLabel::of(self.name.as_str())
    }

    /// Records the outcome of a test of whether the provider answers. So the
    /// outcome still shows after the page reloads.
    ///
    /// `message` is kept only when `status` is
    /// [`ModelProviderTestStatus::Failed`]. A passing test has nothing to
    /// explain, and an old failure reason must go once the provider passes.
    ///
    /// Raises `agents.model_provider_tested` with the outcome, never the
    /// model's answer.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person acting may not manage
    ///   agents.
    pub fn record_test_result(
        &mut self,
        control: &AgentControl<'_>,
        status: ModelProviderTestStatus,
        message: Option<&str>,
    ) -> Result<(), DomainError> {
        ensure_manages(control)?;
        let at = clock::now();
        self.last_test = match status {
            ModelProviderTestStatus::Failed => LastTest::Failed {
                at,
                reason: message.map(UntrustedText::record),
            },
            ModelProviderTestStatus::Passed => LastTest::Passed { at },
        };
        self.touch();
        self.raised.raise(AgentModelProviderTested {
            provider_id: self.id,
            provider_label: self.label(),
            result: status,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    fn touch(&mut self) {
        self.updated_at = clock::now();
    }
    /// The embedding model the provider offers, if any.
    #[must_use]
    pub fn embeddings(&self) -> &ProviderEmbeddings {
        &self.embeddings
    }

    /// Offers `embeddings` from now on: an embedding model by name, or
    /// none. Raises `agents.model_provider_embeddings_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person acting may not manage
    ///   agents.
    /// - [`DomainError::Validation`] when an Anthropic provider is asked to
    ///   offer one: its API has no embeddings endpoint.
    /// - [`DomainError::Conflict`] when it offers exactly that already.
    pub fn offer_embeddings(
        &mut self,
        control: &AgentControl<'_>,
        embeddings: ProviderEmbeddings,
    ) -> Result<(), DomainError> {
        ensure_manages(control)?;
        ensure_kind_embeds(self.kind, &embeddings)?;
        if embeddings == self.embeddings {
            return Err(DomainError::conflict(message!(
                "agents-the-provider-offers-these-embeddings-already",
                "the provider offers this embedding model already"
            )));
        }
        let from = std::mem::replace(&mut self.embeddings, embeddings);
        self.touch();
        self.raised.raise(AgentModelProviderEmbeddingsChanged {
            provider_id: self.id,
            provider_label: self.label(),
            from,
            to: self.embeddings.clone(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }
}

/// Refuses a person who may not manage agents.
///
/// A provider has no owner. Every agent in the tenant may run on it, so
/// only an agent manager changes it. Sam may only view agents. Without this
/// check, Sam points the provider at his own endpoint and reads every run's
/// prompts.
fn ensure_manages(control: &AgentControl<'_>) -> Result<(), DomainError> {
    if control.holds_agent(AgentAction::Manage) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-only-someone-allowed-to-manage-agents-2",
        "only someone allowed to manage agents may change a model provider"
    )))
}

impl<T: TenantScope> std::fmt::Debug for ModelProvider<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelProvider")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("pricing", &self.pricing)
            .field(
                "credential_ref",
                &self.credential_ref.sealed().map(|_| "<redacted>"),
            )
            .field("clearance", &self.clearance)
            .field("status", &self.status)
            .field("last_test_status", &self.last_test.status())
            .field("last_tested_at", &self.last_test.at())
            .finish()
    }
}

impl<T: TenantScope> Raises for ModelProvider<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for ModelProvider<T> {
    type Id = ModelProviderId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::execution::usage::Spend;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{Human, HumanAccount, PersonKey, SealedSecret, TenantId, UserId};

    const MANAGE: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::Manage)];
    const VIEW: [SystemPermission; 1] = [SystemPermission::Agents(AgentAction::View)];

    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    fn holding<'a>(by: &'a Human, system: &'a [SystemPermission]) -> AgentControl<'a> {
        AgentControl::new(assumed_authority(by, TenantId::new(), system, &[]))
    }

    fn deepseek() -> CreateModelProviderParams {
        CreateModelProviderParams {
            id: ModelProviderId::new(),
            name: Label::new("name", "prod-deepseek").unwrap(),
            kind: ModelProviderKind::SelfHosted,
            endpoint: ModelEndpoint::new("http://deepseek.models.svc:8000/v1").unwrap(),
            model: ModelName::new("deepseek-chat").unwrap(),
            pricing: ModelPricing::Unpriced,
            credential_ref: ProviderKey::Keyless,
            clearance: DataClassLevel::Internal,
        }
    }

    fn openai() -> CreateModelProviderParams {
        CreateModelProviderParams {
            id: ModelProviderId::new(),
            name: Label::new("name", "openai").unwrap(),
            kind: ModelProviderKind::OpenAi,
            endpoint: ModelEndpoint::new("https://api.openai.com/v1").unwrap(),
            model: ModelName::new("gpt-4o-mini").unwrap(),
            pricing: ModelPricing::PerMillionTokens {
                input: Spend::from_micros(150_000),
                output: Spend::from_micros(600_000),
            },
            credential_ref: ProviderKey::Sealed(SealedSecret::new("vault://secret/abc").unwrap()),
            clearance: DataClassLevel::Public,
        }
    }

    fn connected(params: CreateModelProviderParams) -> ModelProvider<ResolvedTenant> {
        let bob = person("bob@corp.test");
        ModelProvider::create(&holding(&bob, &MANAGE), params).unwrap()
    }

    fn provider() -> ModelProvider<ResolvedTenant> {
        connected(deepseek())
    }

    /// A new provider is active. It can be disabled and enabled again, but
    /// enabling an active provider is refused.
    #[test]
    fn create_starts_active_and_disable_toggles() {
        let bob = person("bob@corp.test");
        let control = holding(&bob, &MANAGE);
        let mut p = provider();
        assert!(p.is_active());
        p.disable(&control).unwrap();
        assert!(!p.is_active());
        p.enable(&control).unwrap();
        assert!(p.is_active());
        assert!(p.enable(&control).is_err());
    }

    /// Read-only agent authority cannot connect a self-hosted model provider.
    #[test]
    fn only_an_agent_manager_connects_a_provider() {
        let sam = person("sam@corp.test");

        let connected = ModelProvider::<ResolvedTenant>::create(&holding(&sam, &VIEW), deepseek());

        assert!(matches!(connected, Err(DomainError::Forbidden(_))));
    }

    /// A viewer cannot disable, enable or record a provider test. Each
    /// refusal preserves the provider's status and recorded test state.
    #[test]
    fn only_an_agent_manager_disables_enables_or_records_a_test() {
        let sam = person("sam@corp.test");
        let control = holding(&sam, &VIEW);
        let mut p = provider();

        assert!(matches!(
            p.disable(&control),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            p.record_test_result(&control, ModelProviderTestStatus::Passed, None),
            Err(DomainError::Forbidden(_))
        ));
        assert!(p.is_active());
        assert_eq!(p.last_test_status(), None);

        let bob = person("bob@corp.test");
        p.disable(&holding(&bob, &MANAGE)).unwrap();
        assert!(matches!(p.enable(&control), Err(DomainError::Forbidden(_))));
        assert!(!p.is_active());
    }

    /// Deleting a provider requires management authority and a disabled
    /// provider; a viewer is refused even after a manager disables it.
    #[test]
    fn only_an_agent_manager_deletes_a_disabled_provider() {
        let (bob, sam) = (person("bob@corp.test"), person("sam@corp.test"));
        let mut p = provider();

        let while_active = p.delete(&holding(&bob, &MANAGE));
        p.disable(&holding(&bob, &MANAGE)).unwrap();

        assert!(matches!(
            while_active,
            Err(DomainError::InvalidTransition(_))
        ));
        assert!(matches!(
            p.delete(&holding(&sam, &VIEW)),
            Err(DomainError::Forbidden(_))
        ));
        assert!(p.delete(&holding(&bob, &MANAGE)).is_ok());
    }

    /// A provider connected as cleared for internal data reports that
    /// clearance. A run reads it to decide what it may send.
    #[test]
    fn a_provider_keeps_the_clearance_it_was_connected_with() {
        assert_eq!(provider().clearance(), DataClassLevel::Internal);
        assert_eq!(connected(openai()).clearance(), DataClassLevel::Public);
    }

    /// A viewer cannot raise a public provider's clearance. It stays public
    /// until a manager changes it to confidential.
    #[test]
    fn only_an_agent_manager_changes_a_clearance() {
        let sam = person("sam@corp.test");
        let bob = person("bob@corp.test");
        let mut p = connected(openai());

        let by_sam = p.change_clearance(&holding(&sam, &VIEW), DataClassLevel::Restricted);

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(p.clearance(), DataClassLevel::Public);
        p.change_clearance(&holding(&bob, &MANAGE), DataClassLevel::Confidential)
            .unwrap();
        assert_eq!(p.clearance(), DataClassLevel::Confidential);
    }

    /// An oversized failure answer containing a newline is stored as one
    /// line within the untrusted-text length bound.
    #[test]
    fn a_failure_answer_is_kept_short_and_on_one_line() {
        let bob = person("bob@corp.test");
        let mut p = provider();
        let answer = format!("refused\nadmin login ok {}", "x".repeat(10_000));

        p.record_test_result(
            &holding(&bob, &MANAGE),
            ModelProviderTestStatus::Failed,
            Some(&answer),
        )
        .unwrap();

        let kept = p.last_test_message().unwrap();
        assert!(!kept.contains('\n'));
        assert!(kept.chars().count() <= crate::types::naming::untrusted_text::MAX_UNTRUSTED_CHARS);
    }

    /// A provider fails a test with "connection refused", then passes the
    /// next one. The reason shows after the failure and is gone after the pass.
    #[test]
    fn record_test_result_keeps_the_message_only_on_failure() {
        let bob = person("bob@corp.test");
        let control = holding(&bob, &MANAGE);
        let mut p = provider();
        assert_eq!(p.last_test_status(), None);

        p.record_test_result(
            &control,
            ModelProviderTestStatus::Failed,
            Some("connection refused"),
        )
        .unwrap();
        assert_eq!(p.last_test_status(), Some(ModelProviderTestStatus::Failed));
        assert_eq!(p.last_test_message(), Some("connection refused"));
        assert!(p.last_tested_at().is_some());

        p.record_test_result(&control, ModelProviderTestStatus::Passed, None)
            .unwrap();
        assert_eq!(p.last_test_status(), Some(ModelProviderTestStatus::Passed));
        assert_eq!(p.last_test_message(), None);
    }

    /// A provider holds a sealed key. Its debug output does not contain the
    /// key, so a log line cannot leak it.
    #[test]
    fn debug_redacts_the_credential_ref() {
        let p = connected(openai());
        assert!(!format!("{p:?}").contains("vault://secret/abc"));
    }

    /// The debug output still shows the name, endpoint and model once the key
    /// is hidden. So a log line about a failing provider says which one it is.
    #[test]
    fn debug_still_names_the_provider_it_redacted_the_key_of() {
        let p = provider();

        let rendered = format!("{p:?}");

        assert!(rendered.contains("prod-deepseek"), "{rendered}");
        assert!(
            rendered.contains("http://deepseek.models.svc:8000/v1"),
            "{rendered}"
        );
        assert!(rendered.contains("deepseek-chat"), "{rendered}");
    }

    /// An OpenAI provider reads back the endpoint, model and sealed key it was
    /// given, or a call would go somewhere else. A self-hosted one reads back
    /// as keyless.
    #[test]
    fn a_provider_reports_the_endpoint_model_and_credential_it_was_given() {
        let keyed = connected(openai());

        assert_eq!(keyed.endpoint().as_str(), "https://api.openai.com/v1");
        assert_eq!(keyed.model().as_str(), "gpt-4o-mini");
        assert_eq!(
            keyed.credential_ref().sealed().map(SealedSecret::as_str),
            Some("vault://secret/abc")
        );
        assert_eq!(Aggregate::id(&keyed), keyed.id());

        let keyless = provider();
        assert_eq!(
            keyless.credential_ref(),
            &ProviderKey::Keyless,
            "a self-hosted endpoint may need no key at all"
        );
    }

    /// Every status and test outcome reads back from its stored name. A stored
    /// `retired` is an infrastructure error, a sent one a validation error. A
    /// disabled provider that read back as active would be picked for runs.
    #[test]
    fn the_provider_enums_round_trip_through_their_stored_names() {
        let statuses = [
            (ModelProviderStatus::Active, "active"),
            (ModelProviderStatus::Disabled, "disabled"),
        ];
        for (status, name) in statuses {
            assert_eq!(status.as_str(), name);
            assert_eq!(ModelProviderStatus::from_stored(name).unwrap(), status);
        }
        assert!(matches!(
            ModelProviderStatus::from_stored("retired"),
            Err(DomainError::Infrastructure(_))
        ));
        assert!(matches!(
            ModelProviderStatus::parse("retired"),
            Err(DomainError::Validation(_))
        ));

        let outcomes = [
            (ModelProviderTestStatus::Passed, "passed"),
            (ModelProviderTestStatus::Failed, "failed"),
        ];
        for (outcome, name) in outcomes {
            assert_eq!(outcome.as_str(), name);
            assert_eq!(ModelProviderTestStatus::from_stored(name).unwrap(), outcome);
        }
        assert!(ModelProviderTestStatus::from_stored("unknown").is_err());
    }

    /// A test result is recorded five seconds after creation. The provider's
    /// update time moves forward with it.
    #[test]
    fn recording_a_probe_result_moves_the_updated_stamp() {
        let bob = person("bob@corp.test");
        let mut p = provider();
        let before = p.updated_at();
        let frozen = crate::shared::clock::freeze(before + time::Duration::seconds(5));

        p.record_test_result(
            &holding(&bob, &MANAGE),
            ModelProviderTestStatus::Passed,
            None,
        )
        .unwrap();

        assert!(p.updated_at() > before);
        drop(frozen);
    }

    /// A disabled status may move to active. An active status moving to
    /// active is refused.
    #[test]
    fn a_provider_status_only_moves_to_the_other_status() {
        assert_eq!(
            ModelProviderStatus::Disabled.try_transition(ModelProviderStatus::Active),
            Ok(ModelProviderStatus::Active)
        );
        assert!(
            ModelProviderStatus::Active
                .try_transition(ModelProviderStatus::Active)
                .is_err()
        );
    }

    /// A status with no time, a time with no status, and a pass with a reason
    /// are refused. Each would show a provider as tested when it was not, or
    /// keep a failure reason on a passing one.
    #[test]
    fn stored_test_columns_that_contradict_each_other_are_refused() {
        let at = crate::shared::clock::now();

        assert_eq!(
            LastTest::from_stored(None, None, None).unwrap(),
            LastTest::NotYet
        );
        assert!(LastTest::from_stored(Some(ModelProviderTestStatus::Passed), None, None).is_err());
        assert!(LastTest::from_stored(None, Some(at), None).is_err());
        assert!(
            LastTest::from_stored(
                Some(ModelProviderTestStatus::Passed),
                Some(at),
                Some("refused".to_owned())
            )
            .is_err()
        );
        assert!(
            LastTest::from_stored(
                Some(ModelProviderTestStatus::Failed),
                Some(at),
                Some("refused".to_owned())
            )
            .is_ok()
        );
    }

    fn row_of(provider: &ModelProvider<ResolvedTenant>) -> ModelProviderRow {
        ModelProviderRow {
            id: provider.id,
            name: provider.name.clone(),
            kind: provider.kind,
            endpoint: provider.endpoint.clone(),
            model: provider.model.clone(),
            pricing: provider.pricing,
            credential_ref: provider.credential_ref.clone(),
            clearance: provider.clearance,
            embeddings: provider.embeddings.clone(),
            status: provider.status,
            last_test: provider.last_test.clone(),
            created_at: provider.created_at,
            updated_at: provider.updated_at,
        }
    }

    /// A stored provider passed a test one second before it was created. The
    /// row is refused as corrupt.
    #[test]
    fn a_stored_provider_tested_before_it_was_created_is_refused() {
        let provider = provider();
        let row = ModelProviderRow {
            last_test: LastTest::Passed {
                at: provider.created_at - time::Duration::SECOND,
            },
            ..row_of(&provider)
        };

        assert!(refused_as_corrupt(
            &ModelProvider::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A provider cleared for confidential data is stored and read back. It
    /// is still cleared for confidential data, not more and not less.
    #[test]
    fn a_stored_provider_reads_back_its_clearance() {
        let row = ModelProviderRow {
            clearance: DataClassLevel::Confidential,
            ..row_of(&provider())
        };

        let read = ModelProvider::<ResolvedTenant>::reconstitute(row).unwrap();

        assert_eq!(read.clearance(), DataClassLevel::Confidential);
    }

    /// A provider and what it raised since it was connected, the connection
    /// taken out first.
    fn fresh_provider() -> ModelProvider<ResolvedTenant> {
        let mut p = provider();
        raised_names(&mut p);
        p
    }

    /// Bob connects `prod-deepseek`. The connection is raised, naming the
    /// provider and its kind.
    #[test]
    fn connecting_raises_agents_model_provider_connected() {
        let mut p = provider();

        let events = raised(&mut p);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.model_provider_connected"
        );
        assert_eq!(
            events[0].payload().value("kind"),
            Some(&FieldValue::Text("self_hosted".to_owned()))
        );
    }

    /// Bob turns `prod-deepseek` off and on again. Each change is raised.
    #[test]
    fn turning_a_provider_off_and_on_raises_agents_model_provider_status_changed() {
        let bob = person("bob@corp.test");
        let mut p = fresh_provider();

        p.disable(&holding(&bob, &MANAGE)).unwrap();
        p.enable(&holding(&bob, &MANAGE)).unwrap();

        assert_eq!(
            raised_names(&mut p),
            [
                "agents.model_provider_status_changed",
                "agents.model_provider_status_changed"
            ]
        );
    }

    /// Bob deletes the disabled `prod-deepseek`. The deletion is raised.
    #[test]
    fn deleting_raises_agents_model_provider_deleted() {
        let bob = person("bob@corp.test");
        let mut p = fresh_provider();
        p.disable(&holding(&bob, &MANAGE)).unwrap();
        raised_names(&mut p);

        p.delete(&holding(&bob, &MANAGE)).unwrap();

        assert_eq!(raised_names(&mut p), ["agents.model_provider_deleted"]);
    }

    /// Bob records a failed test of `prod-deepseek`. The test is raised with
    /// its outcome, and the reason stays on the provider only.
    #[test]
    fn recording_a_test_raises_agents_model_provider_tested() {
        let bob = person("bob@corp.test");
        let mut p = fresh_provider();

        p.record_test_result(
            &holding(&bob, &MANAGE),
            ModelProviderTestStatus::Failed,
            Some("connection refused"),
        )
        .unwrap();

        let events = raised(&mut p);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.model_provider_tested"
        );
        assert_eq!(
            events[0].payload().value("result"),
            Some(&FieldValue::Text("failed".to_owned()))
        );
        assert_eq!(events[0].payload().value("message"), None);
    }

    /// A viewer's attempt to disable a provider is refused without raising
    /// a status-change event.
    #[test]
    fn a_refused_change_to_a_provider_raises_nothing() {
        let sam = person("sam@corp.test");
        let mut p = fresh_provider();

        let refused = p.disable(&holding(&sam, &VIEW));

        assert!(refused.is_err());
        assert!(raised_names(&mut p).is_empty());
    }

    /// `prod-deepseek` is read back from storage. Loading it is no change,
    /// so it has raised nothing.
    #[test]
    fn a_provider_read_back_from_storage_has_raised_nothing() {
        let mut read = ModelProvider::<ResolvedTenant>::reconstitute(row_of(&provider())).unwrap();

        assert!(raised_names(&mut read).is_empty());
    }

    /// A new key for the OpenAI provider, sealed by the vault.
    fn new_key() -> ProviderKey {
        ProviderKey::Sealed(SealedSecret::new("vault://secret/def").unwrap())
    }

    /// Bob rotates the OpenAI provider's key after a passing test. It holds
    /// the new key, the old test is cleared, and the rotation is raised
    /// without the key in it.
    #[test]
    fn rotating_a_key_replaces_it_and_clears_the_last_test() {
        let bob = person("bob@corp.test");
        let mut p = connected(openai());
        p.record_test_result(
            &holding(&bob, &MANAGE),
            ModelProviderTestStatus::Passed,
            None,
        )
        .unwrap();
        raised_names(&mut p);

        p.rotate_key(&holding(&bob, &MANAGE), new_key()).unwrap();

        assert_eq!(p.credential_ref(), &new_key());
        assert_eq!(p.last_test(), &LastTest::NotYet);
        let events = raised(&mut p);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.model_provider_key_rotated"
        );
        assert!(!format!("{:?}", events[0].payload()).contains("vault://secret/def"));
    }

    /// A viewer cannot replace the OpenAI provider's key with another sealed
    /// key; the proposed credential is not installed.
    #[test]
    fn only_an_agent_manager_rotates_a_key() {
        let sam = person("sam@corp.test");
        let mut p = connected(openai());

        let rotated = p.rotate_key(&holding(&sam, &VIEW), new_key());

        assert!(matches!(rotated, Err(DomainError::Forbidden(_))));
        assert_ne!(p.credential_ref(), &new_key());
    }

    /// OpenAI always takes a key, so taking it away is refused. Rotating to
    /// the key it already holds is a conflict.
    #[test]
    fn a_keyed_provider_keeps_a_key_and_a_rotation_changes_it() {
        let bob = person("bob@corp.test");
        let mut p = connected(openai());
        let current = p.credential_ref().clone();

        let keyless = p.rotate_key(&holding(&bob, &MANAGE), ProviderKey::Keyless);
        let same = p.rotate_key(&holding(&bob, &MANAGE), current);

        assert!(matches!(keyless, Err(DomainError::Validation(_))));
        assert!(matches!(same, Err(DomainError::Conflict(_))));
    }

    /// Bob moves `prod-deepseek` to a newer model with a price. It asks for
    /// that model at that price, the old test is cleared, and the change is
    /// raised naming both models.
    #[test]
    fn changing_the_model_records_both_models() {
        let bob = person("bob@corp.test");
        let mut p = fresh_provider();
        let pricing = ModelPricing::PerMillionTokens {
            input: Spend::from_micros(270_000),
            output: Spend::from_micros(1_100_000),
        };

        p.change_model(
            &holding(&bob, &MANAGE),
            ModelChange {
                model: ModelName::new("deepseek-v3").unwrap(),
                pricing,
            },
        )
        .unwrap();

        assert_eq!(p.model().as_str(), "deepseek-v3");
        assert_eq!(p.pricing(), pricing);
        let events = raised(&mut p);
        assert_eq!(
            events[0].event_type().to_string(),
            "agents.model_provider_model_changed"
        );
    }

    /// A viewer cannot change the model, and a manager cannot submit its
    /// unchanged model and price. Both refusals preserve the current model.
    #[test]
    fn only_an_agent_manager_changes_the_model_and_only_to_something_new() {
        let sam = person("sam@corp.test");
        let bob = person("bob@corp.test");
        let mut p = provider();
        let same = || ModelChange {
            model: ModelName::new("deepseek-chat").unwrap(),
            pricing: ModelPricing::Unpriced,
        };

        let by_sam = p.change_model(
            &holding(&sam, &VIEW),
            ModelChange {
                model: ModelName::new("uncleared").unwrap(),
                pricing: ModelPricing::Unpriced,
            },
        );
        let unchanged = p.change_model(&holding(&bob, &MANAGE), same());

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(matches!(unchanged, Err(DomainError::Conflict(_))));
        assert_eq!(p.model().as_str(), "deepseek-chat");
    }

    /// Bob clears `prod-deepseek` for confidential data. Runs that read
    /// confidential records may now send it prompts, so the change is
    /// raised for the audit trail.
    #[test]
    fn changing_the_clearance_raises_agents_model_provider_clearance_changed() {
        let bob = person("bob@corp.test");
        let mut p = fresh_provider();

        p.change_clearance(&holding(&bob, &MANAGE), DataClassLevel::Confidential)
            .unwrap();

        assert_eq!(
            raised_names(&mut p),
            ["agents.model_provider_clearance_changed"]
        );
    }

    /// Bob clears `prod-deepseek` for internal data, which it has already.
    /// Nothing changed, so nothing is raised.
    #[test]
    fn clearing_a_provider_for_what_it_has_raises_nothing() {
        let bob = person("bob@corp.test");
        let mut p = fresh_provider();

        p.change_clearance(&holding(&bob, &MANAGE), DataClassLevel::Internal)
            .unwrap();

        assert!(raised_names(&mut p).is_empty());
    }
}
