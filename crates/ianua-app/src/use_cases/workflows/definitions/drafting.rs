//! Drafting: the tenant's own model turns a person's words into steps,
//! either a whole new workflow ("build it for me") or what happens after a
//! step of a draft ("what happens next").
//!
//! The model only proposes. Its answer is read as untrusted text, held to a
//! small shape, and every step is checked against what the catalog offers
//! now: an operation the integrations do not offer is left out with a note
//! saying so, never invented. Nothing is saved: the builder places the
//! proposal on the canvas, fills in what it lacks, such as the accounts,
//! and saves it as a draft, where the publish rules hold it like any other.

use std::sync::Arc;

use ianua_domain::domains::agents::execution::chat::{ChatMessage, CompletionRequest};
use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::data::{DataPath, FieldName};
use ianua_domain::domains::workflows::design::node::{NodeKey, Port};
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationKey, OperationSpec};
use ianua_domain::types::{DeclaredAction, Label, ModelProviderId, Text, WorkflowId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::{ModelClient, ModelProviderStore};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::workflows::{IntegrationCatalog, WorkflowStore};
use crate::services::model_targets::active_model;
use crate::use_case::Query;
use crate::use_cases::workflows::lookup::latest_version;

mod proposal;

use self::proposal::{only_note, proposal_from};

/// The most steps one proposal holds.
pub(crate) const MAX_PROPOSED_STEPS: usize = 12;

/// The most tokens the model may answer with.
const ANSWER_TOKENS: u32 = 4_000;

/// What to draft, from whose words, through which model.
pub struct DraftRequest {
    /// The tenant's model the words are given to.
    pub provider_id: ModelProviderId,
    /// What the person wants, in their own words.
    pub words: Text,
    /// Where the steps go: a new workflow, or after a step of a draft.
    pub place: DraftPlace,
}

/// Where proposed steps go.
pub enum DraftPlace {
    /// A whole new workflow, trigger included.
    NewWorkflow,
    /// After `step` of `workflow_id`'s latest version, which they continue.
    After {
        /// The existing automation whose latest graph is being extended.
        workflow_id: WorkflowId,
        /// The step they come after.
        step: NodeKey,
    },
}

/// The steps a model proposed, as far as they fit what is offered.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    /// What starts a new workflow; `None` when steps go after a step.
    pub trigger: Option<ProposedTrigger>,
    /// The steps, in the order the model gave them.
    pub steps: Vec<ProposedStep>,
    /// The arrows between them.
    pub edges: Vec<ProposedEdge>,
    /// What the person should know: steps left out, and why.
    pub notes: Vec<String>,
}

/// What a proposed workflow starts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposedTrigger {
    /// A person starts it.
    Manual,
    /// A call to its webhook.
    Webhook,
    /// A schedule, as the model wrote it; the builder checks it.
    Schedule(String),
    /// An event a service sends.
    ServiceEvent {
        /// The provider adapter offering the proposed event trigger.
        integration: IntegrationKey,
        /// The event, as the model named it.
        event: String,
    },
}

/// A model-suggested graph node awaiting the designer's review.
#[derive(Debug, Clone, PartialEq)]
pub struct ProposedStep {
    /// The node identity used by proposed edges and data references.
    pub key: NodeKey,
    /// Its name for people.
    pub title: Label,
    /// What it does.
    pub kind: ProposedKind,
}

/// What a proposed step does.
#[derive(Debug, Clone, PartialEq)]
pub enum ProposedKind {
    /// Calls an operation the catalog offers.
    Action {
        /// The provider adapter offering the proposed catalog action.
        integration: IntegrationKey,
        /// The catalog action to call with these inputs.
        operation: OperationKey,
        /// Its inputs, each a value or a path to earlier data.
        inputs: Vec<(FieldName, ProposedValue)>,
    },
    /// Gives an agent a goal; the builder picks the agent.
    AgentRun {
        /// The task description the selected agent should pursue.
        goal: Text,
    },
    /// Checks one value, then goes the "yes" or "no" way.
    Condition {
        /// The value checked.
        path: DataPath,
        /// What it should equal, or `None` to check it is there.
        equals: Option<String>,
    },
    /// Waits for a person to approve what follows.
    Approval {
        /// What they are asked.
        summary: Text,
        /// The kind of action that follows.
        class: DeclaredAction,
    },
    /// Waits a while.
    Wait {
        /// How long, in seconds.
        seconds: u32,
    },
}

/// A proposed input's value.
#[derive(Debug, Clone, PartialEq)]
pub enum ProposedValue {
    /// Written out.
    Text(String),
    /// Read from the trigger or an earlier step.
    Path(DataPath),
}

/// A proposed arrow.
#[derive(Debug, Clone, PartialEq)]
pub struct ProposedEdge {
    /// The step it leaves, or `None` for the step the proposal goes after.
    pub from: Option<NodeKey>,
    /// The way out it leaves by.
    pub port: Port,
    /// The step it leads to.
    pub to: NodeKey,
}

/// The ports [`DraftUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DraftPorts {
    /// The versions, for the steps a continuation follows.
    pub workflows: Arc<dyn WorkflowStore>,
    /// What the integrations offer.
    pub catalog: Arc<dyn IntegrationCatalog>,
    /// The tenant's model providers.
    pub providers: Arc<dyn ModelProviderStore>,
    /// Opens a provider's key for one call.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Asks the model.
    pub model_client: Arc<dyn ModelClient>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Drafts steps from a person's words.
pub struct DraftUseCase {
    ports: DraftPorts,
}

impl DraftUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DraftPorts) -> Self {
        Self { ports }
    }

    /// Every operation every installed integration offers now.
    async fn offered(&self) -> Result<Vec<OperationSpec>, AppError> {
        let mut offered = Vec::new();
        for profile in self.ports.catalog.installed().await.or_internal()? {
            offered.extend(
                self.ports
                    .catalog
                    .offered(profile.key())
                    .await
                    .or_internal()?,
            );
        }
        Ok(offered)
    }

    /// What the model is told of where the steps go.
    async fn place_told(
        &self,
        ctx: &CallerContext,
        place: &DraftPlace,
    ) -> Result<String, AppError> {
        let DraftPlace::After { workflow_id, step } = place else {
            return Ok("Propose a whole new workflow, with its trigger.".to_owned());
        };
        let workflow =
            latest_version(self.ports.workflows.as_ref(), &ctx.tenant(), workflow_id).await?;
        let keys: Vec<String> = workflow
            .graph()
            .nodes()
            .iter()
            .map(|node| node.key().to_string())
            .collect();
        Ok(format!(
            "Propose only the steps that come after the step \"{step}\" of an existing draft whose steps are: {}. Leave out the trigger; an edge from null leaves \"{step}\".",
            keys.join(", ")
        ))
    }
}

impl Query for DraftUseCase {
    type Caller = CallerContext;
    type Input = DraftRequest;
    type Output = Result<Proposal, AppError>;

    /// Steps the tenant's model proposes for `request.words`, as far as
    /// they fit what is offered, for the person `ctx` names.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not edit workflows.
    /// - `AppError::NotFound` when the tenant has no such active provider,
    ///   or the workflow continued is gone.
    /// - `AppError::Upstream` when the model cannot be reached or gives no
    ///   answer it can use.
    /// - `AppError::Internal` when a store or the catalog fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: DraftRequest,
    ) -> Result<Proposal, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::Update)
            .map_err(AppError::from_domain)?;
        let offered = self.offered().await?;
        let place = self.place_told(ctx, &request.place).await?;
        let target = active_model(
            self.ports.providers.as_ref(),
            self.ports.encryptor.as_ref(),
            &ctx.tenant(),
            &request.provider_id,
        )
        .await?;
        let prompt = prompt(&offered, &place, &request.words);
        let completion = self
            .ports
            .model_client
            .complete(&target, &prompt)
            .await
            .map_err(|failure| AppError::upstream(failure.error))?;
        let Some(answer) = completion.finished() else {
            return Ok(only_note(
                "The model's answer was cut off before it finished. Ask for fewer steps.",
            ));
        };
        Ok(proposal_from(&answer, &offered, &request.place))
    }
}

/// What the model is asked: its instructions for what is `offered` and
/// where the steps go, then the person's `words`.
fn prompt(offered: &[OperationSpec], place: &str, words: &Text) -> CompletionRequest {
    CompletionRequest {
        messages: vec![
            ChatMessage::system(instructions(offered, place)),
            ChatMessage::user(words.as_str()),
        ],
        max_tokens: Some(ANSWER_TOKENS),
    }
}

/// One operation as the model is shown it: its name, what it does and its
/// inputs.
fn catalog_line(spec: &OperationSpec) -> String {
    let inputs: Vec<&str> = spec
        .inputs()
        .iter()
        .map(|input| input.name().as_str())
        .collect();
    format!(
        "{}.{} ({}) inputs: {}",
        spec.integration(),
        spec.operation(),
        effect_word(spec.effect()),
        inputs.join(", ")
    )
}

/// What the model is asked to do, given what is `offered` and where the
/// steps go.
fn instructions(offered: &[OperationSpec], place: &str) -> String {
    let catalog: Vec<String> = offered.iter().map(catalog_line).collect();
    format!(
        "You draft workflow steps. {place}\n\
Answer with one JSON object and nothing else:\n\
{{\"trigger\": {{\"kind\": \"manual|webhook|schedule|service_event\", \"cron\": \"...\", \"integration\": \"...\", \"event\": \"...\"}},\n\
 \"steps\": [{{\"key\": \"lowercase_key\", \"title\": \"Short name\", \"kind\": \"action|agent_run|condition|approval|wait\",\n\
   \"integration\": \"...\", \"operation\": \"...\", \"inputs\": {{\"name\": {{\"text\": \"...\"}} or {{\"path\": \"trigger.field or step_key.field\"}}}},\n\
   \"goal\": \"for agent_run\", \"path\": \"for condition\", \"equals\": \"for condition\",\n\
   \"summary\": \"for approval\", \"class\": \"read|write|communicate|delete|configure|financial|admin|undeclared\", \"seconds\": 60}}],\n\
 \"edges\": [{{\"from\": \"key or null\", \"port\": \"next|when_true|when_false\", \"to\": \"key\"}}],\n\
 \"notes\": [\"anything the person must know, such as a step no operation fits\"]}}\n\
Use only these operations; if none fits, add a note instead of inventing one:\n{}\n\
Put an approval right before any step that deletes, configures, moves money, administers or is undeclared. At most {MAX_PROPOSED_STEPS} steps.",
        catalog.join("\n")
    )
}

/// A plain word for what an operation does, for the model.
fn effect_word(effect: DeclaredAction) -> &'static str {
    match effect {
        DeclaredAction::Declared(class) => class.as_str(),
        DeclaredAction::Undeclared => "undeclared",
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::{block_on, test_ctx};

    /// Sam may only view workflows, so he may not ask the tenant's model
    /// for steps: he is refused before any model is reached.
    #[test]
    fn suggesting_steps_needs_the_right_to_edit() {
        let use_case = DraftUseCase::new(DraftPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Workflows(WorkflowAction::View),
            ])),
            ..DraftPorts::fakes()
        });
        let request = DraftRequest {
            provider_id: ModelProviderId::new(),
            words: Text::new("words", "post new bugs to #team").unwrap(),
            place: DraftPlace::NewWorkflow,
        };

        let refused = block_on(use_case.execute(&test_ctx(), request));

        assert!(matches!(refused, Err(AppError::Forbidden(_))));
    }
}
