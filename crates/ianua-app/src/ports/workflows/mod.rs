//! Workflows ports: the stores for workflow versions, their executions,
//! integration accounts, risk overrides, webhook secrets, sandboxes,
//! memories and evaluations, the vector store and the embeddings client, and
//! the bundler of a sandbox version's packages; the maker of
//! those secrets; the integration catalog and the
//! adapter that makes an action's call; what keeps one worker on an
//! execution and wakes it when a step falls due; and the pages of a loop's
//! items each approver opened.

use async_trait::async_trait;
use ianua_domain::domains::workflows::account::IntegrationAccount;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::design::workflow::Workflow;
use ianua_domain::domains::workflows::execution::WorkflowExecution;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::domains::workflows::integration::events::{ServiceEventGuide, ServiceEventSpec};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::domains::workflows::integration::risk_override::OperationRiskOverride;
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationSpec};
use ianua_domain::domains::workflows::triggers::CronSchedule;
use ianua_domain::domains::workflows::triggers::before::{GuardedChange, Verdict};
use ianua_domain::domains::workflows::triggers::secret::WorkflowTriggerSecret;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    AgentRunId, EventType, IntegrationAccountId, OperationRiskOverrideId, SealedSecret, TenantId,
    Timezone, TokenHash, WorkflowExecutionId, WorkflowId, WorkflowTriggerId,
};
use time::OffsetDateTime;

mod approval_pages;
mod calendar;
mod calls;
mod company;
mod connections;
mod evaluations;
mod grants;
mod memory;
mod passes;
mod repositories;
mod sandboxes;
mod subscriptions;

pub use self::approval_pages::{ApprovalPages, ItemsViewer};
pub use self::calendar::WorkingCalendar;
pub use self::calls::{ActionRun, ActionRunner, CallCredential, DataCall};
pub use self::company::{CompanyCall, CompanySteps};
pub use self::connections::{
    ConnectionAt, ConnectionSecrets, ConnectionStates, Exchanging, PendingConnectionStore,
    PlaceAsked, ServiceSignIn, SignInAddress, SignInFailure, SignInRequest,
};
pub use self::evaluations::{EvaluationSetStore, EvaluationStore};
pub use self::grants::{GrantExchangeLease, GrantExchanger, GrantTurn, TurnHolder};
pub use self::memory::{
    CrossTenantMemories, Embedder, EmbeddingTarget, MemoryEntries, MemoryStore,
};
pub use self::passes::{RunPassGrant, RunPasses};
pub use self::repositories::{
    CodeRepositories, FileAt, FileRead, Push, Pushed, PushedFile, RepositoryAccount,
    RepositoryRefusal,
};
pub use self::sandboxes::{
    BundleRequest, Bundling, CodeRan, CodeRequest, CodeRunner, ImageRegistryStore, ImageResolver,
    ImageScanner, OfferedRuntime, OwnImages, PackageBundler, PullLogin, Resolving, SandboxRuntimes,
    SandboxSortField, SandboxStore, SandboxTrialStore, SandboxVersionStore, Scanning,
};
pub use self::subscriptions::{
    AccountChannelStore, ChannelAt, ChannelDirectory, ChannelRegistered, CheckBody, CheckReply,
    DeliveryId, DeliveryLedger, DeliveryRetention, EventReading, Greeting, PulledEvents, Reading,
    ReceivedEvent, Registered, RegistrarAnswer, RegistrationFailure, RegistrationKeys, Route,
    RouteKey, Routing, ServiceChannelSetup, ServiceEventReader, ServiceRegistrar,
    ServiceSubscriptionStore, SubscriptionAt, SubscriptionDirectory,
};
use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a listing of workflows can be ordered by.
    pub enum WorkflowSortField {
        /// Order by when the latest version was drafted.
        CreatedAt => "created_at",
        /// Order by when the latest version last changed.
        UpdatedAt => "updated_at",
        /// Order by name.
        Name => "name",
    }
    default = UpdatedAt;
    default direction = Desc;
}

impl SortKeys<WorkflowSortField> for Workflow<ResolvedTenant> {
    fn sort_key(&self, field: WorkflowSortField) -> SortKey {
        match field {
            WorkflowSortField::CreatedAt => Aggregate::created_at(self).into(),
            WorkflowSortField::UpdatedAt => Aggregate::updated_at(self).into(),
            WorkflowSortField::Name => self.name().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

define_sort_field! {
    /// The one order agent flows and executions are listed in: newest
    /// first.
    pub enum NewestFirstField {
        /// Order by creation time.
        CreatedAt => "created_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<NewestFirstField> for Workflow<ResolvedTenant> {
    fn sort_key(&self, field: NewestFirstField) -> SortKey {
        match field {
            NewestFirstField::CreatedAt => Aggregate::created_at(self).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

impl SortKeys<NewestFirstField> for WorkflowExecution<ResolvedTenant> {
    fn sort_key(&self, field: NewestFirstField) -> SortKey {
        match field {
            NewestFirstField::CreatedAt => Aggregate::created_at(self).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

define_sort_field! {
    /// The one order integration accounts are listed in: oldest first.
    pub enum IntegrationAccountSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
    }
    default = CreatedAt;
}

impl SortKeys<IntegrationAccountSortField> for IntegrationAccount<ResolvedTenant> {
    fn sort_key(&self, field: IntegrationAccountSortField) -> SortKey {
        match field {
            IntegrationAccountSortField::CreatedAt => Aggregate::created_at(self).into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

define_sort_field! {
    /// The one order scheduled versions are read in: by tenant, then by
    /// workflow.
    pub enum ScheduledVersionSortField {
        /// Order by tenant.
        Tenant => "tenant_id",
    }
    default = Tenant;
}

impl SortKeys<ScheduledVersionSortField> for ScheduledVersion {
    fn sort_key(&self, field: ScheduledVersionSortField) -> SortKey {
        match field {
            ScheduledVersionSortField::Tenant => self.tenant_id.as_uuid().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.workflow_id.as_uuid().into()
    }
}

/// Dyn-safe port keeping workflow versions, one row per version.
///
/// A workflow and version pair is unique, and at most one version of a
/// workflow is published at a time. Storage refuses a second row for either,
/// so two drafts made from the same version, or two versions published at
/// once, cannot both be kept.
#[async_trait]
pub trait WorkflowStore: Send + Sync + TenantScoped {
    /// One version of a workflow.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_version(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
        version: u32,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError>;

    /// The workflow's highest-numbered version.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_latest(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError>;

    /// The workflow's version in service, when one is published.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_published(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
    ) -> Result<Option<Workflow<ResolvedTenant>>, DomainError>;

    /// The latest version of each workflow the tenant designed, ordered and
    /// paged. Agent flows are left out:
    /// [`list_flows`](Self::list_flows) lists them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list_latest(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<WorkflowSortField>,
        page: &PageRequest,
    ) -> Result<Page<Workflow<ResolvedTenant>>, DomainError>;

    /// The tenant's agent flows, each its one version, newest first and
    /// paged.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list_flows(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<Workflow<ResolvedTenant>>, DomainError>;

    /// Every published version that starts on `event`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list_published_on(
        &self,
        tenant_id: &ScopedTenant,
        event: EventType,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError>;

    /// Every published version that decides `change` before it happens.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list_published_before(
        &self,
        tenant_id: &ScopedTenant,
        change: GuardedChange,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError>;

    /// Every version in service that acts through `account`, by its trigger
    /// or a step.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list_published_using(
        &self,
        tenant_id: &ScopedTenant,
        account: &IntegrationAccountId,
    ) -> Result<Vec<Workflow<ResolvedTenant>>, DomainError>;

    /// Keeps a version drafted just now.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the workflow already has a
    /// version with its number, as when two people draft the next version
    /// from the same one, and `DomainError::Infrastructure` when the store
    /// cannot be written.
    async fn insert(
        &self,
        tenant_id: &ScopedTenant,
        workflow: &Workflow<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Saves a change to a version already kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when it would leave two published
    /// versions of the workflow, and `DomainError::Infrastructure` when the
    /// store cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        workflow: &Workflow<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes every version of the agent flow `id`, the one
    /// [`Workflow::delete_flow`] allowed. A designed workflow is archived,
    /// never deleted.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn delete_flow(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowId,
    ) -> Result<(), DomainError>;
}

/// The version of an execution as it was read: the time it last changed.
///
/// A running execution is changed by the worker driving it, by an agent run
/// it waits on settling, and by people approving, denying or cancelling it.
/// A change saved over a version that moved on would undo the other's: an
/// approval read before the worker took the step would put the step back.
/// So every change to a stored execution goes through
/// [`WorkflowExecutionStore::save_unchanged_since`] with the version it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionVersion(OffsetDateTime);

impl ExecutionVersion {
    /// The version `execution` is at. Only an execution read back from the
    /// store, or the version a save gave back, names a version the store
    /// can compare: one changed in memory carries a time the store has not
    /// kept.
    #[must_use]
    pub fn of(execution: &WorkflowExecution<ResolvedTenant>) -> Self {
        Self(Aggregate::updated_at(execution))
    }

    /// The version a store kept an execution at: `changed_at`, the time it
    /// last changed as the store wrote it.
    #[must_use]
    pub fn stored(changed_at: OffsetDateTime) -> Self {
        Self(changed_at)
    }

    /// The time the execution last changed at this version.
    #[must_use]
    pub fn changed_at(self) -> OffsetDateTime {
        self.0
    }
}

/// Which runs a list holds: the real ones, or the tests of drafts. A list
/// holds one kind only, so a test is never read as work done.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RunKind {
    /// Runs that did their work.
    #[default]
    Real,
    /// Tests, whose steps that would reach out stood in.
    Tests,
}

/// Dyn-safe port keeping workflow executions.
#[async_trait]
pub trait WorkflowExecutionStore: Send + Sync + TenantScoped {
    /// One execution.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowExecutionId,
    ) -> Result<Option<WorkflowExecution<ResolvedTenant>>, DomainError>;

    /// The execution one of whose steps started `run_id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_agent_run(
        &self,
        tenant_id: &ScopedTenant,
        run_id: &AgentRunId,
    ) -> Result<Option<WorkflowExecution<ResolvedTenant>>, DomainError>;

    /// The latest execution of each requested workflow, ordered by creation
    /// time then id descending within each workflow. Missing runs are omitted.
    /// The returned workflows have no guaranteed order. The passes of loops
    /// are left out: each belongs to the execution that started it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when storage or reconstitution fails.
    async fn latest_for_workflows(
        &self,
        tenant_id: &ScopedTenant,
        workflow_ids: &[WorkflowId],
    ) -> Result<Vec<WorkflowExecution<ResolvedTenant>>, DomainError>;

    /// The executions of `kind` of every version of `workflow_id`, newest
    /// first and paged. The passes of loops are left out.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list_for_workflow(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
        kind: RunKind,
        page: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError>;

    /// The passes the loops of execution `execution_id` started, newest
    /// first and paged.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list_passes(
        &self,
        tenant_id: &ScopedTenant,
        execution_id: &WorkflowExecutionId,
        page: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError>;

    /// The executions of `kind` of every workflow the tenant designed,
    /// newest first and paged. The runs of agent flows are left out, as
    /// their flows are, and so are the passes of loops.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list_designed(
        &self,
        tenant_id: &ScopedTenant,
        kind: RunKind,
        page: &PageRequest,
    ) -> Result<Page<WorkflowExecution<ResolvedTenant>>, DomainError>;

    /// Saves a new execution. A change to a stored one goes through
    /// [`save_unchanged_since`](Self::save_unchanged_since), so it cannot
    /// undo a change made since it was read.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when a stored execution already
    /// ended otherwise, and `DomainError::Infrastructure` when the store
    /// cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        execution: &WorkflowExecution<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Saves `execution`, and the agent runs its steps wait on, only when
    /// the stored execution is still at `read`, the version the caller read
    /// before changing it, and gives back the version it is stored at now.
    ///
    /// The check and the write are one statement, and every write moves
    /// the version on, so of two changes read from one version only the
    /// first is kept. The execution must already be stored.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when the stored execution changed since
    ///   `read`, or is gone.
    /// - `DomainError::Infrastructure` when the store cannot be written.
    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        execution: &WorkflowExecution<ResolvedTenant>,
        read: ExecutionVersion,
    ) -> Result<ExecutionVersion, DomainError>;

    /// Deletes the execution `id`: an agent flow's run, deleted with its
    /// flow.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowExecutionId,
    ) -> Result<(), DomainError>;

    /// Removes `tenant_id`'s runs that ended before `cutoff`, oldest first
    /// and a batch at a time, with their loop passes and what they waited
    /// on. A run still running or waiting stays, however old, and so does
    /// one another run was started again from, which goes after it.
    /// Returns how many went.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn purge_ended_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError>;
}

/// Dyn-safe port keeping the secrets workflows' webhooks are called with,
/// at most one per workflow. Only the secret's digest is kept.
#[async_trait]
pub trait WorkflowTriggerSecretStore: Send + Sync + TenantScoped {
    /// The secret whose id the webhook's address names.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowTriggerId,
    ) -> Result<Option<WorkflowTriggerSecret<ResolvedTenant>>, DomainError>;

    /// The secret of `workflow_id`'s webhook, when one was issued.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_for_workflow(
        &self,
        tenant_id: &ScopedTenant,
        workflow_id: &WorkflowId,
    ) -> Result<Option<WorkflowTriggerSecret<ResolvedTenant>>, DomainError>;

    /// Saves a new or replaced secret.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when the workflow already has
    /// another secret, as when two people issue one at once, and
    /// `DomainError::Infrastructure` when the store cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        secret: &WorkflowTriggerSecret<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes the secret `id`, the one
    /// [`WorkflowTriggerSecret::revoke`] allowed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &WorkflowTriggerId,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port making and hashing the secrets workflows' webhooks are
/// called with.
///
/// The hash is keyed, an HMAC under a key the server holds and the database
/// does not, and the same for the same secret every time, so a presented
/// secret is checked by hashing it again and a copied table cannot be
/// searched offline.
#[async_trait]
pub trait WorkflowTriggerSecretGenerator: Send + Sync {
    /// A new random secret and its hash. The secret is shown once, to the
    /// person who asked for it, and never kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source
    /// fails.
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError>;

    /// The hash of a secret a webhook call presented, under the same key
    /// [`generate`](Self::generate) hashed with.
    fn hash_presented(&self, presented: &Secret) -> TokenHash;
}

/// Dyn-safe port keeping the accounts a tenant connected to integrations.
#[async_trait]
pub trait IntegrationAccountStore: Send + Sync + TenantScoped {
    /// One account.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &IntegrationAccountId,
    ) -> Result<Option<IntegrationAccount<ResolvedTenant>>, DomainError>;

    /// The tenant's accounts, oldest first and paged.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        page: &PageRequest,
    ) -> Result<Page<IntegrationAccount<ResolvedTenant>>, DomainError>;

    /// Saves a new or changed account.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        account: &IntegrationAccount<ResolvedTenant>,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port keeping a tenant's raised views of operations, at most one
/// for each integration's operation.
#[async_trait]
pub trait OperationRiskOverrideStore: Send + Sync + TenantScoped {
    /// One override.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &OperationRiskOverrideId,
    ) -> Result<Option<OperationRiskOverride<ResolvedTenant>>, DomainError>;

    /// Every override the tenant set, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<OperationRiskOverride<ResolvedTenant>>, DomainError>;

    /// Saves a new or changed override.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when another override already names
    /// the same operation, and `DomainError::Infrastructure` when the store
    /// cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        risk: &OperationRiskOverride<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes the override `id`, the one
    /// [`OperationRiskOverride::remove`] gave back.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &OperationRiskOverrideId,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port listing what the integrations installed offer.
///
/// It is read at publish and again before every action, so an operation an
/// integration withdrew or changed stops the steps that use it.
#[async_trait]
pub trait IntegrationCatalog: Send + Sync {
    /// Every integration installed, each once, as it presents itself.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the catalog cannot be
    /// read.
    async fn installed(&self) -> Result<Vec<IntegrationProfile>, DomainError>;

    /// How `integration` explains each operation it offers, one guide per
    /// operation. None when no such integration is installed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the catalog cannot be
    /// read.
    async fn guides(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<OperationGuide>, DomainError>;

    /// The operations `integration` offers now, as it declares them. None
    /// when no such integration is installed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the catalog cannot be
    /// read.
    async fn offered(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<OperationSpec>, DomainError>;

    /// The events `integration`'s service sends that a workflow may start
    /// on, as it declares them now. None when no such integration is
    /// installed, or its service sends none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the catalog cannot be
    /// read.
    async fn events(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<ServiceEventSpec>, DomainError>;

    /// How `integration` explains each event it offers, one guide per
    /// event.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the catalog cannot be
    /// read.
    async fn event_guides(
        &self,
        integration: &IntegrationKey,
    ) -> Result<Vec<ServiceEventGuide>, DomainError>;
}

/// Dyn-safe port asking an integration whether an account's credential
/// works, before the account is kept with it.
///
/// The adapter bounds the question with a timeout; a service that does not
/// answer in time is [`AccountCheck::Unreachable`], never accepted.
#[async_trait]
pub trait AccountVerifier: Send + Sync {
    /// What `integration`'s service says of `credential`, with the
    /// credential to keep in its place when asking replaced it.
    async fn check(&self, integration: &IntegrationKey, credential: &Secret) -> CredentialCheck;
}

/// What a service said of a credential, and the credential asking
/// replaced, for a service whose grants rotate on every use: the one
/// asked with no longer works, so the account keeps the replacement.
#[derive(Debug)]
pub struct CredentialCheck {
    /// What the service said.
    pub verdict: AccountCheck,
    /// The credential to keep instead, when asking replaced it.
    pub replaced_by: Option<Secret>,
}

/// Whether the service renewed an account's credential as a call used it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Renewal {
    /// The credential is as it was.
    Unchanged,
    /// The service renewed it; this is the renewed one, sealed for the
    /// account, to keep in its place.
    Renewed(SealedSecret),
}

/// Dyn-safe port for the lease that keeps one worker on an execution at a
/// time, so delivering a wake-up twice drives it once.
#[async_trait]
pub trait ExecutionLease: Send + Sync {
    /// Claims `id` for this worker. `false` when another worker holds a
    /// live claim. A claim whose holder crashed lapses and is taken again.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the claim cannot be made
    /// or read. The caller does not drive the execution then.
    async fn try_claim(&self, id: &WorkflowExecutionId) -> Result<bool, DomainError>;

    /// Lets go of the claim on `id`.
    async fn release(&self, id: &WorkflowExecutionId);
}

/// A version in service that starts on a schedule, with the timezone its
/// tenant reads the schedule in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledVersion {
    /// The owner whose timezone governs this schedule.
    pub tenant_id: TenantId,
    /// The workflow whose version in service starts on the schedule.
    pub workflow_id: WorkflowId,
    /// When it starts.
    pub schedule: CronSchedule,
    /// The tenant's timezone, which the schedule is read in.
    pub timezone: Timezone,
}

/// Dyn-safe port reading, across every tenant, the versions in service
/// that start on a schedule, for the scheduler that fires them.
#[async_trait]
pub trait ScheduledWorkflows: Send + Sync {
    /// A page of them, in [`ScheduledVersionSortField`]'s order, which holds
    /// from one page to the next.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be read, or
    /// the read does not answer within ten seconds.
    async fn list_scheduled(
        &self,
        page: &PageRequest,
    ) -> Result<Page<ScheduledVersion>, DomainError>;
}

/// Dyn-safe port a guarded change asks before it is saved: the tenant's
/// published "before" workflows decide it.
#[async_trait]
pub trait ChangeGuard: Send + Sync {
    /// What the rules decide about `change`, which would do `proposed`, in
    /// `tenant`: Refuse when one refuses, ends undecided, may not start or
    /// does not answer in time; Allow when every one allows, or none is
    /// published.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the rules or their runs
    /// cannot be read or started.
    async fn decide(
        &self,
        tenant: &ScopedTenant,
        auditor: &crate::auditor::RequestAuditor,
        change: GuardedChange,
        proposed: FlowData,
    ) -> Result<Verdict, DomainError>;
}
