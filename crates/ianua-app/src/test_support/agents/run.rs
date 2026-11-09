//! An agent's runs, kept in memory: the model providers and tools a run
//! uses, the model it asks and the tools it calls, the runs themselves and
//! the switches that stop and lease them.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::execution::chat::{AnswerEnd, Completion, CompletionRequest};
use ianua_domain::domains::agents::execution::model_provider::ModelProvider;
use ianua_domain::domains::agents::execution::run::{
    AgentRun, CancelOrder, CancelOrderRow, RunStatus, ToolArguments,
};
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::execution::usage::ModelUsage;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, AgentRunId, AgentToolId, ModelProviderId};

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::agents::{
    ModelClient, ModelFailure, ModelProviderStore, ModelTarget, RunCancellation, RunLease,
    RunSortField, RunStore, RunSummary, RunVersion, ToolInvocationContext, ToolInvoker, ToolStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::agents::shelf::Shelf;
use crate::test_support::listing::page;
use crate::test_support::{Fake, Rewind};

/// In-memory model provider store: providers are kept per tenant, saved in
/// place and deleted for good.
#[derive(Default)]
pub struct FakeModelProviderStore {
    providers: Shelf<ModelProvider<ResolvedTenant>>,
}

impl TenantScoped for FakeModelProviderStore {}

impl FakeModelProviderStore {
    /// A store holding no providers.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many providers are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.providers.count()
    }

    /// Every provider kept, in every tenant, oldest first.
    #[must_use]
    pub fn all(&self) -> Vec<ModelProvider<ResolvedTenant>> {
        self.providers.all()
    }
}

#[async_trait]
impl ModelProviderStore for FakeModelProviderStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ModelProviderId,
    ) -> Result<Option<ModelProvider<ResolvedTenant>>, DomainError> {
        Ok(self
            .providers
            .find(tenant_id, |provider| provider.id() == id))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<ModelProvider<ResolvedTenant>>, DomainError> {
        Ok(self.providers.filter(tenant_id, |_| true))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        provider: &ModelProvider<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.providers.put(tenant_id, provider.clone(), |stored| {
            stored.id() == provider.id()
        });
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        id: &ModelProviderId,
    ) -> Result<(), DomainError> {
        self.providers
            .remove(tenant_id, |provider| provider.id() == id);
        Ok(())
    }
}

/// In-memory tool store: tools are kept per tenant, saved in place and
/// deleted for good.
#[derive(Default)]
pub struct FakeToolStore {
    tools: Shelf<AgentTool<ResolvedTenant>>,
}

impl TenantScoped for FakeToolStore {}

impl FakeToolStore {
    /// A store holding no tools.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many tools are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.tools.count()
    }

    /// Every tool kept, in every tenant, oldest first.
    #[must_use]
    pub fn all(&self) -> Vec<AgentTool<ResolvedTenant>> {
        self.tools.all()
    }
}

#[async_trait]
impl ToolStore for FakeToolStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentToolId,
    ) -> Result<Option<AgentTool<ResolvedTenant>>, DomainError> {
        Ok(self.tools.find(tenant_id, |tool| tool.id() == id))
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AgentTool<ResolvedTenant>>, DomainError> {
        Ok(self.tools.filter(tenant_id, |_| true))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        tool: &AgentTool<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.tools
            .put(tenant_id, tool.clone(), |stored| stored.id() == tool.id());
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &AgentToolId) -> Result<(), DomainError> {
        self.tools.remove(tenant_id, |tool| tool.id() == id);
        Ok(())
    }
}

/// Model client that gives one fixed reply, or fails every call.
pub struct FakeModelClient {
    outcome: Result<String, String>,
    usage: ModelUsage,
}

impl FakeModelClient {
    /// A client that always replies `reply`, reporting no usage.
    #[must_use]
    pub fn replying(reply: &str) -> Self {
        Self {
            outcome: Ok(reply.to_owned()),
            usage: ModelUsage::Unreported,
        }
    }

    /// A client whose backend always fails with `reason`.
    #[must_use]
    pub fn failing(reason: &str) -> Self {
        Self {
            outcome: Err(reason.to_owned()),
            usage: ModelUsage::Unreported,
        }
    }

    /// The same client, reporting `usage` with every reply.
    #[must_use]
    pub fn reporting(self, usage: ModelUsage) -> Self {
        Self { usage, ..self }
    }
}

#[async_trait]
impl ModelClient for FakeModelClient {
    async fn complete(
        &self,
        _target: &ModelTarget,
        _request: &CompletionRequest,
    ) -> Result<Completion, ModelFailure> {
        match &self.outcome {
            Ok(reply) => Ok(Completion {
                content: reply.clone(),
                usage: self.usage,
                ended: AnswerEnd::Finished,
            }),
            Err(reason) => Err(ModelFailure::unbilled(DomainError::infra_msg(
                reason.clone(),
            ))),
        }
    }
}

/// Tool invoker that records each call's tool, step and task token, and
/// answers every call with `reply`.
#[derive(Default)]
pub struct RecordingToolInvoker {
    /// The name of each tool invoked, in order.
    pub calls: Mutex<Vec<String>>,
    /// The run step each invocation belonged to, in order.
    pub steps: Mutex<Vec<u32>>,
    /// The task token each invocation presented, in order.
    pub tokens: Mutex<Vec<String>>,
    /// What every invocation answers.
    pub reply: String,
}

#[async_trait]
impl ToolInvoker for RecordingToolInvoker {
    async fn invoke(
        &self,
        tool: &AgentTool<ResolvedTenant>,
        _arguments: &ToolArguments,
        context: &ToolInvocationContext,
    ) -> Result<String, DomainError> {
        self.tokens
            .lock()
            .unwrap()
            .push(context.authorization.reveal().to_owned());
        self.calls
            .lock()
            .unwrap()
            .push(tool.name().as_str().to_owned());
        self.steps.lock().unwrap().push(context.step);
        Ok(self.reply.clone())
    }
}

/// In-memory run store: runs are kept per tenant and saved in place.
#[derive(Default)]
pub struct FakeRunStore {
    runs: Shelf<AgentRun<ResolvedTenant>>,
    moves_on: AtomicBool,
}

impl TenantScoped for FakeRunStore {}

impl Rewind for FakeRunStore {
    fn mark(&self) -> Box<dyn FnOnce() + Send + Sync + '_> {
        self.runs.mark()
    }
}

impl FakeRunStore {
    /// A store holding no runs.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many runs are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.runs.count()
    }

    /// Every run kept, in every tenant, oldest first.
    #[must_use]
    pub fn all(&self) -> Vec<AgentRun<ResolvedTenant>> {
        self.runs.all()
    }

    /// Makes every later save over a version refused, as when the worker
    /// keeps a step of the run between its reading and its saving.
    pub fn moves_on_before_each_save(&self) {
        self.moves_on.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl RunStore for FakeRunStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        run: &AgentRun<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        self.runs
            .put(tenant_id, run.clone(), |stored| stored.id() == run.id());
        Ok(())
    }

    async fn save_unchanged_since(
        &self,
        tenant_id: &ScopedTenant,
        run: &AgentRun<ResolvedTenant>,
        read: RunVersion,
    ) -> Result<RunVersion, DomainError> {
        let stored = self.runs.find(tenant_id, |stored| stored.id() == run.id());
        let moved_on = self.moves_on.load(Ordering::SeqCst);
        if moved_on || stored.is_none_or(|stored| RunVersion::of(&stored) != read) {
            return Err(DomainError::conflict("the run changed since it was read"));
        }
        self.runs
            .put(tenant_id, run.clone(), |stored| stored.id() == run.id());
        Ok(RunVersion::of(run))
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AgentRunId,
    ) -> Result<Option<AgentRun<ResolvedTenant>>, DomainError> {
        Ok(self.runs.find(tenant_id, |run| run.id() == id))
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        status: Option<RunStatus>,
        request: &PageRequest,
    ) -> Result<Page<RunSummary>, DomainError> {
        let runs = self.runs.filter(tenant_id, |run| {
            run.agent_id() == agent && status.is_none_or(|wanted| run.status() == wanted)
        });
        page(
            runs.iter().map(RunSummary::of).collect(),
            &SortOrder::<RunSortField>::default(),
            request,
        )
    }

    async fn list_in_tenant(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<RunStatus>,
        request: &PageRequest,
    ) -> Result<Page<RunSummary>, DomainError> {
        let runs = self.runs.filter(tenant_id, |run| {
            status.is_none_or(|wanted| run.status() == wanted)
        });
        page(
            runs.iter().map(RunSummary::of).collect(),
            &SortOrder::<RunSortField>::default(),
            request,
        )
    }
}

/// An order the test caller gave to stop `run_id`, as storage reads it back.
///
/// # Panics
///
/// - Never: an order given now is a consistent row.
#[must_use]
pub fn stop_order_for(run_id: AgentRunId) -> CancelOrder {
    CancelOrder::reconstitute(CancelOrderRow {
        run_id,
        by: crate::test_support::agents::caller_person(),
        at: ianua_domain::shared::clock::now(),
    })
    .expect("an order given now is a consistent row")
}

/// The run kill switch and lease, kept in memory for every node at once.
/// Orders are kept per tenant, beside the run they stop.
#[derive(Default)]
pub struct FakeRunControl {
    /// The orders to stop runs, as given, by tenant.
    orders: Shelf<CancelOrder>,
    /// The runs claimed for driving.
    pub claimed: Mutex<Vec<AgentRunId>>,
    /// When set, neither the switch nor the lease can be read or written.
    pub unreadable: AtomicBool,
    /// When set, another driver has taken over every claim.
    pub taken_over: AtomicBool,
}

impl FakeRunControl {
    /// A control with nothing cancelled and nothing claimed.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether an order to stop `run_id` is held, in any tenant.
    #[must_use]
    pub fn has_order_for(&self, run_id: &AgentRunId) -> bool {
        self.orders
            .all()
            .iter()
            .any(|order| order.run_id() == run_id)
    }

    /// Refuses when the control was made unreadable.
    fn ensure_readable(&self) -> Result<(), DomainError> {
        if self.unreadable.load(Ordering::SeqCst) {
            return Err(DomainError::infra_msg("the run control is unreachable"));
        }
        Ok(())
    }
}

impl TenantScoped for FakeRunControl {}

#[async_trait]
impl RunCancellation for FakeRunControl {
    async fn request_cancel(
        &self,
        tenant_id: &ScopedTenant,
        order: &CancelOrder,
    ) -> Result<(), DomainError> {
        self.ensure_readable()?;
        self.orders.put(tenant_id, order.clone(), |held| {
            held.run_id() == order.run_id()
        });
        Ok(())
    }

    async fn order_for(
        &self,
        tenant_id: &ScopedTenant,
        run_id: &AgentRunId,
    ) -> Result<Option<CancelOrder>, DomainError> {
        self.ensure_readable()?;
        Ok(self
            .orders
            .find(tenant_id, |order| order.run_id() == run_id))
    }

    async fn clear(&self, tenant_id: &ScopedTenant, run_id: &AgentRunId) {
        self.orders
            .remove(tenant_id, |order| order.run_id() == run_id);
    }
}

#[async_trait]
impl RunLease for FakeRunControl {
    async fn try_claim(&self, run_id: &AgentRunId) -> Result<bool, DomainError> {
        self.ensure_readable()?;
        let mut claimed = self.claimed.lock().unwrap();
        if claimed.contains(run_id) {
            return Ok(false);
        }
        claimed.push(*run_id);
        Ok(true)
    }

    async fn renew(&self, run_id: &AgentRunId) -> Result<bool, DomainError> {
        self.ensure_readable()?;
        let held = self.claimed.lock().unwrap().contains(run_id);
        Ok(held && !self.taken_over.load(Ordering::SeqCst))
    }

    async fn release(&self, run_id: &AgentRunId) {
        self.claimed.lock().unwrap().retain(|id| id != run_id);
    }
}

impl Fake for Arc<dyn ModelClient> {
    fn fake() -> Self {
        Arc::new(FakeModelClient::replying("ok"))
    }
}

impl Fake for Arc<dyn ModelProviderStore> {
    fn fake() -> Self {
        Arc::new(FakeModelProviderStore::empty())
    }
}

impl Fake for Arc<dyn RunCancellation> {
    fn fake() -> Self {
        Arc::new(FakeRunControl::empty())
    }
}

impl Fake for Arc<dyn RunLease> {
    fn fake() -> Self {
        Arc::new(FakeRunControl::empty())
    }
}

impl Fake for Arc<dyn RunStore> {
    fn fake() -> Self {
        Arc::new(FakeRunStore::empty())
    }
}

impl Fake for Arc<dyn ToolInvoker> {
    fn fake() -> Self {
        Arc::new(RecordingToolInvoker::default())
    }
}

impl Fake for Arc<dyn ToolStore> {
    fn fake() -> Self {
        Arc::new(FakeToolStore::empty())
    }
}
