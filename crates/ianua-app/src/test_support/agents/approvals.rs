//! The approvals people give agents' paused actions, kept in memory.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::delegation::ActingUnder;
use ianua_domain::domains::agents::oversight::approval::{
    ApprovalAction, ApprovalOrigin, ApprovalRequest, ApprovalRequestRow, ApprovalState,
    StoredApprovalOrigin, StoredRunOrigin,
};
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::{AgentId, ApprovalId, DelegationId, PrincipalRef};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::agents::{
    ApprovalBroker, ApprovalStore, GatedAction, Held, RequestOpened, Spending,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::agents::shelf::Shelf;
use crate::test_support::{Fake, Rewind};

/// In-memory approval store: requests are kept per tenant and saved in
/// place, and spending one marks it used, as the store's one-statement write
/// does. Like storage, it refuses a save over a request decided or spent
/// since it was read as a conflict.
#[derive(Default)]
pub struct FakeApprovalStore {
    approvals: Shelf<ApprovalRequest<ResolvedTenant>>,
    lapse_before_save: AtomicBool,
}

impl TenantScoped for FakeApprovalStore {}

impl Rewind for FakeApprovalStore {
    fn mark(&self) -> Box<dyn FnOnce() + Send + Sync + '_> {
        self.approvals.mark()
    }
}

impl FakeApprovalStore {
    /// A store holding no requests.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding no requests yet, where every request still pending
    /// runs out just before the first save of a known one, as a sweep
    /// would leave it, so a use case that read one pending saves its
    /// decision over an expired one.
    #[must_use]
    pub fn lapsing_while_decided() -> Self {
        Self {
            lapse_before_save: AtomicBool::new(true),
            ..Self::default()
        }
    }

    /// Expires every pending request of `tenant_id`, when the store was
    /// made to and a known request is being saved.
    fn sweep_lapses(&self, tenant_id: &ScopedTenant) -> Result<(), DomainError> {
        if !self.lapse_before_save.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        for mut pending in self
            .approvals
            .filter(tenant_id, ApprovalRequest::is_pending)
        {
            pending.expire()?;
            self.approvals.put(tenant_id, pending.clone(), |stored| {
                stored.id() == pending.id()
            });
        }
        Ok(())
    }

    /// How many requests are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.approvals.count()
    }

    /// Every request kept, in every tenant, oldest first.
    #[must_use]
    pub fn all(&self) -> Vec<ApprovalRequest<ResolvedTenant>> {
        self.approvals.all()
    }
}

#[async_trait]
impl ApprovalStore for FakeApprovalStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ApprovalId,
    ) -> Result<Option<ApprovalRequest<ResolvedTenant>>, DomainError> {
        Ok(self
            .approvals
            .find(tenant_id, |approval| approval.id() == id))
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, DomainError> {
        let mut approvals = self.approvals.filter(tenant_id, |approval| {
            approval.agent_id() == agent && status.is_none_or(|wanted| approval.status() == wanted)
        });
        approvals.reverse();
        Ok(approvals)
    }

    async fn list_in_tenant(
        &self,
        tenant_id: &ScopedTenant,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ApprovalRequest<ResolvedTenant>>, DomainError> {
        let mut approvals = self.approvals.filter(tenant_id, |approval| {
            status.is_none_or(|wanted| approval.status() == wanted)
        });
        approvals.reverse();
        Ok(approvals)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        approval: &ApprovalRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let known = |stored: &ApprovalRequest<ResolvedTenant>| stored.id() == approval.id();
        if self.approvals.find(tenant_id, known).is_some() {
            self.sweep_lapses(tenant_id)?;
        }
        let stale = self
            .approvals
            .find(tenant_id, known)
            .is_some_and(|stored| !overwritable(&stored, approval));
        if stale {
            return Err(DomainError::conflict(
                "the approval request was decided or spent since it was read",
            ));
        }
        self.approvals.put(tenant_id, approval.clone(), |stored| {
            stored.id() == approval.id()
        });
        Ok(())
    }

    async fn find_pending_for_action(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &DelegationId,
        action: &ApprovalAction,
        now: OffsetDateTime,
    ) -> Result<Option<ApprovalRequest<ResolvedTenant>>, DomainError> {
        Ok(self.approvals.find(tenant_id, |approval| {
            awaits(approval, delegation, now) && approval.action() == action
        }))
    }

    async fn consume_for_action(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &DelegationId,
        action: &ApprovalAction,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let spent = self.approvals.revise_first(
            tenant_id,
            |approval| spendable(approval, delegation, now) && approval.action() == action,
            consumed,
        )?;
        Ok(spent.is_some())
    }

    async fn count_pending_for_delegation(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &DelegationId,
        now: OffsetDateTime,
    ) -> Result<u32, DomainError> {
        let open = self
            .approvals
            .filter(tenant_id, |approval| awaits(approval, delegation, now))
            .len();
        Ok(u32::try_from(open).unwrap_or(u32::MAX))
    }

    async fn count_signed_by(
        &self,
        tenant_id: &ScopedTenant,
        approver: &PrincipalRef,
        since: OffsetDateTime,
    ) -> Result<u32, DomainError> {
        let signed = self
            .approvals
            .filter(tenant_id, |_| true)
            .iter()
            .map(|approval| signatures_by(approval, approver, since))
            .sum::<usize>();
        Ok(u32::try_from(signed).unwrap_or(u32::MAX))
    }
}

/// Whether `next` may be written over `stored`, as storage allows: while
/// it still waits, when an approval is spent, or with the same decision
/// again. A copy read before another decision is refused.
fn overwritable(
    stored: &ApprovalRequest<ResolvedTenant>,
    next: &ApprovalRequest<ResolvedTenant>,
) -> bool {
    let spent =
        stored.status() == ApprovalStatus::Approved && next.status() == ApprovalStatus::Consumed;
    let same_decision = stored.status() == next.status()
        && stored.decided_by() == next.decided_by()
        && stored.decided_at() == next.decided_at();
    stored.status() == ApprovalStatus::Pending || spent || same_decision
}

/// Whether `approval` uses `delegation`.
fn uses(approval: &ApprovalRequest<ResolvedTenant>, delegation: &DelegationId) -> bool {
    *approval.delegation_id() == ActingUnder::Delegation(*delegation)
}

/// Whether `approval` under `delegation` still awaits a decision at `now`.
fn awaits(
    approval: &ApprovalRequest<ResolvedTenant>,
    delegation: &DelegationId,
    now: OffsetDateTime,
) -> bool {
    uses(approval, delegation) && approval.is_pending() && now < approval.expires_at()
}

/// Whether `approval` under `delegation` is approved and unexpired at `now`.
fn spendable(
    approval: &ApprovalRequest<ResolvedTenant>,
    delegation: &DelegationId,
    now: OffsetDateTime,
) -> bool {
    uses(approval, delegation) && approval.status().is_approved() && now < approval.expires_at()
}

/// How many approvals `approver` gave on `approval` since `since`: the
/// granting one and the first of two. A denial is not one.
fn signatures_by(
    approval: &ApprovalRequest<ResolvedTenant>,
    approver: &PrincipalRef,
    since: OffsetDateTime,
) -> usize {
    let granted = matches!(
        approval.status(),
        ApprovalStatus::Approved | ApprovalStatus::Consumed
    ) && approval.decided_by() == Some(*approver)
        && approval.decided_at().is_some_and(|at| at >= since);
    let first = approval
        .first_approval()
        .is_some_and(|first| first.by.principal() == *approver && first.at >= since);
    usize::from(granted) + usize::from(first)
}

/// `approval`, used up by its action now.
fn consumed(
    approval: &ApprovalRequest<ResolvedTenant>,
) -> Result<ApprovalRequest<ResolvedTenant>, DomainError> {
    let ApprovalState::Approved {
        approval: granting,
        first,
    } = approval.state().clone()
    else {
        return Err(DomainError::invalid_transition(
            "only an approved approval can be spent",
        ));
    };
    ApprovalRequest::reconstitute(ApprovalRequestRow {
        id: *approval.id(),
        agent_id: *approval.agent_id(),
        delegation_id: *approval.delegation_id(),
        origin: stored_origin(approval.origin()),
        parties: approval.parties().clone(),
        action_class: approval.action_class(),
        action: approval.action().clone(),
        state: ApprovalState::Consumed {
            approval: granting,
            first,
        },
        created_at: approval.created_at(),
        expires_at: approval.expires_at(),
        updated_at: clock::now().max(approval.updated_at()),
    })
}

/// `origin` as storage keeps it.
fn stored_origin(origin: &ApprovalOrigin) -> StoredApprovalOrigin {
    match origin {
        ApprovalOrigin::Opened(by) => StoredApprovalOrigin::Opened(by.clone()),
        ApprovalOrigin::Run(run) => StoredApprovalOrigin::Run(StoredRunOrigin {
            run_id: *run.run_id(),
            agent_id: *run.agent_id(),
            started_by: run.started_by().clone(),
            pending_call: run.pending_call().clone(),
            exposure: run.exposure(),
            chain: run.chain(),
        }),
    }
}

impl Fake for Arc<dyn ApprovalStore> {
    fn fake() -> Self {
        Arc::new(FakeApprovalStore::empty())
    }
}

/// How the API behind a [`FakeApprovalBroker`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerAnswers {
    /// It answers each question as the API would.
    Answering,
    /// It holds nothing more: too many requests are open.
    Full,
    /// It refuses every question, as for a revoked delegation.
    Refusing,
    /// It cannot be reached.
    Unreachable,
}

/// The API as the gateway's approval broker reaches it, in memory: an
/// action is held once and found again after, and an approval granted for
/// exactly an action is spent on it once.
pub struct FakeApprovalBroker {
    answers: BrokerAnswers,
    granted: Mutex<Vec<GatedAction>>,
    held: Mutex<Vec<(GatedAction, ApprovalId)>>,
}

impl FakeApprovalBroker {
    fn with(answers: BrokerAnswers) -> Self {
        Self {
            answers,
            granted: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
        }
    }

    /// An API that answers every question.
    #[must_use]
    pub fn answering() -> Self {
        Self::with(BrokerAnswers::Answering)
    }

    /// An API with too many requests open to hold another.
    #[must_use]
    pub fn full() -> Self {
        Self::with(BrokerAnswers::Full)
    }

    /// An API that refuses every question.
    #[must_use]
    pub fn refusing() -> Self {
        Self::with(BrokerAnswers::Refusing)
    }

    /// An API the gateway cannot reach.
    #[must_use]
    pub fn unreachable() -> Self {
        Self::with(BrokerAnswers::Unreachable)
    }

    /// A person approves exactly `action`, once.
    pub fn grant(&self, action: &GatedAction) {
        self.granted.lock().unwrap().push(action.clone());
    }

    /// Fails the question unless the API answers it.
    fn ensure_answering(&self) -> Result<(), DomainError> {
        match self.answers {
            BrokerAnswers::Answering | BrokerAnswers::Full => Ok(()),
            BrokerAnswers::Refusing => Err(DomainError::forbidden("the delegation is not live")),
            BrokerAnswers::Unreachable => Err(DomainError::infra_msg("the API did not answer")),
        }
    }
}

impl TenantScoped for FakeApprovalBroker {}

#[async_trait]
impl ApprovalBroker for FakeApprovalBroker {
    async fn hold(
        &self,
        _tenant_id: &ScopedTenant,
        action: &GatedAction,
    ) -> Result<Held, DomainError> {
        self.ensure_answering()?;
        if self.answers == BrokerAnswers::Full {
            return Ok(Held::TooManyOpen);
        }
        let mut held = self.held.lock().unwrap();
        if let Some((_, approval_id)) = held.iter().find(|(open, _)| open == action) {
            return Ok(Held::AwaitingDecision {
                approval_id: *approval_id,
                opened: RequestOpened::Before,
            });
        }
        let approval_id = ApprovalId::new();
        held.push((action.clone(), approval_id));
        Ok(Held::AwaitingDecision {
            approval_id,
            opened: RequestOpened::Now,
        })
    }

    async fn spend(
        &self,
        _tenant_id: &ScopedTenant,
        action: &GatedAction,
    ) -> Result<Spending, DomainError> {
        self.ensure_answering()?;
        let mut granted = self.granted.lock().unwrap();
        let Some(at) = granted.iter().position(|approved| approved == action) else {
            return Ok(Spending::NoneGranted);
        };
        granted.remove(at);
        Ok(Spending::Spent)
    }
}

impl Fake for Arc<dyn ApprovalBroker> {
    fn fake() -> Self {
        Arc::new(FakeApprovalBroker::answering())
    }
}
