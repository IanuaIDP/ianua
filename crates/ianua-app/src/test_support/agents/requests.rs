//! The delegations agents ask people for, kept in memory, and requests
//! built as tests need them.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::{CapabilitySet, DelegationConstraints};
use ianua_domain::domains::agents::authority::delegation_request::{
    AskDelegationParams, DelegationReason, DelegationRequest, DelegationRequestRow, RequestState,
};
use ianua_domain::domains::agents::identity::acting::ActingAgent;
use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentId, DelegationRequestId, Human, PrincipalRef, Seconds};

use crate::ports::TenantScoped;
use crate::ports::agents::DelegationRequestStore;
use crate::tenancy::ScopedTenant;
use crate::test_support::agents::shelf::Shelf;
use crate::test_support::{Fake, block_on, test_ctx};

/// In-memory delegation request store: requests are kept per tenant and
/// saved in place. Like storage, it refuses a save over a request answered
/// since it was read as a conflict.
#[derive(Default)]
pub struct FakeDelegationRequestStore {
    requests: Shelf<DelegationRequest<ResolvedTenant>>,
    refused_before_save: AtomicBool,
}

impl TenantScoped for FakeDelegationRequestStore {}

impl FakeDelegationRequestStore {
    /// A store holding no requests.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding `requests` in the test tenant, where every one still
    /// pending is refused by someone else just before the first save of a
    /// known one, so a use case that read one pending saves its answer over
    /// a refused one.
    #[must_use]
    pub fn refused_while_answered(
        requests: impl IntoIterator<Item = DelegationRequest<ResolvedTenant>>,
    ) -> Self {
        let store = Self::holding(requests);
        store.refused_before_save.store(true, Ordering::SeqCst);
        store
    }

    /// Refuses every pending request of `tenant_id`, as someone else would,
    /// when the store was made to.
    fn someone_refuses(&self, tenant_id: &ScopedTenant) -> Result<(), DomainError> {
        if !self.refused_before_save.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        let pending = self
            .requests
            .filter(tenant_id, |stored| stored.state() == RequestState::Pending);
        for request in pending {
            let refused = refused(&request)?;
            self.requests
                .put(tenant_id, refused, |stored| stored.id() == request.id());
        }
        Ok(())
    }

    /// A store holding `requests` in the test tenant.
    ///
    /// # Panics
    ///
    /// - Never: the fake store keeps every request.
    #[must_use]
    pub fn holding(requests: impl IntoIterator<Item = DelegationRequest<ResolvedTenant>>) -> Self {
        let store = Self::empty();
        for request in requests {
            block_on(store.save(&test_ctx().tenant(), &request)).expect("the fake store keeps it");
        }
        store
    }

    /// How many requests are kept, in every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.requests.count()
    }

    /// The request with `id`, in whichever tenant it is kept.
    #[must_use]
    pub fn stored(&self, id: &DelegationRequestId) -> Option<DelegationRequest<ResolvedTenant>> {
        self.requests
            .all()
            .into_iter()
            .find(|request| request.id() == id)
    }

    /// `tenant`'s requests `wanted` picks out, newest first.
    fn newest_first(
        &self,
        tenant: &ScopedTenant,
        wanted: impl Fn(&DelegationRequest<ResolvedTenant>) -> bool,
    ) -> Vec<DelegationRequest<ResolvedTenant>> {
        let mut requests = self.requests.filter(tenant, wanted);
        requests.sort_by_key(|request| std::cmp::Reverse(request.created_at()));
        requests
    }
}

#[async_trait]
impl DelegationRequestStore for FakeDelegationRequestStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &DelegationRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let known = |stored: &DelegationRequest<ResolvedTenant>| stored.id() == request.id();
        if self.requests.find(tenant_id, known).is_some() {
            self.someone_refuses(tenant_id)?;
        }
        let answered = self.requests.find(tenant_id, known).is_some_and(|stored| {
            stored.state() != RequestState::Pending && stored.state() != request.state()
        });
        if answered {
            return Err(DomainError::conflict(
                "the delegation request was answered since it was read",
            ));
        }
        self.requests.put(tenant_id, request.clone(), known);
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &DelegationRequestId,
    ) -> Result<Option<DelegationRequest<ResolvedTenant>>, DomainError> {
        Ok(self.requests.find(tenant_id, |stored| stored.id() == id))
    }

    async fn list_for_agent(
        &self,
        tenant_id: &ScopedTenant,
        agent: &AgentId,
    ) -> Result<Vec<DelegationRequest<ResolvedTenant>>, DomainError> {
        Ok(self.newest_first(tenant_id, |stored| stored.agent_id() == agent))
    }

    async fn list_asked_of(
        &self,
        tenant_id: &ScopedTenant,
        asked_of: &PrincipalRef,
    ) -> Result<Vec<DelegationRequest<ResolvedTenant>>, DomainError> {
        Ok(self.newest_first(tenant_id, |stored| {
            stored.asked_of().principal() == *asked_of
        }))
    }
}

/// `request` as it stands once someone refused it the moment it was asked,
/// read back the way storage reads it.
fn refused(
    request: &DelegationRequest<ResolvedTenant>,
) -> Result<DelegationRequest<ResolvedTenant>, DomainError> {
    let at = request.created_at();
    DelegationRequest::reconstitute(DelegationRequestRow {
        id: *request.id(),
        agent_id: *request.agent_id(),
        asked_of: request.asked_of().clone(),
        granted: request.granted().clone(),
        constraints: request.constraints().clone(),
        reason: request.reason().clone(),
        state: RequestState::Denied { at },
        created_at: request.created_at(),
        expires_at: request.expires_at(),
        updated_at: at,
    })
}

impl Fake for Arc<dyn DelegationRequestStore> {
    fn fake() -> Self {
        Arc::new(FakeDelegationRequestStore::empty())
    }
}

/// What a test agent asks for: `granted`, for ten minutes, passed on at
/// most one level, because it needs to read the monthly reports.
///
/// # Panics
///
/// - Never: the limits and reason are valid.
#[must_use]
pub fn ask_params(asked_of: Human, granted: CapabilitySet) -> AskDelegationParams {
    AskDelegationParams {
        asked_of,
        granted,
        constraints: DelegationConstraints::new(Seconds::new(600), 1)
            .expect("ten minutes and one level are within bounds"),
        reason: DelegationReason::new("I need to read the monthly reports")
            .expect("the reason is valid"),
    }
}

/// `agent`, signed in as itself, asking `asked_of` for `granted`.
///
/// # Panics
///
/// - When `agent` may not act now.
#[must_use]
pub fn asked_request(
    agent: &AgentIdentity<ResolvedTenant>,
    asked_of: Human,
    granted: CapabilitySet,
) -> DelegationRequest<ResolvedTenant> {
    DelegationRequest::ask(
        &ActingAgent::assumed(*agent.id()),
        agent,
        ask_params(asked_of, granted),
    )
    .expect("an agent free to act asks in its own name")
}
