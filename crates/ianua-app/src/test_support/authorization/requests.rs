//! In-memory access requests, the limit a tenant sets on them, and access
//! reviews.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::access_request::{
    AccessRequest, AccessRequestRow, AccessRequestStatus, AskedAccess, RequestAnswer,
};
use ianua_domain::domains::authorization::access_review::{
    AccessReview, AccessReviewDraft, AccessReviewRow, AccessReviewStatus, AccessReviewVerdict,
    ReviewItem, ReviewItemRow, ReviewScope, ReviewSuggestion, Unanswered,
};
use ianua_domain::domains::authorization::request_policy::{
    AccessRequestPolicy, AccessRequestPolicyRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AccessRequestId, AccessReviewId, Human, HumanAccount, Label, Lifetime, PersonKey, PrincipalRef,
    TenantId, Text, UserId,
};
use time::{Duration, OffsetDateTime};

use crate::listing::{Page, PageRequest, Sort, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authorization::{
    AccessRequestFilter, AccessRequestPolicyStore, AccessRequestSortField, AccessRequestStore,
    AccessReviewFilter, AccessReviewSortField, AccessReviewStore, OverdueReview,
    OverdueReviewSortField, ReviewItemSortField,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::authorization::copies::{copy_access_request, copy_access_review};
use crate::test_support::authorization::records::AccessSources;
use crate::test_support::listing::page;

/// A pending request for `asked`, for two hours, made through a fresh
/// account by the person signing in as `address`, at `requested_at`, as
/// storage would hand it back.
#[must_use]
pub fn pending_request_by(
    asked: AskedAccess,
    address: &str,
    requested_at: OffsetDateTime,
) -> AccessRequest<ResolvedTenant> {
    AccessRequest::reconstitute(AccessRequestRow {
        id: AccessRequestId::new(),
        requester: Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).expect("a valid address"),
        ),
        asked,
        reason: Text::new("reason", "on call tonight").expect("a valid reason"),
        length: Lifetime::seconds(2 * 3600).expect("a valid length"),
        status: AccessRequestStatus::Pending,
        answer: RequestAnswer::Unanswered,
        requested_at,
    })
    .expect("a pending request is a consistent row")
}

/// In-memory access request store, tenant by tenant. Like storage, it
/// refuses a save over a request no longer pending as a conflict.
#[derive(Default)]
pub struct FakeAccessRequestStore {
    requests: Mutex<Vec<(TenantId, AccessRequest<ResolvedTenant>)>>,
    withdrawn_before_save: AtomicBool,
    lapsed_batches: Mutex<Vec<usize>>,
}

impl TenantScoped for FakeAccessRequestStore {}

impl FakeAccessRequestStore {
    /// The number of requests materialized by each expiry read.
    #[must_use]
    pub fn lapsed_batch_sizes(&self) -> Vec<usize> {
        self.lapsed_batches.lock().unwrap().clone()
    }

    /// A store holding no request.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `requests` in `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        requests: impl IntoIterator<Item = AccessRequest<ResolvedTenant>>,
    ) -> Self {
        Self {
            requests: Mutex::new(
                requests
                    .into_iter()
                    .map(|request| (tenant_id, request))
                    .collect(),
            ),
            withdrawn_before_save: AtomicBool::new(false),
            lapsed_batches: Mutex::new(Vec::new()),
        }
    }

    /// A store holding `requests` in `tenant_id`, where the asker withdraws
    /// every one of them just before the first save asked of the store, so
    /// a use case that read one still pending saves over a withdrawn one.
    #[must_use]
    pub fn withdrawn_while_answered(
        tenant_id: TenantId,
        requests: impl IntoIterator<Item = AccessRequest<ResolvedTenant>>,
    ) -> Self {
        Self {
            withdrawn_before_save: AtomicBool::new(true),
            ..Self::holding(tenant_id, requests)
        }
    }

    /// Withdraws every held request, as the asker would, when the store was
    /// made to.
    fn asker_withdraws(
        &self,
        requests: &mut [(TenantId, AccessRequest<ResolvedTenant>)],
    ) -> Result<(), DomainError> {
        if !self.withdrawn_before_save.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        for (_, held) in requests.iter_mut() {
            *held = withdrawn(held)?;
        }
        Ok(())
    }

    /// Where the request `id` of `tenant_id` stands, as stored.
    #[must_use]
    pub fn status_of(
        &self,
        tenant_id: TenantId,
        id: &AccessRequestId,
    ) -> Option<AccessRequestStatus> {
        self.matching(tenant_id, |request| request.id() == id)
            .ok()?
            .pop()
            .map(|request| request.status())
    }

    /// How many requests are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn matching(
        &self,
        tenant_id: TenantId,
        keep: impl Fn(&AccessRequest<ResolvedTenant>) -> bool,
    ) -> Result<Vec<AccessRequest<ResolvedTenant>>, DomainError> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, request)| *tenant == tenant_id && keep(request))
            .map(|(_, request)| copy_access_request(request))
            .collect()
    }
}

#[async_trait]
impl AccessRequestStore for FakeAccessRequestStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccessRequestId,
    ) -> Result<Option<AccessRequest<ResolvedTenant>>, DomainError> {
        Ok(self
            .matching(**tenant_id, |request| request.id() == id)?
            .pop())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: AccessRequestFilter,
        request: &PageRequest,
    ) -> Result<Page<AccessRequest<ResolvedTenant>>, DomainError> {
        let kept = self.matching(**tenant_id, |request| match filter {
            AccessRequestFilter::All => true,
            AccessRequestFilter::Pending => request.status() == AccessRequestStatus::Pending,
            AccessRequestFilter::AskedBy(principal) => request.requester().principal() == principal,
        })?;
        page(
            kept,
            &SortOrder::<AccessRequestSortField>::default(),
            request,
        )
    }

    async fn find_lapsed(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        request: &PageRequest,
    ) -> Result<Page<AccessRequest<ResolvedTenant>>, DomainError> {
        let due = self.matching(**tenant_id, |request| {
            request.status() == AccessRequestStatus::Pending && request.answer_by() <= now
        })?;
        let order = SortOrder::single(Sort::ascending(AccessRequestSortField::RequestedAt));
        let batch = page(due, &order, request)?;
        self.lapsed_batches.lock().unwrap().push(batch.items.len());
        Ok(batch)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        request: &AccessRequest<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_access_request(request)?;
        let mut requests = self.requests.lock().unwrap();
        self.asker_withdraws(&mut requests)?;
        let settled = requests.iter().any(|(tenant, held)| {
            *tenant == **tenant_id
                && held.id() == request.id()
                && held.status() != AccessRequestStatus::Pending
        });
        if settled {
            return Err(DomainError::conflict(
                "this request was already answered, withdrawn or run out",
            ));
        }
        requests.retain(|(tenant, held)| !(*tenant == **tenant_id && held.id() == request.id()));
        requests.push((**tenant_id, copy));
        Ok(())
    }
}

/// `request` as its asker would leave it on withdrawing it, read back the
/// way storage reads it.
fn withdrawn(
    request: &AccessRequest<ResolvedTenant>,
) -> Result<AccessRequest<ResolvedTenant>, DomainError> {
    AccessRequest::reconstitute(AccessRequestRow {
        id: *request.id(),
        requester: request.requester().clone(),
        asked: request.asked(),
        reason: request.reason().clone(),
        length: request.length(),
        status: AccessRequestStatus::Cancelled,
        answer: RequestAnswer::Unanswered,
        requested_at: request.requested_at(),
    })
}

impl Fake for Arc<dyn AccessRequestStore> {
    fn fake() -> Self {
        Arc::new(FakeAccessRequestStore::empty())
    }
}

/// A tenant's limit on access requests of at most `longest`, as storage
/// would hand it back.
#[must_use]
pub fn stored_request_policy(longest: Lifetime) -> AccessRequestPolicy<ResolvedTenant> {
    AccessRequestPolicy::reconstitute(AccessRequestPolicyRow {
        longest,
        updated_at: ianua_domain::shared::clock::now() - Duration::days(1),
    })
    .expect("a limit of at most a month is a consistent row")
}

/// In-memory store of each tenant's limit on access requests.
#[derive(Default)]
pub struct FakeAccessRequestPolicyStore {
    policies: Mutex<Vec<(TenantId, AccessRequestPolicy<ResolvedTenant>)>>,
}

impl TenantScoped for FakeAccessRequestPolicyStore {}

impl FakeAccessRequestPolicyStore {
    /// A store where no tenant set a limit.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `policy` as `tenant_id`'s.
    #[must_use]
    pub fn holding(tenant_id: TenantId, policy: AccessRequestPolicy<ResolvedTenant>) -> Self {
        Self {
            policies: Mutex::new(vec![(tenant_id, policy)]),
        }
    }

    /// The longest `tenant_id` lets its people ask for, as stored.
    #[must_use]
    pub fn longest_of(&self, tenant_id: TenantId) -> Option<Lifetime> {
        self.policies
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, _)| *tenant == tenant_id)
            .map(|(_, policy)| policy.limits().longest())
    }
}

#[async_trait]
impl AccessRequestPolicyStore for FakeAccessRequestPolicyStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<AccessRequestPolicy<ResolvedTenant>>, DomainError> {
        self.policies
            .lock()
            .unwrap()
            .iter()
            .find(|(tenant, _)| *tenant == **tenant_id)
            .map(|(_, policy)| copy_request_policy(policy))
            .transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        policy: &AccessRequestPolicy<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let copy = copy_request_policy(policy)?;
        let mut policies = self.policies.lock().unwrap();
        policies.retain(|(tenant, _)| *tenant != **tenant_id);
        policies.push((**tenant_id, copy));
        Ok(())
    }
}

impl Fake for Arc<dyn AccessRequestPolicyStore> {
    fn fake() -> Self {
        Arc::new(FakeAccessRequestPolicyStore::empty())
    }
}

/// `policy` read back the way storage reads it.
fn copy_request_policy(
    policy: &AccessRequestPolicy<ResolvedTenant>,
) -> Result<AccessRequestPolicy<ResolvedTenant>, DomainError> {
    AccessRequestPolicy::reconstitute(AccessRequestPolicyRow {
        longest: policy.limits().longest(),
        updated_at: policy.updated_at(),
    })
}

/// An open review header counting `holders`, all undecided, with the
/// person signing in as `reviewer` deciding, due at `due` and started two
/// weeks before, as storage would hand it back. Holders nobody decides on
/// keep their access. Tests exercising items seed them separately with
/// [`FakeAccessReviewStore::seed_items`].
#[must_use]
pub fn open_review_of(
    scope: ReviewScope,
    holders: &[PrincipalRef],
    reviewer: &str,
    due: OffsetDateTime,
) -> AccessReview<ResolvedTenant> {
    AccessReview::reconstitute(AccessReviewRow {
        id: AccessReviewId::new(),
        name: Label::new("review_name", "Finance, Q3").expect("a valid name"),
        scope,
        reviewers: vec![Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(reviewer).expect("a valid address"),
        )],
        due,
        unanswered: Unanswered::KeepAccess,
        holder_count: u64::try_from(holders.len()).expect("fixture count fits"),
        pending_count: u64::try_from(holders.len()).expect("fixture count fits"),
        remove_count: 0,
        status: AccessReviewStatus::Open,
        started_at: due - Duration::days(14),
    })
    .expect("an open review is a consistent row")
}

/// In-memory access review store, tenant by tenant.
#[derive(Default)]
pub struct FakeAccessReviewStore {
    reviews: Mutex<Vec<(TenantId, AccessReview<ResolvedTenant>)>>,
    overdue_batches: Mutex<Vec<usize>>,
    overdue_hydrated: Mutex<Vec<usize>>,
    full_reads: AtomicUsize,
    reads_at_completion: Mutex<Vec<usize>>,
    unreadable: Mutex<Option<AccessReviewId>>,
    items: Mutex<Vec<(TenantId, ReviewItem)>>,
    item_batches: Mutex<Vec<usize>>,
    sources: AccessSources,
}

impl TenantScoped for FakeAccessReviewStore {}

impl FakeAccessReviewStore {
    /// Reads current holdings when atomically starting a new snapshot.
    #[must_use]
    pub fn reading(sources: AccessSources) -> Self {
        Self {
            sources,
            ..Self::empty()
        }
    }

    /// Seeds the separate pending item rows of an already persisted header.
    pub fn seed_items(
        &self,
        tenant: TenantId,
        review: &AccessReview<ResolvedTenant>,
        holders: &[PrincipalRef],
    ) {
        let mut items = self.items.lock().unwrap();
        items.retain(|(owner, item)| *owner != tenant || item.review_id() != review.id());
        items.extend(holders.iter().enumerate().map(|(position, holder)| {
            let item = ReviewItem::reconstitute(ReviewItemRow {
                review,
                review_id: *review.id(),
                position: u64::try_from(position + 1).unwrap(),
                holder: *holder,
                verdict: AccessReviewVerdict::Pending,
                suggestion: ReviewSuggestion::Nothing,
            })
            .unwrap();
            (tenant, item)
        }));
    }

    /// The bounded holder counts materialized by item-page reads.
    #[must_use]
    pub fn item_batch_sizes(&self) -> Vec<usize> {
        self.item_batches.lock().unwrap().clone()
    }

    /// The separate stored items used for assertions without another port read.
    #[must_use]
    pub fn stored_items(&self, tenant: TenantId, id: &AccessReviewId) -> Vec<ReviewItem> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, item)| *owner == tenant && item.review_id() == id)
            .map(|(_, item)| item.clone())
            .collect()
    }
    /// Makes one aggregate read fail while its parent position remains readable.
    pub fn fail_reading(&self, id: AccessReviewId) {
        *self.unreadable.lock().unwrap() = Some(id);
    }

    /// Full aggregates returned by each overdue selection.
    #[must_use]
    pub fn overdue_hydration_counts(&self) -> Vec<usize> {
        self.overdue_hydrated.lock().unwrap().clone()
    }

    /// Full aggregates read before each completed review was saved.
    #[must_use]
    pub fn hydration_counts_at_completion(&self) -> Vec<usize> {
        self.reads_at_completion.lock().unwrap().clone()
    }

    /// The number of parent positions returned by each overdue read.
    #[must_use]
    pub fn overdue_batch_sizes(&self) -> Vec<usize> {
        self.overdue_batches.lock().unwrap().clone()
    }

    /// A store holding no review.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `reviews` in `tenant_id`.
    #[must_use]
    pub fn holding(
        tenant_id: TenantId,
        reviews: impl IntoIterator<Item = AccessReview<ResolvedTenant>>,
    ) -> Self {
        Self {
            reviews: Mutex::new(
                reviews
                    .into_iter()
                    .map(|review| (tenant_id, review))
                    .collect(),
            ),
            overdue_batches: Mutex::new(Vec::new()),
            overdue_hydrated: Mutex::new(Vec::new()),
            full_reads: AtomicUsize::new(0),
            reads_at_completion: Mutex::new(Vec::new()),
            unreadable: Mutex::new(None),
            items: Mutex::new(Vec::new()),
            item_batches: Mutex::new(Vec::new()),
            sources: AccessSources::default(),
        }
    }

    /// The review `id` of `tenant_id`, read back the way storage reads it.
    #[must_use]
    pub fn stored(
        &self,
        tenant_id: TenantId,
        id: &AccessReviewId,
    ) -> Option<AccessReview<ResolvedTenant>> {
        self.matching(tenant_id, |review| review.id() == id)
            .ok()?
            .pop()
    }

    /// How many reviews are held, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.reviews.lock().unwrap().len()
    }

    /// Rebuilds the matching aggregates and records how many were hydrated.
    fn matching(
        &self,
        tenant_id: TenantId,
        keep: impl Fn(&AccessReview<ResolvedTenant>) -> bool,
    ) -> Result<Vec<AccessReview<ResolvedTenant>>, DomainError> {
        let found: Vec<_> = self
            .reviews
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, review)| *tenant == tenant_id && keep(review))
            .map(|(_, review)| copy_access_review(review))
            .collect::<Result<_, _>>()?;
        self.full_reads.fetch_add(found.len(), Ordering::Relaxed);
        Ok(found)
    }
}

#[async_trait]
impl AccessReviewStore for FakeAccessReviewStore {
    async fn start(
        &self,
        tenant: &ScopedTenant,
        draft: AccessReviewDraft<ResolvedTenant>,
    ) -> Result<AccessReview<ResolvedTenant>, DomainError> {
        let mut holders: Vec<_> = match draft.scope() {
            ReviewScope::Role(role) => self
                .sources
                .assignments
                .of_tenant(**tenant)?
                .into_iter()
                .filter(|held| *held.role_id() == role && held.is_in_force(draft.started_at()))
                .map(|held| *held.principal())
                .collect(),
            ReviewScope::Group(group) => self
                .sources
                .memberships
                .of_tenant(**tenant)?
                .into_iter()
                .filter(|held| *held.group_id() == group && held.is_in_force(draft.started_at()))
                .map(|held| *held.principal())
                .collect(),
        };
        holders.sort_by_key(PrincipalRef::id);
        holders.dedup();
        let review = draft.started(u64::try_from(holders.len()).map_err(DomainError::infra)?)?;
        self.save(tenant, &review).await?;
        self.seed_items(**tenant, &review, &holders);
        Ok(review)
    }

    async fn hold(
        &self,
        tenant: &ScopedTenant,
        id: &AccessReviewId,
    ) -> Result<Option<AccessReview<ResolvedTenant>>, DomainError> {
        self.find_by_id(tenant, id).await
    }

    async fn list_items(
        &self,
        tenant: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        request: &PageRequest,
    ) -> Result<Page<ReviewItem>, DomainError> {
        let items = self.stored_items(**tenant, review.id());
        let found = page(items, &SortOrder::<ReviewItemSortField>::default(), request)?;
        self.item_batches.lock().unwrap().push(found.items.len());
        Ok(found)
    }

    async fn find_item(
        &self,
        tenant: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        holder: &PrincipalRef,
    ) -> Result<Option<ReviewItem>, DomainError> {
        Ok(self
            .stored_items(**tenant, review.id())
            .into_iter()
            .find(|item| item.holder() == holder))
    }

    async fn find_items(
        &self,
        tenant: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        holders: &[PrincipalRef],
    ) -> Result<Vec<ReviewItem>, DomainError> {
        Ok(self
            .stored_items(**tenant, review.id())
            .into_iter()
            .filter(|item| holders.contains(item.holder()))
            .collect())
    }

    async fn save_suggestions(
        &self,
        tenant: &ScopedTenant,
        items: &[ReviewItem],
    ) -> Result<(), DomainError> {
        for item in items {
            self.save_item(tenant, item).await?;
        }
        Ok(())
    }

    async fn save_item(&self, tenant: &ScopedTenant, item: &ReviewItem) -> Result<(), DomainError> {
        let mut items = self.items.lock().unwrap();
        items.retain(|(owner, held)| {
            *owner != **tenant
                || held.review_id() != item.review_id()
                || held.position() != item.position()
        });
        items.push((**tenant, item.clone()));
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &AccessReviewId,
    ) -> Result<Option<AccessReview<ResolvedTenant>>, DomainError> {
        if self.unreadable.lock().unwrap().as_ref() == Some(id) {
            return Err(DomainError::infra_msg("review aggregate cannot be read"));
        }
        Ok(self
            .matching(**tenant_id, |review| review.id() == id)?
            .pop())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: AccessReviewFilter,
        request: &PageRequest,
    ) -> Result<Page<AccessReview<ResolvedTenant>>, DomainError> {
        let kept = self.matching(**tenant_id, |review| match filter {
            AccessReviewFilter::All => true,
            AccessReviewFilter::Open => review.status() == AccessReviewStatus::Open,
        })?;
        page(
            kept,
            &SortOrder::<AccessReviewSortField>::default(),
            request,
        )
    }

    async fn find_overdue(
        &self,
        tenant_id: &ScopedTenant,
        now: OffsetDateTime,
        request: &PageRequest,
    ) -> Result<Page<OverdueReview>, DomainError> {
        let reads_before = self.full_reads.load(Ordering::Relaxed);
        let due = self
            .reviews
            .lock()
            .unwrap()
            .iter()
            .filter(|(tenant, review)| {
                *tenant == **tenant_id
                    && review.status() == AccessReviewStatus::Open
                    && review.due() <= now
            })
            .map(|(_, review)| OverdueReview {
                id: *review.id(),
                due: review.due(),
            })
            .collect();
        let batch = page(
            due,
            &SortOrder::<OverdueReviewSortField>::default(),
            request,
        )?;
        self.overdue_batches.lock().unwrap().push(batch.items.len());
        self.overdue_hydrated
            .lock()
            .unwrap()
            .push(self.full_reads.load(Ordering::Relaxed) - reads_before);
        Ok(batch)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        if review.status() == AccessReviewStatus::Completed {
            self.reads_at_completion
                .lock()
                .unwrap()
                .push(self.full_reads.load(Ordering::Relaxed));
        }
        let copy = copy_access_review(review)?;
        let mut reviews = self.reviews.lock().unwrap();
        reviews.retain(|(tenant, held)| !(*tenant == **tenant_id && held.id() == review.id()));
        reviews.push((**tenant_id, copy));
        Ok(())
    }
}

impl Fake for Arc<dyn AccessReviewStore> {
    fn fake() -> Self {
        Arc::new(FakeAccessReviewStore::empty())
    }
}
