//! Complete overdue access reviews: the background sweep that completes the
//! reviews still open once their due date has passed.
//!
//! Carol and Dan were named to review Finance by Friday and never got to
//! it. On Saturday the platform completes the review as it was left: each
//! holder marked remove loses the access, and so does each nobody decided
//! on when the review said unanswered access goes. Nobody's rights are
//! checked; the review decided. It still never leaves the tenant without an
//! administrator: such a review stays open, is logged, and is tried again
//! on the next run until someone calls it off.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_review::AccessReview;
use ianua_domain::domains::authorization::review_removals::ReviewRemovals;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AccessReviewId, ActorRef};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::listing::{Limit, PageRequest};
use crate::ports::authorization::{
    AccessRecordStore, AccessReviewStore, GroupMembershipStore, GroupStore, RoleAssignmentStore,
    RoleStore,
};
use crate::ports::runtime::UnitOfWork;
use crate::ports::shared::AuditLabelResolver;
use crate::ports::tenant::TenantStore;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::access_reviews::removals::{
    CompletionStores, RemovalAuthority, RemovalBatch, remove_batch,
};
use crate::use_cases::authorization::sweeps::swept;

/// The ports [`CompleteOverdueUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CompleteOverduePorts {
    /// Lists the tenants to look in.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Finds and saves the reviews past their due date.
    pub review_store: Arc<dyn AccessReviewStore>,
    /// Reads who holds what, to keep an administrator.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Loads and removes the role assignments taken away.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// Loads and removes the memberships ended.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// Loads the role a review covers.
    pub role_store: Arc<dyn RoleStore>,
    /// Loads the group a review covers.
    pub group_store: Arc<dyn GroupStore>,
    /// Names each holder in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Keeps each completion, its removals and their records together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Completes every access review left open past its due date.
pub struct CompleteOverdueUseCase {
    ports: CompleteOverduePorts,
}

/// One tenant the sweep works in, with the auditor its records go through.
struct InTenant<'a> {
    /// The scope whose overdue reviews this sweep completes.
    tenant: ScopedTenant,
    /// Its auditor, attributing records to the system.
    auditor: &'a RequestAuditor,
    /// The time each due date is compared with.
    now: OffsetDateTime,
}

impl CompleteOverdueUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CompleteOverduePorts) -> Self {
        Self { ports }
    }

    /// Completes one full review at a time after selecting only parent
    /// positions. Read failures abort; earlier individual completions remain
    /// committed because a page is not one atomic unit.
    async fn complete_in(&self, within: &InTenant<'_>) -> Result<u64, AppError> {
        let store = self.ports.review_store.as_ref();
        let mut completed: u64 = 0;
        let limit = Limit::internal(500);
        let mut page = PageRequest::first(limit);
        loop {
            let overdue = store
                .find_overdue(&within.tenant, within.now, &page)
                .await
                .or_internal()?;
            for candidate in overdue.items {
                completed =
                    completed.saturating_add(self.complete_candidate(within, &candidate.id).await?);
            }
            let Some(next) = overdue.next else {
                return Ok(completed);
            };
            page = PageRequest::new(Some(next), limit);
        }
    }

    /// Hydrates one selected review, skipping a concurrently removed row.
    /// Read failures abort before the individual unit; processing failures
    /// retain the existing rollback and retry-on-next-run policy.
    async fn complete_candidate(
        &self,
        within: &InTenant<'_>,
        id: &AccessReviewId,
    ) -> Result<u64, AppError> {
        let Some(review) = self
            .ports
            .review_store
            .find_by_id(&within.tenant, id)
            .await
            .or_internal()?
        else {
            return Ok(0);
        };
        let work = self.complete(within, review);
        Ok(swept(self.ports.unit_of_work.as_ref(), "access review", work).await)
    }

    /// Locks and completes one header through item pages within the existing unit.
    async fn complete(
        &self,
        within: &InTenant<'_>,
        selected: AccessReview<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.ports
            .access_records
            .hold_grants(&within.tenant)
            .await
            .or_internal()?;
        let mut review = self
            .ports
            .review_store
            .hold(&within.tenant, selected.id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "authorization-access-review-not-found",
                "access review not found"
            ))?;
        self.complete_pages(within, &mut review).await?;
        self.ports
            .review_store
            .save(&within.tenant, &review)
            .await
            .or_internal()?;
        within
            .auditor
            .dispatch_by(&ActorRef::System, review.take_events(&within.tenant))
            .await
            .or_internal()
    }

    /// Traverses each immutable position once without buffering holders or events.
    async fn complete_pages(
        &self,
        within: &InTenant<'_>,
        review: &mut AccessReview<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let mut completion = review
            .complete_overdue(within.now)
            .map_err(AppError::from_domain)?;
        let limit = Limit::internal(500);
        let mut request = PageRequest::first(limit);
        loop {
            let page = self
                .ports
                .review_store
                .list_items(&within.tenant, review, &request)
                .await
                .or_internal()?;
            let removals = completion
                .overdue_removals(&page.items)
                .map_err(AppError::from_domain)?;
            self.remove_page(within, &removals).await?;
            let Some(next) = page.next else {
                break;
            };
            request = PageRequest::new(Some(next), limit);
        }
        review.finish(completion).map_err(AppError::from_domain)
    }

    /// Removes one authorized page and records its effects before the next read.
    async fn remove_page(
        &self,
        within: &InTenant<'_>,
        removals: &ReviewRemovals,
    ) -> Result<(), AppError> {
        if removals.holders().is_empty() {
            return Ok(());
        }
        let batch = RemovalBatch {
            tenant: &within.tenant,
            scope: removals.scope(),
            principals: removals.holders(),
        };
        let labels = self
            .ports
            .audit_label_resolver
            .principals(&within.tenant, batch.principals)
            .await
            .or_internal()?;
        let stores = self.completion_stores();
        let mut taken =
            remove_batch(stores, &batch, RemovalAuthority::Overdue(removals), &labels).await?;
        let events = taken
            .iter_mut()
            .flat_map(|held| held.take_events(&within.tenant))
            .collect();
        within
            .auditor
            .dispatch_by(&ActorRef::System, events)
            .await
            .or_internal()
    }

    /// Shares the same scoped stores for each page's guard and batch deletion.
    fn completion_stores(&self) -> CompletionStores<'_> {
        CompletionStores {
            records: self.ports.access_records.as_ref(),
            assignments: self.ports.assignment_store.as_ref(),
            memberships: self.ports.membership_store.as_ref(),
        }
    }
}

impl Command for CompleteOverdueUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<u64, AppError>;

    /// Completes every review in every tenant still open once its due date
    /// came by `now`, takes away the access each says goes, and returns how
    /// many were completed.
    ///
    /// Each review is kept together with its removals and their records as
    /// one unit. One that cannot be completed, such as one that would leave
    /// its tenant without an administrator, is logged and tried again on
    /// the next run. Each tenant's records go through `auditor` scoped to
    /// that tenant, attributed to the system.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants, or a tenant's overdue
    ///   reviews, cannot be read.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<u64, AppError> {
        let mut completed: u64 = 0;
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next_ids().await? {
            for tenant_id in batch {
                let tenant_auditor = auditor.with_tenant(tenant_id);
                let within = InTenant {
                    tenant: ScopedTenant::for_background(tenant_id),
                    auditor: &tenant_auditor,
                    now,
                };
                completed = completed.saturating_add(self.complete_in(&within).await?);
            }
        }
        Ok(completed)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_review::{
        AccessReviewRow, AccessReviewStatus, AccessReviewVerdict, ReviewChoice, ReviewItem,
        ReviewItemRow, ReviewScope, ReviewSuggestion, Unanswered,
    };
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{
        AccessReviewId, Human, HumanAccount, Label, PersonKey, PrincipalRef, RoleId, UserId,
    };
    use time::Duration;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeAccessReviewStore, FakeRoleAssignmentStore,
        FakeRoleStore, open_review_of, stored_assignment, stored_role,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    /// A tenant where Bob and Eve hold `role` straight, with the review
    /// store the sweep reads.
    struct Tenant {
        bob: PrincipalRef,
        eve: PrincipalRef,
        role_id: RoleId,
        reviews: Arc<FakeAccessReviewStore>,
        sources: AccessSources,
    }

    fn tenant_with(role: Role<ResolvedTenant>) -> Tenant {
        let tenant = test_ctx().tenant_id();
        let bob = PrincipalRef::User(UserId::new());
        let eve = PrincipalRef::User(UserId::new());
        let role_id = *role.id();
        let held = [
            stored_assignment(bob, role_id),
            stored_assignment(eve, role_id),
        ];
        Tenant {
            bob,
            eve,
            role_id,
            reviews: Arc::new(FakeAccessReviewStore::empty()),
            sources: AccessSources {
                roles: Arc::new(FakeRoleStore::holding(tenant, [role])),
                assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, held)),
                ..AccessSources::default()
            },
        }
    }

    fn tenant() -> Tenant {
        tenant_with(stored_role("finance", Vec::new(), Vec::new()))
    }

    impl Tenant {
        /// A review of the role, due at `due`, where Carol marked Bob keep
        /// and nobody decided on Eve, whose access goes when unanswered.
        fn review_due(&self, due: OffsetDateTime) -> AccessReviewId {
            let carol = Human::new(
                HumanAccount::User(UserId::new()),
                PersonKey::new("carol@acme.test").unwrap(),
            );
            let review = AccessReview::reconstitute(AccessReviewRow {
                id: AccessReviewId::new(),
                name: Label::new("review_name", "Finance, Q3").unwrap(),
                scope: ReviewScope::Role(self.role_id),
                reviewers: vec![carol.clone()],
                due,
                unanswered: Unanswered::RemoveAccess,
                holder_count: 2,
                pending_count: 1,
                remove_count: 0,
                status: AccessReviewStatus::Open,
                started_at: due - Duration::days(14),
            })
            .unwrap();
            block_on(self.reviews.save(&test_ctx().tenant(), &review)).unwrap();
            self.reviews
                .seed_items(test_ctx().tenant_id(), &review, &[self.bob, self.eve]);
            self.keep_bob(&review, carol);
            *review.id()
        }

        /// Carol's recorded keep decision leaves only Eve unanswered in this review.
        fn keep_bob(&self, review: &AccessReview<ResolvedTenant>, carol: Human) {
            let kept = ReviewItem::reconstitute(ReviewItemRow {
                review,
                review_id: *review.id(),
                position: 1,
                holder: self.bob,
                verdict: AccessReviewVerdict::Decided {
                    choice: ReviewChoice::Keep,
                    reviewer: carol,
                },
                suggestion: ReviewSuggestion::Nothing,
            })
            .unwrap();
            block_on(self.reviews.save_item(&test_ctx().tenant(), &kept)).unwrap();
        }

        /// Later overdue reviews retain Eve's holding when their unanswered items complete.
        fn seed_kept_reviews(&self, count: usize) {
            for _ in 0..count {
                let review = open_review_of(
                    ReviewScope::Role(self.role_id),
                    &[self.eve],
                    "carol@acme.test",
                    clock::now() - Duration::days(1),
                );
                block_on(self.reviews.save(&test_ctx().tenant(), &review)).unwrap();
                self.reviews
                    .seed_items(test_ctx().tenant_id(), &review, &[self.eve]);
            }
        }

        fn ports(&self, unit: &Arc<RecordingUnitOfWork>) -> CompleteOverduePorts {
            CompleteOverduePorts {
                tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                review_store: self.reviews.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.sources.clone())),
                assignment_store: self.sources.assignments.clone(),
                membership_store: self.sources.memberships.clone(),
                role_store: self.sources.roles.clone(),
                group_store: self.sources.groups.clone(),
                unit_of_work: unit.clone(),
                ..CompleteOverduePorts::fakes()
            }
        }

        fn status(&self, id: &AccessReviewId) -> AccessReviewStatus {
            self.reviews
                .stored(test_ctx().tenant_id(), id)
                .unwrap()
                .status()
        }

        fn holds(&self, principal: PrincipalRef) -> bool {
            self.sources
                .assignments
                .of_tenant(test_ctx().tenant_id())
                .unwrap()
                .iter()
                .any(|held| *held.principal() == principal)
        }

        fn sweep(&self, sink: &Arc<FakeEventDispatcher>, unit: &Arc<RecordingUnitOfWork>) -> u64 {
            let use_case = CompleteOverdueUseCase::new(self.ports(unit));
            block_on(use_case.execute(&(), &test_auditor(sink.clone()), clock::now())).unwrap()
        }
    }

    /// The Finance review was due yesterday. Carol kept Bob and never got
    /// to Eve. The sweep completes it: Eve loses the role, Bob keeps it,
    /// and the completion and the removal are recorded together.
    #[test]
    fn an_overdue_review_is_completed_by_its_unanswered_rule() {
        let tenant = tenant();
        let id = tenant.review_due(clock::now() - Duration::days(1));
        let sink = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());

        let completed = tenant.sweep(&sink, &unit);

        assert_eq!(completed, 1);
        assert_eq!(tenant.status(&id), AccessReviewStatus::Completed);
        assert!(tenant.holds(tenant.bob));
        assert!(!tenant.holds(tenant.eve));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "authorization.role_revoked",
                "authorization.access_review_completed"
            ]
        );
        assert_eq!(unit.settlements(), [Settlement::Commit]);
    }

    /// A 501-holder snapshot removes every direct holding through two pages.
    /// The transaction records all removals then completion, without whole
    /// tenant reads or one access-record read for each holder.
    #[test]
    fn one_large_review_completes_through_bounded_holder_pages() {
        let tenant = large_review();
        let unit = Arc::new(RecordingUnitOfWork::default());
        let records = Arc::new(FakeAccessRecordStore::reading(tenant.sources.clone()));
        let mut ports = tenant.ports(&unit);
        ports.access_records = records.clone();
        let sink = Arc::new(FakeEventDispatcher::new());
        let completed = block_on(CompleteOverdueUseCase::new(ports).execute(
            &(),
            &test_auditor(sink.clone()),
            clock::now(),
        ))
        .unwrap();

        assert_eq!(completed, 1);
        assert_eq!(tenant.reviews.item_batch_sizes(), [500, 1]);
        assert_eq!(tenant.sources.assignments.count(), 0);
        assert_eq!(records.whole_reads(), 0);
        assert_eq!(records.holder_reads(), 4);
        assert_eq!(unit.settlements(), [Settlement::Commit]);
        let events = sink.records.lock().unwrap();
        assert_eq!(events.len(), 502);
        assert_eq!(
            events.last().unwrap(),
            "authorization.access_review_completed"
        );
    }

    /// A stored overdue review contains 501 direct role holders awaiting removal.
    fn large_review() -> Tenant {
        let mut tenant = tenant();
        let holders: Vec<_> = (0..501)
            .map(|_| PrincipalRef::User(UserId::new()))
            .collect();
        tenant.sources.assignments = Arc::new(FakeRoleAssignmentStore::holding(
            test_ctx().tenant_id(),
            holders
                .iter()
                .map(|holder| stored_assignment(*holder, tenant.role_id)),
        ));
        let review = pending_review(tenant.role_id);
        block_on(tenant.reviews.save(&test_ctx().tenant(), &review)).unwrap();
        tenant
            .reviews
            .seed_items(test_ctx().tenant_id(), &review, &holders);
        tenant
    }

    /// All 501 holders are unanswered and lose access when this overdue review completes.
    fn pending_review(role_id: RoleId) -> AccessReview<ResolvedTenant> {
        let due = clock::now() - Duration::DAY;
        AccessReview::reconstitute(AccessReviewRow {
            id: AccessReviewId::new(),
            name: Label::new("review_name", "All holders").unwrap(),
            scope: ReviewScope::Role(role_id),
            reviewers: vec![Human::new(
                HumanAccount::User(UserId::new()),
                PersonKey::new("carol@acme.test").unwrap(),
            )],
            due,
            unanswered: Unanswered::RemoveAccess,
            holder_count: 501,
            pending_count: 501,
            remove_count: 0,
            status: AccessReviewStatus::Open,
            started_at: due - Duration::days(14),
        })
        .unwrap()
    }

    /// The oldest review would remove the last administrator, but later
    /// reviews keep that access. The blocked review is attempted once and
    /// remains open while all later pages finish with bounded parent reads.
    #[test]
    fn overdue_review_batches_advance_past_a_blocked_review() {
        let admin = stored_role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
            Vec::new(),
        );
        let tenant = tenant_with(admin);
        let blocked = tenant.review_due(clock::now() - Duration::days(2));
        block_on(tenant.sources.assignments.delete(
            &test_ctx().tenant(),
            &tenant.bob,
            &tenant.role_id,
        ))
        .unwrap();
        tenant.seed_kept_reviews(500);
        let sink = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());

        let completed = tenant.sweep(&sink, &unit);

        assert_eq!(completed, 500);
        assert_eq!(tenant.status(&blocked), AccessReviewStatus::Open);
        assert!(tenant.holds(tenant.eve));
        assert_eq!(sink.records.lock().unwrap().len(), 500);
        assert_eq!(
            unit.settlements()
                .iter()
                .filter(|outcome| **outcome == Settlement::Rollback)
                .count(),
            1
        );
        assert_eq!(tenant.reviews.overdue_batch_sizes(), [500, 1]);
    }

    /// Three overdue reviews keep their holders. Selection loads no holder
    /// collections, and each review completes before the next is hydrated.
    #[test]
    fn overdue_selection_hydrates_only_the_review_being_completed() {
        let tenant = tenant();
        for _ in 0..3 {
            let review = open_review_of(
                ReviewScope::Role(tenant.role_id),
                &[tenant.bob, tenant.eve],
                "carol@acme.test",
                clock::now() - Duration::days(1),
            );
            block_on(tenant.reviews.save(&test_ctx().tenant(), &review)).unwrap();
            tenant
                .reviews
                .seed_items(test_ctx().tenant_id(), &review, &[tenant.bob, tenant.eve]);
        }
        let sink = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());

        let completed = tenant.sweep(&sink, &unit);

        assert_eq!(completed, 3);
        assert_eq!(sink.records.lock().unwrap().len(), 3);
        assert_eq!(unit.settlements(), vec![Settlement::Commit; 3]);
        assert_eq!(tenant.reviews.overdue_hydration_counts(), [0]);
        assert_eq!(tenant.reviews.hydration_counts_at_completion(), [2, 4, 6]);
        assert_eq!(tenant.reviews.item_batch_sizes(), [2, 2, 2]);
    }

    /// A failed review read aborts the sweep after the earlier review commits.
    /// The unreadable review stays open, and both holders keep their access.
    #[test]
    fn a_later_review_read_failure_aborts_after_prior_completions() {
        let tenant = tenant();
        let first = open_review_of(
            ReviewScope::Role(tenant.role_id),
            &[tenant.bob, tenant.eve],
            "carol@acme.test",
            clock::now() - Duration::days(2),
        );
        let unreadable = open_review_of(
            ReviewScope::Role(tenant.role_id),
            &[tenant.bob, tenant.eve],
            "carol@acme.test",
            clock::now() - Duration::days(1),
        );
        for review in [&first, &unreadable] {
            block_on(tenant.reviews.save(&test_ctx().tenant(), review)).unwrap();
            tenant
                .reviews
                .seed_items(test_ctx().tenant_id(), review, &[tenant.bob, tenant.eve]);
        }
        tenant.reviews.fail_reading(*unreadable.id());
        let sink = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());
        let use_case = CompleteOverdueUseCase::new(tenant.ports(&unit));

        let result = block_on(use_case.execute(&(), &test_auditor(sink.clone()), clock::now()));

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert_eq!(tenant.status(first.id()), AccessReviewStatus::Completed);
        assert_eq!(tenant.status(unreadable.id()), AccessReviewStatus::Open);
        assert!(tenant.holds(tenant.bob) && tenant.holds(tenant.eve));
        assert_eq!(sink.records.lock().unwrap().len(), 1);
        assert_eq!(unit.settlements(), [Settlement::Commit]);
    }

    /// A review due next week stays open during the sweep. Eve keeps her role,
    /// and no completion event is recorded.
    #[test]
    fn a_review_not_yet_due_is_left_open() {
        let tenant = tenant();
        let id = tenant.review_due(clock::now() + Duration::days(7));
        let sink = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());

        let completed = tenant.sweep(&sink, &unit);

        assert_eq!(completed, 0);
        assert_eq!(tenant.status(&id), AccessReviewStatus::Open);
        assert!(tenant.holds(tenant.eve));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// An overdue review cannot remove the tenant's last administrator.
    /// The review stays open, Eve keeps her role, and the unit rolls back.
    #[test]
    fn a_review_that_would_leave_no_administrator_stays_open() {
        let admin = stored_role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
            Vec::new(),
        );
        let tenant = tenant_with(admin);
        let id = tenant.review_due(clock::now() - Duration::days(1));
        block_on(tenant.sources.assignments.delete(
            &test_ctx().tenant(),
            &tenant.bob,
            &tenant.role_id,
        ))
        .unwrap();
        let sink = Arc::new(FakeEventDispatcher::new());
        let unit = Arc::new(RecordingUnitOfWork::default());

        let completed = tenant.sweep(&sink, &unit);

        assert_eq!(completed, 0);
        assert_eq!(tenant.status(&id), AccessReviewStatus::Open);
        assert!(tenant.holds(tenant.eve));
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }
}
