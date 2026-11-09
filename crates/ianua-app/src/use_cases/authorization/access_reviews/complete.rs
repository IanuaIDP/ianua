//! Completes a review through bounded holder pages in one atomic unit.
//! A late refusal or audit failure rolls back every page and leaves it open.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_review::AccessReview;
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AccessReviewId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest};
use crate::ports::authorization::{
    AccessRecordStore, AccessReviewStore, GroupMembershipStore, GroupStore, RoleAssignmentStore,
    RoleStore,
};
use crate::ports::runtime::UnitOfWork;
use crate::ports::shared::{AuditLabelResolver, ControlPlaneLabelResolver};
use crate::services::kept_together::kept_together;
use crate::use_case::Command;
use crate::use_cases::authorization::access_reviews::lookup::{
    ReviewReader, SEES_OR_RUNS_REVIEWS, owned_review_for_update,
};
use crate::use_cases::authorization::access_reviews::removals::{
    CompletionStores, RemovalAuthority, RemovalBatch, caller_labels, remove_batch,
};

/// The ports [`CompleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CompletePorts {
    /// Rolls back every page even when the refusal is a client error.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// Loads and saves the review.
    pub review_store: Arc<dyn AccessReviewStore>,
    /// Reads who holds what, for what a group brings and to keep an
    /// administrator.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Loads and removes the role assignments taken away.
    pub assignment_store: Arc<dyn RoleAssignmentStore>,
    /// Loads and removes the memberships ended.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// Loads the role a review covers.
    pub role_store: Arc<dyn RoleStore>,
    /// Loads the group a review covers.
    pub group_store: Arc<dyn GroupStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Names each holder in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Names a holder who is an organization member in the audit record.
    pub control_plane_label_resolver: Arc<dyn ControlPlaneLabelResolver>,
}

/// Completes a review without collecting its holders or removals in memory.
pub struct CompleteUseCase {
    ports: CompletePorts,
}

impl CompleteUseCase {
    /// A use case working through the scoped ports.
    #[must_use]
    pub fn new(ports: CompletePorts) -> Self {
        Self { ports }
    }

    /// Performs all reads, removals and final audit inside the rollback-on-error unit.
    async fn completed(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: AccessReviewId,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let mut review = self.locked_review(ctx, &authority, &id).await?;
        self.complete_pages(ctx, auditor, &authority, &mut review)
            .await?;
        self.ports
            .review_store
            .save(&tenant, &review)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), review.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(review)
    }

    /// Locks grants before the visible review header to serialize its removals.
    async fn locked_review(
        &self,
        ctx: &CallerContext,
        authority: &TenantAuthority,
        id: &AccessReviewId,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        self.ports
            .access_records
            .hold_grants(&tenant)
            .await
            .or_internal()?;
        owned_review_for_update(
            self.ports.review_store.as_ref(),
            &tenant,
            id,
            ReviewReader {
                authority,
                besides: SEES_OR_RUNS_REVIEWS,
            },
        )
        .await
    }

    /// Traverses the locked snapshot, recording each bounded page in the same unit.
    async fn complete_pages(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        authority: &TenantAuthority,
        review: &mut AccessReview<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let mut completion = review.complete(authority).map_err(AppError::from_domain)?;
        let limit = Limit::internal(500);
        let mut request = PageRequest::first(limit);
        let store = self.ports.review_store.as_ref();
        let tenant = ctx.tenant();
        loop {
            let page = store
                .list_items(&tenant, review, &request)
                .await
                .or_internal()?;
            let principals = completion
                .removals(&page.items)
                .map_err(AppError::from_domain)?;
            let batch = RemovalBatch::for_review(&tenant, review, &principals);
            self.remove_page(ctx, auditor, authority, batch).await?;
            let Some(next) = page.next else {
                break;
            };
            request = PageRequest::new(Some(next), limit);
        }
        review.finish(completion).map_err(AppError::from_domain)
    }

    /// Applies caller authority and one set of batch labels to this page.
    async fn remove_page(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        authority: &TenantAuthority,
        batch: RemovalBatch<'_>,
    ) -> Result<(), AppError> {
        if batch.principals.is_empty() {
            return Ok(());
        }
        let labels = caller_labels(
            self.ports.audit_label_resolver.as_ref(),
            self.ports.control_plane_label_resolver.as_ref(),
            ctx,
            batch.principals,
        )
        .await?;
        let stores = CompletionStores {
            records: self.ports.access_records.as_ref(),
            assignments: self.ports.assignment_store.as_ref(),
            memberships: self.ports.membership_store.as_ref(),
        };
        let mut taken =
            remove_batch(stores, &batch, RemovalAuthority::Caller(authority), &labels).await?;
        let events = taken
            .iter_mut()
            .flat_map(|held| held.take_events(batch.tenant))
            .collect();
        auditor
            .dispatch_by(&authority.actor(), events)
            .await
            .or_internal()
    }
}

impl Command for CompleteUseCase {
    type Caller = CallerContext;
    type Input = AccessReviewId;
    type Output = Result<AccessReview<ResolvedTenant>, AppError>;

    /// Completes every snapshot holder in one unit, checking current authority
    /// and administrator safety before each bounded batch.
    ///
    /// # Errors
    ///
    /// Refuses inaccessible or closed reviews, early unanswered completion,
    /// unauthorized removals and losing the last administrator; persistence
    /// and audit errors fail the whole operation.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: AccessReviewId,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        kept_together(
            self.ports.unit_of_work.as_ref(),
            self.completed(ctx, auditor, id),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_review::{
        AccessReviewStatus, ReviewChoice, ReviewScope,
    };
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{EventLabel, GroupId, PrincipalRef, RoleId, UserId};
    use time::Duration;

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeAccessReviewStore, FakeGroupMembershipStore,
        FakeGroupStore, FakeRoleAssignmentStore, FakeRoleStore, open_review_of, stored_assignment,
        stored_group, stored_membership, stored_role,
    };
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    /// The person every fake caller signs in as.
    const CALLER: &str = "caller@example.test";

    /// A tenant where Bob holds `role` straight and sits in "Finance",
    /// which carries nothing, with a review of one of them.
    struct Tenant {
        bob: PrincipalRef,
        group_id: GroupId,
        role_id: RoleId,
        reviews: Arc<FakeAccessReviewStore>,
        sources: AccessSources,
    }

    fn tenant_with(role: Role<ResolvedTenant>) -> Tenant {
        let tenant = test_ctx().tenant_id();
        let bob = PrincipalRef::User(UserId::new());
        let finance = stored_group("Finance", GroupPlace::TopLevel, Vec::new());
        let (group_id, role_id) = (*finance.id(), *role.id());
        Tenant {
            bob,
            group_id,
            role_id,
            reviews: Arc::new(FakeAccessReviewStore::empty()),
            sources: AccessSources {
                roles: Arc::new(FakeRoleStore::holding(tenant, [role])),
                assignments: Arc::new(FakeRoleAssignmentStore::holding(
                    tenant,
                    [stored_assignment(bob, role_id)],
                )),
                groups: Arc::new(FakeGroupStore::holding(tenant, [finance])),
                memberships: Arc::new(FakeGroupMembershipStore::holding(
                    tenant,
                    [stored_membership(bob, group_id)],
                )),
                ..AccessSources::default()
            },
        }
    }

    fn tenant() -> Tenant {
        tenant_with(stored_role("finance", Vec::new(), Vec::new()))
    }

    impl Tenant {
        /// A review of `scope` listing Bob, undecided, with the caller
        /// reviewing, due next week.
        fn undecided(&self, scope: ReviewScope) -> AccessReview<ResolvedTenant> {
            open_review_of(scope, &[self.bob], CALLER, clock::now() + Duration::days(7))
        }

        /// `review`, saved.
        fn saved(&self, review: &AccessReview<ResolvedTenant>) -> AccessReviewId {
            block_on(self.reviews.save(&test_ctx().tenant(), review)).unwrap();
            self.reviews
                .seed_items(test_ctx().tenant_id(), review, &[self.bob]);
            *review.id()
        }

        /// A review of `scope` with Bob marked remove by the caller.
        fn removing_bob(&self, scope: ReviewScope) -> AccessReviewId {
            let mut review = self.undecided(scope);
            let caller = FakeTenantAuthorities::holding(&[]);
            let reviewer = block_on(caller.authority(&test_ctx())).unwrap();
            self.reviews
                .seed_items(test_ctx().tenant_id(), &review, &[self.bob]);
            let mut item = self
                .reviews
                .stored_items(test_ctx().tenant_id(), review.id())
                .remove(0);
            review
                .decide(
                    &mut item,
                    ReviewChoice::Remove,
                    &reviewer,
                    EventLabel::of("bob"),
                )
                .unwrap();
            block_on(self.reviews.save(&test_ctx().tenant(), &review)).unwrap();
            block_on(self.reviews.save_item(&test_ctx().tenant(), &item)).unwrap();
            *review.id()
        }

        /// A review of the role with Bob marked remove, due next week.
        fn removing_bobs_role(&self) -> AccessReviewId {
            self.removing_bob(ReviewScope::Role(self.role_id))
        }

        fn ports(&self) -> CompletePorts {
            CompletePorts {
                review_store: self.reviews.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(self.sources.clone())),
                assignment_store: self.sources.assignments.clone(),
                membership_store: self.sources.memberships.clone(),
                role_store: self.sources.roles.clone(),
                group_store: self.sources.groups.clone(),
                ..CompletePorts::fakes()
            }
        }

        fn status(&self, id: &AccessReviewId) -> AccessReviewStatus {
            self.reviews
                .stored(test_ctx().tenant_id(), id)
                .unwrap()
                .status()
        }
    }

    fn complete(
        ports: CompletePorts,
        sink: &Arc<FakeEventDispatcher>,
        id: AccessReviewId,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        block_on(CompleteUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    /// Ann reviewed "finance" and marked Bob remove. She completes the
    /// review: it is completed, Bob no longer holds the role, and both are
    /// recorded.
    #[test]
    fn completing_takes_away_the_role_of_each_holder_marked_remove() {
        let tenant = tenant();
        let id = tenant.removing_bobs_role();
        let sink = Arc::new(FakeEventDispatcher::new());

        complete(tenant.ports(), &sink, id).unwrap();

        assert_eq!(tenant.status(&id), AccessReviewStatus::Completed);
        assert_eq!(tenant.sources.assignments.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "authorization.role_revoked",
                "authorization.access_review_completed"
            ]
        );
    }

    /// A manually completed 501-holder snapshot is paged inside one explicit
    /// transaction and finishes with one completion audit record.
    #[test]
    fn manual_completion_pages_the_snapshot_inside_one_unit() {
        let tenant = tenant();
        let holders: Vec<_> = (0..501)
            .map(|_| PrincipalRef::User(UserId::new()))
            .collect();
        let review = open_review_of(
            ReviewScope::Role(tenant.role_id),
            &holders,
            CALLER,
            clock::now() - Duration::DAY,
        );
        block_on(tenant.reviews.save(&test_ctx().tenant(), &review)).unwrap();
        tenant
            .reviews
            .seed_items(test_ctx().tenant_id(), &review, &holders);
        let unit = Arc::new(RecordingUnitOfWork::default());
        let mut ports = tenant.ports();
        ports.unit_of_work = unit.clone();
        let sink = Arc::new(FakeEventDispatcher::new());

        complete(ports, &sink, *review.id()).unwrap();

        assert_eq!(tenant.reviews.item_batch_sizes(), [500, 1]);
        assert_eq!(unit.settlements(), [Settlement::Commit]);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_review_completed"]
        );
    }

    /// Completing an undecided review before its deadline returns a conflict,
    /// requests rollback and leaves the review open.
    #[test]
    fn a_client_refusal_rolls_back_the_completion_unit() {
        let tenant = tenant();
        let id = tenant.saved(&tenant.undecided(ReviewScope::Role(tenant.role_id)));
        let unit = Arc::new(RecordingUnitOfWork::default());
        let mut ports = tenant.ports();
        ports.unit_of_work = unit.clone();
        let result = complete(ports, &Arc::new(FakeEventDispatcher::new()), id);
        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
        assert_eq!(tenant.status(&id), AccessReviewStatus::Open);
    }

    /// Ann reviewed "Finance" and marked Bob remove. Completing ends his
    /// place in it.
    #[test]
    fn completing_ends_the_membership_of_each_member_marked_remove() {
        let tenant = tenant();
        let id = tenant.removing_bob(ReviewScope::Group(tenant.group_id));
        let sink = Arc::new(FakeEventDispatcher::new());

        complete(tenant.ports(), &sink, id).unwrap();

        assert_eq!(tenant.sources.memberships.count(), 0);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            [
                "authorization.group_member_removed",
                "authorization.access_review_completed"
            ]
        );
    }

    /// Ann completes a review where nobody decided on Bob yet, with a week
    /// to go. It is refused as a conflict and Bob keeps his role.
    #[test]
    fn an_undecided_review_is_not_completed_before_it_is_due() {
        let tenant = tenant();
        let id = tenant.saved(&tenant.undecided(ReviewScope::Role(tenant.role_id)));

        let result = complete(tenant.ports(), &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.status(&id), AccessReviewStatus::Open);
        assert_eq!(tenant.sources.assignments.count(), 1);
    }

    /// A reviewer without assignment rights cannot complete Bob's removal.
    /// His role stays stored, the review stays open and no event is recorded.
    #[test]
    fn a_completer_who_could_not_take_it_by_hand_is_refused() {
        let tenant = tenant();
        let id = tenant.removing_bobs_role();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = CompletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = complete(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(tenant.sources.assignments.count(), 1);
        assert_eq!(tenant.status(&id), AccessReviewStatus::Open);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A review is hidden from a caller who neither reviews nor may view or
    /// assign roles. Attempting completion leaves the review open.
    #[test]
    fn a_review_the_caller_may_not_reach_is_not_found() {
        let tenant = tenant();
        let due = clock::now() + Duration::days(7);
        let scope = ReviewScope::Role(tenant.role_id);
        let id = tenant.saved(&open_review_of(scope, &[tenant.bob], "dan@acme.test", due));
        let ports = CompletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..tenant.ports()
        };

        let result = complete(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(tenant.status(&id), AccessReviewStatus::Open);
    }

    /// Completing a review cannot remove the tenant's sole administrator;
    /// the conflict leaves Bob's admin assignment stored.
    #[test]
    fn a_review_never_removes_the_last_administrator() {
        let admin = stored_role(
            "admin",
            vec![SystemPermission::ManageUsers, SystemPermission::ManageRoles],
            Vec::new(),
        );
        let tenant = tenant_with(admin);
        let id = tenant.removing_bobs_role();

        let result = complete(tenant.ports(), &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(tenant.sources.assignments.count(), 1);
    }

    /// Ann completes a review the tenant does not have. It is not found.
    #[test]
    fn an_unknown_review_is_not_found() {
        let tenant = tenant();

        let result = complete(
            tenant.ports(),
            &Arc::new(FakeEventDispatcher::new()),
            AccessReviewId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot complete the review; Bob's role remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let tenant = tenant();
        let id = tenant.removing_bobs_role();
        let ports = CompletePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..tenant.ports()
        };

        let result = complete(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(tenant.sources.assignments.count(), 1);
    }
}
