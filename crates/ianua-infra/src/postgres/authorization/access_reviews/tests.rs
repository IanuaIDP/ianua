//! Header-only review reads, immutable holder snapshots and atomic decisions.

/// Real storage checks for snapshots, tenant boundaries and atomic rollback.
#[cfg(test)]
mod cases {
    use std::sync::Arc;

    use ianua_app::auditor::RequestAuditor;
    use ianua_app::listing::{Limit, Page, PageRequest};
    use ianua_app::ports::authorization::{
        AccessReviewFilter, AccessReviewStore as _, GroupMembershipStore as _, GroupStore as _,
        OverdueReview, RoleAssignmentStore as _, RoleStore as _,
    };
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_app::tenancy::ScopedTenant;
    use ianua_app::test_support::FailingEventDispatcher;
    use ianua_domain::domains::authorization::access_review::{
        AccessReview, AccessReviewDraft, AccessReviewStatus, AccessReviewVerdict, HolderSuggestion,
        NewAccessReview, ReviewChoice, ReviewItem, ReviewScope, ReviewSuggestion, Unanswered,
    };
    use ianua_domain::domains::authorization::authority::TenantAuthority;
    use ianua_domain::domains::authorization::group::Group;
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::events::raised::Raises as _;
    use ianua_domain::test_support::authority::assumed_authority;
    use ianua_domain::types::{
        AccessReviewId, EventLabel, Expiry, GroupId, Human, PrincipalRef, RoleId, Text, UserId,
    };

    use crate::postgres::authorization::access_reviews::PgAccessReviewStore;
    use crate::postgres::authorization::{
        PgGroupMembershipStore, PgGroupStore, PgRoleAssignmentStore, PgRoleStore,
    };
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::{
        assignment, assignment_until, group, human, label, membership_until, role, tenant,
    };

    struct Fixture {
        db: TestDb,
        store: PgAccessReviewStore,
        assignments: PgRoleAssignmentStore,
        tenant: ScopedTenant,
        role: RoleId,
        reviewer: Human,
        authority: &'static TenantAuthority,
    }

    /// A persisted role and reviewer authority for a tenant, with real stores.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let reviewer = human(UserId::new(), "reviewer@acme.example");
        let authority = assumed_authority(
            &reviewer,
            *tenant,
            &[SystemPermission::Roles(RoleAction::Assign)],
            &[],
        );
        let held = role("Finance");
        PgRoleStore::new(Arc::clone(&db.databases))
            .save(&tenant, &held)
            .await
            .unwrap();
        Fixture {
            store: PgAccessReviewStore::new(Arc::clone(&db.databases)),
            assignments: PgRoleAssignmentStore::new(Arc::clone(&db.databases)),
            db,
            tenant,
            role: *held.id(),
            reviewer,
            authority,
        }
    }

    /// Commits successful storage work and rolls back failures, as requests do.
    fn settlement<T>(result: &Result<T, DomainError>) -> Settlement {
        match result {
            Ok(_) => Settlement::Commit,
            Err(_) => Settlement::Rollback,
        }
    }

    impl Fixture {
        /// Gives the role to distinct users through the ordinary assignment store.
        async fn holders(&self, count: usize) -> Vec<PrincipalRef> {
            let mut holders = Vec::with_capacity(count);
            for _ in 0..count {
                let holder = PrincipalRef::User(UserId::new());
                self.assignments
                    .save(&self.tenant, &assignment(holder, self.role))
                    .await
                    .unwrap();
                holders.push(holder);
            }
            holders
        }

        /// Authorizes a snapshot at a fixed instant, with a future deadline.
        fn draft(
            &self,
            scope: ReviewScope,
            started: i64,
            due: i64,
        ) -> AccessReviewDraft<ResolvedTenant> {
            let _clock = clock::freeze(at(started));
            AccessReview::prepare(
                NewAccessReview {
                    name: label("Finance review"),
                    scope,
                    scope_label: EventLabel::of("Finance"),
                    reviewers: vec![self.reviewer.clone()],
                    due: at(due),
                    unanswered: Unanswered::RemoveAccess,
                },
                self.authority,
            )
            .unwrap()
        }

        /// Starts one immutable role snapshot and commits its header and items.
        async fn opened(&self) -> AccessReview<ResolvedTenant> {
            let draft = self.draft(ReviewScope::Role(self.role), 100, 1000);
            atomically(
                &PgUnitOfWork,
                self.store.start(&self.tenant, draft),
                settlement,
            )
            .await
            .unwrap()
            .unwrap()
        }

        /// Reads a review header without hydrating any holder rows.
        async fn header(&self, id: &AccessReviewId) -> AccessReview<ResolvedTenant> {
            self.store
                .find_by_id(&self.tenant, id)
                .await
                .unwrap()
                .unwrap()
        }

        /// Reads a bounded holder page through the review's owning tenant.
        async fn items(
            &self,
            review: &AccessReview<ResolvedTenant>,
            page: &PageRequest,
        ) -> Page<ReviewItem> {
            self.store
                .list_items(&self.tenant, review, page)
                .await
                .unwrap()
        }

        /// Looks up one holder without requiring that it belongs to the snapshot.
        async fn item(
            &self,
            review: &AccessReview<ResolvedTenant>,
            holder: &PrincipalRef,
        ) -> Option<ReviewItem> {
            self.store
                .find_item(&self.tenant, review, holder)
                .await
                .unwrap()
        }

        /// Reads header pages using the supplied status filter and cursor.
        async fn headers(
            &self,
            filter: AccessReviewFilter,
            page: &PageRequest,
        ) -> Page<AccessReview<ResolvedTenant>> {
            self.store.list(&self.tenant, filter, page).await.unwrap()
        }

        /// Reads the overdue sweep at the fixture's fixed deadline.
        async fn overdue(&self, page: &PageRequest) -> Page<OverdueReview> {
            self.store
                .find_overdue(&self.tenant, at(1000), page)
                .await
                .unwrap()
        }

        /// Persists a group with the supplied directly held roles.
        async fn group(&self, name: &str, roles: Vec<RoleId>) -> Group<ResolvedTenant> {
            let group = group(name, roles);
            PgGroupStore::new(Arc::clone(&self.db.databases))
                .save(&self.tenant, &group)
                .await
                .unwrap();
            group
        }

        /// Persists a direct group membership with an explicit expiry boundary.
        async fn join_until(&self, holder: PrincipalRef, group: GroupId, expiry: Expiry) {
            PgGroupMembershipStore::new(Arc::clone(&self.db.databases))
                .save(&self.tenant, &membership_until(holder, group, expiry))
                .await
                .unwrap();
        }

        /// Locks the review, decides one holder, and saves both item and counters in the ambient transaction.
        async fn decide_holder(
            &self,
            id: &AccessReviewId,
            holder: &PrincipalRef,
            choice: ReviewChoice,
        ) -> Result<AccessReview<ResolvedTenant>, DomainError> {
            let mut review = self.store.hold(&self.tenant, id).await?.unwrap();
            let mut item = self
                .store
                .find_item(&self.tenant, &review, holder)
                .await?
                .unwrap();
            review.decide(&mut item, choice, self.authority, EventLabel::of("holder"))?;
            self.store.save_item(&self.tenant, &item).await?;
            self.store.save(&self.tenant, &review).await?;
            Ok(review)
        }

        /// Saves two suggestions after deciding the first holder, excluding a stranger from the batch read.
        async fn suggest_holders(
            &self,
            id: &AccessReviewId,
            held: &[PrincipalRef],
            stranger: PrincipalRef,
        ) -> Result<(), DomainError> {
            let mut review = self.decide_holder(id, &held[0], ReviewChoice::Keep).await?;
            let mut items = self
                .store
                .find_items(&self.tenant, &review, &[held[0], held[1], stranger])
                .await?;
            assert_eq!(items.len(), 2);
            review.suggest(
                &mut items,
                vec![
                    suggestion(held[0], ReviewChoice::Remove),
                    suggestion(held[1], ReviewChoice::Keep),
                ],
                self.authority,
            )?;
            self.store.save_suggestions(&self.tenant, &items).await
        }

        /// Completes every removal page before publishing audit events in the ambient transaction.
        async fn complete_with_audit(
            &self,
            id: &AccessReviewId,
            auditor: &RequestAuditor,
        ) -> Result<(), DomainError> {
            let mut review = self.store.hold(&self.tenant, id).await?.unwrap();
            let mut completion = review.complete_overdue(at(1000))?;
            let mut request = page(500);
            loop {
                let items = self
                    .store
                    .list_items(&self.tenant, &review, &request)
                    .await?;
                let removed = completion.removals(&items.items)?;
                self.assignments
                    .delete_for_principals(&self.tenant, &self.role, &removed)
                    .await?;
                let Some(next) = request.following(&items) else {
                    break;
                };
                request = next;
            }
            review.finish(completion)?;
            self.store.save(&self.tenant, &review).await?;
            auditor.dispatch(&review.take_events(&self.tenant)).await
        }

        /// Removes the first page, proves only the last holder remains, then refuses completion.
        async fn refuse_last_page(&self, id: &AccessReviewId) -> Result<(), DomainError> {
            let review = self.store.hold(&self.tenant, id).await?.unwrap();
            let mut completion = review.complete_overdue(at(1000))?;
            let request = page(500);
            let first = self
                .store
                .list_items(&self.tenant, &review, &request)
                .await?;
            let removed = completion.removals(&first.items)?;
            self.assignments
                .delete_for_principals(&self.tenant, &self.role, &removed)
                .await?;
            assert_eq!(
                self.assignments
                    .count_by_role(&self.tenant, &self.role)
                    .await?,
                1
            );
            let last = self
                .store
                .list_items(&self.tenant, &review, &request.following(&first).unwrap())
                .await?;
            assert_eq!(last.items.len(), 1);
            Err(DomainError::conflict(
                "the final holder cannot be withdrawn",
            ))
        }

        /// Counts the role's assignments after a transaction has settled.
        async fn assignment_count(&self) -> u64 {
            self.assignments
                .count_by_role(&self.tenant, &self.role)
                .await
                .unwrap()
        }
    }

    /// Supplies a review suggestion with the reason whose stored text is asserted below.
    fn suggestion(holder: PrincipalRef, choice: ReviewChoice) -> HolderSuggestion {
        HolderSuggestion {
            holder,
            choice,
            reason: Text::new("reason", "no Finance app since June").unwrap(),
        }
    }

    /// Rejects unknown review ids and hides headers and snapshot holders from other tenants.
    async fn assert_unknown_or_foreign(
        fx: &Fixture,
        opened: &AccessReview<ResolvedTenant>,
        active: &PrincipalRef,
    ) {
        let foreign = fx.store.find_by_id(&tenant(), opened.id()).await.unwrap();
        let unknown = fx
            .store
            .find_by_id(&fx.tenant, &AccessReviewId::new())
            .await
            .unwrap();
        let items = fx
            .store
            .list_items(&tenant(), opened, &page(10))
            .await
            .unwrap();
        let item = fx.store.find_item(&tenant(), opened, active).await.unwrap();
        assert!(foreign.is_none());
        assert!(unknown.is_none());
        assert!(items.items.is_empty());
        assert!(item.is_none());
    }

    /// Only the selected holder carries the saved decision; other snapshot items stay pending.
    fn assert_holder_verdicts(items: &[ReviewItem], holder: &PrincipalRef, choice: ReviewChoice) {
        assert_eq!(items.len(), 3);
        for item in items {
            if item.holder() == holder {
                assert!(
                    matches!(item.verdict(), AccessReviewVerdict::Decided { choice: saved, .. } if *saved == choice)
                );
            } else {
                assert_eq!(item.verdict(), &AccessReviewVerdict::Pending);
            }
        }
    }

    /// The first holder retains its keep decision beside the stored remove suggestion and reason.
    fn assert_decided_suggestion(first: &ReviewItem) {
        assert!(matches!(
            first.suggestion(),
            ReviewSuggestion::Made { choice: ReviewChoice::Remove, reason }
                if reason.as_str() == "no Finance app since June"
        ));
        assert!(matches!(
            first.verdict(),
            AccessReviewVerdict::Decided {
                choice: ReviewChoice::Keep,
                ..
            }
        ));
    }

    /// One bounded page request used by the holder and review checks.
    fn page(size: u32) -> PageRequest {
        PageRequest::first(Limit::internal(size))
    }

    /// More than 500 direct holders are snapshotted once. Later grants and
    /// withdrawals leave the snapshot intact, and holder pages have no gaps.
    #[tokio::test]
    async fn holder_pages_cover_the_complete_immutable_snapshot() {
        let fx = fixture().await;
        let held = fx.holders(501).await;
        let opened = fx.opened().await;
        let later = fx.holders(1).await[0];
        fx.assignments
            .delete(&fx.tenant, &held[0], &fx.role)
            .await
            .unwrap();
        let request = page(500);

        let first = fx.items(&opened, &request).await;
        let next = request.following(&first).unwrap();
        let last = fx.items(&opened, &next).await;

        assert_eq!(opened.holder_count(), 501);
        assert_eq!(opened.pending_count(), 501);
        assert_eq!(first.items.len(), 500);
        assert_eq!(last.items.len(), 1);
        assert!(!last.has_next());
        let items: Vec<_> = first.items.iter().chain(&last.items).collect();
        assert_eq!(
            items.iter().map(|item| item.position()).collect::<Vec<_>>(),
            (1..=501).collect::<Vec<_>>()
        );
        assert!(
            held.iter()
                .all(|holder| items.iter().any(|item| item.holder() == holder))
        );
        assert!(items.iter().all(|item| *item.holder() != later));
        assert!(fx.item(&opened, &held[0]).await.is_some());
        assert!(fx.item(&opened, &later).await.is_none());
    }

    /// Headers and overdue positions do not decode holder rows. A corrupt item
    /// is refused only when the explicitly requested holder page reaches it.
    #[tokio::test]
    async fn header_reads_never_hydrate_the_holder_collection() {
        let fx = fixture().await;
        fx.holders(2).await;
        let opened = fx.opened().await;
        fx.db
            .tamper("UPDATE access_review_items SET position = 99999 WHERE position = 1")
            .await;

        let found = fx
            .store
            .find_by_id(&fx.tenant, opened.id())
            .await
            .unwrap()
            .unwrap();
        let listed = fx
            .store
            .list(&fx.tenant, AccessReviewFilter::All, &page(10))
            .await
            .unwrap();
        let overdue = fx
            .store
            .find_overdue(&fx.tenant, at(1000), &page(10))
            .await
            .unwrap();

        assert_eq!(found.holder_count(), 2);
        assert_eq!(listed.items.len(), 1);
        assert_eq!(overdue.items.len(), 1);
        assert!(matches!(
            fx.store.list_items(&fx.tenant, &found, &page(10)).await,
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Only direct assignments active at the snapshot instant belong to the role
    /// review; inherited roles and assignments ending now stay out.
    #[tokio::test]
    async fn role_snapshots_keep_only_active_direct_holders() {
        let fx = fixture().await;
        let active = fx.holders(1).await[0];
        let ended = PrincipalRef::User(UserId::new());
        fx.assignments
            .save(
                &fx.tenant,
                &assignment_until(ended, fx.role, Expiry::At(at(100))),
            )
            .await
            .unwrap();
        let inherited = PrincipalRef::User(UserId::new());
        let team = fx.group("Inherited", vec![fx.role]).await;
        fx.join_until(inherited, *team.id(), Expiry::Never).await;
        let opened = fx.opened().await;

        let items = fx.items(&opened, &page(10)).await;

        assert_eq!(opened.holder_count(), 1);
        assert_eq!(items.items[0].holder(), &active);
        assert_unknown_or_foreign(&fx, &opened, &active).await;
    }

    /// A group snapshot includes only that group's direct active memberships,
    /// including a membership that has not yet reached its expiry boundary.
    #[tokio::test]
    async fn group_snapshots_respect_group_scope_and_expiry() {
        let fx = fixture().await;
        let own = fx.group("Own", Vec::new()).await;
        let other = fx.group("Other", Vec::new()).await;
        let active = PrincipalRef::User(UserId::new());
        let ended = PrincipalRef::User(UserId::new());
        fx.join_until(active, *own.id(), Expiry::At(at(101))).await;
        fx.join_until(ended, *own.id(), Expiry::At(at(100))).await;
        fx.join_until(ended, *other.id(), Expiry::Never).await;
        let draft = fx.draft(ReviewScope::Group(*own.id()), 100, 1000);
        let opened = atomically(&PgUnitOfWork, fx.store.start(&fx.tenant, draft), settlement)
            .await
            .unwrap()
            .unwrap();

        let items = fx.items(&opened, &page(10)).await;

        assert_eq!(opened.holder_count(), 1);
        assert_eq!(items.items[0].holder(), &active);
    }

    /// An empty snapshot is refused atomically, leaving neither a header nor items.
    #[tokio::test]
    async fn an_empty_scope_leaves_no_review() {
        let fx = fixture().await;
        let draft = fx.draft(ReviewScope::Role(fx.role), 100, 1000);
        let id = *draft.id();

        let result = atomically(&PgUnitOfWork, fx.store.start(&fx.tenant, draft), settlement)
            .await
            .unwrap();

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert!(
            fx.store
                .find_by_id(&fx.tenant, &id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fx.store
                .list(&fx.tenant, AccessReviewFilter::All, &page(10))
                .await
                .unwrap()
                .items
                .is_empty()
        );
    }

    /// Suggestions beside two holders are read in one go and saved in one
    /// go: each reads back beside its holder, a decision already made is
    /// kept, the third holder has none, and a holder the review does not
    /// list is left out of the read.
    #[tokio::test]
    async fn suggestions_are_saved_beside_their_holders_and_keep_decisions() {
        let fx = fixture().await;
        let held = fx.holders(3).await;
        let opened = fx.opened().await;
        let _clock = clock::freeze(at(101));
        let stranger = PrincipalRef::User(UserId::new());
        atomically(
            &PgUnitOfWork,
            fx.suggest_holders(opened.id(), &held, stranger),
            settlement,
        )
        .await
        .unwrap()
        .unwrap();

        let first = fx.item(&opened, &held[0]).await.unwrap();
        assert_decided_suggestion(&first);
        assert!(matches!(
            fx.item(&opened, &held[1]).await.unwrap().suggestion(),
            ReviewSuggestion::Made {
                choice: ReviewChoice::Keep,
                ..
            }
        ));
        assert_eq!(
            *fx.item(&opened, &held[2]).await.unwrap().suggestion(),
            ReviewSuggestion::Nothing
        );
    }

    /// A decision updates one holder and the locked header counters, preserving
    /// every other item and its snapshot position, including replacement choices.
    #[tokio::test]
    async fn decisions_update_one_item_and_its_header_counts() {
        let fx = fixture().await;
        let held = fx.holders(3).await;
        let opened = fx.opened().await;
        let _clock = clock::freeze(at(101));
        for choice in [ReviewChoice::Remove, ReviewChoice::Keep] {
            atomically(
                &PgUnitOfWork,
                fx.decide_holder(opened.id(), &held[1], choice),
                settlement,
            )
            .await
            .unwrap()
            .unwrap();
            let review = fx.header(opened.id()).await;
            assert_eq!(review.holder_count(), 3);
            assert_eq!(review.pending_count(), 2);
            assert_eq!(
                review.remove_count(),
                u64::from(choice == ReviewChoice::Remove)
            );
            let items = fx.items(&review, &page(10)).await;
            assert_holder_verdicts(&items.items, &held[1], choice);
        }
    }

    /// Audit failure after completing two pages rolls back every removal:
    /// all 501 assignments remain and the review stays open with 501 pending.
    #[tokio::test]
    async fn audit_failure_rolls_back_every_completion_page() {
        let fx = fixture().await;
        let held = fx.holders(501).await;
        let opened = fx.opened().await;
        let auditor = RequestAuditor::system(Arc::new(FailingEventDispatcher));
        let result = atomically(
            &PgUnitOfWork,
            fx.complete_with_audit(opened.id(), &auditor),
            settlement,
        )
        .await
        .unwrap();

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
        let review = fx.header(opened.id()).await;
        assert_eq!(review.status(), AccessReviewStatus::Open);
        assert_eq!(review.pending_count(), 501);
        assert_eq!(fx.assignment_count().await, 501);
        assert!(
            fx.assignments
                .exists(&fx.tenant, &held[0], &fx.role)
                .await
                .unwrap()
        );
        assert!(
            fx.assignments
                .exists(&fx.tenant, &held[500], &fx.role)
                .await
                .unwrap()
        );
    }

    /// Refusal on the final page restores the first page's removals even
    /// when the outer request commits; all 501 assignments and the open review remain.
    #[tokio::test]
    async fn a_late_refusal_rolls_back_inside_a_committed_request() {
        let fx = fixture().await;
        fx.holders(501).await;
        let opened = fx.opened().await;
        let result = atomically(
            &PgUnitOfWork,
            async { atomically(&PgUnitOfWork, fx.refuse_last_page(opened.id()), settlement).await },
            |_| Settlement::Commit,
        )
        .await
        .unwrap()
        .unwrap();

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(fx.assignment_count().await, 501);
        assert_eq!(
            fx.header(opened.id()).await.status(),
            AccessReviewStatus::Open
        );
    }

    /// Header pages retain newest-first order, open filtering and due-time cursor
    /// ties after cancellation, without loading their snapshot items.
    #[tokio::test]
    async fn header_and_due_pages_keep_order_and_status_filters() {
        let fx = fixture().await;
        fx.holders(1).await;
        let old = fx.opened().await;
        let draft = fx.draft(ReviewScope::Role(fx.role), 200, 1000);
        let mut newer = atomically(&PgUnitOfWork, fx.store.start(&fx.tenant, draft), settlement)
            .await
            .unwrap()
            .unwrap();
        let first = fx.headers(AccessReviewFilter::All, &page(1)).await;
        assert_eq!(first.items[0].id(), newer.id());
        let last = fx
            .headers(AccessReviewFilter::All, &page(1).following(&first).unwrap())
            .await;
        assert_eq!(last.items[0].id(), old.id());
        assert!(!last.has_next());
        let due = fx.overdue(&page(1)).await;
        let rest = fx.overdue(&page(1).following(&due).unwrap()).await;
        assert_eq!(rest.items.len(), 1);
        assert_ne!(due.items[0].id, rest.items[0].id);
        assert!(!rest.has_next());
        newer.cancel(fx.authority).unwrap();
        fx.store.save(&fx.tenant, &newer).await.unwrap();
        let open = fx.headers(AccessReviewFilter::Open, &page(10)).await;
        assert_eq!(open.items.len(), 1);
        assert_eq!(open.items[0].id(), old.id());
    }
}
