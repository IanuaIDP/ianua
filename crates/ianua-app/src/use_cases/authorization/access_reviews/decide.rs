//! Decide access review: a reviewer marks one holder keep or remove.
//!
//! Only a named reviewer decides, never about their own access, and only
//! while the review is open. A reviewer may change their mind until then.
//! Nothing is taken away here: that happens when the review is completed.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_review::{AccessReview, ReviewChoice, ReviewItem};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AccessReviewId, EventLabel, PrincipalRef};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessReviewStore;
use crate::ports::shared::{AuditLabelResolver, ControlPlaneLabelResolver};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::access_reviews::lookup::{
    ReviewReader, SEES_REVIEWS, existing_item, owned_review_for_update,
};
use crate::use_cases::authorization::audit_labels::principal_label;

/// The ports [`DecideUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DecidePorts {
    /// Loads and saves the review.
    pub review_store: Arc<dyn AccessReviewStore>,
    /// Who the caller is in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Names the holder in the audit record.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// Names a holder who is an organization member in the audit record.
    pub control_plane_label_resolver: Arc<dyn ControlPlaneLabelResolver>,
}

/// Which review, which holder, and what the reviewer chose.
pub struct DecideRequest {
    /// The access assessment receiving this holder's decision.
    pub review_id: AccessReviewId,
    /// The holder decided on.
    pub holder: PrincipalRef,
    /// Keep or remove.
    pub choice: ReviewChoice,
}

/// Records a reviewer's choice for one holder.
pub struct DecideUseCase {
    ports: DecidePorts,
}

impl DecideUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DecidePorts) -> Self {
        Self { ports }
    }

    /// Resolves the one decision's holder through tenant or organization scope.
    async fn decision_label(
        &self,
        ctx: &CallerContext,
        holder: &PrincipalRef,
    ) -> Result<EventLabel, AppError> {
        principal_label(
            self.ports.audit_label_resolver.as_ref(),
            self.ports.control_plane_label_resolver.as_ref(),
            ctx,
            holder,
        )
        .await
    }

    /// Persists only the locked header counters and the one changed item.
    async fn save_decision(
        &self,
        tenant: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        item: &ReviewItem,
    ) -> Result<(), AppError> {
        self.ports
            .review_store
            .save(tenant, review)
            .await
            .or_internal()?;
        self.ports
            .review_store
            .save_item(tenant, item)
            .await
            .or_internal()
    }
}

impl Command for DecideUseCase {
    type Caller = CallerContext;
    type Input = DecideRequest;
    type Output = Result<AccessReview<ResolvedTenant>, AppError>;

    /// Records the caller's choice for `request.holder` and saves it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such review, the
    ///   caller may not see it (neither one of its reviewers nor allowed to
    ///   view roles), or it does not list the holder.
    /// - `AppError::Forbidden` when the caller sees the review but is not
    ///   one of its reviewers, or the holder is the caller's own account.
    /// - `AppError::Conflict` when the review is closed or past due.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DecideRequest,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let store = self.ports.review_store.as_ref();
        let mut review = owned_review_for_update(
            store,
            &tenant,
            &request.review_id,
            ReviewReader {
                authority: &authority,
                besides: SEES_REVIEWS,
            },
        )
        .await?;
        let mut item = existing_item(store, &tenant, &review, &request.holder).await?;
        let label = self.decision_label(ctx, &request.holder).await?;
        review
            .decide(&mut item, request.choice, &authority, label)
            .map_err(AppError::from_domain)?;

        self.save_decision(&tenant, &review, &item).await?;
        auditor
            .dispatch_by(&authority.actor(), review.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(review)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_review::{AccessReviewVerdict, ReviewScope};
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{RoleId, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::authorization::{FakeAccessReviewStore, open_review_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The person every fake caller signs in as.
    const CALLER: &str = "caller@example.test";

    /// A review of Bob, and of the caller, due next week, with `reviewer`
    /// deciding.
    fn review_by(reviewer: &str) -> (Arc<FakeAccessReviewStore>, AccessReviewId, PrincipalRef) {
        let bob = PrincipalRef::User(UserId::new());
        let caller = PrincipalRef::User(test_caller_id());
        let scope = ReviewScope::Role(RoleId::new());
        let due = clock::now() + Duration::days(7);
        let review = open_review_of(scope, &[bob, caller], reviewer, due);
        let id = *review.id();
        let store = FakeAccessReviewStore::holding(test_ctx().tenant_id(), [review]);
        let header = store.stored(test_ctx().tenant_id(), &id).unwrap();
        store.seed_items(test_ctx().tenant_id(), &header, &[bob, caller]);
        (Arc::new(store), id, bob)
    }

    fn decide(
        store: &Arc<FakeAccessReviewStore>,
        sink: &Arc<FakeEventDispatcher>,
        request: DecideRequest,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        decide_through(
            DecidePorts {
                review_store: store.clone(),
                ..DecidePorts::fakes()
            },
            sink,
            request,
        )
    }

    fn decide_through(
        ports: DecidePorts,
        sink: &Arc<FakeEventDispatcher>,
        request: DecideRequest,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        block_on(DecideUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    fn remove(review_id: AccessReviewId, holder: PrincipalRef) -> DecideRequest {
        DecideRequest {
            review_id,
            holder,
            choice: ReviewChoice::Remove,
        }
    }

    /// Ann reviews and marks Bob remove. Her choice is saved and recorded.
    #[test]
    fn a_reviewer_decides_on_a_holder() {
        let (store, id, bob) = review_by(CALLER);
        let sink = Arc::new(FakeEventDispatcher::new());

        decide(&store, &sink, remove(id, bob)).unwrap();

        let items = store.stored_items(test_ctx().tenant_id(), &id);
        let decided = items.iter().find(|item| *item.holder() == bob).unwrap();
        assert!(matches!(
            decided.verdict(),
            AccessReviewVerdict::Decided {
                choice: ReviewChoice::Remove,
                ..
            }
        ));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_review_decided"]
        );
    }

    /// Role view permission does not allow a caller outside the named reviewers
    /// to decide on Bob's access. The refusal records no decision.
    #[test]
    fn only_a_named_reviewer_decides() {
        let (store, id, bob) = review_by("carol@acme.test");
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = DecidePorts {
            review_store: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::View),
            ])),
            ..DecidePorts::fakes()
        };

        let result = decide_through(ports, &sink, remove(id, bob));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A caller who neither reviews nor may view roles sees the review as
    /// missing when attempting to decide on Bob's access.
    #[test]
    fn a_review_the_caller_may_not_see_is_not_found() {
        let (store, id, bob) = review_by("carol@acme.test");
        let ports = DecidePorts {
            review_store: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..DecidePorts::fakes()
        };

        let result = decide_through(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            remove(id, bob),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A named reviewer cannot decide to keep their own access.
    #[test]
    fn nobody_decides_on_their_own_access() {
        let (store, id, _) = review_by(CALLER);
        let own = DecideRequest {
            choice: ReviewChoice::Keep,
            ..remove(id, PrincipalRef::User(test_caller_id()))
        };

        let result = decide(&store, &Arc::new(FakeEventDispatcher::new()), own);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann decides on Dan, whom the review does not list. He is not found.
    #[test]
    fn a_holder_the_review_does_not_list_is_not_found() {
        let (store, id, _) = review_by(CALLER);
        let dan = PrincipalRef::User(UserId::new());

        let sink = Arc::new(FakeEventDispatcher::new());

        let result = decide(&store, &sink, remove(id, dan));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann decides in a review the tenant does not have. It is not found.
    #[test]
    fn an_unknown_review_is_not_found() {
        let (store, _, bob) = review_by(CALLER);

        let result = decide(
            &store,
            &Arc::new(FakeEventDispatcher::new()),
            remove(AccessReviewId::new(), bob),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot decide to remove Bob's access.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id, bob) = review_by(CALLER);
        let ports = DecidePorts {
            review_store: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..DecidePorts::fakes()
        };

        let sink = Arc::new(FakeEventDispatcher::new());

        let result = decide_through(ports, &sink, remove(id, bob));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
