//! Cancel access review: call a review off; nothing it decided takes
//! effect.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_review::AccessReview;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::AccessReviewId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessReviewStore;
use crate::use_case::Command;
use crate::use_cases::authorization::access_reviews::lookup::existing_review;

/// The ports [`CancelUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelPorts {
    /// Loads and saves the review.
    pub review_store: Arc<dyn AccessReviewStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Calls off an access review of the caller's tenant.
pub struct CancelUseCase {
    ports: CancelPorts,
}

impl CancelUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CancelPorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelUseCase {
    type Caller = CallerContext;
    type Input = AccessReviewId;
    type Output = Result<AccessReview<ResolvedTenant>, AppError>;

    /// Calls review `id` off for the caller and records it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not assign roles, checked
    ///   before the review is looked up so a made-up id is refused the same
    ///   as a real one.
    /// - `AppError::NotFound` when the tenant has no such review.
    /// - `AppError::Domain` when the review is no longer open.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: AccessReviewId,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Roles(RoleAction::Assign))
            .map_err(AppError::from_domain)?;
        let store = self.ports.review_store.as_ref();
        let mut review = existing_review(store, &tenant, &id).await?;
        review.cancel(&authority).map_err(AppError::from_domain)?;

        store.save(&tenant, &review).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), review.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(review)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_review::{AccessReviewStatus, ReviewScope};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{PrincipalRef, RoleId, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeAccessReviewStore, open_review_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A store holding an open review of Bob's role, reviewed by Carol.
    fn open_review() -> (Arc<FakeAccessReviewStore>, AccessReviewId) {
        let review = open_review_of(
            ReviewScope::Role(RoleId::new()),
            &[PrincipalRef::User(UserId::new())],
            "carol@acme.test",
            clock::now() + Duration::days(7),
        );
        let id = *review.id();
        let store = FakeAccessReviewStore::holding(test_ctx().tenant_id(), [review]);
        (Arc::new(store), id)
    }

    fn cancel(
        ports: CancelPorts,
        sink: &Arc<FakeEventDispatcher>,
        id: AccessReviewId,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        block_on(CancelUseCase::new(ports).execute(&test_ctx(), &test_auditor(sink.clone()), id))
    }

    fn ports_over(store: &Arc<FakeAccessReviewStore>) -> CancelPorts {
        CancelPorts {
            review_store: store.clone(),
            ..CancelPorts::fakes()
        }
    }

    fn status(store: &FakeAccessReviewStore, id: &AccessReviewId) -> AccessReviewStatus {
        store.stored(test_ctx().tenant_id(), id).unwrap().status()
    }

    /// Ann calls the review off. It is cancelled and recorded.
    #[test]
    fn a_review_is_called_off_and_recorded() {
        let (store, id) = open_review();
        let sink = Arc::new(FakeEventDispatcher::new());

        cancel(ports_over(&store), &sink, id).unwrap();

        assert_eq!(status(&store, &id), AccessReviewStatus::Cancelled);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_review_cancelled"]
        );
    }

    /// Ann calls off a review the tenant does not have. It is not found.
    #[test]
    fn an_unknown_review_is_not_found() {
        let (store, _) = open_review();

        let result = cancel(
            ports_over(&store),
            &Arc::new(FakeEventDispatcher::new()),
            AccessReviewId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Cancelling a review without assignment permission is forbidden.
    /// The review stays open and no cancellation is recorded.
    #[test]
    fn a_caller_who_may_not_assign_roles_is_refused() {
        let (store, id) = open_review();
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = CancelPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports_over(&store)
        };

        let result = cancel(ports, &sink, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status(&store, &id), AccessReviewStatus::Open);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot cancel an access review.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = open_review();
        let ports = CancelPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports_over(&store)
        };

        let result = cancel(ports, &Arc::new(FakeEventDispatcher::new()), id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
