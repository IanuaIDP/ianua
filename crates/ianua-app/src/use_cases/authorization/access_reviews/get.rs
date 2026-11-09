//! Get access review: one review header with snapshot and decision counts,
//! for its reviewers and for those who may view roles.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_review::AccessReview;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AccessReviewId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::AccessReviewStore;
use crate::use_case::Query;
use crate::use_cases::authorization::access_reviews::lookup::{
    ReviewReader, SEES_REVIEWS, owned_review,
};

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads the review.
    pub review_store: Arc<dyn AccessReviewStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one access review of the caller's tenant.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = AccessReviewId;
    type Output = Result<AccessReview<ResolvedTenant>, AppError>;

    /// Review `id`, with summary counts; holders are read through item pages.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such review, or the
    ///   caller is not one of its reviewers and may not view roles: a
    ///   review they may not read cannot be told from one that is not
    ///   there.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: AccessReviewId,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        owned_review(
            self.ports.review_store.as_ref(),
            &ctx.tenant(),
            &id,
            ReviewReader {
                authority: &authority,
                besides: SEES_REVIEWS,
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_review::ReviewScope;
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{PrincipalRef, RoleId, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeAccessReviewStore, open_review_of};
    use crate::test_support::{block_on, test_ctx};

    /// A store holding a review reviewed by `reviewer`, read by a caller
    /// holding nothing.
    fn reviewed_by(reviewer: &str) -> (GetPorts, AccessReviewId) {
        let review = open_review_of(
            ReviewScope::Role(RoleId::new()),
            &[PrincipalRef::User(UserId::new())],
            reviewer,
            clock::now() + Duration::days(7),
        );
        let id = *review.id();
        let ports = GetPorts {
            review_store: Arc::new(FakeAccessReviewStore::holding(
                test_ctx().tenant_id(),
                [review],
            )),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
        };
        (ports, id)
    }

    fn get(ports: GetPorts, id: AccessReviewId) -> Result<AccessReview<ResolvedTenant>, AppError> {
        block_on(GetUseCase::new(ports).execute(&test_ctx(), id))
    }

    /// Ann may view nothing, but she is the review's reviewer. She reads it.
    #[test]
    fn a_reviewer_reads_their_review() {
        let (ports, id) = reviewed_by("caller@example.test");

        assert_eq!(*get(ports, id).unwrap().id(), id);
    }

    /// Ann may view roles and reads a review Carol runs.
    #[test]
    fn a_caller_who_may_view_roles_reads_any_review() {
        let (ports, id) = reviewed_by("carol@acme.test");
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[
                SystemPermission::Roles(RoleAction::View),
            ])),
            ..ports
        };

        assert!(get(ports, id).is_ok());
    }

    /// Ann reads a review the tenant does not have. It is not found.
    #[test]
    fn an_unknown_review_is_not_found() {
        let (ports, _) = reviewed_by("caller@example.test");

        assert!(matches!(
            get(ports, AccessReviewId::new()),
            Err(AppError::NotFound(_))
        ));
    }

    /// A review is hidden as missing from a caller who is neither its reviewer
    /// nor authorized to view roles.
    #[test]
    fn anyone_else_finds_nothing() {
        let (ports, id) = reviewed_by("carol@acme.test");

        assert!(matches!(get(ports, id), Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot read an access review.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (ports, id) = reviewed_by("caller@example.test");
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports
        };

        assert!(matches!(get(ports, id), Err(AppError::Unauthenticated)));
    }
}
