//! List access reviews: the tenant's reviews, open ones or all, newest
//! first.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_review::AccessReview;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::listing::{Page, PageRequest};
use crate::ports::authorization::{AccessReviewFilter, AccessReviewStore};
use crate::use_case::Query;

/// The ports [`ListUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListPorts {
    /// Lists the reviews.
    pub review_store: Arc<dyn AccessReviewStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which reviews to list, and which page.
pub struct ListRequest {
    /// Which reviews.
    pub filter: AccessReviewFilter,
    /// Which page of them, newest first.
    pub page: PageRequest,
}

/// Lists the access reviews of the caller's tenant.
pub struct ListUseCase {
    ports: ListPorts,
}

impl ListUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListUseCase {
    type Caller = CallerContext;
    type Input = ListRequest;
    type Output = Result<Page<AccessReview<ResolvedTenant>>, AppError>;

    /// One page of the reviews `request.filter` keeps, newest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view roles.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListRequest,
    ) -> Result<Page<AccessReview<ResolvedTenant>>, AppError> {
        let ListRequest { filter, page } = request;
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .map_err(AppError::from_domain)?;
        self.ports
            .review_store
            .list(&ctx.tenant(), filter, &page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_review::ReviewScope;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{PrincipalRef, RoleId, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeAccessReviewStore, open_review_of};
    use crate::test_support::{block_on, test_ctx};

    fn one_open_review() -> ListPorts {
        let review = open_review_of(
            ReviewScope::Role(RoleId::new()),
            &[PrincipalRef::User(UserId::new())],
            "carol@acme.test",
            clock::now() + Duration::days(7),
        );
        ListPorts {
            review_store: Arc::new(FakeAccessReviewStore::holding(
                test_ctx().tenant_id(),
                [review],
            )),
            ..ListPorts::fakes()
        }
    }

    fn list(ports: ListPorts) -> Result<Page<AccessReview<ResolvedTenant>>, AppError> {
        block_on(ListUseCase::new(ports).execute(
            &test_ctx(),
            ListRequest {
                filter: AccessReviewFilter::Open,
                page: PageRequest::default(),
            },
        ))
    }

    /// Ann lists the open reviews and sees the one under way.
    #[test]
    fn open_reviews_are_listed() {
        assert_eq!(list(one_open_review()).unwrap().items.len(), 1);
    }

    /// Listing access reviews is forbidden without role view permission.
    #[test]
    fn a_caller_who_may_not_view_roles_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..one_open_review()
        };

        assert!(matches!(list(ports), Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list access reviews.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..one_open_review()
        };

        assert!(matches!(list(ports), Err(AppError::Unauthenticated)));
    }
}
