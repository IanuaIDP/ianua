//! Suggest keep or remove: someone who runs reviews puts a suggestion and
//! its reason beside holders of an open review.
//!
//! Nothing is decided here: the reviewers still mark each holder keep or
//! remove. Nobody suggests about their own access.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_review::{
    AccessReview, HolderSuggestion, ReviewItem,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{AccessReviewId, PrincipalRef};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessReviewStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::access_reviews::lookup::{
    ReviewReader, SEES_OR_RUNS_REVIEWS, owned_review_for_update,
};

/// Which review, and what is suggested beside which holders.
pub struct SuggestRequest {
    /// The access assessment receiving these suggested decisions.
    pub review_id: AccessReviewId,
    /// One suggestion per holder.
    pub suggestions: Vec<HolderSuggestion>,
}

/// The ports [`SuggestUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SuggestPorts {
    /// Locks the review, reads its items and saves their suggestions.
    pub review_store: Arc<dyn AccessReviewStore>,
    /// Who the caller is in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Puts suggestions beside holders of an open review.
pub struct SuggestUseCase {
    ports: SuggestPorts,
}

impl SuggestUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SuggestPorts) -> Self {
        Self { ports }
    }

    /// The review's items of the holders `suggestions` name, read in one
    /// go; a holder it does not list is left out, for the review to refuse.
    async fn items_of(
        &self,
        tenant: &ScopedTenant,
        review: &AccessReview<ResolvedTenant>,
        suggestions: &[HolderSuggestion],
    ) -> Result<Vec<ReviewItem>, AppError> {
        let holders: Vec<PrincipalRef> = suggestions
            .iter()
            .map(|suggestion| suggestion.holder)
            .collect();
        self.ports
            .review_store
            .find_items(tenant, review, &holders)
            .await
            .or_internal()
    }
}

impl Command for SuggestUseCase {
    type Caller = CallerContext;
    type Input = SuggestRequest;
    type Output = Result<AccessReview<ResolvedTenant>, AppError>;

    /// Puts each suggestion beside its holder and saves them together.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `NotFound` for a missing review or a caller neither reviewing nor allowed to view/assign roles.
    /// - `AppError::Forbidden` without role assignment rights or for suggestions about one's own access.
    /// - `AppError::Conflict` for a closed/overdue review; `Domain` for no/excess suggestions or duplicate/unlisted holders.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SuggestRequest,
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
                besides: SEES_OR_RUNS_REVIEWS,
            },
        )
        .await?;
        let mut items = self
            .items_of(&tenant, &review, &request.suggestions)
            .await?;
        review
            .suggest(&mut items, request.suggestions, &authority)
            .map_err(AppError::from_domain)?;

        store
            .save_suggestions(&tenant, &items)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), review.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(review)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_review::{
        ReviewChoice, ReviewScope, ReviewSuggestion,
    };
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{RoleId, Text, UserId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::authorization::{FakeAccessReviewStore, open_review_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A review of Bob, Lee and the caller, due next week, with Carol
    /// deciding.
    fn review() -> (
        Arc<FakeAccessReviewStore>,
        AccessReviewId,
        [PrincipalRef; 3],
    ) {
        let holders = [
            PrincipalRef::User(UserId::new()),
            PrincipalRef::User(UserId::new()),
            PrincipalRef::User(test_caller_id()),
        ];
        let review = open_review_of(
            ReviewScope::Role(RoleId::new()),
            &holders,
            "carol@acme.test",
            clock::now() + Duration::days(7),
        );
        let id = *review.id();
        let store = FakeAccessReviewStore::holding(test_ctx().tenant_id(), [review]);
        let header = store.stored(test_ctx().tenant_id(), &id).unwrap();
        store.seed_items(test_ctx().tenant_id(), &header, &holders);
        (Arc::new(store), id, holders)
    }

    /// The right to assign roles, which runs reviews.
    const RUNS_REVIEWS: SystemPermission = SystemPermission::Roles(RoleAction::Assign);

    /// The caller suggests `suggestions` while holding `rights`.
    fn suggest(
        store: &Arc<FakeAccessReviewStore>,
        sink: &Arc<FakeEventDispatcher>,
        rights: &[SystemPermission],
        request: SuggestRequest,
    ) -> Result<AccessReview<ResolvedTenant>, AppError> {
        let ports = SuggestPorts {
            review_store: store.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(rights)),
        };
        block_on(SuggestUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            request,
        ))
    }

    /// A suggestion for `holder`.
    fn removing(holder: PrincipalRef) -> HolderSuggestion {
        HolderSuggestion {
            holder,
            choice: ReviewChoice::Remove,
            reason: Text::new("reason", "no Finance app since June").unwrap(),
        }
    }

    /// The suggestion saved beside `holder`.
    fn saved_for(
        store: &Arc<FakeAccessReviewStore>,
        id: AccessReviewId,
        holder: PrincipalRef,
    ) -> ReviewSuggestion {
        store
            .stored_items(test_ctx().tenant_id(), &id)
            .into_iter()
            .find(|item| *item.holder() == holder)
            .map(|item| item.suggestion().clone())
            .unwrap()
    }

    /// Ann, who may assign roles, suggests removing Bob. The suggestion is
    /// saved beside Bob alone, and one record is written.
    #[test]
    fn a_suggestion_is_saved_beside_its_holder_and_recorded() {
        let (store, id, [bob, lee, _]) = review();
        let sink = Arc::new(FakeEventDispatcher::new());

        suggest(
            &store,
            &sink,
            &[RUNS_REVIEWS],
            SuggestRequest {
                review_id: id,
                suggestions: vec![removing(bob)],
            },
        )
        .unwrap();

        assert!(matches!(
            saved_for(&store, id, bob),
            ReviewSuggestion::Made {
                choice: ReviewChoice::Remove,
                ..
            }
        ));
        assert_eq!(saved_for(&store, id, lee), ReviewSuggestion::Nothing);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_review_suggested"]
        );
    }

    /// Suggestions require assignment rights and cannot concern the caller's
    /// own access. Both refusals leave suggestions absent and record nothing.
    #[test]
    fn suggesting_needs_the_right_and_never_about_oneself() {
        let (store, id, [bob, _, caller]) = review();
        let sink = Arc::new(FakeEventDispatcher::new());

        let by_viewer = suggest(
            &store,
            &sink,
            &[SystemPermission::Roles(RoleAction::View)],
            SuggestRequest {
                review_id: id,
                suggestions: vec![removing(bob)],
            },
        );
        let own = suggest(
            &store,
            &sink,
            &[RUNS_REVIEWS],
            SuggestRequest {
                review_id: id,
                suggestions: vec![removing(caller)],
            },
        );

        assert!(matches!(by_viewer, Err(AppError::Forbidden(_))));
        assert!(matches!(own, Err(AppError::Forbidden(_))));
        assert_eq!(saved_for(&store, id, bob), ReviewSuggestion::Nothing);
        assert_eq!(saved_for(&store, id, caller), ReviewSuggestion::Nothing);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Including an unlisted holder rejects the entire suggestion batch,
    /// leaving the listed holder without a suggestion too.
    #[test]
    fn a_holder_the_review_does_not_list_refuses_every_suggestion() {
        let (store, id, [bob, _, _]) = review();
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = suggest(
            &store,
            &sink,
            &[RUNS_REVIEWS],
            SuggestRequest {
                review_id: id,
                suggestions: vec![removing(bob), removing(PrincipalRef::User(UserId::new()))],
            },
        );

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(saved_for(&store, id, bob), ReviewSuggestion::Nothing);
    }
}
