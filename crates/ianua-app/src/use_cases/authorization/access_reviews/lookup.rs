//! Loading the review a caller names, the people it names as reviewers,
//! and the role or group it covers, which the access review use cases
//! start with.

use std::collections::HashMap;

use ianua_domain::domains::authorization::access_review::{AccessReview, ReviewItem, ReviewScope};
use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{
    AccessReviewId, EventLabel, Human, HumanAccount, PersonKey, PrincipalRef, UserId,
};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::{AccessReviewStore, GroupStore, RoleStore};
use crate::ports::identity::UserStore;
use crate::services::lookup::existing_role;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authorization::lookup::existing_group;

/// Locks the tenant's review `id` for a mutation after authority was checked.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such review.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_review(
    store: &dyn AccessReviewStore,
    tenant: &ScopedTenant,
    id: &AccessReviewId,
) -> Result<AccessReview<ResolvedTenant>, AppError> {
    store
        .hold(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authorization-access-review-not-found",
            "access review not found"
        ))
}

/// The rights that let someone who is not one of a review's reviewers see
/// it: viewing roles.
pub(super) const SEES_REVIEWS: &[SystemPermission] = &[SystemPermission::Roles(RoleAction::View)];

/// The rights that let someone who is not one of a review's reviewers see
/// it or complete it: viewing roles, or assigning them.
pub(super) const SEES_OR_RUNS_REVIEWS: &[SystemPermission] = &[
    SystemPermission::Roles(RoleAction::View),
    SystemPermission::Roles(RoleAction::Assign),
];

/// Who a review is looked up for, and the rights that let them reach it
/// when they are not one of its reviewers.
pub(super) struct ReviewReader<'a> {
    /// What the caller holds.
    pub(super) authority: &'a TenantAuthority,
    /// Any of these lets a caller who does not review it reach it.
    pub(super) besides: &'a [SystemPermission],
}

impl ReviewReader<'_> {
    /// Whether the reader reaches `review`.
    fn reaches(&self, review: &AccessReview<ResolvedTenant>) -> bool {
        review.is_reviewed_by(self.authority.who())
            || self
                .besides
                .iter()
                .any(|right| self.authority.holds(*right))
    }
}

/// The tenant's review `id`, read as missing unless `reader` reaches it,
/// so a caller cannot tell a review they may not act on from one that does
/// not exist.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such review, or `reader`
///   does not reach it.
/// - `AppError::Internal` on storage failure.
pub(super) async fn owned_review(
    store: &dyn AccessReviewStore,
    tenant: &ScopedTenant,
    id: &AccessReviewId,
    reader: ReviewReader<'_>,
) -> Result<AccessReview<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .filter(|review| reader.reaches(review))
        .or_not_found(message!(
            "authorization-access-review-not-found",
            "access review not found"
        ))
}

/// Locks an existing header before a mutation, preserving visibility refusal.
pub(super) async fn owned_review_for_update(
    store: &dyn AccessReviewStore,
    tenant: &ScopedTenant,
    id: &AccessReviewId,
    reader: ReviewReader<'_>,
) -> Result<AccessReview<ResolvedTenant>, AppError> {
    store
        .hold(tenant, id)
        .await
        .or_internal()?
        .filter(|review| reader.reaches(review))
        .or_not_found(message!(
            "authorization-access-review-not-found",
            "access review not found"
        ))
}

/// The review's item for `holder`.
///
/// # Errors
///
/// - `AppError::NotFound` if the review has no item for `holder`.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_item(
    store: &dyn AccessReviewStore,
    tenant: &ScopedTenant,
    review: &AccessReview<ResolvedTenant>,
    holder: &PrincipalRef,
) -> Result<ReviewItem, AppError> {
    store
        .find_item(tenant, review, holder)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authorization-review-holder-not-found",
            "review holder not found"
        ))
}

/// The people `users` are, each through their account in the tenant.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such user.
/// - `AppError::Internal` on storage failure.
pub(super) async fn reviewers_named(
    store: &dyn UserStore,
    tenant: &ScopedTenant,
    users: &[UserId],
) -> Result<Vec<Human>, AppError> {
    if users.is_empty() {
        return Ok(Vec::new());
    }
    let found: HashMap<_, _> = store
        .find_by_ids(tenant, users)
        .await
        .or_internal()?
        .into_iter()
        .map(|user| (*user.id(), PersonKey::of(user.email())))
        .collect();
    users
        .iter()
        .map(|id| {
            let person = found
                .get(id)
                .or_not_found(message!("app-user-not-found", "user not found"))?;
            Ok(Human::new(HumanAccount::User(*id), person.clone()))
        })
        .collect()
}

/// How the audit trail names the role or group `scope` covers.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such role or group.
/// - `AppError::Internal` on storage failure.
pub(super) async fn scope_label(
    roles: &dyn RoleStore,
    groups: &dyn GroupStore,
    tenant: &ScopedTenant,
    scope: ReviewScope,
) -> Result<EventLabel, AppError> {
    let name = match scope {
        ReviewScope::Role(id) => existing_role(roles, tenant, &id).await?.name().clone(),
        ReviewScope::Group(id) => existing_group(groups, tenant, &id).await?.name().clone(),
    };
    Ok(EventLabel::of(name.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{block_on, test_ctx};

    /// Reviewers are resolved in one read, keeping requested order and
    /// repetitions so the domain can still refuse duplicate reviewers.
    #[test]
    fn reviewers_share_one_read_and_keep_the_requested_order() {
        let ann = UserId::new();
        let bob = UserId::new();
        let store = FakeUserStore::with_user(ann, "ann@acme.test");
        store.add_active_user(bob, "bob@acme.test");

        let found = block_on(reviewers_named(
            &store,
            &test_ctx().tenant(),
            &[bob, ann, bob],
        ))
        .unwrap();

        assert_eq!(
            found.iter().map(Human::account).collect::<Vec<_>>(),
            [
                HumanAccount::User(bob),
                HumanAccount::User(ann),
                HumanAccount::User(bob)
            ]
        );
        assert_eq!(store.id_reads().len(), 1);
    }

    /// One missing reviewer makes the whole lookup fail as not found,
    /// even when another requested reviewer exists.
    #[test]
    fn a_missing_reviewer_refuses_the_whole_lookup() {
        let ann = UserId::new();
        let store = FakeUserStore::with_user(ann, "ann@acme.test");

        let result = block_on(reviewers_named(
            &store,
            &test_ctx().tenant(),
            &[ann, UserId::new()],
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
