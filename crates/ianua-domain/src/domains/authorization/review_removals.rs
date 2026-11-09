//! Who an overdue access review takes access from, once the platform
//! completes it.
//!
//! A review names its reviewers and a due date. Carol and Dan never got to
//! it, and the review said unanswered access goes. When it is past due the
//! platform completes it, and each holder it then names loses the role or
//! the group. Nobody signed in does this, so no one's rights are checked.
//! What makes it safe is that only the review itself hands out this list,
//! and a holding is taken away only when it is the one the list names.

use crate::domains::authorization::access_review::ReviewScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{AccessReviewId, PrincipalRef};

/// One bounded page of holders an authorized overdue review takes access from.
///
/// Only a completion authorized by [`AccessReview::complete_overdue`] makes
/// one, after checking each item's parent and contiguous snapshot position.
/// Its removals and all other pages settle in one transaction with the review.
///
/// [`AccessReview::complete_overdue`]: crate::domains::authorization::access_review::AccessReview::complete_overdue
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRemovals {
    review_id: AccessReviewId,
    scope: ReviewScope,
    holders: Vec<PrincipalRef>,
}

impl ReviewRemovals {
    /// The removals of `review_id`, which covers `scope`, from `holders`.
    pub(crate) fn of(
        review_id: AccessReviewId,
        scope: ReviewScope,
        holders: Vec<PrincipalRef>,
    ) -> Self {
        Self {
            review_id,
            scope,
            holders,
        }
    }

    /// The review that decided them.
    #[must_use]
    pub fn review_id(&self) -> &AccessReviewId {
        &self.review_id
    }

    /// What the review covers.
    #[must_use]
    pub fn scope(&self) -> ReviewScope {
        self.scope
    }

    /// Who loses it.
    #[must_use]
    pub fn holders(&self) -> &[PrincipalRef] {
        &self.holders
    }

    /// Refuses taking `covered` from `holder` when these removals do not
    /// name that holder, or the review covered something else.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the review covered another role or
    ///   group, or does not take access from `holder`.
    pub(crate) fn ensure_names(
        &self,
        holder: &PrincipalRef,
        covered: ReviewScope,
    ) -> Result<(), DomainError> {
        if self.scope != covered || !self.holders.contains(holder) {
            return Err(DomainError::forbidden(message!(
                "authorization-the-review-does-not-take-this",
                "the review does not take this access away"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GroupId, RoleId, UserId};

    /// A review authorizing removal of Bob's billing role cannot remove Ann's
    /// role or Bob's group membership; it permits only the named holding.
    #[test]
    fn only_the_holders_and_scope_named_are_taken() {
        let billing = ReviewScope::Role(RoleId::new());
        let bob = PrincipalRef::User(UserId::new());
        let ann = PrincipalRef::User(UserId::new());
        let removals = ReviewRemovals::of(AccessReviewId::new(), billing, vec![bob]);

        let bobs_role = removals.ensure_names(&bob, billing);
        let anns_role = removals.ensure_names(&ann, billing);
        let bobs_group = removals.ensure_names(&bob, ReviewScope::Group(GroupId::new()));

        assert!(bobs_role.is_ok());
        assert!(matches!(anns_role, Err(DomainError::Forbidden(_))));
        assert!(matches!(bobs_group, Err(DomainError::Forbidden(_))));
    }
}
