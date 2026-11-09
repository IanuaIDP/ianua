//! Suggestions beside a review's holders: keep or remove, and why, for the
//! reviewers to follow or not.
//!
//! Ann runs reviews. When the Finance review opens, her workflow reads what
//! each holder really used and suggests removing Bob, "no Finance app opened
//! since June", and keeping Lee. Carol, the reviewer, sees both beside their
//! names and still decides each one herself.

use crate::domains::authorization::access_review::{
    AccessReview, ReviewChoice, ReviewItem, ReviewSuggestion,
};
use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::access_reviews::AccessReviewSuggested;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{PrincipalRef, Text};

/// The most holders one call puts a suggestion beside.
pub(crate) const MAX_SUGGESTIONS: usize = 500;

/// What is suggested for one holder of a review's snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderSuggestion {
    /// The holder it is beside.
    pub holder: PrincipalRef,
    /// Keep or remove.
    pub choice: ReviewChoice,
    /// Why, in a sentence the reviewer reads.
    pub reason: Text,
}

/// Puts each of `suggestions` beside its holder's item in `review`, once
/// every one is found to fit, so either every item gets its suggestion or
/// none does; the record of what was suggested comes back.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] for a suggestion about `by`'s own access.
/// - [`DomainError::Validation`] for no suggestion or more than
///   `MAX_SUGGESTIONS`, a holder named twice, or a holder `items` does
///   not hold.
/// - [`DomainError::Infrastructure`] for an item of another review.
pub(super) fn put_beside<T: TenantScope>(
    review: &AccessReview<T>,
    items: &mut [ReviewItem],
    suggestions: Vec<HolderSuggestion>,
    by: &TenantAuthority,
) -> Result<AccessReviewSuggested, DomainError> {
    ensure_suggestions(&suggestions, by)?;
    for suggestion in &suggestions {
        item_of(items, &suggestion.holder)?.ensure_review(review)?;
    }
    let made = AccessReviewSuggested {
        review_id: *review.id(),
        suggested: suggestions.len(),
        removed: suggestions
            .iter()
            .filter(|suggestion| suggestion.choice == ReviewChoice::Remove)
            .count(),
        occurred_at: crate::shared::clock::now(),
    };
    for suggestion in suggestions {
        let Some(item) = items
            .iter_mut()
            .find(|item| *item.holder() == suggestion.holder)
        else {
            continue;
        };
        item.suggest(ReviewSuggestion::Made {
            choice: suggestion.choice,
            reason: suggestion.reason,
        });
    }
    Ok(made)
}

/// The item of `holder` among `items`.
fn item_of<'a>(
    items: &'a [ReviewItem],
    holder: &PrincipalRef,
) -> Result<&'a ReviewItem, DomainError> {
    items
        .iter()
        .find(|item| item.holder() == holder)
        .ok_or_else(|| {
            DomainError::invalid(message!(
                "authorization-a-suggestion-names-someone-the-review",
                "a suggestion names someone the review does not list"
            ))
        })
}

/// Refuses no suggestion or too many, a holder named twice, and a
/// suggestion about the suggester's own access.
fn ensure_suggestions(
    suggestions: &[HolderSuggestion],
    by: &TenantAuthority,
) -> Result<(), DomainError> {
    validate_count("suggestions", suggestions.len(), 1..=MAX_SUGGESTIONS)?;
    if first_repeat(suggestions.iter().map(|suggestion| suggestion.holder)).is_some() {
        return Err(DomainError::invalid(message!(
            "authorization-each-holder-is-suggested-for-once",
            "each holder is suggested for once"
        )));
    }
    let own = by.who().principal();
    if suggestions
        .iter()
        .any(|suggestion| suggestion.holder == own)
    {
        return Err(DomainError::forbidden(message!(
            "authorization-nobody-suggests-whether-they-keep-their",
            "nobody suggests whether they keep their own access"
        )));
    }
    Ok(())
}
