//! An access review as its rows hold it, the review and one row per
//! holder: read back into the aggregate, and written out from it.

use ianua_domain::domains::authorization::access_review::{
    AccessReview, AccessReviewRow, AccessReviewVerdict, ReviewItem, ReviewItemRow, ReviewScope,
    ReviewSuggestion,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AccessReviewId, GroupId, Human, Label, RoleId, Text};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{
    HumanColumns, human_from, maybe_human_from, principal_from,
};
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const ACCESS_REVIEW: Stored = Stored("access review");

/// The word of a review of a role's holders.
const ROLE: &str = "role";

/// The word of a review of a group's members.
const GROUP: &str = "group";

/// Only the stable position of a review selected by the overdue sweep.
pub(super) struct OverdueReviewRecord {
    /// The review to hydrate individually.
    pub(super) id: Uuid,
    /// The unchanged timestamp used by the parent cursor.
    pub(super) due: OffsetDateTime,
}

/// A review as it is read, without its holders. The store's checked
/// queries fill it.
pub(super) struct AccessReviewRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) scope: String,
    pub(super) scope_id: Uuid,
    pub(super) reviewer_kinds: Vec<String>,
    pub(super) reviewer_ids: Vec<Uuid>,
    pub(super) reviewer_persons: Vec<String>,
    pub(super) due: OffsetDateTime,
    pub(super) unanswered: String,
    pub(super) status: String,
    pub(super) started_at: OffsetDateTime,
    pub(super) holder_count: i64,
    pub(super) pending_count: i64,
    pub(super) remove_count: i64,
}

/// One holder of a review as it is read, and what was decided.
pub(super) struct ReviewItemRecord {
    pub(super) review_id: Uuid,
    pub(super) position: i64,
    pub(super) holder_kind: String,
    pub(super) holder_id: Uuid,
    pub(super) choice: Option<String>,
    pub(super) reviewer_kind: Option<String>,
    pub(super) reviewer_id: Option<Uuid>,
    pub(super) reviewer_person: Option<String>,
    pub(super) suggested_choice: Option<String>,
    pub(super) suggested_reason: Option<String>,
}

impl AccessReviewRecord {
    /// The review header rebuilt without materializing its holder snapshot.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the rows break a rule the review
    /// keeps.
    pub(super) fn into_review(self) -> Result<AccessReview<ResolvedTenant>, DomainError> {
        AccessReview::reconstitute(AccessReviewRow {
            id: AccessReviewId::from_uuid(self.id),
            name: ACCESS_REVIEW.value("name", Label::new("name", self.name))?,
            scope: scope_from(&self.scope, self.scope_id)?,
            reviewers: reviewers_from(
                &self.reviewer_kinds,
                self.reviewer_ids,
                self.reviewer_persons,
            )?,
            due: self.due,
            unanswered: ACCESS_REVIEW.choice(&self.unanswered)?,
            holder_count: unsigned(self.holder_count, "negative holder count")?,
            pending_count: unsigned(self.pending_count, "negative pending count")?,
            remove_count: unsigned(self.remove_count, "negative removal count")?,
            status: ACCESS_REVIEW.choice(&self.status)?,
            started_at: self.started_at,
        })
    }
}

impl ReviewItemRecord {
    /// Rebuilds one holder against its owning header and named reviewers.
    ///
    /// # Errors
    ///
    /// Returns infrastructure failure for corrupt identity, position or verdict.
    pub(super) fn into_item(
        self,
        review: &AccessReview<ResolvedTenant>,
    ) -> Result<ReviewItem, DomainError> {
        let reviewer = maybe_human_from(
            ACCESS_REVIEW,
            self.reviewer_kind,
            self.reviewer_id,
            self.reviewer_person,
        )?;
        ReviewItem::reconstitute(ReviewItemRow {
            review,
            review_id: AccessReviewId::from_uuid(self.review_id),
            position: unsigned(self.position, "negative holder position")?,
            holder: principal_from(ACCESS_REVIEW, &self.holder_kind, self.holder_id)?,
            verdict: verdict_from(self.choice, reviewer)?,
            suggestion: suggestion_from(self.suggested_choice, self.suggested_reason)?,
        })
    }
}

/// A suggestion is either entirely absent or has both a choice and reason.
fn suggestion_from(
    choice: Option<String>,
    reason: Option<String>,
) -> Result<ReviewSuggestion, DomainError> {
    match (choice, reason) {
        (None, None) => Ok(ReviewSuggestion::Nothing),
        (Some(choice), Some(reason)) => Ok(ReviewSuggestion::Made {
            choice: ACCESS_REVIEW.choice(&choice)?,
            reason: ACCESS_REVIEW.value("suggested reason", Text::new("reason", reason))?,
        }),
        _ => Err(DomainError::corrupt_row(
            ACCESS_REVIEW.0,
            "a suggestion with no choice or no reason",
        )),
    }
}

/// Rejects negative stored counters and positions before domain validation.
fn unsigned(value: i64, reason: &'static str) -> Result<u64, DomainError> {
    u64::try_from(value).map_err(|_| DomainError::corrupt_row(ACCESS_REVIEW.0, reason))
}

/// A decision is either entirely absent or has both a choice and reviewer.
fn verdict_from(
    choice: Option<String>,
    reviewer: Option<Human>,
) -> Result<AccessReviewVerdict, DomainError> {
    match (choice, reviewer) {
        (None, None) => Ok(AccessReviewVerdict::Pending),
        (Some(choice), Some(reviewer)) => Ok(AccessReviewVerdict::Decided {
            choice: ACCESS_REVIEW.choice(&choice)?,
            reviewer,
        }),
        _ => Err(DomainError::corrupt_row(
            ACCESS_REVIEW.0,
            "a decision with no choice or no reviewer",
        )),
    }
}

/// What a word and an id say a review covers.
fn scope_from(word: &str, id: Uuid) -> Result<ReviewScope, DomainError> {
    match word {
        ROLE => Ok(ReviewScope::Role(RoleId::from_uuid(id))),
        GROUP => Ok(ReviewScope::Group(GroupId::from_uuid(id))),
        _ => Err(DomainError::corrupt_row(
            ACCESS_REVIEW.0,
            "covers something unknown",
        )),
    }
}

/// The reviewers three lists hold, entry n of each being one reviewer.
fn reviewers_from(
    kinds: &[String],
    ids: Vec<Uuid>,
    persons: Vec<String>,
) -> Result<Vec<Human>, DomainError> {
    if kinds.len() != ids.len() || ids.len() != persons.len() {
        return Err(DomainError::corrupt_row(
            ACCESS_REVIEW.0,
            "half of a reviewer",
        ));
    }
    kinds
        .iter()
        .zip(ids)
        .zip(persons)
        .map(|((kind, id), person)| human_from(ACCESS_REVIEW, kind, id, person))
        .collect()
}

/// The bounded named reviewers stored in parallel header arrays.
pub(super) struct ReviewerColumns<'a> {
    pub(super) kinds: Vec<&'static str>,
    pub(super) ids: Vec<Uuid>,
    pub(super) persons: Vec<&'a str>,
}

impl<'a> ReviewerColumns<'a> {
    /// Preserves the named reviewer order across all three stored arrays.
    pub(super) fn of(reviewers: &'a [Human]) -> Self {
        let reviewers: Vec<HumanColumns<'a>> = reviewers.iter().map(HumanColumns::of).collect();
        Self {
            kinds: reviewers.iter().map(|reviewer| reviewer.kind).collect(),
            ids: reviewers.iter().map(|reviewer| reviewer.id).collect(),
            persons: reviewers.iter().map(|reviewer| reviewer.person).collect(),
        }
    }
}

/// The role or group whose direct holdings the snapshot captures.
pub(super) struct ScopeColumns {
    pub(super) kind: &'static str,
    pub(super) id: Uuid,
}

impl ScopeColumns {
    /// Retains the scope's typed identity when writing its discriminator.
    pub(super) fn of(scope: ReviewScope) -> Self {
        match scope {
            ReviewScope::Role(role) => Self {
                kind: ROLE,
                id: *role.as_uuid(),
            },
            ReviewScope::Group(group) => Self {
                kind: GROUP,
                id: *group.as_uuid(),
            },
        }
    }
}

/// One holder's decision, written without replacing any snapshot rows.
pub(super) struct DecisionColumns<'a> {
    pub(super) choice: Option<&'static str>,
    pub(super) reviewer_kind: Option<&'static str>,
    pub(super) reviewer_id: Option<Uuid>,
    pub(super) reviewer_person: Option<&'a str>,
}

impl<'a> DecisionColumns<'a> {
    /// Maps pending verdicts to nulls and decided verdicts to complete columns.
    pub(super) fn of(item: &'a ReviewItem) -> Self {
        let decided = match item.verdict() {
            AccessReviewVerdict::Pending => None,
            AccessReviewVerdict::Decided { choice, reviewer } => {
                Some((choice.word(), HumanColumns::of(reviewer)))
            }
        };
        Self {
            choice: decided.as_ref().map(|(choice, _)| *choice),
            reviewer_kind: decided.as_ref().map(|(_, reviewer)| reviewer.kind),
            reviewer_id: decided.as_ref().map(|(_, reviewer)| reviewer.id),
            reviewer_person: decided.as_ref().map(|(_, reviewer)| reviewer.person),
        }
    }
}

/// The suggestions beside several holders, column by column, for one
/// batched write.
pub(super) struct SuggestionColumns<'a> {
    pub(super) positions: Vec<i64>,
    pub(super) choices: Vec<&'static str>,
    pub(super) reasons: Vec<&'a str>,
}

impl<'a> SuggestionColumns<'a> {
    /// The columns of every item that carries a suggestion.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` for a position past what
    /// storage holds.
    pub(super) fn of(items: &'a [ReviewItem]) -> Result<Self, DomainError> {
        let mut columns = Self {
            positions: Vec::with_capacity(items.len()),
            choices: Vec::with_capacity(items.len()),
            reasons: Vec::with_capacity(items.len()),
        };
        for item in items {
            let ReviewSuggestion::Made { choice, reason } = item.suggestion() else {
                continue;
            };
            columns
                .positions
                .push(i64::try_from(item.position()).map_err(DomainError::infra)?);
            columns.choices.push(choice.word());
            columns.reasons.push(reason.as_str());
        }
        Ok(columns)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::authorization::open_review_of;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{PrincipalRef, UserId};
    use time::Duration;

    use super::*;

    /// A consistent header representing one separately stored pending holder.
    fn header() -> AccessReview<ResolvedTenant> {
        open_review_of(
            ReviewScope::Role(RoleId::new()),
            &[PrincipalRef::User(UserId::new())],
            "reviewer@example.test",
            clock::now() + Duration::days(7),
        )
    }

    /// A pending stored item belonging to the supplied header.
    fn item_record(review: &AccessReview<ResolvedTenant>) -> ReviewItemRecord {
        ReviewItemRecord {
            review_id: *review.id().as_uuid(),
            position: 1,
            holder_kind: "user".to_owned(),
            holder_id: *UserId::new().as_uuid(),
            choice: None,
            reviewer_kind: None,
            reviewer_id: None,
            reviewer_person: None,
            suggested_choice: None,
            suggested_reason: None,
        }
    }

    /// A suggestion without its reason is rejected as corrupt. A complete
    /// suggestion retains its position, choice and reason when written back.
    #[test]
    fn partial_suggestions_are_corrupt_and_whole_ones_read_back() {
        let review = header();
        let mut half = item_record(&review);
        half.suggested_choice = Some("remove".to_owned());
        let mut whole = item_record(&review);
        whole.suggested_choice = Some("remove".to_owned());
        whole.suggested_reason = Some("no Finance app since June".to_owned());

        let item = whole.into_item(&review).unwrap();

        assert!(matches!(
            half.into_item(&review),
            Err(DomainError::Infrastructure(_))
        ));
        let columns = SuggestionColumns::of(std::slice::from_ref(&item)).unwrap();
        assert_eq!(columns.positions, [1]);
        assert_eq!(columns.choices, ["remove"]);
        assert_eq!(columns.reasons, ["no Finance app since June"]);
    }

    /// Negative stored counts are rejected as corrupt, while zero and the
    /// largest signed count convert to their unsigned values.
    #[test]
    fn negative_stored_counts_are_corrupt() {
        assert!(matches!(
            unsigned(-1, "negative count"),
            Err(DomainError::Infrastructure(_))
        ));
        assert_eq!(unsigned(0, "negative count").unwrap(), 0);
        assert_eq!(
            unsigned(i64::MAX, "negative count").unwrap(),
            i64::MAX as u64
        );
    }

    /// Items with another review's ID or a position outside the snapshot are
    /// rejected as corrupt; the owning review accepts its valid item.
    #[test]
    fn item_rows_are_checked_against_their_own_header() {
        let review = header();
        assert!(item_record(&review).into_item(&review).is_ok());
        for position in [-1, 0, 2] {
            let mut row = item_record(&review);
            row.position = position;
            assert!(matches!(
                row.into_item(&review),
                Err(DomainError::Infrastructure(_))
            ));
        }
        let mut row = item_record(&review);
        row.review_id = *AccessReviewId::new().as_uuid();
        assert!(matches!(
            row.into_item(&review),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// A stored choice without a reviewer is rejected as corrupt. A pending
    /// verdict writes null choice and reviewer columns.
    #[test]
    fn partial_decisions_are_corrupt_and_pending_columns_are_empty() {
        let review = header();
        let item = item_record(&review).into_item(&review).unwrap();
        let columns = DecisionColumns::of(&item);
        assert!(columns.choice.is_none());
        assert!(columns.reviewer_kind.is_none());
        assert!(columns.reviewer_id.is_none());
        assert!(columns.reviewer_person.is_none());
        let mut row = item_record(&review);
        row.choice = Some("keep".to_owned());
        assert!(matches!(
            row.into_item(&review),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
