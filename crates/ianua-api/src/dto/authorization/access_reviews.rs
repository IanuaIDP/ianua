//! Access review bodies: a review of who keeps a role or a place in a
//! group, the holders it lists with what was decided and suggested for
//! each, and a reviewer's choice.

use ianua_app::use_cases::authorization::access_reviews::{DecideRequest, StartRequest};
use ianua_domain::domains::authorization::access_review::{
    AccessReview, AccessReviewStatus, AccessReviewVerdict, ReviewChoice, ReviewItem, ReviewScope,
    ReviewSuggestion, Unanswered,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{AccessReviewId, GroupId, Label, RoleId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::principal::{OwnerDto, PrincipalKind};
use crate::error::ApiError;

/// What a review covers: the holders of a role, or the members of a group.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ReviewScopeBody {
    /// The role's holders.
    Role {
        /// The role's id.
        id: Uuid,
    },
    /// The group's members.
    Group {
        /// The group's id.
        id: Uuid,
    },
}

impl From<ReviewScopeBody> for ReviewScope {
    fn from(body: ReviewScopeBody) -> Self {
        match body {
            ReviewScopeBody::Role { id } => Self::Role(RoleId::from_uuid(id)),
            ReviewScopeBody::Group { id } => Self::Group(GroupId::from_uuid(id)),
        }
    }
}

impl From<ReviewScope> for ReviewScopeBody {
    fn from(scope: ReviewScope) -> Self {
        match scope {
            ReviewScope::Role(role) => Self::Role {
                id: *role.as_uuid(),
            },
            ReviewScope::Group(group) => Self::Group {
                id: *group.as_uuid(),
            },
        }
    }
}

/// What happens at the due date to a holder nobody decided on.
#[derive(Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UnansweredBody {
    /// They keep their access.
    KeepAccess,
    /// They lose it.
    RemoveAccess,
}

impl From<UnansweredBody> for Unanswered {
    fn from(body: UnansweredBody) -> Self {
        match body {
            UnansweredBody::KeepAccess => Self::KeepAccess,
            UnansweredBody::RemoveAccess => Self::RemoveAccess,
        }
    }
}

impl From<Unanswered> for UnansweredBody {
    fn from(unanswered: Unanswered) -> Self {
        match unanswered {
            Unanswered::KeepAccess => Self::KeepAccess,
            Unanswered::RemoveAccess => Self::RemoveAccess,
        }
    }
}

/// Selects the access to review, its reviewers and the deadline outcome.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct StartAccessReviewBody {
    /// What the review is called, such as `Q4 admins`.
    pub name: String,
    /// The role or group it covers.
    pub scope: ReviewScopeBody,
    /// The tenant users who decide, at most 20.
    pub reviewer_ids: Vec<Uuid>,
    /// When it is due (RFC 3339): undecided holders are then settled by
    /// `unanswered`.
    #[serde(with = "time::serde::rfc3339")]
    pub due: OffsetDateTime,
    /// What happens to a holder nobody decided on by the due date.
    pub unanswered: UnansweredBody,
}

impl TryFrom<StartAccessReviewBody> for StartRequest {
    type Error = ApiError;

    fn try_from(body: StartAccessReviewBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            scope: body.scope.into(),
            reviewers: body
                .reviewer_ids
                .into_iter()
                .map(UserId::from_uuid)
                .collect(),
            due: body.due,
            unanswered: body.unanswered.into(),
        })
    }
}

/// A reviewer's choice for a holder.
#[derive(Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReviewChoiceBody {
    /// The holder keeps the access.
    Keep,
    /// The holder loses it when the review completes.
    Remove,
}

impl From<ReviewChoiceBody> for ReviewChoice {
    fn from(body: ReviewChoiceBody) -> Self {
        match body {
            ReviewChoiceBody::Keep => Self::Keep,
            ReviewChoiceBody::Remove => Self::Remove,
        }
    }
}

impl From<ReviewChoice> for ReviewChoiceBody {
    fn from(choice: ReviewChoice) -> Self {
        match choice {
            ReviewChoice::Keep => Self::Keep,
            ReviewChoice::Remove => Self::Remove,
        }
    }
}

/// A reviewer's decision on one holder.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DecideAccessReviewBody {
    /// Distinguishes a user, organization member, agent or consumer by UUID.
    pub holder_kind: PrincipalKind,
    /// The holder's id.
    pub holder_id: Uuid,
    /// Whether they keep the access.
    pub choice: ReviewChoiceBody,
}

impl DecideAccessReviewBody {
    /// Deciding on the holder this body names in review `review_id`.
    #[must_use]
    pub(crate) fn request(&self, review_id: AccessReviewId) -> DecideRequest {
        DecideRequest {
            review_id,
            holder: self.holder_kind.with_id(self.holder_id),
            choice: self.choice.into(),
        }
    }
}

/// Where a review stands.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessReviewStatusResponse {
    /// Reviewers are still deciding.
    Open,
    /// Done, and what it decided carried out.
    Completed,
    /// Called off; nobody's access changed.
    Cancelled,
}

impl From<AccessReviewStatus> for AccessReviewStatusResponse {
    fn from(status: AccessReviewStatus) -> Self {
        match status {
            AccessReviewStatus::Open => Self::Open,
            AccessReviewStatus::Completed => Self::Completed,
            AccessReviewStatus::Cancelled => Self::Cancelled,
        }
    }
}

/// One holder a review lists, and what was decided for them.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewItemResponse {
    /// The immutable position within this review's holder snapshot.
    pub position: u64,
    /// The principal whose access the reviewer must keep or remove.
    pub holder: OwnerDto,
    /// `keep` or `remove`, absent while nobody decided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choice: Option<ReviewChoiceBody>,
    /// The reviewer who decided, absent while nobody did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<OwnerDto>,
    /// What is suggested beside the holder, absent while nothing is. The
    /// reviewer still decides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<ReviewSuggestionResponse>,
}

/// Keep or remove, suggested beside a holder, and why.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewSuggestionResponse {
    /// `keep` or `remove`.
    pub choice: ReviewChoiceBody,
    /// Why, in a sentence the reviewer reads.
    pub reason: String,
}

impl ReviewSuggestionResponse {
    /// The suggestion beside a holder, when there is one.
    fn of(suggestion: &ReviewSuggestion) -> Option<Self> {
        match suggestion {
            ReviewSuggestion::Nothing => None,
            ReviewSuggestion::Made { choice, reason } => Some(Self {
                choice: ReviewChoiceBody::from(*choice),
                reason: reason.as_str().to_owned(),
            }),
        }
    }
}

impl From<&ReviewItem> for ReviewItemResponse {
    fn from(item: &ReviewItem) -> Self {
        let (choice, decided_by) = match item.verdict() {
            AccessReviewVerdict::Pending => (None, None),
            AccessReviewVerdict::Decided { choice, reviewer } => (
                Some(ReviewChoiceBody::from(*choice)),
                Some(OwnerDto::from_human(reviewer)),
            ),
        };
        Self {
            position: item.position(),
            holder: OwnerDto::from_principal(item.holder()),
            choice,
            decided_by,
            suggestion: ReviewSuggestionResponse::of(item.suggestion()),
        }
    }
}

/// The scope, reviewers and progress of an access recertification.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AccessReviewResponse {
    /// The review's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: AccessReviewId,
    /// What it is called.
    pub name: String,
    /// The role or group it covers.
    pub scope: ReviewScopeBody,
    /// The accounts that decide.
    pub reviewers: Vec<OwnerDto>,
    /// When it is due.
    #[serde(with = "time::serde::rfc3339")]
    pub due: OffsetDateTime,
    /// What happens to an undecided holder at the due date.
    pub unanswered: UnansweredBody,
    /// Where it stands.
    pub status: AccessReviewStatusResponse,
    /// When it started.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// The number of holders captured when the review started.
    pub holder_count: u64,
    /// The number of holders without an explicit decision.
    pub pending_count: u64,
    /// The number explicitly marked for removal, excluding unanswered holders.
    pub remove_count: u64,
}

impl From<&AccessReview<ResolvedTenant>> for AccessReviewResponse {
    fn from(review: &AccessReview<ResolvedTenant>) -> Self {
        Self {
            id: *review.id(),
            name: review.name().as_str().to_owned(),
            scope: review.scope().into(),
            reviewers: review
                .reviewers()
                .iter()
                .map(OwnerDto::from_human)
                .collect(),
            due: review.due(),
            unanswered: review.unanswered().into(),
            status: review.status().into(),
            started_at: review.started_at(),
            holder_count: review.holder_count(),
            pending_count: review.pending_count(),
            remove_count: review.remove_count(),
        }
    }
}
