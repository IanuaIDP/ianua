//! Events about access reviews: started, suggested for, decided, completed
//! or called off.

use time::OffsetDateTime;

use crate::domains::authorization::access_review::{ReviewChoice, ReviewScope};
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{AccessReviewId, EventLabel, Label, PrincipalRef};

/// An access review was started.
#[derive(Debug)]
pub struct AccessReviewStarted {
    /// The snapshot whose holders now await reviewer decisions.
    pub(crate) review_id: AccessReviewId,
    /// What it is called.
    pub(crate) name: Label,
    /// What it covers.
    pub(crate) scope: ReviewScope,
    /// The covered role's or group's name, for the audit trail.
    pub(crate) scope_label: EventLabel,
    /// How many holders it lists.
    pub(crate) holder_count: u64,
    /// By when it is due.
    pub(crate) due: OffsetDateTime,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessReviewStarted => crate::types::event_type::AuthorizationEvent::AccessReviewStarted,
    fn payload(&self) -> EventData {
        let (key, covered) = scope_reference(self.scope, &self.scope_label);
        EventData::new()
            .field("review", self.review_id.to_string())
            .field("name", self.name.to_string())
            .reference(key, covered)
            .field("count", self.holder_count.to_string())
            .field("end", self.due.to_string())
    }
}

/// A reviewer decided whether one holder keeps their access.
#[derive(Debug)]
pub struct AccessReviewDecided {
    /// The snapshot containing the holder whose verdict changed.
    pub(crate) review_id: AccessReviewId,
    /// The holder decided on.
    pub(crate) holder: PrincipalRef,
    /// The holder's display label, for the audit trail.
    pub(crate) holder_label: EventLabel,
    /// What was decided.
    pub(crate) choice: ReviewChoice,
    /// When.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessReviewDecided => crate::types::event_type::AuthorizationEvent::AccessReviewDecided,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("review", self.review_id.to_string())
            .reference(
                "holder",
                Reference::new(
                    self.holder.ref_kind(),
                    self.holder.id().to_string(),
                    self.holder_label.as_str(),
                ),
            )
            .field("effect", self.choice.as_str())
    }
}

/// Suggestions were put beside holders of an access review, for its
/// reviewers to follow or not.
#[derive(Debug)]
pub struct AccessReviewSuggested {
    /// The snapshot receiving advice without changing holder verdicts.
    pub(crate) review_id: AccessReviewId,
    /// How many holders were given a suggestion.
    pub(crate) suggested: usize,
    /// How many of those it suggests removing.
    pub(crate) removed: usize,
    /// When.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessReviewSuggested => crate::types::event_type::AuthorizationEvent::AccessReviewSuggested,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("review", self.review_id.to_string())
            .field("count", self.suggested.to_string())
            .field("revoked_count", self.removed.to_string())
    }
}

/// An access review was completed: how many kept their access and how many
/// lose it.
#[derive(Debug)]
pub struct AccessReviewCompleted {
    /// The snapshot whose decisions now determine retained and removed access.
    pub(crate) review_id: AccessReviewId,
    /// How many lose their access.
    pub(crate) removed: u64,
    /// How many keep it.
    pub(crate) kept: u64,
    /// When it was completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessReviewCompleted => crate::types::event_type::AuthorizationEvent::AccessReviewCompleted,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("review", self.review_id.to_string())
            .field("revoked_count", self.removed.to_string())
            .field("remaining", self.kept.to_string())
    }
}

/// An access review was called off; nothing it decided takes effect.
#[derive(Debug)]
pub struct AccessReviewCancelled {
    /// The snapshot abandoned without applying its decisions.
    pub(crate) review_id: AccessReviewId,
    /// When it was called off.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccessReviewCancelled => crate::types::event_type::AuthorizationEvent::AccessReviewCancelled,
    fn payload(&self) -> EventData {
        EventData::new().field("review", self.review_id.to_string())
    }
}

/// The key and reference a review's scope is recorded under.
fn scope_reference(scope: ReviewScope, label: &EventLabel) -> (&'static str, Reference) {
    match scope {
        ReviewScope::Role(role) => (
            "role",
            Reference::new(RefKind::ROLE, role.to_string(), label.as_str()),
        ),
        ReviewScope::Group(group) => (
            "group",
            Reference::new(RefKind::GROUP, group.to_string(), label.as_str()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::event::DomainEventCore;

    /// A review completes with one removal and three kept. The record says
    /// both counts.
    #[test]
    fn a_completed_review_records_how_many_lose_and_keep_access() {
        let event = AccessReviewCompleted {
            review_id: AccessReviewId::new(),
            removed: 1,
            kept: 3,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("revoked_count"), Some("1"));
        assert_eq!(payload.get("remaining"), Some("3"));
    }
}
