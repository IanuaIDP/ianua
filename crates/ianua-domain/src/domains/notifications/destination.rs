//! Places outside the app an organization's notifications go to: a Slack
//! channel, a Teams channel or a webhook of its own.
//!
//! Acme wants its security alerts where its on-call team already looks.
//! Ann adds the team's Slack channel as a destination, for critical
//! authentication and organization alerts only. Each notification fanned
//! out to Acme is then also posted there, when the destination is active
//! and its filter covers the notification.
//!
//! Every change is made by a member holding the right to manage the
//! organization's notifications. Where alerts go decides who learns of an
//! attack first, so a plain member cannot point them elsewhere.

mod endpoint;

pub use endpoint::{
    DestinationEndpoint, DestinationEndpointRow, DestinationKind, EndpointDelivery,
};
use time::OffsetDateTime;

use crate::domains::notifications::category::NotificationCategory;
use crate::domains::notifications::events::{
    DestinationAdded, DestinationChanged, DestinationPaused, DestinationRemoved, DestinationResumed,
};
use crate::domains::notifications::severity::NotificationSeverity;
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::permission::{OrgNotificationAction, OrgPermission};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{EventLabel, Label, NotificationDestinationId, OrganizationId};

/// The right every change to a destination needs.
const MANAGES_NOTIFICATIONS: OrgPermission =
    OrgPermission::Notifications(OrgNotificationAction::Manage);

/// Which notifications a destination receives: those in its categories, at
/// or above its minimum severity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationFilter {
    categories: Vec<NotificationCategory>,
    minimum: NotificationSeverity,
}

impl DestinationFilter {
    /// Notifications in `categories` at `minimum` severity or above.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it names no category, more than
    ///   there are, or one category twice.
    pub fn new(
        categories: Vec<NotificationCategory>,
        minimum: NotificationSeverity,
    ) -> Result<Self, DomainError> {
        validate_count("categories", categories.len(), category_range())?;
        if first_repeat(categories.iter().copied()).is_some() {
            return Err(DomainError::invalid(message!(
                "notifications-a-destination-lists-each-category-once",
                "a destination lists each category once"
            )));
        }
        Ok(Self {
            categories,
            minimum,
        })
    }

    /// The categories it receives.
    #[must_use]
    pub fn categories(&self) -> &[NotificationCategory] {
        &self.categories
    }

    /// The least severity it receives.
    #[must_use]
    pub fn minimum(&self) -> NotificationSeverity {
        self.minimum
    }

    /// Whether a notification of `category` at `severity` passes.
    #[must_use]
    pub fn covers(&self, category: NotificationCategory, severity: NotificationSeverity) -> bool {
        severity >= self.minimum && self.categories.contains(&category)
    }
}

/// Whether a destination is being sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationState {
    /// Notifications are posted to it.
    Active,
    /// Nothing is posted to it until it is resumed.
    Paused,
}

impl DestinationState {
    /// The stable name storage carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
        }
    }

    /// The state with this stored name, if there is one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            _ => None,
        }
    }
}

/// What adding or reconfiguring a destination asks for.
#[derive(Debug, Clone)]
pub struct NewDestination {
    /// What the organization calls it, such as "On-call Slack".
    pub name: Label,
    /// Where it posts.
    pub endpoint: DestinationEndpoint,
    /// Which notifications it receives.
    pub filter: DestinationFilter,
}

/// A destination as storage holds it, read back through
/// [`NotificationDestination::reconstitute`].
pub struct NotificationDestinationRow {
    /// The destination.
    pub id: NotificationDestinationId,
    /// The organization that owns it.
    pub organization_id: OrganizationId,
    /// What it is called.
    pub name: Label,
    /// Where it posts.
    pub endpoint: DestinationEndpointRow,
    /// The categories it receives.
    pub categories: Vec<NotificationCategory>,
    /// The least severity it receives.
    pub minimum_severity: NotificationSeverity,
    /// Whether it is being sent to.
    pub state: DestinationState,
    /// When it was added.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A place outside the app one organization's notifications go to.
#[derive(Debug, Clone)]
pub struct NotificationDestination {
    id: NotificationDestinationId,
    organization_id: OrganizationId,
    name: Label,
    endpoint: DestinationEndpoint,
    filter: DestinationFilter,
    state: DestinationState,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl NotificationDestination {
    /// Adds `new` as the active destination `id` of `organization_id`, as
    /// `by` decides. The id is chosen before, so the endpoint can be sealed
    /// for it. Raises `notifications.destination_added`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not manage the
    ///   organization's notifications.
    pub fn add(
        id: NotificationDestinationId,
        organization_id: OrganizationId,
        new: NewDestination,
        by: &OrgControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(&organization_id, MANAGES_NOTIFICATIONS)?;
        let now = crate::shared::clock::now();
        let mut destination = Self {
            id,
            organization_id,
            name: new.name,
            endpoint: new.endpoint,
            filter: new.filter,
            state: DestinationState::Active,
            created_at: now,
            updated_at: now,
            raised: RaisedEvents::default(),
        };
        destination.raised.raise_organization(DestinationAdded {
            organization_id,
            destination_id: destination.id,
            destination_label: destination.label(),
            kind: destination.endpoint.kind(),
            occurred_at: now,
        });
        Ok(destination)
    }

    /// Rebuilds a destination from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row lists no category,
    ///   more than there are or one twice, or says it changed before it
    ///   was added.
    pub fn reconstitute(row: NotificationDestinationRow) -> Result<Self, DomainError> {
        RowCheck::of("notification destination")
            .holds(
                category_range().contains(&row.categories.len()),
                "a number of categories out of range",
            )
            .holds(
                first_repeat(row.categories.iter().copied()).is_none(),
                "a category listed twice",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was added",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            name: row.name,
            endpoint: DestinationEndpoint::from_row(row.endpoint),
            filter: DestinationFilter {
                categories: row.categories,
                minimum: row.minimum_severity,
            },
            state: row.state,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The destination.
    #[must_use]
    pub fn id(&self) -> &NotificationDestinationId {
        &self.id
    }

    /// The organization that owns it.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// What it is called.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Where it posts.
    #[must_use]
    pub fn endpoint(&self) -> &DestinationEndpoint {
        &self.endpoint
    }

    /// Which notifications it receives.
    #[must_use]
    pub fn filter(&self) -> &DestinationFilter {
        &self.filter
    }

    /// Whether it is being sent to.
    #[must_use]
    pub fn state(&self) -> DestinationState {
        self.state
    }

    /// When it was added.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether a notification of `category` at `severity` is posted here
    /// now: the destination is active and its filter covers it.
    #[must_use]
    pub fn receives(&self, category: NotificationCategory, severity: NotificationSeverity) -> bool {
        self.state == DestinationState::Active && self.filter.covers(category, severity)
    }

    /// Replaces its name, where it posts and what it receives with `new`, as
    /// `by` decides. Raises `notifications.destination_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not manage the
    ///   organization's notifications.
    pub fn reconfigure(
        &mut self,
        new: NewDestination,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, MANAGES_NOTIFICATIONS)?;
        self.name = new.name;
        self.endpoint = new.endpoint;
        self.filter = new.filter;
        self.touch();
        self.raised.raise_organization(DestinationChanged {
            organization_id: self.organization_id,
            destination_id: self.id,
            destination_label: self.label(),
            kind: self.endpoint.kind(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Stops posting to it until it is resumed, as `by` decides. Raises
    /// `notifications.destination_paused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not manage the
    ///   organization's notifications.
    /// - [`DomainError::InvalidTransition`] when it is already paused.
    pub fn pause(&mut self, by: &OrgControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, MANAGES_NOTIFICATIONS)?;
        self.move_to(DestinationState::Active, DestinationState::Paused)?;
        self.raised.raise_organization(DestinationPaused {
            organization_id: self.organization_id,
            destination_id: self.id,
            destination_label: self.label(),
            kind: self.endpoint.kind(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Posts to a paused destination again, as `by` decides. Raises
    /// `notifications.destination_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not manage the
    ///   organization's notifications.
    /// - [`DomainError::InvalidTransition`] when it is not paused.
    pub fn resume(&mut self, by: &OrgControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, MANAGES_NOTIFICATIONS)?;
        self.move_to(DestinationState::Paused, DestinationState::Active)?;
        self.raised.raise_organization(DestinationResumed {
            organization_id: self.organization_id,
            destination_id: self.id,
            destination_label: self.label(),
            kind: self.endpoint.kind(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Removes it, as `by` decides, once the caller deletes it. Raises
    /// `notifications.destination_removed`; the caller takes it after the
    /// delete.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not manage the
    ///   organization's notifications.
    pub fn remove(&mut self, by: &OrgControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, MANAGES_NOTIFICATIONS)?;
        self.raised.raise_organization(DestinationRemoved {
            organization_id: self.organization_id,
            destination_id: self.id,
            destination_label: self.label(),
            kind: self.endpoint.kind(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Moves from `from` to `to`, refusing when it is not at `from`.
    fn move_to(&mut self, from: DestinationState, to: DestinationState) -> Result<(), DomainError> {
        if self.state != from {
            return Err(DomainError::invalid_transition(message!(
                "notifications-the-destination-is-not",
                format!(
                    "the destination is {}, not {}",
                    self.state.as_str(),
                    from.as_str()
                )
            )));
        }
        self.state = to;
        self.touch();
        Ok(())
    }

    /// How a record names it.
    fn label(&self) -> EventLabel {
        EventLabel::of(self.name.as_str())
    }

    /// Bumps the `updated_at` timestamp.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

impl RaisesComplete for NotificationDestination {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// How many categories a filter may list: at least one, at most every one.
fn category_range() -> std::ops::RangeInclusive<usize> {
    1..=NotificationCategory::all().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::members::control::tests::{
        acting, founder, member_of, session_of,
    };
    use crate::domains::organization::members::org_user::OrgUser;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_complete_names;
    use crate::types::{PublicHttpsUrl, SealedSecret};

    /// What `f` gives back when `member` acts through a fresh session of
    /// their own.
    fn by<R>(member: &OrgUser, f: impl FnOnce(&OrgControl<'_>) -> R) -> R {
        let session = session_of(member);
        f(&acting(member, &session))
    }

    /// The on-call Slack channel, for critical authentication alerts.
    fn on_call() -> NewDestination {
        NewDestination {
            name: label("On-call Slack"),
            endpoint: DestinationEndpoint::slack(
                &PublicHttpsUrl::new("https://hooks.slack.com/services/T0/B0/x").unwrap(),
                SealedSecret::new("v1.c2xhY2s").unwrap(),
            )
            .unwrap(),
            filter: DestinationFilter::new(
                vec![NotificationCategory::Authentication],
                NotificationSeverity::Critical,
            )
            .unwrap(),
        }
    }

    /// The on-call channel added by `owner` to their organization.
    fn added_by(owner: &OrgUser) -> NotificationDestination {
        by(owner, |c| {
            NotificationDestination::add(
                NotificationDestinationId::new(),
                *owner.organization_id(),
                on_call(),
                c,
            )
        })
        .unwrap()
    }

    /// Ann, an owner, adds Acme's on-call Slack channel. It starts active
    /// and records that it was added.
    #[test]
    fn an_owner_adds_a_destination() {
        let ann = founder();

        let mut destination = added_by(&ann);

        assert_eq!(destination.state(), DestinationState::Active);
        assert_eq!(destination.organization_id(), ann.organization_id());
        assert_eq!(
            raised_complete_names(&mut destination),
            ["notifications.destination_added"]
        );
    }

    /// A plain member lacks notification-management authority and cannot
    /// add the organization's Slack destination.
    #[test]
    fn a_plain_member_adds_no_destination() {
        let ann = founder();
        let sam = member_of(&ann);

        let result = by(&sam, |c| {
            NotificationDestination::add(
                NotificationDestinationId::new(),
                *ann.organization_id(),
                on_call(),
                c,
            )
        });

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ownership in another organization does not permit adding a
    /// destination to Acme.
    #[test]
    fn an_owner_of_another_organization_adds_nothing_here() {
        let ann = founder();
        let mallory = founder();

        let result = by(&mallory, |c| {
            NotificationDestination::add(
                NotificationDestinationId::new(),
                *ann.organization_id(),
                on_call(),
                c,
            )
        });

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A plain member cannot reconfigure, pause or remove the on-call
    /// destination, which remains active after all three refusals.
    #[test]
    fn a_plain_member_changes_no_destination() {
        let ann = founder();
        let sam = member_of(&ann);
        let mut destination = added_by(&ann);

        let refused = [
            by(&sam, |c| destination.reconfigure(on_call(), c)),
            by(&sam, |c| destination.pause(c)),
            by(&sam, |c| destination.remove(c)),
        ];

        for result in refused {
            assert!(matches!(result, Err(DomainError::Forbidden(_))));
        }
        assert_eq!(destination.state(), DestinationState::Active);
    }

    /// A critical authentication alert reaches the on-call channel. A
    /// warning, or an alert of another category, does not.
    #[test]
    fn it_receives_only_what_its_filter_covers() {
        let destination = added_by(&founder());

        assert!(destination.receives(
            NotificationCategory::Authentication,
            NotificationSeverity::Critical
        ));
        assert!(!destination.receives(
            NotificationCategory::Authentication,
            NotificationSeverity::Warning
        ));
        assert!(!destination.receives(
            NotificationCategory::Branding,
            NotificationSeverity::Critical
        ));
    }

    /// Ann pauses the channel during maintenance. Nothing is posted until
    /// she resumes it.
    #[test]
    fn a_paused_destination_receives_nothing_until_resumed() {
        let ann = founder();
        let mut destination = added_by(&ann);

        by(&ann, |c| destination.pause(c)).unwrap();
        let while_paused = destination.receives(
            NotificationCategory::Authentication,
            NotificationSeverity::Critical,
        );
        by(&ann, |c| destination.resume(c)).unwrap();

        assert!(!while_paused);
        assert!(destination.receives(
            NotificationCategory::Authentication,
            NotificationSeverity::Critical
        ));
        assert_eq!(
            raised_complete_names(&mut destination),
            [
                "notifications.destination_added",
                "notifications.destination_paused",
                "notifications.destination_resumed",
            ]
        );
    }

    /// Pausing a paused destination, or resuming an active one, is refused.
    #[test]
    fn a_destination_moves_only_from_the_state_it_is_in() {
        let ann = founder();
        let mut destination = added_by(&ann);

        let resumed_while_active = by(&ann, |c| destination.resume(c));
        by(&ann, |c| destination.pause(c)).unwrap();
        let paused_twice = by(&ann, |c| destination.pause(c));

        assert!(matches!(
            resumed_while_active,
            Err(DomainError::InvalidTransition(_))
        ));
        assert!(matches!(
            paused_twice,
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// Ann renames the channel and widens it to warnings. The change is
    /// kept and recorded.
    #[test]
    fn an_owner_reconfigures_a_destination() {
        let ann = founder();
        let mut destination = added_by(&ann);
        let wider = NewDestination {
            name: label("Security Slack"),
            filter: DestinationFilter::new(
                vec![NotificationCategory::Authentication],
                NotificationSeverity::Warning,
            )
            .unwrap(),
            ..on_call()
        };

        by(&ann, |c| destination.reconfigure(wider, c)).unwrap();

        assert_eq!(destination.name().as_str(), "Security Slack");
        assert!(destination.receives(
            NotificationCategory::Authentication,
            NotificationSeverity::Warning
        ));
        assert!(
            raised_complete_names(&mut destination)
                .contains(&"notifications.destination_changed".to_owned())
        );
    }

    /// Ann removes the channel. The removal is recorded for the caller to
    /// take once it is deleted.
    #[test]
    fn an_owner_removes_a_destination() {
        let ann = founder();
        let mut destination = added_by(&ann);

        by(&ann, |c| destination.remove(c)).unwrap();

        assert!(
            raised_complete_names(&mut destination)
                .contains(&"notifications.destination_removed".to_owned())
        );
    }

    /// A filter with no category, or with one category twice, is refused.
    #[test]
    fn a_filter_lists_each_category_once_and_at_least_one() {
        let empty = DestinationFilter::new(Vec::new(), NotificationSeverity::Info);
        let doubled = DestinationFilter::new(
            vec![NotificationCategory::Crypto, NotificationCategory::Crypto],
            NotificationSeverity::Info,
        );

        assert!(matches!(empty, Err(DomainError::Validation(_))));
        assert!(matches!(doubled, Err(DomainError::Validation(_))));
    }

    /// The row a stored `destination` is read back from.
    fn row_of(destination: &NotificationDestination) -> NotificationDestinationRow {
        NotificationDestinationRow {
            id: destination.id,
            organization_id: destination.organization_id,
            name: destination.name.clone(),
            endpoint: DestinationEndpointRow::Slack {
                hook: SealedSecret::new("v1.c2xhY2s").unwrap(),
            },
            categories: destination.filter.categories.clone(),
            minimum_severity: destination.filter.minimum,
            state: destination.state,
            created_at: destination.created_at,
            updated_at: destination.updated_at,
        }
    }

    /// A destination saved and read back is the same destination.
    #[test]
    fn a_stored_destination_reads_back_as_it_was() {
        let destination = added_by(&founder());

        let read = NotificationDestination::reconstitute(row_of(&destination)).unwrap();

        assert_eq!(read.id(), destination.id());
        assert_eq!(read.filter(), destination.filter());
        assert_eq!(read.endpoint().kind(), DestinationKind::Slack);
    }

    /// A stored row with no category, a category twice, or changed before
    /// it was added is refused as corrupt, never repaired.
    #[test]
    fn a_row_breaking_its_rules_is_refused() {
        let destination = added_by(&founder());
        let empty = NotificationDestinationRow {
            categories: Vec::new(),
            ..row_of(&destination)
        };
        let doubled = NotificationDestinationRow {
            categories: vec![NotificationCategory::Crypto, NotificationCategory::Crypto],
            ..row_of(&destination)
        };
        let backwards = NotificationDestinationRow {
            updated_at: destination.created_at - time::Duration::seconds(1),
            ..row_of(&destination)
        };

        for row in [empty, doubled, backwards] {
            assert!(refused_as_corrupt(&NotificationDestination::reconstitute(
                row
            )));
        }
    }

    /// Each state's stored name reads back as the same state.
    #[test]
    fn a_state_parses_back_from_its_stored_name() {
        for state in [DestinationState::Active, DestinationState::Paused] {
            assert_eq!(DestinationState::parse(state.as_str()), Some(state));
        }
        assert_eq!(DestinationState::parse("deleted"), None);
    }
}
