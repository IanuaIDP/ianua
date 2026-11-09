//! Events an aggregate raises while it changes, kept on the aggregate until
//! the change is saved.
//!
//! An aggregate records what happened at the moment it changes: pausing a
//! topic raises `TopicPaused` with the topic as it is then, a retention
//! change keeps the policy it replaced. The application saves the aggregate
//! and then takes the events out with [`Raises::take_events`], naming the
//! tenant it saved for. That tenant is stamped on every event, so a record
//! can never name a tenant other than the one the change was written to,
//! and the application never builds an event itself.
//!
//! A refused change raises nothing, and an aggregate that is dropped without
//! being saved drops what it raised, so nothing is recorded that did not
//! happen.
//!
//! Two kinds of aggregate raise events, and each has its list:
//!
//! - **A tenant aggregate** (`Topic<T>`, `User<T>`) does not hold its
//!   tenant. It keeps bodies in [`Raised<T>`], implements [`Raises`], and
//!   the tenant is stamped when the application takes them with
//!   `take_events(&tenant)`.
//! - **An aggregate that knows its scope** (an operator, an organization's
//!   aggregates, and the tenant itself, whose records name it) keeps whole
//!   events in `RaisedEvents`, implements [`RaisesComplete`], and the
//!   application takes them with `take_events()`.

use std::fmt;
use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::isolation::scope::TenantScope;
use crate::shared::events::data::EventData;
use crate::shared::events::event::{
    DomainEvent, DomainEventCore, OrganizationDomainEvent, PlatformDomainEvent, TenantDomainEvent,
};
use crate::types::{EventType, TenantId};

/// A tenant event as an aggregate raises it, before it knows its tenant.
///
/// Implemented by [`tenant_event!`](crate::shared::events::event::tenant_event)
/// and nothing else. The tenant is added when the event is taken out of
/// [`Raised`].
pub(crate) trait TenantEventBody: DomainEventCore {}

/// The tenant a change was saved for, which every event it raised is
/// stamped with.
///
/// Every [`TenantScope`] is one. The application's scoped tenant, the one
/// its stores take, is another, so the tenant that names the events is the
/// one the save went to.
pub trait SavedFor {
    /// The tenant the change was saved for.
    fn saved_for(&self) -> TenantId;
}

impl<S: TenantScope> SavedFor for S {
    fn saved_for(&self) -> TenantId {
        *self.tenant_id()
    }
}

/// An aggregate that raises its own tenant events.
pub trait Raises {
    /// The events raised since they were last taken, oldest first, each
    /// stamped with the tenant the change was saved for. Taking them leaves
    /// none behind.
    ///
    /// Call it once the save succeeded, and dispatch what it returns.
    /// Events not taken are lost with the aggregate.
    #[must_use]
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent>;
}

/// The events a tenant aggregate raised and has not handed over yet.
///
/// A fresh or rebuilt aggregate starts with none. A copy of an aggregate
/// starts with none too, so an event is never recorded twice through a
/// clone. Two aggregates are compared without them: what they raised is not
/// part of what they are.
pub struct Raised<T: TenantScope> {
    pending: Vec<Box<dyn TenantEventBody>>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Raised<T> {
    /// Keeps `event` until it is taken.
    pub(crate) fn raise(&mut self, event: impl TenantEventBody + 'static) {
        self.pending.push(Box::new(event));
    }

    /// Keeps `event` in place of any kept event of its type. A change made
    /// in several steps before it is saved, such as a route renamed and
    /// moved in one edit, is recorded once, as it stands at the end.
    pub(crate) fn raise_latest(&mut self, event: impl TenantEventBody + 'static) {
        let event_type = event.event_type();
        self.pending.retain(|kept| kept.event_type() != event_type);
        self.raise(event);
    }

    /// Whether an event of `event_type` is kept and not yet taken.
    pub(crate) fn holds(&self, event_type: EventType) -> bool {
        self.pending
            .iter()
            .any(|kept| kept.event_type() == event_type)
    }

    /// Every event kept, oldest first, stamped with the tenant `saved_for`
    /// names. None are kept afterwards.
    pub(crate) fn take(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        let tenant_id = saved_for.saved_for();
        self.pending
            .drain(..)
            .map(|body| DomainEvent::tenant(Box::new(Scoped { tenant_id, body })))
            .collect()
    }
}

impl<T: TenantScope> Default for Raised<T> {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            _scope: PhantomData,
        }
    }
}

impl<T: TenantScope> Clone for Raised<T> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<T: TenantScope> PartialEq for Raised<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<T: TenantScope> fmt::Debug for Raised<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.pending.iter().map(|event| event.event_type()))
            .finish()
    }
}

/// An aggregate whose events already know their scope: an operator's and
/// other platform events, an organization's events, and the tenant's own
/// records, which name the tenant itself.
///
/// Nothing is stamped when the events are taken. The aggregate filled in
/// the scope from what it is when it raised them.
pub trait RaisesComplete {
    /// The events raised since they were last taken, oldest first. Taking
    /// them leaves none behind.
    ///
    /// Call it once the save succeeded, and dispatch what it returns.
    /// Events not taken are lost with the aggregate.
    #[must_use]
    fn take_events(&mut self) -> Vec<DomainEvent>;
}

/// The whole events an aggregate that knows its scope raised and has not
/// handed over yet.
///
/// It is [`Raised`] for aggregates that are not kept per tenant: the
/// platform's operators, an organization's aggregates, the tenant itself.
/// Each event is complete when it is raised: a platform event names no
/// scope, an organization event its organization, and a tenant's own record
/// the tenant's id. The aggregate implements [`RaisesComplete`] by handing
/// over [`take`](Self::take).
///
/// ```ignore
/// pub struct Operator { /* fields */ raised: RaisedEvents }
///
/// pub fn disable(&mut self, by: &OperatorAuthority) -> Result<(), DomainError> {
///     /* change, refusing before anything is raised */
///     self.raised.raise_platform(OperatorDisabled { operator_id: self.id, .. });
///     Ok(())
/// }
///
/// impl RaisesComplete for Operator {
///     fn take_events(&mut self) -> Vec<DomainEvent> { self.raised.take() }
/// }
/// ```
///
/// Like [`Raised`], a fresh or rebuilt aggregate starts with none, a copy
/// starts with none, and two aggregates are compared without them.
///
#[derive(Default)]
pub(crate) struct RaisedEvents {
    pending: Vec<DomainEvent>,
}

impl RaisedEvents {
    /// Keeps the platform event `event` until it is taken.
    pub(crate) fn raise_platform(&mut self, event: impl PlatformDomainEvent + 'static) {
        self.pending.push(DomainEvent::platform(Box::new(event)));
    }

    /// Keeps the organization event `event` until it is taken. It names
    /// the organization it happened in already.
    pub(crate) fn raise_organization(&mut self, event: impl OrganizationDomainEvent + 'static) {
        self.pending
            .push(DomainEvent::organization(Box::new(event)));
    }

    /// Keeps `body` as an event of `tenant_id` until it is taken. For the
    /// tenant aggregate, whose own records name the tenant it is, and for a
    /// record that holds its tenant's id, such as a break-glass grant.
    pub(crate) fn raise_tenant(
        &mut self,
        tenant_id: TenantId,
        body: impl TenantEventBody + 'static,
    ) {
        self.pending.push(scoped(tenant_id, body));
    }

    /// Every event kept, oldest first. None are kept afterwards.
    pub(crate) fn take(&mut self) -> Vec<DomainEvent> {
        std::mem::take(&mut self.pending)
    }
}

impl Clone for RaisedEvents {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl PartialEq for RaisedEvents {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl fmt::Debug for RaisedEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.pending.iter().map(DomainEvent::event_type))
            .finish()
    }
}

/// A raised event with the tenant it was saved for.
struct Scoped {
    tenant_id: TenantId,
    body: Box<dyn TenantEventBody>,
}

impl DomainEventCore for Scoped {
    fn event_type(&self) -> EventType {
        self.body.event_type()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.body.occurred_at()
    }

    fn payload(&self) -> EventData {
        self.body.payload()
    }
}

impl TenantDomainEvent for Scoped {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// `body` as a tenant event of `tenant_id`, for an event no aggregate
/// raises: an observation of traffic or a refused start, each on the
/// domain conventions' `OBSERVATIONS` list, and test support that needs a
/// whole event.
pub(crate) fn scoped(tenant_id: TenantId, body: impl TenantEventBody + 'static) -> DomainEvent {
    DomainEvent::tenant(Box::new(Scoped {
        tenant_id,
        body: Box::new(body),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::SlugLimits;
    use crate::types::event_type::MessagingEvent;
    use crate::types::{Fact, TenantSlug};

    struct Happened(EventType);

    impl DomainEventCore for Happened {
        fn event_type(&self) -> EventType {
            self.0
        }

        fn occurred_at(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }

        fn payload(&self) -> EventData {
            EventData::new().field("kind", self.0.to_string())
        }
    }

    impl TenantEventBody for Happened {}

    const PAUSED: EventType = EventType::Messaging(MessagingEvent::TopicPaused);
    const RESUMED: EventType = EventType::Messaging(MessagingEvent::TopicResumed);

    fn acme() -> ResolvedTenant {
        ResolvedTenant::new(
            TenantId::new(),
            TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
        )
    }

    fn raised(events: &[EventType]) -> Raised<ResolvedTenant> {
        let mut raised = Raised::default();
        for event in events {
            raised.raise(Happened(*event));
        }
        raised
    }

    fn types(events: &[DomainEvent]) -> Vec<EventType> {
        events.iter().map(DomainEvent::event_type).collect()
    }

    /// Acme saves a topic it paused. The event taken out names Acme, the
    /// tenant the save went to, and keeps its type and payload. Nobody is
    /// named as the actor yet; the application adds who did it.
    #[test]
    fn taking_stamps_the_tenant_the_change_was_saved_for() {
        let acme = acme();
        let mut raised = raised(&[PAUSED]);

        let events = raised.take(&acme);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tenant_id(), Some(acme.tenant_id()));
        assert_eq!(events[0].event_type(), PAUSED);
        assert_eq!(events[0].payload(), Happened(PAUSED).payload());
        assert!(matches!(events[0].performed_by(), Fact::Unknown));
    }

    /// A topic is paused and resumed before it is saved. Both events come
    /// out, in the order they happened.
    #[test]
    fn events_come_out_in_the_order_they_were_raised() {
        let mut raised = raised(&[PAUSED, RESUMED]);

        let events = raised.take(&acme());

        assert_eq!(types(&events), [PAUSED, RESUMED]);
    }

    /// The events of a save are taken once. Taking again finds none, so a
    /// change is never recorded twice.
    #[test]
    fn taking_leaves_nothing_behind() {
        let acme = acme();
        let mut raised = raised(&[PAUSED]);

        let first = raised.take(&acme);
        let second = raised.take(&acme);

        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
    }

    /// An aggregate that raised a pause is copied. The copy has raised
    /// nothing, so saving both would not record the pause twice, and the
    /// original still holds it.
    #[test]
    fn a_copy_carries_no_events() {
        let mut original = raised(&[PAUSED]);

        let mut copy = original.clone();

        assert!(copy.take(&acme()).is_empty());
        assert_eq!(types(&original.take(&acme())), [PAUSED]);
    }

    /// Two aggregates that are otherwise the same compare equal whatever
    /// each has raised; the events are not part of what they are.
    #[test]
    fn what_was_raised_does_not_change_equality() {
        assert_eq!(raised(&[PAUSED]), raised(&[]));
    }

    /// Printing an aggregate shows the types of the events it holds and
    /// never their payloads, which may name people.
    #[test]
    fn debug_names_only_the_event_types() {
        let raised = raised(&[PAUSED]);

        assert_eq!(format!("{raised:?}"), format!("[{PAUSED:?}]"));
    }

    /// A topic is paused, resumed and paused again before it is saved. The
    /// latest pause replaces the first, so one pause is recorded, after the
    /// resume it followed.
    #[test]
    fn raising_the_latest_replaces_a_kept_event_of_its_type() {
        let mut raised = raised(&[PAUSED, RESUMED]);

        raised.raise_latest(Happened(PAUSED));

        assert_eq!(types(&raised.take(&acme())), [RESUMED, PAUSED]);
    }

    /// A pause is kept and not yet taken. It is held until it is taken, and
    /// a resume never was.
    #[test]
    fn holds_tells_whether_an_event_of_a_type_is_kept() {
        let mut raised = raised(&[PAUSED]);

        let before = (raised.holds(PAUSED), raised.holds(RESUMED));
        let _ = raised.take(&acme());

        assert_eq!(before, (true, false));
        assert!(!raised.holds(PAUSED));
    }

    impl PlatformDomainEvent for Happened {}

    /// An operator is disabled and Acme renames itself. The platform event
    /// comes out naming no tenant, the tenant's own record names Acme, and
    /// both in the order they were raised, with no actor yet.
    #[test]
    fn whole_events_come_out_as_they_were_raised() {
        let acme = TenantId::new();
        let mut raised = RaisedEvents::default();
        raised.raise_platform(Happened(PAUSED));
        raised.raise_tenant(acme, Happened(RESUMED));

        let events = raised.take();

        assert_eq!(types(&events), [PAUSED, RESUMED]);
        assert_eq!(events[0].tenant_id(), None);
        assert_eq!(events[1].tenant_id(), Some(&acme));
        assert!(matches!(events[1].performed_by(), Fact::Unknown));
    }

    /// Something that happened in one organization.
    struct HappenedIn(EventType, crate::types::OrganizationId);

    impl DomainEventCore for HappenedIn {
        fn event_type(&self) -> EventType {
            self.0
        }

        fn occurred_at(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }

        fn payload(&self) -> EventData {
            EventData::empty()
        }
    }

    impl OrganizationDomainEvent for HappenedIn {
        fn organization_id(&self) -> &crate::types::OrganizationId {
            &self.1
        }
    }

    /// Acme's member is renamed. The organization event comes out naming
    /// Acme and no tenant, with no actor yet.
    #[test]
    fn an_organization_event_comes_out_naming_its_organization() {
        let acme = crate::types::OrganizationId::new();
        let mut raised = RaisedEvents::default();
        raised.raise_organization(HappenedIn(PAUSED, acme));

        let events = raised.take();

        assert_eq!(types(&events), [PAUSED]);
        assert_eq!(events[0].organization_id(), Some(&acme));
        assert_eq!(events[0].tenant_id(), None);
        assert!(matches!(events[0].performed_by(), Fact::Unknown));
    }

    /// Whole events are taken once, and a copy of the aggregate holding
    /// them holds none, so nothing is recorded twice.
    #[test]
    fn whole_events_are_taken_once_and_never_copied() {
        let mut raised = RaisedEvents::default();
        raised.raise_platform(Happened(PAUSED));

        let mut copy = raised.clone();
        let first = raised.take();

        assert!(copy.take().is_empty());
        assert_eq!(types(&first), [PAUSED]);
        assert!(raised.take().is_empty());
    }

    /// Printing whole events shows their types only, and two lists compare
    /// equal whatever they hold.
    #[test]
    fn whole_events_print_their_types_and_leave_equality_alone() {
        let mut raised = RaisedEvents::default();
        raised.raise_platform(Happened(PAUSED));

        assert_eq!(format!("{raised:?}"), format!("[{PAUSED:?}]"));
        assert_eq!(raised, RaisedEvents::default());
    }
}
