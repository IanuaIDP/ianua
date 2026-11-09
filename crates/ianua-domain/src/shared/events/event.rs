use time::OffsetDateTime;

use crate::shared::events::chain::{ChainDepth, EventOrigin};
use crate::shared::events::data::EventData;
use crate::types::{ActorRef, EventType, Fact, OrganizationId, TenantId};

/// Shared behavior for all domain events regardless of scope.
///
/// Every event has a type, a time and a payload. The scope lives in the
/// sub-traits [`TenantDomainEvent`], [`OrganizationDomainEvent`] and
/// [`PlatformDomainEvent`].
///
/// Who acted is not part of this trait. Aggregates don't know who called
/// them. The app layer adds the actor when it wraps the event into a
/// [`DomainEvent`].
pub trait DomainEventCore: Send + Sync {
    /// The type of this event.
    ///
    /// Each context uses its own variant, such as
    /// `EventType::Authentication(AuthenticationEvent::LoginSucceeded)`.
    fn event_type(&self) -> EventType;

    /// When this event occurred, in UTC.
    fn occurred_at(&self) -> OffsetDateTime;

    /// Structured event data for audit storage and cross-service transport.
    ///
    /// [`EventData`] is a key-value map with no serde in it. The adapter
    /// layer turns it into JSON at the boundary.
    fn payload(&self) -> EventData;
}

/// A domain event scoped to a specific tenant.
///
/// Every tenant aggregate, such as a user, a session or a role, raises
/// events of this kind. `tenant_id()` has no default, so a tenant event
/// without a tenant ID does not compile.
pub trait TenantDomainEvent: DomainEventCore {
    /// The tenant this event belongs to. Always present.
    fn tenant_id(&self) -> &TenantId;
}

/// A domain event scoped to a specific organization.
///
/// Organization aggregates, such as the organization itself or billing,
/// raise events of this kind. `organization_id()` has no default, so an
/// organization event without an organization ID does not compile.
pub trait OrganizationDomainEvent: DomainEventCore {
    /// The organization this event belongs to. Always present.
    fn organization_id(&self) -> &OrganizationId;
}

/// A domain event at the platform level, with no tenant or organization.
///
/// Platform entities, such as operators and system configuration, raise
/// events of this kind.
pub trait PlatformDomainEvent: DomainEventCore {}

/// Implements [`DomainEventCore`] for an event that keeps its time in
/// `occurred_at`, given its event type and its payload.
///
/// The type and time accessors are the same for every event. Only the
/// payload differs, so that is all an event spells out.
macro_rules! event_core {
    ($event:ident => $kind:expr, fn payload(&$this:ident) -> EventData $body:block) => {
        impl $crate::shared::events::event::DomainEventCore for $event {
            fn event_type(&self) -> $crate::types::EventType {
                $kind.into()
            }

            fn occurred_at(&self) -> ::time::OffsetDateTime {
                self.occurred_at
            }

            fn payload(&$this) -> $crate::shared::events::data::EventData $body
        }
    };
}
pub(crate) use event_core;

/// A tenant event, which carries no tenant of its own: [`event_core!`] plus
/// [`TenantEventBody`](crate::shared::events::raised::TenantEventBody).
///
/// The aggregate that changes raises it into its
/// [`Raised`](crate::shared::events::raised::Raised) list, and the tenant the
/// change is saved for is stamped on it when the events are taken out. So
/// the tenant an event names is always the one its change was written to.
macro_rules! tenant_event {
    ($event:ident => $kind:expr, $($payload:tt)+) => {
        $crate::shared::events::event::event_core!($event => $kind, $($payload)+);

        impl $crate::shared::events::raised::TenantEventBody for $event {}
    };
}
pub(crate) use tenant_event;

/// An organization event: [`event_core!`] plus [`OrganizationDomainEvent`]
/// read from the event's `organization_id`.
macro_rules! organization_event {
    ($event:ident => $kind:expr, $($payload:tt)+) => {
        $crate::shared::events::event::event_core!($event => $kind, $($payload)+);

        impl $crate::shared::events::event::OrganizationDomainEvent for $event {
            fn organization_id(&self) -> &$crate::types::OrganizationId {
                &self.organization_id
            }
        }
    };
}
pub(crate) use organization_event;

/// A platform event: [`event_core!`] plus [`PlatformDomainEvent`].
macro_rules! platform_event {
    ($event:ident => $kind:expr, $($payload:tt)+) => {
        $crate::shared::events::event::event_core!($event => $kind, $($payload)+);

        impl $crate::shared::events::event::PlatformDomainEvent for $event {}
    };
}
pub(crate) use platform_event;

/// Any domain event, wrapped so one event bus can carry all of them.
///
/// Three scopes:
/// - **Tenant**: one tenant. Most events are this.
/// - **Organization**: one organization.
/// - **Platform**: no scope, such as operator changes or system config.
///
/// The application layer adds the actor here, not the aggregate. The
/// aggregate raises the bare event. The app layer wraps it with
/// [`with_actor`](Self::with_actor) or [`system`](Self::system) before
/// dispatching.
pub enum DomainEvent {
    /// An event scoped to a tenant.
    Tenant {
        /// The domain event.
        event: Box<dyn TenantDomainEvent>,
        /// Who performed the action. Unknown until the app layer sets it.
        performed_by: Fact<ActorRef>,
        /// Whether a workflow execution's work raised it, and how deep that
        /// execution is in its chain. A workflow this event triggers starts
        /// one deeper.
        origin: EventOrigin,
    },
    /// An event scoped to an organization.
    Organization {
        /// The domain event.
        event: Box<dyn OrganizationDomainEvent>,
        /// Who performed the action. Unknown until the app layer sets it.
        performed_by: Fact<ActorRef>,
    },
    /// A platform-level event with no tenant or organization scope.
    Platform {
        /// The domain event.
        event: Box<dyn PlatformDomainEvent>,
        /// Who performed the action. Unknown until the app layer sets it.
        performed_by: Fact<ActorRef>,
    },
}

impl DomainEvent {
    /// Wraps a tenant event. The actor is set later.
    #[must_use]
    pub fn tenant(event: Box<dyn TenantDomainEvent>) -> Self {
        Self::Tenant {
            event,
            performed_by: Fact::Unknown,
            origin: EventOrigin::Outside,
        }
    }

    /// Marks this event as raised by the work of a workflow execution this
    /// deep in its chain.
    ///
    /// That work is the execution itself, an agent run, or an action it
    /// started. Only a tenant event can start a workflow, so an organization
    /// or platform event is left as it is.
    #[must_use]
    pub fn from_execution(mut self, depth: ChainDepth) -> Self {
        if let Self::Tenant { origin, .. } = &mut self {
            *origin = EventOrigin::Execution(depth);
        }
        self
    }

    /// Where the event came from: outside any workflow, or from an
    /// execution's work.
    ///
    /// A workflow this event triggers continues from this depth.
    #[must_use]
    pub fn origin(&self) -> EventOrigin {
        match self {
            Self::Tenant { origin, .. } => *origin,
            Self::Organization { .. } | Self::Platform { .. } => EventOrigin::Outside,
        }
    }

    /// Wraps an organization event. The actor is set later.
    #[must_use]
    pub fn organization(event: Box<dyn OrganizationDomainEvent>) -> Self {
        Self::Organization {
            event,
            performed_by: Fact::Unknown,
        }
    }

    /// Wraps a platform event. The actor is set later.
    #[must_use]
    pub fn platform(event: Box<dyn PlatformDomainEvent>) -> Self {
        Self::Platform {
            event,
            performed_by: Fact::Unknown,
        }
    }

    /// Attaches the actor who performed this action.
    ///
    /// Called by the application layer after the aggregate produces
    /// the event and before dispatching to the event bus.
    #[must_use]
    pub fn with_actor(mut self, actor: ActorRef) -> Self {
        match &mut self {
            Self::Tenant { performed_by, .. }
            | Self::Organization { performed_by, .. }
            | Self::Platform { performed_by, .. } => *performed_by = Fact::Known(actor),
        }
        self
    }

    /// Marks the system as the actor, for an event no person or agent caused.
    #[must_use]
    pub fn system(self) -> Self {
        self.with_actor(ActorRef::System)
    }

    /// Who performed the action. Unknown until the app layer sets it.
    #[must_use]
    pub fn performed_by(&self) -> Fact<&ActorRef> {
        match self {
            Self::Tenant { performed_by, .. }
            | Self::Organization { performed_by, .. }
            | Self::Platform { performed_by, .. } => performed_by.as_ref(),
        }
    }

    /// The event type, regardless of scope.
    #[must_use]
    pub fn event_type(&self) -> EventType {
        match self {
            Self::Tenant { event, .. } => event.event_type(),
            Self::Organization { event, .. } => event.event_type(),
            Self::Platform { event, .. } => event.event_type(),
        }
    }

    /// When this event occurred, regardless of scope.
    #[must_use]
    pub fn occurred_at(&self) -> OffsetDateTime {
        match self {
            Self::Tenant { event, .. } => event.occurred_at(),
            Self::Organization { event, .. } => event.occurred_at(),
            Self::Platform { event, .. } => event.occurred_at(),
        }
    }

    /// The structured payload, regardless of scope.
    #[must_use]
    pub fn payload(&self) -> EventData {
        match self {
            Self::Tenant { event, .. } => event.payload(),
            Self::Organization { event, .. } => event.payload(),
            Self::Platform { event, .. } => event.payload(),
        }
    }

    /// The tenant ID, if this is a tenant-scoped event.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&TenantId> {
        match self {
            Self::Tenant { event, .. } => Some(event.tenant_id()),
            Self::Organization { .. } | Self::Platform { .. } => None,
        }
    }

    /// The organization ID, if this is an organization-scoped event.
    #[must_use]
    pub fn organization_id(&self) -> Option<&OrganizationId> {
        match self {
            Self::Organization { event, .. } => Some(event.organization_id()),
            Self::Tenant { .. } | Self::Platform { .. } => None,
        }
    }

    /// An owned copy of this event: its type, time, payload, scope and actor.
    ///
    /// For a consumer that acts on the event after the original is gone, such
    /// as one that waits for the write it describes to be committed.
    #[must_use]
    pub fn recorded(&self) -> Self {
        let core = Recorded {
            event_type: self.event_type(),
            occurred_at: self.occurred_at(),
            payload: self.payload(),
        };
        let scope = match self {
            Self::Tenant { event, .. } => CopyScope::Tenant(*event.tenant_id()),
            Self::Organization { event, .. } => CopyScope::Organization(*event.organization_id()),
            Self::Platform { .. } => CopyScope::Platform,
        };
        Self::copied(scope, core, self.performed_by().cloned(), self.origin())
    }

    /// A copy of an event made of what is kept of it: its type, time and
    /// payload in `core`, where it belongs, who performed it and, for a
    /// tenant's, where it came from.
    pub(crate) fn copied(
        scope: CopyScope,
        core: Recorded,
        performed_by: Fact<ActorRef>,
        origin: EventOrigin,
    ) -> Self {
        match scope {
            CopyScope::Tenant(tenant_id) => Self::Tenant {
                event: Box::new(RecordedTenantEvent { core, tenant_id }),
                performed_by,
                origin,
            },
            CopyScope::Organization(organization_id) => Self::Organization {
                event: Box::new(RecordedOrganizationEvent {
                    core,
                    organization_id,
                }),
                performed_by,
            },
            CopyScope::Platform => Self::Platform {
                event: Box::new(core),
                performed_by,
            },
        }
    }
}

/// Where a copy of an event belongs.
#[derive(Clone, Copy)]
pub(crate) enum CopyScope {
    /// One tenant's.
    Tenant(TenantId),
    /// One organization's.
    Organization(OrganizationId),
    /// The platform's.
    Platform,
}

/// What every recorded copy of an event carries, whatever its scope.
pub(crate) struct Recorded {
    pub(crate) event_type: EventType,
    pub(crate) occurred_at: OffsetDateTime,
    pub(crate) payload: EventData,
}

impl DomainEventCore for Recorded {
    fn event_type(&self) -> EventType {
        self.event_type
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        self.payload.clone()
    }
}

impl PlatformDomainEvent for Recorded {}

/// A recorded copy of a tenant event.
struct RecordedTenantEvent {
    core: Recorded,
    tenant_id: TenantId,
}

impl DomainEventCore for RecordedTenantEvent {
    fn event_type(&self) -> EventType {
        self.core.event_type()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.core.occurred_at()
    }

    fn payload(&self) -> EventData {
        self.core.payload()
    }
}

impl TenantDomainEvent for RecordedTenantEvent {
    fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// A recorded copy of an organization event.
struct RecordedOrganizationEvent {
    core: Recorded,
    organization_id: OrganizationId,
}

impl DomainEventCore for RecordedOrganizationEvent {
    fn event_type(&self) -> EventType {
        self.core.event_type()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.core.occurred_at()
    }

    fn payload(&self) -> EventData {
        self.core.payload()
    }
}

impl OrganizationDomainEvent for RecordedOrganizationEvent {
    fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }
}

impl std::fmt::Debug for DomainEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DomainEvent({})", self.event_type())
    }
}

/// Wraps any tenant event. The actor is set later.
impl<T: TenantDomainEvent + 'static> From<T> for DomainEvent {
    fn from(event: T) -> Self {
        Self::tenant(Box::new(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::event_type::{OrganizationEvent, TenantEvent};

    struct Scoped {
        tenant_id: TenantId,
    }

    impl Scoped {
        fn new() -> Self {
            Self {
                tenant_id: TenantId::new(),
            }
        }
    }

    impl DomainEventCore for Scoped {
        fn event_type(&self) -> EventType {
            EventType::Tenant(TenantEvent::Provisioned)
        }

        fn occurred_at(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }

        fn payload(&self) -> EventData {
            EventData::new()
        }
    }

    impl TenantDomainEvent for Scoped {
        fn tenant_id(&self) -> &TenantId {
            &self.tenant_id
        }
    }

    struct OrgScoped {
        organization_id: OrganizationId,
    }

    impl DomainEventCore for OrgScoped {
        fn event_type(&self) -> EventType {
            EventType::Organization(OrganizationEvent::Created)
        }

        fn occurred_at(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }

        fn payload(&self) -> EventData {
            EventData::new()
        }
    }

    impl OrganizationDomainEvent for OrgScoped {
        fn organization_id(&self) -> &OrganizationId {
            &self.organization_id
        }
    }

    struct Global;

    impl DomainEventCore for Global {
        fn event_type(&self) -> EventType {
            EventType::Tenant(TenantEvent::Provisioned)
        }

        fn occurred_at(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }

        fn payload(&self) -> EventData {
            EventData::new()
        }
    }

    impl PlatformDomainEvent for Global {}

    /// An event raised by an execution's work reports that execution's
    /// depth, and its recorded copy does too. An event from outside reports
    /// `Outside`, so a workflow it triggers starts a new chain.
    #[test]
    fn an_event_raised_by_an_execution_says_so() {
        let outside = DomainEvent::from(Scoped::new());
        let inside = DomainEvent::from(Scoped::new()).from_execution(ChainDepth::FIRST);

        assert_eq!(outside.origin(), EventOrigin::Outside);
        assert_eq!(inside.origin(), EventOrigin::Execution(ChainDepth::FIRST));
        assert_eq!(
            inside.recorded().origin(),
            EventOrigin::Execution(ChainDepth::FIRST)
        );
    }

    /// A tenant event reports its tenant and no organization. An
    /// organization event does the reverse, and a platform event reports
    /// neither. The scope decides which audit trail an event goes into.
    #[test]
    fn each_scope_reports_only_the_id_it_has() {
        let scoped = Scoped::new();
        let tenant_id = scoped.tenant_id;
        let organization_id = OrganizationId::new();

        let tenant_event = DomainEvent::tenant(Box::new(scoped));
        assert_eq!(tenant_event.tenant_id(), Some(&tenant_id));
        assert_eq!(tenant_event.organization_id(), None);

        let org_event = DomainEvent::organization(Box::new(OrgScoped { organization_id }));
        assert_eq!(org_event.organization_id(), Some(&organization_id));
        assert_eq!(org_event.tenant_id(), None);

        let platform_event = DomainEvent::platform(Box::new(Global));
        assert_eq!(platform_event.tenant_id(), None);
        assert_eq!(platform_event.organization_id(), None);
    }

    /// A tenant event prints as `DomainEvent(tenant.provisioned)`. The
    /// payload may hold personal data, so `Debug` never prints it.
    #[test]
    fn debug_names_the_event_type_and_nothing_else() {
        let event = DomainEvent::tenant(Box::new(Scoped::new()));

        assert_eq!(format!("{event:?}"), "DomainEvent(tenant.provisioned)");
    }

    /// A tenant event with a user as actor is copied with `recorded`. The
    /// copy has the same type, time, payload, tenant and actor, so a consumer
    /// that runs after commit sees what happened.
    #[test]
    fn a_recorded_tenant_event_keeps_its_type_scope_and_actor() {
        let original = Scoped::new();
        let tenant_id = original.tenant_id;
        let actor = ActorRef::User(crate::types::UserId::new());
        let event = DomainEvent::from(original).with_actor(actor);

        let recorded = event.recorded();

        assert_eq!(recorded.event_type(), event.event_type());
        assert_eq!(recorded.occurred_at(), event.occurred_at());
        assert_eq!(recorded.payload(), event.payload());
        assert_eq!(recorded.tenant_id(), Some(&tenant_id));
        assert!(matches!(
            recorded.performed_by(),
            Fact::Known(ActorRef::User(_))
        ));
    }

    /// A recorded copy of an organization event still names its
    /// organization and still has no tenant.
    #[test]
    fn a_recorded_organization_event_keeps_its_organization() {
        let organization_id = OrganizationId::new();
        let event = DomainEvent::organization(Box::new(OrgScoped { organization_id }));

        let recorded = event.recorded();

        assert_eq!(recorded.organization_id(), Some(&organization_id));
        assert_eq!(recorded.tenant_id(), None);
    }
}
