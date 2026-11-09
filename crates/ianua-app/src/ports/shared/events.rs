//! The single point where use cases send their events.

use async_trait::async_trait;
use ianua_domain::domains::audit::builder::{AuditContext, build_audit_record};
use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::AuditRecordId;
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// An event as the bus hands it to the worker once it is recorded: the
/// event, the context it was recorded in, and the id of its audit record.
///
/// The id names the event once, however often the bus delivers it, so the
/// jobs planned from it are keyed by it and planned once.
pub struct PublishedEvent {
    /// The id of the event's audit record.
    pub id: AuditRecordId,
    /// The audited change made available to subscribers.
    pub event: DomainEvent,
    /// Who made it, and where.
    pub context: AuditContext,
}

impl PublishedEvent {
    /// The event's audit record, as it was written.
    #[must_use]
    pub fn record(&self) -> AuditRecord {
        AuditRecord {
            id: self.id,
            ..build_audit_record(&self.event, &self.context)
        }
    }
}

/// Dyn-safe port for dispatching domain events.
///
/// The single point where use cases send events after a successful
/// operation. The infra implementation does two things:
/// - **Audit persistence**: writes to the audit log (Postgres).
/// - **Event broadcast**: publishes to the message bus (NATS).
///
/// Use cases know neither destination. They call `dispatch` and the
/// infrastructure delivers.
#[async_trait]
pub trait EventDispatcher: Send + Sync {
    /// Dispatches domain events for persistence and broadcast.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if audit persistence fails.
    /// Event bus failures are logged but do not fail the operation, since
    /// the audit log is the source of truth.
    async fn dispatch(&self, events: &[DomainEvent], ctx: &AuditContext)
    -> Result<(), DomainError>;
}

/// Dyn-safe port reading a recorded event back by the id of its audit
/// record, for a job planned from it that runs later.
#[async_trait]
pub trait RecordedEvents: Send + Sync + TenantScoped {
    /// The tenant's audit record `id`, or `None` when it is gone, as after
    /// its retention ended.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be read, or the
    /// read does not answer within five seconds.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &AuditRecordId,
    ) -> Result<Option<AuditRecord>, DomainError>;
}

/// What the platform does on its own account on hearing an event, once
/// for each event however often the bus hands it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventReaction {
    /// An agent's action judged against its intent.
    Drift,
    /// An agent's allowed action checked for meeting another agent.
    Convergence,
    /// A refused way out held against the agent behind it.
    EgressDenial,
}

impl EventReaction {
    /// The word the reaction is kept under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drift => "drift",
            Self::Convergence => "convergence",
            Self::EgressDenial => "egress_denial",
        }
    }
}

/// One reaction to one event, to be noted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReactionNote {
    /// The consumer operation whose completion is being noted.
    pub reaction: EventReaction,
    /// The audit record of the event reacted to.
    pub record: AuditRecordId,
    /// Notes of the tenant's from before this moment are forgotten: by
    /// then the bus can hand none of their events out again.
    pub forget_before: OffsetDateTime,
}

/// Whether a reaction to an event was noted now or before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Noted {
    /// Noted now: the reaction has not acted on the event yet.
    First,
    /// Noted before: the reaction acted on the event already.
    Before,
}

/// Dyn-safe port noting the events a reaction acted on, so an event handed
/// out twice is acted on once.
#[async_trait]
pub trait EventReactions: Send + Sync + TenantScoped {
    /// Notes `note` for `tenant_id` in the running unit of work, so the
    /// note is kept exactly when what the reaction changed is, and
    /// forgets the tenant's notes from before `note.forget_before`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the note cannot be
    /// written, or the write does not answer within five seconds.
    async fn note(
        &self,
        tenant_id: &ScopedTenant,
        note: &ReactionNote,
    ) -> Result<Noted, DomainError>;
}
