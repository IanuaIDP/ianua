//! Who hears about an event: the people who run the plane it happened on.
//!
//! The person who acted is never told of their own action. An event goes to
//! the others who run the plane that saw it happen:
//! - an organization's events, and a tenant's events an org user or an
//!   operator made, go to the organization's other users;
//! - a tenant's other events go to the tenant's administrators and the
//!   organization's members with access to the tenant, never to its users
//!   at large;
//! - platform events go to the other operators.
//!
//! The tenant user a tenant's event is about is told too, in their own
//! tenant, whichever plane it was made from: Carol hears that her account
//! was locked whether an admin of the tenant or a member of the
//! organization locked it.

use ianua_domain::domains::audit::builder::{AuditActor, AuditContext};
use ianua_domain::shared::events::data::{FieldValue, RefKind};
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{ActorRef, Fact, OrganizationId, TenantId, UserId};
use uuid::Uuid;

/// The people told about one event, and the one among them left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::use_cases::notifications) enum Audience {
    /// The users of an organization.
    Organization {
        /// The organization whose users are told.
        organization_id: OrganizationId,
        /// The tenant the event happened in, for an event made on the
        /// management plane, or `None` for the organization's own events.
        about_tenant: Option<TenantId>,
        /// Who acted, left out.
        actor: Option<Uuid>,
        /// The tenant user a management-plane event is about, told in
        /// their own tenant though they run nothing.
        subject: Option<UserId>,
    },
    /// The people who run a tenant: its administrators and the
    /// organization's members with access to it, and the person the event
    /// is about.
    Tenant {
        /// The tenant whose administrators are told.
        tenant_id: TenantId,
        /// Who acted, left out.
        actor: Option<Uuid>,
        /// The tenant user the event is about, told though they run
        /// nothing, unless they acted themselves.
        subject: Option<UserId>,
    },
    /// The platform's operators.
    Platform {
        /// Who acted, left out.
        actor: Option<Uuid>,
    },
}

impl Audience {
    /// Who hears about `event`, recorded in `context`.
    ///
    /// `None` for a tenant event an org user or an operator made where the
    /// context names no organization: there is no one to tell.
    pub(in crate::use_cases::notifications) fn of(
        event: &DomainEvent,
        context: &AuditContext,
    ) -> Option<Self> {
        let actor = acting(event, context);
        match event {
            DomainEvent::Tenant { event: inner, .. } => {
                Self::for_tenant_event(*inner.tenant_id(), actor, event, context)
            }
            DomainEvent::Organization { event: inner, .. } => Some(Self::Organization {
                organization_id: *inner.organization_id(),
                about_tenant: None,
                actor: org_user(actor),
                subject: None,
            }),
            DomainEvent::Platform { .. } => Some(Self::Platform {
                actor: operator(actor),
            }),
        }
    }

    /// Who hears about an event in `tenant_id`: the organization when the
    /// management plane made it, the people who run the tenant otherwise.
    fn for_tenant_event(
        tenant_id: TenantId,
        actor: Option<&ActorRef>,
        event: &DomainEvent,
        context: &AuditContext,
    ) -> Option<Self> {
        let Some(manager) = ManagementActor::of(actor) else {
            return Some(Self::Tenant {
                tenant_id,
                actor: tenant_user(actor).map(|user| *user.as_uuid()),
                subject: subject_of(event),
            });
        };
        let Fact::Known(organization_id) = context.organization_id() else {
            return None;
        };
        Some(Self::Organization {
            organization_id,
            about_tenant: Some(tenant_id),
            actor: manager.org_user(),
            subject: subject_of(event),
        })
    }

    /// The tenant user the event happened to, with their tenant, when it
    /// is a tenant's event about one, whichever plane made it.
    pub(in crate::use_cases::notifications) fn subject(&self) -> Option<(TenantId, UserId)> {
        match *self {
            Self::Tenant {
                tenant_id, subject, ..
            } => Some((tenant_id, subject?)),
            Self::Organization {
                about_tenant,
                subject,
                ..
            } => Some((about_tenant?, subject?)),
            Self::Platform { .. } => None,
        }
    }

    /// Who acted, left out of the audience.
    pub(in crate::use_cases::notifications) fn actor(&self) -> Option<Uuid> {
        match self {
            Self::Organization { actor, .. }
            | Self::Tenant { actor, .. }
            | Self::Platform { actor } => *actor,
        }
    }
}

/// Someone who acted on a tenant from the management plane.
enum ManagementActor {
    /// One of the organization's users.
    OrgUser(Uuid),
    /// An operator, who is not among the organization's users.
    Operator,
}

impl ManagementActor {
    /// The manager `actor` is, or `None` when they acted from inside the
    /// tenant.
    fn of(actor: Option<&ActorRef>) -> Option<Self> {
        match actor? {
            ActorRef::OrgUser(id) => Some(Self::OrgUser(*id.as_uuid())),
            ActorRef::Operator(_) => Some(Self::Operator),
            _ => None,
        }
    }

    /// The org user to leave out of the organization's audience.
    fn org_user(&self) -> Option<Uuid> {
        match self {
            Self::OrgUser(id) => Some(*id),
            Self::Operator => None,
        }
    }
}

/// Who acted: the caller the request resolved, or else the actor the event
/// names.
///
/// The request's caller is what the audit record trusts, and the only one
/// that tells an org user from a tenant user. Reading the same source keeps
/// a notification's audience and its audit entry naming the same person.
fn acting<'a>(event: &'a DomainEvent, context: &'a AuditContext) -> Option<&'a ActorRef> {
    if let AuditActor::Caller(caller) = context.actor() {
        return Some(caller);
    }
    match event.performed_by() {
        Fact::Known(actor) => Some(actor),
        Fact::Unknown => None,
    }
}

/// The acting org user. Org actions name their actor as an org user or as
/// a user with the same id, so both count.
fn org_user(actor: Option<&ActorRef>) -> Option<Uuid> {
    match actor? {
        ActorRef::OrgUser(id) => Some(*id.as_uuid()),
        ActorRef::User(id) => Some(*id.as_uuid()),
        _ => None,
    }
}

/// The acting operator.
fn operator(actor: Option<&ActorRef>) -> Option<Uuid> {
    match actor? {
        ActorRef::Operator(id) => Some(*id.as_uuid()),
        _ => None,
    }
}

/// The tenant user who acted.
fn tenant_user(actor: Option<&ActorRef>) -> Option<UserId> {
    match actor? {
        ActorRef::User(id) => Some(*id),
        _ => None,
    }
}

/// The payload keys an event names the account it happened to under: the
/// account itself, the holder of a role, the member of a group.
const SUBJECT_KEYS: [&str; 3] = ["user", "holder", "member"];

/// The tenant user `event` is about: the user its payload names as the
/// account it happened to. An event a person made about themselves names no
/// user, since its actor already does.
///
/// Only the keys that name that account count. A role given by Sam names
/// him too, as its granter; he is not the account it happened to, and is
/// never told as if it were his own.
fn subject_of(event: &DomainEvent) -> Option<UserId> {
    let payload = event.payload();
    SUBJECT_KEYS.iter().find_map(|key| {
        let FieldValue::Reference(reference) = payload.value(key)? else {
            return None;
        };
        if reference.kind() != RefKind::USER {
            return None;
        }
        Uuid::parse_str(reference.id()).ok().map(UserId::from_uuid)
    })
}
