use time::OffsetDateTime;

use crate::shared::events::data::EventData;
use crate::types::{
    ActorRef, AuditRecordId, EventType, Fact, IpAddress, OrganizationId, TenantId, UserAgent,
};

/// Where an audited event belongs: the platform, an organization or a tenant.
///
/// A record always says which of the three it is. So a tenant's record is
/// never filed under no tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditScope {
    /// Platform-level: no organization or tenant.
    Platform,
    /// One organization, not a tenant of it.
    Organization(OrganizationId),
    /// Files the record under a tenant, retaining its organization when known.
    Tenant {
        /// The organization owning it, when the record knows it.
        organization: Fact<OrganizationId>,
        /// The isolation boundary under which the record is filed.
        tenant: TenantId,
    },
}

impl AuditScope {
    /// The scope an organization and a tenant give: the tenant when one is
    /// known, else the organization, else the platform.
    #[must_use]
    pub fn of(organization: Fact<OrganizationId>, tenant: Fact<TenantId>) -> Self {
        match (tenant, organization) {
            (Fact::Known(tenant), organization) => Self::Tenant {
                organization,
                tenant,
            },
            (Fact::Unknown, Fact::Known(organization)) => Self::Organization(organization),
            (Fact::Unknown, Fact::Unknown) => Self::Platform,
        }
    }

    /// The organization, when the record names one. Storage keeps it this way.
    #[must_use]
    pub fn organization_id(&self) -> Option<&OrganizationId> {
        match self {
            Self::Organization(organization)
            | Self::Tenant {
                organization: Fact::Known(organization),
                ..
            } => Some(organization),
            Self::Platform
            | Self::Tenant {
                organization: Fact::Unknown,
                ..
            } => None,
        }
    }

    /// The tenant, when the record belongs to one. Storage keeps it this way.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&TenantId> {
        match self {
            Self::Tenant { tenant, .. } => Some(tenant),
            Self::Platform | Self::Organization(_) => None,
        }
    }
}

/// The entity an audited action affected, or that it affected none.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuditTarget {
    /// It affected no one entity.
    #[default]
    Untargeted,
    /// This entity, by id. The id is text because the entity can be of any
    /// kind, such as a user, a role, a session or a connection.
    Entity(String),
}

impl AuditTarget {
    /// The entity id, when there is one. Storage keeps it this way.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Untargeted => None,
            Self::Entity(id) => Some(id),
        }
    }
}

/// A stored audit record: what happened, who did it, when and from where.
///
/// Every significant action writes one. Records are only ever added. They
/// are never changed, and deleted only when a whole tenant is wiped.
///
/// This is a read-only query result, not an aggregate. It keeps no rules,
/// so its fields are public.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// The record's id.
    pub id: AuditRecordId,

    /// Where the event belongs: the platform, an organization, or a tenant.
    pub scope: AuditScope,

    /// Who performed the action.
    pub actor: ActorRef,

    /// The type of event that occurred.
    pub event_type: EventType,

    /// The entity the action affected, or that it affected none.
    pub target: AuditTarget,

    /// The IP address the request came from, when known.
    pub ip_address: Fact<IpAddress>,

    /// The request's User-Agent header, when known.
    pub user_agent: Fact<UserAgent>,

    /// The event's details, as [`DomainEventCore::payload`](crate::shared::events::event::DomainEventCore::payload)
    /// gives them.
    pub payload: EventData,

    /// Whether the actor acted in their own name, or an operator acted as a
    /// user.
    pub acted_through: crate::domains::audit::builder::ActedThrough,

    /// When the event happened, in UTC.
    pub occurred_at: OffsetDateTime,
}
