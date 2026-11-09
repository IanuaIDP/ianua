//! The wire shape of a principal: a kind and an id.
//!
//! Four things hold authority here: a tenant user, an org user, an agent and
//! a consumer. A grant naming only a UUID could not tell one from another,
//! and two kinds sharing a UUID would share the grant, so every agents body
//! that names a principal names its kind too.

use ianua_domain::types::{AgentId, ConsumerId, Human, OrgUserId, PrincipalRef, UserId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Distinguishes authority holders whose UUIDs may otherwise coincide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A tenant user.
    User,
    /// An org user (management plane).
    OrgUser,
    /// An automated actor registered in the tenant.
    Agent,
    /// A consumer: a non-human caller outside the platform.
    Consumer,
}

impl PrincipalKind {
    /// The kind of `principal`.
    #[must_use]
    pub fn of(principal: &PrincipalRef) -> Self {
        match principal {
            PrincipalRef::User(_) => Self::User,
            PrincipalRef::OrgUser(_) => Self::OrgUser,
            PrincipalRef::Agent(_) => Self::Agent,
            PrincipalRef::Consumer(_) => Self::Consumer,
        }
    }

    /// The principal of this kind with `id`.
    #[must_use]
    pub fn with_id(self, id: Uuid) -> PrincipalRef {
        match self {
            Self::User => PrincipalRef::User(UserId::from_uuid(id)),
            Self::OrgUser => PrincipalRef::OrgUser(OrgUserId::from_uuid(id)),
            Self::Agent => PrincipalRef::Agent(AgentId::from_uuid(id)),
            Self::Consumer => PrincipalRef::Consumer(ConsumerId::from_uuid(id)),
        }
    }
}

/// A principal on the wire, such as an agent's owner or a delegator.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct OwnerDto {
    /// Kind of principal.
    pub kind: PrincipalKind,
    /// Identifier of the principal.
    pub id: Uuid,
    /// The principal's display name, when it could be resolved. Left out
    /// when it was not looked up, or the principal no longer exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl OwnerDto {
    /// The domain principal this names.
    #[must_use]
    pub(crate) fn to_principal(&self) -> PrincipalRef {
        self.kind.with_id(self.id)
    }

    /// `principal` on the wire, its name not looked up.
    #[must_use]
    pub(crate) fn from_principal(principal: &PrincipalRef) -> Self {
        Self {
            kind: PrincipalKind::of(principal),
            id: principal.id(),
            display_name: None,
        }
    }

    /// The account `human` acted through, on the wire.
    #[must_use]
    pub(crate) fn from_human(human: &Human) -> Self {
        Self::from_principal(&human.principal())
    }
}
