//! Events about roles, their permissions and who holds them.

use time::OffsetDateTime;

use crate::domains::authorization::permission::PermissionSet;
use crate::domains::authorization::role::DefaultAssignment;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{ActorRef, EventLabel, Expiry, Label, PrincipalRef, RoleId};

/// A new role was created within a tenant.
#[derive(Debug)]
pub struct RoleCreated {
    /// The newly created role.
    pub(crate) role_id: RoleId,
    /// The role's display name.
    pub(crate) name: Label,
    /// When the role was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RoleCreated => crate::types::event_type::AuthorizationEvent::RoleCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "role",
            Reference::new(RefKind::ROLE, self.role_id.to_string(), self.name.as_str()),
        )
    }
}

/// A role was given to a user, an organization member, an agent or a
/// consumer.
///
/// The holder now has the role's system and custom permissions in the tenant.
#[derive(Debug)]
pub struct RoleAssigned {
    /// Who received the role.
    pub(crate) holder: PrincipalRef,
    /// The holder's display label at assignment time, for the audit trail.
    pub(crate) holder_label: EventLabel,
    /// The role that was assigned.
    pub(crate) role_id: RoleId,
    /// The role's name at assignment time, for the audit trail.
    pub(crate) role_label: EventLabel,
    /// Who made the assignment, or [`ActorRef::System`] for an automatic one.
    ///
    /// The payload records it as `granted_by`, because it can differ from the
    /// actor. When Ann accepts Sam's invitation, Ann is the actor and Sam is
    /// the granter.
    pub(crate) assigned_by: ActorRef,
    /// The granter's display label, when a granter is recorded.
    pub(crate) granted_by_label: Option<EventLabel>,
    /// When the role is taken away again, or that it is not.
    pub(crate) until: Expiry,
    /// When the assignment was made.
    pub(crate) occurred_at: OffsetDateTime,
}

impl RoleAssigned {
    /// The granter as a reference of its own kind. The label is the id when
    /// no label was captured.
    fn granter(&self) -> Option<Reference> {
        let kind = self.assigned_by.ref_kind()?;
        let id = self.assigned_by.audit_label();
        let label = self
            .granted_by_label
            .as_ref()
            .map(EventLabel::as_str)
            .unwrap_or(&id);
        Some(Reference::new(kind, id.as_str(), label))
    }
}

tenant_event! {
    RoleAssigned => crate::types::event_type::AuthorizationEvent::RoleAssigned,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("holder", holder_reference(&self.holder, &self.holder_label))
            .reference(
                "role",
                Reference::new(
                    RefKind::ROLE,
                    self.role_id.to_string(),
                    self.role_label.as_str(),
                ),
            )
            .optional_reference("granted_by", self.granter())
            .optional("expires_at", expiry_text(self.until))
    }
}

/// A role given until a time reached it, and was taken from its holder.
#[derive(Debug)]
pub struct RoleAssignmentExpired {
    /// Who lost the role.
    pub(crate) holder: PrincipalRef,
    /// The holder's display label, for the audit trail.
    pub(crate) holder_label: EventLabel,
    /// The role that ended.
    pub(crate) role_id: RoleId,
    /// The role's name, for the audit trail.
    pub(crate) role_label: EventLabel,
    /// When the role ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RoleAssignmentExpired => crate::types::event_type::AuthorizationEvent::RoleAssignmentExpired,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("holder", holder_reference(&self.holder, &self.holder_label))
            .reference(
                "role",
                Reference::new(
                    RefKind::ROLE,
                    self.role_id.to_string(),
                    self.role_label.as_str(),
                ),
            )
    }
}

/// When a holding ends, as the audit trail writes it, or nothing for one
/// that does not end.
pub(crate) fn expiry_text(until: Expiry) -> Option<String> {
    until.instant().map(|at| at.to_string())
}

/// A role was removed from a principal.
///
/// From now on the holder lacks this role's permissions within the tenant.
#[derive(Debug)]
pub struct RoleRevoked {
    /// Who lost the role.
    pub(crate) holder: PrincipalRef,
    /// The holder's display label at revocation time, for the audit trail.
    pub(crate) holder_label: EventLabel,
    /// The role that was removed.
    pub(crate) role_id: RoleId,
    /// The role's name at revocation time, for the audit trail.
    pub(crate) role_label: EventLabel,
    /// When the revocation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RoleRevoked => crate::types::event_type::AuthorizationEvent::RoleRevoked,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("holder", holder_reference(&self.holder, &self.holder_label))
            .reference(
                "role",
                Reference::new(
                    RefKind::ROLE,
                    self.role_id.to_string(),
                    self.role_label.as_str(),
                ),
            )
    }
}

/// A role was deleted from the tenant.
///
/// Everyone who held this role loses its permissions. The event keeps the
/// role's name for the audit trail, since the role itself is gone.
#[derive(Debug)]
pub struct RoleDeleted {
    /// The role that was deleted.
    pub(crate) role_id: RoleId,
    /// The role's name when it was deleted, for the audit trail.
    pub(crate) name: Label,
    /// When the deletion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RoleDeleted => crate::types::event_type::AuthorizationEvent::RoleDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "role",
            Reference::new(RefKind::ROLE, self.role_id.to_string(), self.name.as_str()),
        )
    }
}

/// A role's holders were reassigned to another role.
///
/// Raised before the source role is deleted. Every user who held
/// `from_role_id` now holds `to_role_id` instead. The audit trail gets the
/// number of users moved.
#[derive(Debug)]
pub struct RoleReassigned {
    /// The role the users were moved off of.
    pub(crate) from_role_id: RoleId,
    /// The vacated role's name at reassignment time, for the audit trail.
    pub(crate) from_role_label: EventLabel,
    /// The role the users were moved onto.
    pub(crate) to_role_id: RoleId,
    /// The receiving role's name at reassignment time, for the audit trail.
    pub(crate) to_role_label: EventLabel,
    /// How many users were reassigned.
    pub(crate) reassigned_count: u64,
    /// When the reassignment occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RoleReassigned => crate::types::event_type::AuthorizationEvent::RoleReassigned,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "from_role",
                Reference::new(
                    RefKind::ROLE,
                    self.from_role_id.to_string(),
                    self.from_role_label.as_str(),
                ),
            )
            .reference(
                "to_role",
                Reference::new(
                    RefKind::ROLE,
                    self.to_role_id.to_string(),
                    self.to_role_label.as_str(),
                ),
            )
            .field("reassigned_count", self.reassigned_count.to_string())
    }
}

/// A role was renamed.
///
/// Captures both old and new names for the audit trail.
#[derive(Debug)]
pub struct RoleRenamed {
    /// The role that was renamed.
    pub(crate) role_id: RoleId,
    /// The previous name.
    pub(crate) old_name: Label,
    /// The replacement display label captured in the audit trail.
    pub(crate) new_name: Label,
    /// When the rename occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RoleRenamed => crate::types::event_type::AuthorizationEvent::RoleRenamed,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "role",
                Reference::new(
                    RefKind::ROLE,
                    self.role_id.to_string(),
                    self.new_name.as_str(),
                ),
            )
            .change("name", self.old_name.as_str(), self.new_name.as_str())
    }
}

/// Whether every new user gets a role changed.
///
/// A role given to new users is handed to everyone who joins from now on,
/// with no one assigning it. So turning that on is recorded like a grant to
/// all of them.
#[derive(Debug)]
pub struct RoleDefaultAssignmentChanged {
    /// The permission bundle whose automatic assignment to joiners changed.
    pub(crate) role_id: RoleId,
    /// The role's name at the change, for the audit trail.
    pub(crate) role_label: EventLabel,
    /// Whether new users got it before.
    pub(crate) previous: DefaultAssignment,
    /// Whether new users get it now.
    pub(crate) current: DefaultAssignment,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RoleDefaultAssignmentChanged => crate::types::event_type::AuthorizationEvent::RoleDefaultAssignmentChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "role",
                Reference::new(
                    RefKind::ROLE,
                    self.role_id.to_string(),
                    self.role_label.as_str(),
                ),
            )
            .change(
                "default_assignment",
                self.previous.as_str(),
                self.current.as_str(),
            )
    }
}

/// Permissions were granted to a role.
///
/// Carries every permission one save added, in one event. Ann ticks a
/// hundred boxes and saves once. She gets one audit record and one
/// notification, not a hundred.
///
/// System and custom permissions are reported apart. A save touching both
/// raises one event of each kind, so each event's label is true.
#[derive(Debug)]
pub struct PermissionGranted {
    /// The role that received them.
    pub(crate) role_id: RoleId,
    /// The role's name at grant time, for the audit trail.
    pub(crate) role_label: EventLabel,
    /// What was granted, and of which kind.
    pub(crate) permissions: PermissionSet,
    /// When the grant occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PermissionGranted => crate::types::event_type::AuthorizationEvent::PermissionGranted,
    fn payload(&self) -> EventData {
        permission_payload(self.role_id, self.role_label.as_str(), &self.permissions)
    }
}

/// Permissions were revoked from a role.
///
/// Users holding this role lose all of them. Grouped per save for
/// the same reason as [`PermissionGranted`].
#[derive(Debug)]
pub struct PermissionRevoked {
    /// The role that lost them.
    pub(crate) role_id: RoleId,
    /// The role's name at revocation time, for the audit trail.
    pub(crate) role_label: EventLabel,
    /// What was revoked, and of which kind.
    pub(crate) permissions: PermissionSet,
    /// When the revocation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PermissionRevoked => crate::types::event_type::AuthorizationEvent::PermissionRevoked,
    fn payload(&self) -> EventData {
        permission_payload(self.role_id, self.role_label.as_str(), &self.permissions)
    }
}

/// The payload shared by granting and revoking. It names the role and the
/// permissions that changed.
///
/// `permission_type` is read off the set, so it cannot disagree with the
/// values it labels.
fn permission_payload(role_id: RoleId, role_label: &str, permissions: &PermissionSet) -> EventData {
    EventData::new()
        .reference(
            "role",
            Reference::new(RefKind::ROLE, role_id.to_string(), role_label),
        )
        .field("permission_type", permissions.kind())
        .field("permissions", permissions.values().join(", "))
        .field("permission_count", permissions.len().to_string())
}

/// A role's holder as its own reference, of the kind it is.
fn holder_reference(holder: &PrincipalRef, label: &EventLabel) -> Reference {
    Reference::new(holder.ref_kind(), holder.id().to_string(), label.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;
    use crate::types::{OrgUserId, UserId};

    /// An organization member grants Ada the editor role. The event names
    /// the granter as an organization user. As a tenant user, the audit link
    /// would point at a user who does not exist.
    #[test]
    fn a_granter_is_named_as_the_kind_of_actor_it_is() {
        let assigned = RoleAssigned {
            holder: PrincipalRef::User(UserId::new()),
            holder_label: EventLabel::of("ada@acme.com"),
            role_id: RoleId::new(),
            role_label: EventLabel::of("editor"),
            assigned_by: ActorRef::OrgUser(OrgUserId::new()),
            granted_by_label: Some(EventLabel::of("owner@acme.com")),
            until: Expiry::Never,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = assigned.payload();
        let Some(FieldValue::Reference(granter)) = payload.value("granted_by") else {
            panic!("the granter is recorded as a reference");
        };

        assert_eq!(granter.kind(), RefKind::ORG_USER);
    }

    /// The editor role is taken from the agent "billing-bot". The event names
    /// the holder as an agent, not a user, so the audit trail links to the
    /// right kind of principal.
    #[test]
    fn a_role_holder_is_named_as_the_kind_of_principal_it_is() {
        let revoked = RoleRevoked {
            holder: PrincipalRef::Agent(crate::types::AgentId::new()),
            holder_label: EventLabel::of("billing-bot"),
            role_id: RoleId::new(),
            role_label: EventLabel::of("editor"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = revoked.payload();
        let Some(FieldValue::Reference(holder)) = payload.value("holder") else {
            panic!("the holder is recorded as a reference");
        };

        assert_eq!(holder.kind(), RefKind::AGENT);
    }

    /// Ann makes the editor role go to every new user. The record keeps
    /// both settings, so a review sees when everyone joining began to get
    /// it.
    #[test]
    fn a_default_assignment_change_keeps_both_settings() {
        let changed = RoleDefaultAssignmentChanged {
            role_id: RoleId::new(),
            role_label: EventLabel::of("editor"),
            previous: DefaultAssignment::Manual,
            current: DefaultAssignment::NewUsers,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = changed.payload();
        let Some(FieldValue::Change(change)) = payload.value("default_assignment") else {
            panic!("the default assignment is recorded as a change");
        };

        assert_eq!(
            (change.from(), change.to()),
            (Some("manual"), Some("new_users"))
        );
    }
}
