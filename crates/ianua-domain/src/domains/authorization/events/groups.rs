//! Events about groups, their members and the roles they carry.

use time::OffsetDateTime;

use crate::domains::authorization::events::roles::expiry_text;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, Expiry, GroupId, Label, PrincipalRef, RoleId};

/// A group was created within a tenant.
#[derive(Debug)]
pub struct GroupCreated {
    /// The newly created group.
    pub(crate) group_id: GroupId,
    /// The group name.
    pub(crate) name: Label,
    /// The group it was nested under, with that group's name, or that it
    /// sits at the top.
    pub(crate) parent: NestedUnder,
    /// When the group was created.
    pub(crate) occurred_at: OffsetDateTime,
}

/// Where a new group was nested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NestedUnder {
    /// At the top of the tree.
    TopLevel,
    /// Under this group, named as it was then.
    Group {
        /// The parent group.
        id: GroupId,
        /// Its name.
        label: EventLabel,
    },
}

impl NestedUnder {
    /// The parent group as a reference, when there is one.
    fn reference(&self) -> Option<Reference> {
        let Self::Group { id, label } = self else {
            return None;
        };
        Some(Reference::new(
            RefKind::GROUP,
            id.to_string(),
            label.as_str(),
        ))
    }
}

impl GroupCreated {
    /// The parent group as a reference, when there is one.
    fn parent(&self) -> Option<Reference> {
        self.parent.reference()
    }
}

/// A group was moved to another place in the tree.
///
/// Every member now holds what the new place brings, and no longer what the
/// old one brought. So the move is audited like a role given or taken.
#[derive(Debug)]
pub struct GroupMoved {
    /// The moved group.
    pub(crate) group_id: GroupId,
    /// The group's name at the time, for the audit trail.
    pub(crate) group_label: EventLabel,
    /// Where it sat before.
    pub(crate) from: NestedUnder,
    /// Where it sits now.
    pub(crate) to: NestedUnder,
    /// When the move occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    GroupMoved => crate::types::event_type::AuthorizationEvent::GroupMoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "group",
                Reference::new(
                    RefKind::GROUP,
                    self.group_id.to_string(),
                    self.group_label.as_str(),
                ),
            )
            .optional_reference("parent", self.to.reference())
            .optional_reference("previous_parent", self.from.reference())
    }
}

tenant_event! {
    GroupCreated => crate::types::event_type::AuthorizationEvent::GroupCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "group",
                Reference::new(
                    RefKind::GROUP,
                    self.group_id.to_string(),
                    self.name.as_str(),
                ),
            )
            .optional_reference("parent", self.parent())
    }
}

/// A group was deleted from the tenant.
#[derive(Debug)]
pub struct GroupDeleted {
    /// The deleted group.
    pub(crate) group_id: GroupId,
    /// The group's name when it was deleted, for the audit trail.
    pub(crate) name: Label,
    /// When the deletion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    GroupDeleted => crate::types::event_type::AuthorizationEvent::GroupDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "group",
            Reference::new(
                RefKind::GROUP,
                self.group_id.to_string(),
                self.name.as_str(),
            ),
        )
    }
}

/// A group was renamed.
#[derive(Debug)]
pub struct GroupRenamed {
    /// The renamed group.
    pub(crate) group_id: GroupId,
    /// The previous name.
    pub(crate) old_name: Label,
    /// The replacement display label captured in the audit trail.
    pub(crate) new_name: Label,
    /// When the rename occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    GroupRenamed => crate::types::event_type::AuthorizationEvent::GroupRenamed,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "group",
                Reference::new(
                    RefKind::GROUP,
                    self.group_id.to_string(),
                    self.new_name.as_str(),
                ),
            )
            .change("name", self.old_name.as_str(), self.new_name.as_str())
    }
}

/// A role was assigned to a group.
#[derive(Debug)]
pub struct GroupRoleAssigned {
    /// The group that received the role.
    pub(crate) group_id: GroupId,
    /// The group's name at assignment time, for the audit trail.
    pub(crate) group_label: EventLabel,
    /// The role that was assigned.
    pub(crate) role_id: RoleId,
    /// The role's name at assignment time, for the audit trail.
    pub(crate) role_label: EventLabel,
    /// When the assignment occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    GroupRoleAssigned => crate::types::event_type::AuthorizationEvent::GroupRoleAssigned,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "group",
                Reference::new(
                    RefKind::GROUP,
                    self.group_id.to_string(),
                    self.group_label.as_str(),
                ),
            )
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

/// A role was removed from a group.
#[derive(Debug)]
pub struct GroupRoleUnassigned {
    /// The group that lost the role.
    pub(crate) group_id: GroupId,
    /// The group's name at unassignment time, for the audit trail.
    pub(crate) group_label: EventLabel,
    /// The role that was removed.
    pub(crate) role_id: RoleId,
    /// The role's name at unassignment time, for the audit trail.
    pub(crate) role_label: EventLabel,
    /// When the unassignment occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    GroupRoleUnassigned => crate::types::event_type::AuthorizationEvent::GroupRoleUnassigned,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "group",
                Reference::new(
                    RefKind::GROUP,
                    self.group_id.to_string(),
                    self.group_label.as_str(),
                ),
            )
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

/// A person or a machine identity was added to a group.
#[derive(Debug)]
pub struct GroupMemberAdded {
    /// The group the principal was added to.
    pub(crate) group_id: GroupId,
    /// The group's name at the time of the addition, for the audit trail.
    pub(crate) group_label: EventLabel,
    /// The member who was added. A machine identity holds the group's roles
    /// the same way a person does.
    pub(crate) member: PrincipalRef,
    /// The added member's display label, for the audit trail.
    pub(crate) member_label: EventLabel,
    /// When the membership ends again, or that it does not.
    pub(crate) until: Expiry,
    /// When the membership was created.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    GroupMemberAdded => crate::types::event_type::AuthorizationEvent::GroupMemberAdded,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "group",
                Reference::new(
                    RefKind::GROUP,
                    self.group_id.to_string(),
                    self.group_label.as_str(),
                ),
            )
            .reference(
                "member",
                Reference::new(
                    self.member.ref_kind(),
                    self.member.id().to_string(),
                    self.member_label.as_str(),
                ),
            )
            .optional("expires_at", expiry_text(self.until))
    }
}

/// A membership given until a time reached it and ended. The member no
/// longer holds what the group brings.
#[derive(Debug)]
pub struct GroupMembershipExpired {
    /// The group the membership was of.
    pub(crate) group_id: GroupId,
    /// The group's name, for the audit trail.
    pub(crate) group_label: EventLabel,
    /// The member who left.
    pub(crate) member: PrincipalRef,
    /// The member's display label, for the audit trail.
    pub(crate) member_label: EventLabel,
    /// When the membership ended.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    GroupMembershipExpired => crate::types::event_type::AuthorizationEvent::GroupMembershipExpired,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "group",
                Reference::new(
                    RefKind::GROUP,
                    self.group_id.to_string(),
                    self.group_label.as_str(),
                ),
            )
            .reference(
                "member",
                Reference::new(
                    self.member.ref_kind(),
                    self.member.id().to_string(),
                    self.member_label.as_str(),
                ),
            )
    }
}

/// A principal was removed from a group.
#[derive(Debug)]
pub struct GroupMemberRemoved {
    /// The group the principal was removed from.
    pub(crate) group_id: GroupId,
    /// The group's name at the time of the removal, for the audit trail.
    pub(crate) group_label: EventLabel,
    /// The principal who was removed.
    pub(crate) member: PrincipalRef,
    /// The removed member's display label, for the audit trail.
    pub(crate) member_label: EventLabel,
    /// When the removal occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    GroupMemberRemoved => crate::types::event_type::AuthorizationEvent::GroupMemberRemoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "group",
                Reference::new(
                    RefKind::GROUP,
                    self.group_id.to_string(),
                    self.group_label.as_str(),
                ),
            )
            .reference(
                "member",
                Reference::new(
                    self.member.ref_kind(),
                    self.member.id().to_string(),
                    self.member_label.as_str(),
                ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::events::roles::RoleAssigned;
    use crate::shared::events::event::DomainEventCore;
    use crate::test_support::builders::label;
    use crate::types::{ActorRef, UserId};

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// A role granted by a user names that granter, and one granted by the
    /// system names none.
    #[test]
    fn assignment_references_name_only_a_human_granter() {
        let user_id = UserId::new();

        let assigned = RoleAssigned {
            holder: PrincipalRef::User(user_id),
            holder_label: EventLabel::of("ada@acme.com"),
            role_id: RoleId::new(),
            role_label: EventLabel::of("editor"),
            assigned_by: ActorRef::User(user_id),
            granted_by_label: Some(EventLabel::of("root@acme.com")),
            until: crate::types::Expiry::Never,
            occurred_at: now(),
        };
        assert!(assigned.payload().value("granted_by").is_some());

        let unattributed = RoleAssigned {
            assigned_by: ActorRef::System,
            granted_by_label: None,
            ..assigned
        };
        assert!(unattributed.payload().value("granted_by").is_none());
    }

    /// A group nested under "staff" names its parent, and a top-level group names none.
    #[test]
    fn group_references_name_only_an_existing_parent() {
        let nested = GroupCreated {
            group_id: GroupId::new(),
            name: label("engineering"),
            parent: NestedUnder::Group {
                id: GroupId::new(),
                label: EventLabel::of("staff"),
            },
            occurred_at: now(),
        };
        assert!(nested.payload().value("parent").is_some());

        let root = GroupCreated {
            parent: NestedUnder::TopLevel,
            ..nested
        };
        assert!(root.payload().value("parent").is_none());
    }

    /// Backend moves from the top of the tree to under Engineering. The
    /// record names Engineering as the new parent and no old one, so a
    /// reader sees where the members' new rights came from.
    #[test]
    fn a_move_names_the_new_parent_and_the_old_one() {
        let moved = GroupMoved {
            group_id: GroupId::new(),
            group_label: EventLabel::of("backend"),
            from: NestedUnder::TopLevel,
            to: NestedUnder::Group {
                id: GroupId::new(),
                label: EventLabel::of("engineering"),
            },
            occurred_at: now(),
        };

        assert!(moved.payload().value("parent").is_some());
        assert!(moved.payload().value("previous_parent").is_none());
    }
}
