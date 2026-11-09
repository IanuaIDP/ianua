//! Authorization domain events.

/// Events about just-in-time access requests.
pub mod access_requests;
/// Events about access reviews.
pub mod access_reviews;
/// Events about the tenant's break-glass policy.
pub mod break_glass;
/// Events about which app permissions clear for which data.
pub mod clearance;
/// Events about groups, their members and the roles they carry.
pub mod groups;
/// Events about policies: their rules, review, activation and simulation.
pub mod policies;
/// Events about relationships on the objects of a tenant's app.
pub mod relationships;
/// Events about the resource types a tenant declares.
pub mod resource_types;
/// Events about roles, their permissions and who holds them.
pub mod roles;
/// Events about separation-of-duties rules.
pub mod separation;

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::domains::authorization::access_request::AskedAccess;
    use crate::domains::authorization::access_review::{ReviewChoice, ReviewScope};
    use crate::domains::authorization::break_glass::SelfService;
    use crate::domains::authorization::events::access_requests::*;
    use crate::domains::authorization::events::access_reviews::*;
    use crate::domains::authorization::events::break_glass::*;
    use crate::domains::authorization::events::clearance::*;
    use crate::domains::authorization::events::groups::*;
    use crate::domains::authorization::events::policies::*;
    use crate::domains::authorization::events::relationships::*;
    use crate::domains::authorization::events::resource_types::*;
    use crate::domains::authorization::events::roles::*;
    use crate::domains::authorization::events::separation::*;
    use crate::domains::authorization::permission::{
        CustomPermission, PermissionSegment, PermissionSet, SystemPermission,
    };
    use crate::domains::authorization::policy::action::PolicyAction;
    use crate::domains::authorization::policy::version::{PolicyVersion, VersionBase};
    use crate::domains::authorization::relationship::{
        ObjectKey, ObjectRef, RelationLink, RelationSubject,
    };
    use crate::domains::authorization::role::DefaultAssignment;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::shared::events::event::DomainEventCore;
    use crate::test_support::builders::label;
    use crate::types::{
        AccessRequestId, AccessReviewId, ActorRef, Enablement, EventLabel, Expiry, GroupId,
        Lifetime, PrincipalRef, RelationshipId, ResourceTypeId, RoleId, SeparationRuleId, Text,
        UrlPath, UserId,
    };

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn project() -> ObjectRef {
        ObjectRef::new(
            PermissionSegment::new("resource", "project").unwrap(),
            ObjectKey::new("42").unwrap(),
        )
    }

    fn payroll() -> CustomPermission {
        CustomPermission::new("payroll", "read").unwrap()
    }

    /// Every event this module defines. The tests run over this one list,
    /// so a new event added here is checked too.
    /// The exhaustive inventory stays inline so convention checks find every event.
    #[allow(clippy::too_many_lines)]
    fn every_event() -> Vec<Box<dyn DomainEventCore>> {
        let role_id = RoleId::new();
        let user_id = UserId::new();
        let group_id = GroupId::new();
        let resource_type_id = ResourceTypeId::new();
        let request_id = AccessRequestId::new();
        let review_id = AccessReviewId::new();

        vec![
            Box::new(RoleCreated {
                role_id,
                name: label("editor"),
                occurred_at: now(),
            }),
            Box::new(RoleAssigned {
                holder: PrincipalRef::User(user_id),
                holder_label: EventLabel::of("ada@acme.com"),
                role_id,
                role_label: EventLabel::of("editor"),
                assigned_by: ActorRef::User(user_id),
                granted_by_label: Some(EventLabel::of("root@acme.com")),
                until: Expiry::Never,
                occurred_at: now(),
            }),
            Box::new(RoleRevoked {
                holder: PrincipalRef::User(user_id),
                holder_label: EventLabel::of("ada@acme.com"),
                role_id,
                role_label: EventLabel::of("editor"),
                occurred_at: now(),
            }),
            Box::new(RoleDeleted {
                role_id,
                name: label("editor"),
                occurred_at: now(),
            }),
            Box::new(RoleReassigned {
                from_role_id: role_id,
                from_role_label: EventLabel::of("editor"),
                to_role_id: RoleId::new(),
                to_role_label: EventLabel::of("viewer"),
                reassigned_count: 3,
                occurred_at: now(),
            }),
            Box::new(RoleRenamed {
                role_id,
                old_name: label("editor"),
                new_name: label("author"),
                occurred_at: now(),
            }),
            Box::new(RoleDefaultAssignmentChanged {
                role_id,
                role_label: EventLabel::of("editor"),
                previous: DefaultAssignment::Manual,
                current: DefaultAssignment::NewUsers,
                occurred_at: now(),
            }),
            Box::new(PermissionGranted {
                role_id,
                role_label: EventLabel::of("editor"),
                permissions: PermissionSet::System(vec![SystemPermission::ManageUsers]),
                occurred_at: now(),
            }),
            Box::new(PermissionRevoked {
                role_id,
                role_label: EventLabel::of("editor"),
                permissions: PermissionSet::System(vec![SystemPermission::ManageUsers]),
                occurred_at: now(),
            }),
            Box::new(GroupCreated {
                group_id,
                name: label("engineering"),
                parent: NestedUnder::Group {
                    id: GroupId::new(),
                    label: EventLabel::of("staff"),
                },
                occurred_at: now(),
            }),
            Box::new(GroupDeleted {
                group_id,
                name: label("engineering"),
                occurred_at: now(),
            }),
            Box::new(GroupRenamed {
                group_id,
                old_name: label("engineering"),
                new_name: label("platform"),
                occurred_at: now(),
            }),
            Box::new(GroupMoved {
                group_id,
                group_label: EventLabel::of("backend"),
                from: NestedUnder::TopLevel,
                to: NestedUnder::Group {
                    id: GroupId::new(),
                    label: EventLabel::of("engineering"),
                },
                occurred_at: now(),
            }),
            Box::new(GroupRoleAssigned {
                group_id,
                group_label: EventLabel::of("engineering"),
                role_id,
                role_label: EventLabel::of("editor"),
                occurred_at: now(),
            }),
            Box::new(GroupRoleUnassigned {
                group_id,
                group_label: EventLabel::of("engineering"),
                role_id,
                role_label: EventLabel::of("editor"),
                occurred_at: now(),
            }),
            Box::new(GroupMemberAdded {
                group_id,
                group_label: EventLabel::of("engineering"),
                member: PrincipalRef::User(user_id),
                member_label: EventLabel::of("ada@acme.com"),
                until: Expiry::At(now()),
                occurred_at: now(),
            }),
            Box::new(GroupMemberRemoved {
                group_id,
                group_label: EventLabel::of("engineering"),
                member: PrincipalRef::Consumer(crate::types::ConsumerId::new()),
                member_label: EventLabel::of("billing-partner"),
                occurred_at: now(),
            }),
            Box::new(PolicyRuleAdded {
                rule_name: label("block-admin"),
                priority: 10,
                occurred_at: now(),
            }),
            Box::new(PolicyRuleRemoved {
                rule_name: label("block-admin"),
                occurred_at: now(),
            }),
            Box::new(PolicyRuleSwitched {
                rule_name: label("block-admin"),
                to: Enablement::Disabled,
                occurred_at: now(),
            }),
            Box::new(PolicyDefaultActionChanged {
                previous: PolicyAction::Allow,
                current: PolicyAction::AuditOnly,
                occurred_at: now(),
            }),
            Box::new(PolicyDraftStarted {
                rule_count: 2,
                version: PolicyVersion::FIRST,
                based_on: VersionBase::Blank,
                occurred_at: now(),
            }),
            Box::new(BreakGlassPolicyChanged {
                previous: SelfService::Off,
                current: SelfService::Off,
                occurred_at: now(),
            }),
            Box::new(PolicySubmittedForReview {
                rule_count: 4,
                version: PolicyVersion::FIRST,
                occurred_at: now(),
            }),
            Box::new(PolicyActivated {
                rule_count: 4,
                version: PolicyVersion::FIRST,
                occurred_at: now(),
            }),
            Box::new(PolicyRejected { occurred_at: now() }),
            Box::new(PolicyArchived {
                version: PolicyVersion::FIRST,
                occurred_at: now(),
            }),
            Box::new(PolicySimulated {
                simulated_path: Some(UrlPath::new("/admin").unwrap()),
                result_allowed: SimulatedDecision::Denied,
                matched_rule: Some(label("block-admin")),
                version: PolicyVersion::FIRST,
                occurred_at: now(),
            }),
            Box::new(PolicyRuleChanged {
                previous_name: label("block-admin"),
                rule_name: label("block-admin-pages"),
                priority: 10,
                occurred_at: now(),
            }),
            Box::new(PolicyRulesReordered {
                order: vec![label("block-admin"), label("allow-office")],
                occurred_at: now(),
            }),
            Box::new(RoleAssignmentExpired {
                holder: PrincipalRef::User(user_id),
                holder_label: EventLabel::of("ada@acme.com"),
                role_id,
                role_label: EventLabel::of("editor"),
                occurred_at: now(),
            }),
            Box::new(GroupMembershipExpired {
                group_id,
                group_label: EventLabel::of("engineering"),
                member: PrincipalRef::User(user_id),
                member_label: EventLabel::of("ada@acme.com"),
                occurred_at: now(),
            }),
            Box::new(AccessRequested {
                request_id,
                holder: PrincipalRef::User(user_id),
                holder_label: EventLabel::of("ada@acme.com"),
                asked: AskedAccess::Role(role_id),
                asked_label: EventLabel::of("on-call"),
                reason: Text::new("reason", "INC-42").unwrap(),
                length: Lifetime::seconds(7200).unwrap(),
                occurred_at: now(),
            }),
            Box::new(AccessRequestApproved {
                request_id,
                holder: PrincipalRef::User(user_id),
                holder_label: EventLabel::of("ada@acme.com"),
                asked: AskedAccess::Group(group_id),
                asked_label: EventLabel::of("production"),
                until: now(),
                occurred_at: now(),
            }),
            Box::new(AccessRequestDenied {
                request_id,
                holder: PrincipalRef::User(user_id),
                holder_label: EventLabel::of("ada@acme.com"),
                asked: AskedAccess::Role(role_id),
                asked_label: EventLabel::of("on-call"),
                occurred_at: now(),
            }),
            Box::new(AccessRequestCancelled {
                request_id,
                holder: PrincipalRef::User(user_id),
                holder_label: EventLabel::of("ada@acme.com"),
                occurred_at: now(),
            }),
            Box::new(AccessRequestExpired {
                request_id,
                holder: PrincipalRef::User(user_id),
                holder_label: EventLabel::of("ada@acme.com"),
                occurred_at: now(),
            }),
            Box::new(AccessRequestPolicyChanged {
                previous: Lifetime::seconds(86_400).unwrap(),
                current: Lifetime::seconds(3_600).unwrap(),
                occurred_at: now(),
            }),
            Box::new(RelationshipAdded {
                relationship_id: RelationshipId::new(),
                object: project(),
                link: RelationLink::Holds {
                    relation: PermissionSegment::new("relation", "write").unwrap(),
                    subject: RelationSubject::Principal(PrincipalRef::User(user_id)),
                },
                occurred_at: now(),
            }),
            Box::new(RelationshipRemoved {
                relationship_id: RelationshipId::new(),
                object: project(),
                link: RelationLink::Under(project()),
                occurred_at: now(),
            }),
            Box::new(AccessReviewStarted {
                review_id,
                name: label("Finance, Q3"),
                scope: ReviewScope::Group(group_id),
                scope_label: EventLabel::of("finance"),
                holder_count: 4,
                due: now(),
                occurred_at: now(),
            }),
            Box::new(AccessReviewDecided {
                review_id,
                holder: PrincipalRef::User(user_id),
                holder_label: EventLabel::of("ada@acme.com"),
                choice: ReviewChoice::Remove,
                occurred_at: now(),
            }),
            Box::new(AccessReviewSuggested {
                review_id,
                suggested: 4,
                removed: 1,
                occurred_at: now(),
            }),
            Box::new(AccessReviewCompleted {
                review_id,
                removed: 1,
                kept: 3,
                occurred_at: now(),
            }),
            Box::new(AccessReviewCancelled {
                review_id,
                occurred_at: now(),
            }),
            Box::new(SeparationRuleAdded {
                rule_id: SeparationRuleId::new(),
                name: label("raise or approve"),
                first: EventLabel::of("raise payments"),
                second: EventLabel::of("approve payments"),
                occurred_at: now(),
            }),
            Box::new(SeparationRuleRemoved {
                rule_id: SeparationRuleId::new(),
                name: label("raise or approve"),
                occurred_at: now(),
            }),
            Box::new(ClearanceRuleAdded {
                permission: payroll(),
                up_to: DataClassLevel::Confidential,
                occurred_at: now(),
            }),
            Box::new(ClearanceRuleChanged {
                permission: payroll(),
                previous: DataClassLevel::Confidential,
                up_to: DataClassLevel::Restricted,
                occurred_at: now(),
            }),
            Box::new(ClearanceRuleRemoved {
                permission: payroll(),
                occurred_at: now(),
            }),
            Box::new(ResourceTypeDeclared {
                resource_type_id,
                key: PermissionSegment::new("key", "project").unwrap(),
                display_name: label("Project"),
                action_count: 3,
                occurred_at: now(),
            }),
            Box::new(ResourceTypeUpdated {
                resource_type_id,
                key: PermissionSegment::new("key", "project").unwrap(),
                display_name: label("Project"),
                action_count: 4,
                occurred_at: now(),
            }),
            Box::new(ResourceTypeDeleted {
                resource_type_id,
                key: PermissionSegment::new("key", "project").unwrap(),
                occurred_at: now(),
            }),
        ]
    }

    /// The policy transition that carries nothing of its own.
    ///
    /// Rejecting a policy needs only the tenant and the time, both on the
    /// envelope already, so the payload is empty. Archiving names the
    /// version kept.
    const WITHOUT_PAYLOAD: [&str; 1] = ["authorization.policy_rejected"];

    /// Every event has a non-empty payload, except policy rejected, which
    /// stays empty since the envelope already holds all it says.
    #[test]
    fn every_event_carries_a_payload_unless_it_has_nothing_to_say() {
        for event in every_event() {
            let name = event.event_type().as_str().to_owned();
            let payload = event.payload();

            if WITHOUT_PAYLOAD.contains(&name.as_str()) {
                assert!(payload.is_empty(), "{name} grew a payload");
                continue;
            }

            assert!(!payload.is_empty(), "{name} has an empty payload");
        }
    }

    /// Every event type starts with `authorization.` and no two events share
    /// a type. So a subscriber can tell each event apart.
    #[test]
    fn every_event_names_itself() {
        let mut seen = std::collections::HashSet::new();

        for event in every_event() {
            let name = event.event_type().as_str().to_owned();
            assert!(name.starts_with("authorization."), "unexpected type {name}");
            assert!(seen.insert(name.clone()), "{name} listed twice");
        }
    }
}
