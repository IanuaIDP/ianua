//! Rows of the authorization context.
//!
//! Every builder makes a record valid by default, dated from the fixed
//! moment of [`at`], and a test changes what it is about with struct
//! update syntax on the matching `*_row` builder.
//!
//! # Panics
//!
//! Every builder panics when given a name, key or address that is not a
//! valid one, which is a mistake in the test.

use ianua_app::ports::authorization::{DecisionBasis, DecisionRecord, MatchedRule};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::access_check::{
    AccessDecision, AccessQuestion, AllowedBy, CheckTarget, DeniedBecause,
};
use ianua_domain::domains::authorization::access_request::{
    AccessRequest, AccessRequestRow, AccessRequestStatus, AskedAccess, RequestAnswer,
};
use ianua_domain::domains::authorization::clearance::{ClearanceRules, ClearanceRulesRow};
use ianua_domain::domains::authorization::group::{
    Group, GroupMembership, GroupMembershipRow, GroupOrigin, GroupPlace, GroupRow,
};
use ianua_domain::domains::authorization::permission::{
    CustomPermission, PermissionSegment, RoleAction, SystemPermission,
};
use ianua_domain::domains::authorization::policy::action::PolicyAction;
use ianua_domain::domains::authorization::policy::condition::PolicyCondition;
use ianua_domain::domains::authorization::policy::review::Submission;
use ianua_domain::domains::authorization::policy::rule::PolicyRule;
use ianua_domain::domains::authorization::policy::set::{PolicySet, PolicySetRow};
use ianua_domain::domains::authorization::policy::status::PolicyStatus;
use ianua_domain::domains::authorization::policy::version::{PolicyVersion, VersionBase};
use ianua_domain::domains::authorization::relationship::{
    ObjectKey, ObjectRef, RelationLink, RelationSubject, Relationship, RelationshipRow,
};
use ianua_domain::domains::authorization::request_policy::{
    AccessRequestPolicy, AccessRequestPolicyRow,
};
use ianua_domain::domains::authorization::resource_type::{
    ActionDefinition, ResourceType, ResourceTypeRow,
};
use ianua_domain::domains::authorization::role::{DefaultAssignment, Role, RoleRow};
use ianua_domain::domains::authorization::role_assignment::{RoleAssignment, RoleAssignmentRow};
use ianua_domain::domains::authorization::separation::{SeparationRule, SeparationRuleRow};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{
    AccessRequestId, ActorRef, ApiKeyId, DecisionRecordId, Expiry, GroupId, Human, HumanAccount,
    Label, Lifetime, PathPrefix, PersonKey, PrincipalRef, RelationshipId, ResourceTypeId, RoleId,
    SeparationRuleId, TenantId, Text, UserId,
};
use time::{Duration, OffsetDateTime};

use crate::test_support::rows::at;

/// A tenant of its own, as a request resolves it.
#[must_use]
pub fn tenant() -> ScopedTenant {
    ScopedTenant::for_background(TenantId::new())
}

/// A name as a label.
#[must_use]
pub fn label(name: &str) -> Label {
    Label::new("name", name).expect("a valid name")
}

/// A key or an action as a permission segment.
#[must_use]
pub fn segment(value: &str) -> PermissionSegment {
    PermissionSegment::new("segment", value).expect("a valid segment")
}

/// The person at `address`, signed in through the tenant account `user`.
#[must_use]
pub fn human(user: UserId, address: &str) -> Human {
    Human::new(
        HumanAccount::User(user),
        PersonKey::new(address).expect("a valid address"),
    )
}

/// The row of a role called `name` that may view roles and read projects,
/// given only when assigned.
#[must_use]
pub fn role_row(name: &str) -> RoleRow {
    RoleRow {
        id: RoleId::new(),
        name: label(name),
        system_permissions: vec![SystemPermission::Roles(RoleAction::View)],
        custom_permissions: vec![CustomPermission::new("project", "read").expect("a permission")],
        is_default: DefaultAssignment::Manual,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// A role called `name`, as [`role_row`] describes it.
#[must_use]
pub fn role(name: &str) -> Role<ResolvedTenant> {
    Role::reconstitute(role_row(name)).expect("a consistent role")
}

/// A role called `name` every new user gets.
#[must_use]
pub fn default_role(name: &str) -> Role<ResolvedTenant> {
    Role::reconstitute(RoleRow {
        is_default: DefaultAssignment::NewUsers,
        ..role_row(name)
    })
    .expect("a consistent role")
}

/// `role_id` given straight to `principal` by the platform, ending at
/// `expires`.
#[must_use]
pub fn assignment_until(
    principal: PrincipalRef,
    role_id: RoleId,
    expires: Expiry,
) -> RoleAssignment<ResolvedTenant> {
    RoleAssignment::reconstitute(RoleAssignmentRow {
        principal,
        role_id,
        assigned_by: ActorRef::System,
        assigned_at: at(0),
        expires,
    })
    .expect("a consistent assignment")
}

/// `role_id` given straight to `principal` by the platform, with no end.
#[must_use]
pub fn assignment(principal: PrincipalRef, role_id: RoleId) -> RoleAssignment<ResolvedTenant> {
    assignment_until(principal, role_id, Expiry::Never)
}

/// `role_id` given straight to `principal` two days before now, ended a
/// day before now: for reads that ask what is in force at this moment.
#[must_use]
pub fn ended_assignment(
    principal: PrincipalRef,
    role_id: RoleId,
) -> RoleAssignment<ResolvedTenant> {
    let now = OffsetDateTime::now_utc();
    RoleAssignment::reconstitute(RoleAssignmentRow {
        principal,
        role_id,
        assigned_by: ActorRef::System,
        assigned_at: now.saturating_sub(Duration::days(2)),
        expires: Expiry::At(now.saturating_sub(Duration::days(1))),
    })
    .expect("a consistent assignment")
}

/// The row of a dashboard group called `name` at the top of the tree,
/// carrying no role.
#[must_use]
pub fn group_row(name: &str) -> GroupRow {
    GroupRow {
        id: GroupId::new(),
        name: label(name),
        origin: GroupOrigin::Dashboard,
        place: GroupPlace::TopLevel,
        role_ids: Vec::new(),
        created_at: at(0),
        updated_at: at(0),
    }
}

/// A dashboard group called `name` at the top of the tree, carrying
/// `role_ids`.
#[must_use]
pub fn group(name: &str, role_ids: Vec<RoleId>) -> Group<ResolvedTenant> {
    Group::reconstitute(GroupRow {
        role_ids,
        ..group_row(name)
    })
    .expect("a consistent group")
}

/// A dashboard group called `name` sitting at `place`, carrying no role.
#[must_use]
pub fn group_under(name: &str, place: GroupPlace) -> Group<ResolvedTenant> {
    Group::reconstitute(GroupRow {
        place,
        ..group_row(name)
    })
    .expect("a consistent group")
}

/// `principal` in `group_id` since `joined`, with no end.
#[must_use]
pub fn joined_at(
    principal: PrincipalRef,
    group_id: GroupId,
    joined: OffsetDateTime,
) -> GroupMembership<ResolvedTenant> {
    GroupMembership::reconstitute(GroupMembershipRow {
        principal,
        group_id,
        joined_at: joined,
        expires: Expiry::Never,
    })
    .expect("a consistent membership")
}

/// `principal` in `group_id`, ending at `expires`.
#[must_use]
pub fn membership_until(
    principal: PrincipalRef,
    group_id: GroupId,
    expires: Expiry,
) -> GroupMembership<ResolvedTenant> {
    GroupMembership::reconstitute(GroupMembershipRow {
        principal,
        group_id,
        joined_at: at(0),
        expires,
    })
    .expect("a consistent membership")
}

/// `principal` in `group_id` from two days before now, ended a day before
/// now: for reads that ask what is in force at this moment.
///
/// # Panics
///
/// Never: the membership ends after it began.
#[must_use]
pub fn ended_membership(
    principal: PrincipalRef,
    group_id: GroupId,
) -> GroupMembership<ResolvedTenant> {
    let now = OffsetDateTime::now_utc();
    GroupMembership::reconstitute(GroupMembershipRow {
        principal,
        group_id,
        joined_at: now.saturating_sub(Duration::days(2)),
        expires: Expiry::At(now.saturating_sub(Duration::days(1))),
    })
    .expect("a consistent membership")
}

/// `principal` in `group_id`, with no end.
#[must_use]
pub fn membership(principal: PrincipalRef, group_id: GroupId) -> GroupMembership<ResolvedTenant> {
    membership_until(principal, group_id, Expiry::Never)
}

/// The row of a resource type keyed `key` holding internal data, with
/// `read` and a `write` that brings it.
#[must_use]
pub fn resource_type_row(key: &str) -> ResourceTypeRow {
    ResourceTypeRow {
        id: ResourceTypeId::new(),
        key: segment(key),
        display_name: label(key),
        description: Some(Text::new("description", "What the app keeps").expect("a valid text")),
        actions: vec![
            ActionDefinition::new(segment("read"), label("Read"), Vec::new()),
            ActionDefinition::new(segment("write"), label("Write"), vec![segment("read")]),
        ],
        created_at: at(0),
        updated_at: at(0),
        data_class: DataClassLevel::Internal,
    }
}

/// A resource type keyed `key`, as [`resource_type_row`] describes it.
#[must_use]
pub fn resource_type(key: &str) -> ResourceType<ResolvedTenant> {
    ResourceType::reconstitute(resource_type_row(key)).expect("a consistent resource type")
}

/// The object of type `resource_type` the app keys `key`.
#[must_use]
pub fn object(resource_type: &str, key: &str) -> ObjectRef {
    ObjectRef::new(
        segment(resource_type),
        ObjectKey::new(key).expect("a valid key"),
    )
}

/// The relationship written at `written` saying `link` about `object`.
fn relationship(
    object: ObjectRef,
    link: RelationLink,
    written: OffsetDateTime,
) -> Relationship<ResolvedTenant> {
    Relationship::reconstitute(RelationshipRow {
        id: RelationshipId::new(),
        object,
        link,
        created_at: written,
    })
    .expect("a consistent relationship")
}

/// `subject` holding `relation` on `object`, written at `written`.
#[must_use]
pub fn holds(
    object: ObjectRef,
    relation: &str,
    subject: RelationSubject,
    written: OffsetDateTime,
) -> Relationship<ResolvedTenant> {
    let link = RelationLink::Holds {
        relation: segment(relation),
        subject,
    };
    relationship(object, link, written)
}

/// `object` sitting under `parent`, written at `written`.
#[must_use]
pub fn under(
    object: ObjectRef,
    parent: ObjectRef,
    written: OffsetDateTime,
) -> Relationship<ResolvedTenant> {
    relationship(object, RelationLink::Under(parent), written)
}

/// A rule called `name` keeping `first` and `second` apart.
#[must_use]
pub fn separation(name: &str, first: &RoleId, second: &RoleId) -> SeparationRule<ResolvedTenant> {
    SeparationRule::reconstitute(SeparationRuleRow {
        id: SeparationRuleId::new(),
        name: label(name),
        first: *first,
        second: *second,
        created_at: at(0),
    })
    .expect("a consistent separation rule")
}

/// Clearance rules, each written `resource:action` with the level it
/// clears for, changed last at `updated`.
#[must_use]
pub fn clearance(
    rules: &[(&str, DataClassLevel)],
    updated: OffsetDateTime,
) -> ClearanceRules<ResolvedTenant> {
    ClearanceRules::reconstitute(ClearanceRulesRow {
        rules: rules
            .iter()
            .map(|(permission, level)| {
                (
                    CustomPermission::parse(permission).expect("a permission"),
                    *level,
                )
            })
            .collect(),
        updated_at: updated,
    })
    .expect("consistent clearance rules")
}

/// The longest a tenant lets its people ask for access, set at `updated`.
#[must_use]
pub fn request_policy(
    longest: Lifetime,
    updated: OffsetDateTime,
) -> AccessRequestPolicy<ResolvedTenant> {
    AccessRequestPolicy::reconstitute(AccessRequestPolicyRow {
        longest,
        updated_at: updated,
    })
    .expect("a consistent limit")
}

/// The row of a pending request for two hours in a group, asked at
/// `asked` by the person at `address` through a tenant account.
#[must_use]
pub fn pending_request_row(address: &str, asked: OffsetDateTime) -> AccessRequestRow {
    AccessRequestRow {
        id: AccessRequestId::new(),
        requester: human(UserId::new(), address),
        asked: AskedAccess::Group(GroupId::new()),
        reason: Text::new("reason", "on call tonight").expect("a valid reason"),
        length: Lifetime::seconds(2 * 3600).expect("a valid length"),
        status: AccessRequestStatus::Pending,
        answer: RequestAnswer::Unanswered,
        requested_at: asked,
    }
}

/// A pending request, as [`pending_request_row`] describes it.
#[must_use]
pub fn pending_request(address: &str, asked: OffsetDateTime) -> AccessRequest<ResolvedTenant> {
    AccessRequest::reconstitute(pending_request_row(address, asked)).expect("a consistent request")
}

/// `request` approved at `answered` by the person at `approver`.
#[must_use]
pub fn approved_request(
    request: &AccessRequest<ResolvedTenant>,
    approver: &str,
    answered: OffsetDateTime,
) -> AccessRequest<ResolvedTenant> {
    AccessRequest::reconstitute(AccessRequestRow {
        id: *request.id(),
        requester: request.requester().clone(),
        asked: request.asked(),
        reason: request.reason().clone(),
        length: request.length(),
        status: AccessRequestStatus::Approved,
        answer: RequestAnswer::By {
            approver: human(UserId::new(), approver),
            at: answered,
        },
        requested_at: request.requested_at(),
    })
    .expect("a consistent approval")
}

/// The rule `block-admin`, which denies every path under `/admin`.
#[must_use]
pub fn block_admin_rule() -> PolicyRule {
    PolicyRule::new(
        label("block-admin"),
        vec![PolicyCondition::PathPrefix(
            PathPrefix::new("/admin").expect("a valid prefix"),
        )],
        PolicyAction::Deny {
            reason: Text::new("reason", "admin blocked").expect("a valid reason"),
        },
        10,
    )
    .expect("a valid rule")
}

/// Version `number` of a policy holding [`block_admin_rule`] that denies
/// what it does not match, in `status`: started blank when it is the
/// first, copied from the one before otherwise, and sent to review by
/// someone unless it is a draft.
#[must_use]
pub fn policy_version(number: u32, status: PolicyStatus) -> PolicySet {
    let version = PolicyVersion::from_stored(number).expect("a version number");
    let based_on = match number {
        1 => VersionBase::Blank,
        later => VersionBase::CopyOf(
            PolicyVersion::from_stored(later.saturating_sub(1)).expect("a version number"),
        ),
    };
    let submitted = match status {
        PolicyStatus::Draft => Submission::NotSubmitted,
        PolicyStatus::Review | PolicyStatus::Active | PolicyStatus::Archived => {
            Submission::By(human(UserId::new(), "pat@acme.example"))
        }
    };
    PolicySet::reconstitute(PolicySetRow {
        rules: vec![block_admin_rule()],
        default_action: PolicyAction::Deny {
            reason: Text::new("reason", "closed").expect("a valid reason"),
        },
        status,
        version,
        based_on,
        submitted,
    })
    .expect("a consistent policy version")
}

/// The question an app asks: may the subject read any project.
fn reading_projects() -> AccessQuestion {
    AccessQuestion::new(segment("read"), CheckTarget::AnyOf(segment("project")))
}

/// The record of an app's check, made at `decided`, that let `subject`
/// read projects through the permission it holds.
#[must_use]
pub fn allowed_check(subject: PrincipalRef, decided: OffsetDateTime) -> DecisionRecord {
    DecisionRecord {
        id: DecisionRecordId::new(),
        asked_by: ActorRef::ApiKey(ApiKeyId::new()),
        subject,
        basis: DecisionBasis::AppCheck {
            question: reading_projects(),
            decision: AccessDecision::Allowed(AllowedBy::Permission(
                CustomPermission::new("project", "read").expect("a permission"),
            )),
        },
        decided_at: decided,
    }
}

/// The record of an app's check, made at `decided`, that refused
/// `subject` reading projects, since nothing they hold gives it.
#[must_use]
pub fn refused_check(subject: PrincipalRef, decided: OffsetDateTime) -> DecisionRecord {
    DecisionRecord {
        basis: DecisionBasis::AppCheck {
            question: reading_projects(),
            decision: AccessDecision::Denied(DeniedBecause::NotHeld),
        },
        ..allowed_check(subject, decided)
    }
}

/// The record of a request the policy's `version` let through at
/// `decided`, settled by `matched`.
#[must_use]
pub fn policy_decision(
    version: PolicyVersion,
    matched: MatchedRule,
    decided: OffsetDateTime,
) -> DecisionRecord {
    DecisionRecord {
        id: DecisionRecordId::new(),
        asked_by: ActorRef::System,
        subject: PrincipalRef::User(UserId::new()),
        basis: DecisionBasis::Policy {
            version,
            matched,
            action: PolicyAction::Allow,
        },
        decided_at: decided,
    }
}
