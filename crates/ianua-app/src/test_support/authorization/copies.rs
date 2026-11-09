//! Copies of the authorization records that do not implement `Clone`, read
//! back through their `reconstitute` the way storage reads them, so a fake
//! hands out what a real store would and refuses what it would refuse.

use ianua_domain::domains::authorization::access_request::{AccessRequest, AccessRequestRow};
use ianua_domain::domains::authorization::access_review::{AccessReview, AccessReviewRow};
use ianua_domain::domains::authorization::break_glass::{BreakGlassGrant, BreakGlassGrantRow};
use ianua_domain::domains::authorization::clearance::{ClearanceRules, ClearanceRulesRow};
use ianua_domain::domains::authorization::group::{
    Group, GroupMembership, GroupMembershipRow, GroupRow,
};
use ianua_domain::domains::authorization::relationship::{Relationship, RelationshipRow};
use ianua_domain::domains::authorization::role_assignment::{RoleAssignment, RoleAssignmentRow};
use ianua_domain::domains::authorization::separation::{SeparationRule, SeparationRuleRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PrincipalRef, Revocation};

/// The principal-kind words in the ordering used by stored holding cursors.
pub(crate) fn principal_sort_word(principal: &PrincipalRef) -> &'static str {
    match principal {
        PrincipalRef::Agent(_) => "agent",
        PrincipalRef::Consumer(_) => "consumer",
        PrincipalRef::OrgUser(_) => "org_user",
        PrincipalRef::User(_) => "user",
    }
}

/// Reconstitutes the request from stored fields for an independent fake-store read.
pub(crate) fn copy_access_request(
    request: &AccessRequest<ResolvedTenant>,
) -> Result<AccessRequest<ResolvedTenant>, DomainError> {
    AccessRequest::reconstitute(AccessRequestRow {
        id: *request.id(),
        requester: request.requester().clone(),
        asked: request.asked(),
        reason: request.reason().clone(),
        length: request.length(),
        status: request.status(),
        answer: request.answer().clone(),
        requested_at: request.requested_at(),
    })
}

/// Reconstitutes the review from stored fields without sharing mutable state.
pub(crate) fn copy_access_review(
    review: &AccessReview<ResolvedTenant>,
) -> Result<AccessReview<ResolvedTenant>, DomainError> {
    AccessReview::reconstitute(AccessReviewRow {
        id: *review.id(),
        name: review.name().clone(),
        scope: review.scope(),
        reviewers: review.reviewers().to_vec(),
        due: review.due(),
        unanswered: review.unanswered(),
        holder_count: review.holder_count(),
        pending_count: review.pending_count(),
        remove_count: review.remove_count(),
        status: review.status(),
        started_at: review.started_at(),
    })
}

/// Reconstitutes the relation from stored fields for an independent fake-store read.
pub(crate) fn copy_relationship(
    relationship: &Relationship<ResolvedTenant>,
) -> Result<Relationship<ResolvedTenant>, DomainError> {
    Relationship::reconstitute(RelationshipRow {
        id: *relationship.id(),
        object: relationship.object().clone(),
        link: relationship.link().clone(),
        created_at: relationship.created_at(),
    })
}

/// Reconstitutes the conflicting-role rule from its stored fields.
pub(crate) fn copy_separation_rule(
    rule: &SeparationRule<ResolvedTenant>,
) -> Result<SeparationRule<ResolvedTenant>, DomainError> {
    let (first, second) = rule.roles();
    SeparationRule::reconstitute(SeparationRuleRow {
        id: *rule.id(),
        name: rule.name().clone(),
        first: *first,
        second: *second,
        created_at: rule.created_at(),
    })
}

/// A copy of `rules`.
pub(crate) fn copy_clearance(
    rules: &ClearanceRules<ResolvedTenant>,
) -> Result<ClearanceRules<ResolvedTenant>, DomainError> {
    ClearanceRules::reconstitute(ClearanceRulesRow {
        rules: rules
            .rules()
            .iter()
            .map(|rule| (rule.permission().clone(), rule.up_to()))
            .collect(),
        updated_at: rules.updated_at(),
    })
}

/// Reconstitutes the grant with its original principal, role and expiry.
pub(crate) fn copy_assignment(
    assignment: &RoleAssignment<ResolvedTenant>,
) -> Result<RoleAssignment<ResolvedTenant>, DomainError> {
    RoleAssignment::reconstitute(RoleAssignmentRow {
        principal: *assignment.principal(),
        role_id: *assignment.role_id(),
        assigned_by: assignment.assigned_by().clone(),
        assigned_at: assignment.assigned_at(),
        expires: assignment.expires(),
    })
}

/// Reconstitutes the membership container from its stored fields.
pub(crate) fn copy_group(
    group: &Group<ResolvedTenant>,
) -> Result<Group<ResolvedTenant>, DomainError> {
    Group::reconstitute(GroupRow {
        id: *group.id(),
        name: group.name().clone(),
        origin: group.origin(),
        place: *group.place(),
        role_ids: group.role_ids().to_vec(),
        created_at: group.created_at(),
        updated_at: group.updated_at(),
    })
}

/// Reconstitutes the principal's membership with its original lifetime.
pub(crate) fn copy_membership(
    membership: &GroupMembership<ResolvedTenant>,
) -> Result<GroupMembership<ResolvedTenant>, DomainError> {
    GroupMembership::reconstitute(GroupMembershipRow {
        principal: *membership.principal(),
        group_id: *membership.group_id(),
        joined_at: membership.joined_at(),
        expires: membership.expires(),
    })
}

/// A copy of `grant`.
pub(crate) fn copy_break_glass(grant: &BreakGlassGrant) -> Result<BreakGlassGrant, DomainError> {
    BreakGlassGrant::reconstitute(BreakGlassGrantRow {
        id: *grant.id(),
        tenant_id: *grant.tenant_id(),
        user_id: *grant.user_id(),
        grantee_person: grant.grantee_person().clone(),
        access: grant.access().clone(),
        reason: grant.reason().clone(),
        approved_by: grant.approved_by().clone(),
        expires_at: grant.expires_at(),
        revocation: Revocation::from_stored(grant.revoked_at()),
        created_at: grant.created_at(),
    })
}
