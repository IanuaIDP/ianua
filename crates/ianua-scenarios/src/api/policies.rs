//! A tenant's policy and the groups its rules name.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::policies::{
    AccessRequest, AskForGroup, BlankDraft, Group, GroupMember, GroupRead, GroupRole, NewGroup,
    NewGroupMember, NewRule, Policy, ReviewItem,
};

/// `POST …/authorization/access-requests`: the caller asks for a place in
/// a group.
#[must_use]
pub fn ask_for_group(tenant: &TenantPath, asked: &AskForGroup) -> Request<AccessRequest> {
    Request::of(Call::post(tenant.at("/authorization/access-requests")).json(asked))
}

/// `POST …/authorization/access-requests/{id}/approve`.
#[must_use]
pub fn approve_request(tenant: &TenantPath, request_id: &str) -> Request<AccessRequest> {
    Request::of(Call::post(tenant.at(&format!(
        "/authorization/access-requests/{request_id}/approve"
    ))))
}

/// `POST …/authorization/groups`.
#[must_use]
pub fn create_group(tenant: &TenantPath, group: &NewGroup) -> Request<Group> {
    Request::of(Call::post(tenant.at("/authorization/groups")).json(group))
}

/// `GET …/authorization/groups/{id}`: one group as it was kept.
#[must_use]
pub fn group(tenant: &TenantPath, group_id: &str) -> Request<GroupRead> {
    Request::of(Call::get(
        tenant.at(&format!("/authorization/groups/{group_id}")),
    ))
}

/// `POST …/authorization/groups/{id}/members`.
#[must_use]
pub fn add_member(
    tenant: &TenantPath,
    group_id: &str,
    member: &NewGroupMember,
) -> Request<serde::de::IgnoredAny> {
    let path = tenant.at(&format!("/authorization/groups/{group_id}/members"));
    Request::of(Call::post(path).json(member))
}

/// `GET …/authorization/groups/{id}/members`: the group's members, the
/// longest-standing first.
#[must_use]
pub fn members(tenant: &TenantPath, group_id: &str) -> Request<Page<GroupMember>> {
    let path = tenant.at(&format!("/authorization/groups/{group_id}/members"));
    Request::of(Call::get(path))
}

/// `DELETE …/authorization/groups/{id}/members/{kind}/{member}`: takes a
/// member out of the group; `kind` is `user` for a tenant user.
#[must_use]
pub fn remove_member(tenant: &TenantPath, group_id: &str, kind: &str, member: &str) -> Request<()> {
    let path = tenant.at(&format!(
        "/authorization/groups/{group_id}/members/{kind}/{member}"
    ));
    Request::of(Call::delete(path))
}

/// `POST …/authorization/groups/{id}/roles`: the group holds a role, so
/// its members act with it.
#[must_use]
pub fn grant_group_role(tenant: &TenantPath, group_id: &str, role: &GroupRole) -> Request<()> {
    let path = tenant.at(&format!("/authorization/groups/{group_id}/roles"));
    Request::of(Call::post(path).json(role))
}

/// `DELETE …/authorization/groups/{id}/roles/{role}`: the group holds the
/// role no more.
#[must_use]
pub fn withdraw_group_role(tenant: &TenantPath, group_id: &str, role_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/authorization/groups/{group_id}/roles/{role_id}"));
    Request::of(Call::delete(path))
}

/// `POST …/authorization/policy/draft`.
#[must_use]
pub fn start_draft(tenant: &TenantPath, draft: &BlankDraft) -> Request<Policy> {
    Request::of(Call::post(tenant.at("/authorization/policy/draft")).json(draft))
}

/// `POST …/authorization/policy/rules`.
#[must_use]
pub fn add_rule(tenant: &TenantPath, rule: &NewRule) -> Request<Policy> {
    Request::of(Call::post(tenant.at("/authorization/policy/rules")).json(rule))
}

/// `POST …/authorization/policy/status`, moving the draft on as
/// `transition` says: `submit_for_review`, then `activate` by another
/// person.
#[must_use]
pub fn move_on(tenant: &TenantPath, transition: &str) -> Request<Policy> {
    Request::of(Call::post(tenant.at("/authorization/policy/status")).json(&transition))
}

/// `GET …/authorization/access-reviews/{id}/items`: the holders a review
/// lists, in the order it listed them.
#[must_use]
pub fn review_items(tenant: &TenantPath, review_id: &str) -> Request<Page<ReviewItem>> {
    let path = tenant.at(&format!("/authorization/access-reviews/{review_id}/items"));
    Request::of(Call::get(path))
}
