//! An organization's members: listing them, inviting and accepting,
//! their roles in the organization and in its tenants, their status, and
//! what they reach.

use super::{OrgPath, Request, with_query};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::organization::{
    AcceptMemberInvitation, ChangeMemberEmail, ChangeMemberPassword, ChangeMemberStatus,
    ChangeRole, CreateMember, GrantableRole, InviteMember, Member, MemberAddress, MemberInvited,
    MemberJoined, MemberPasswordReset, Reach, ResetMemberPassword, TenantRoles,
};
use crate::wire::people::LinkToken;

/// `GET …/users`, those whose address contains `email` when one is named.
#[must_use]
pub fn list(org: &OrgPath, email: Option<&str>) -> Request<Page<Member>> {
    let pairs: Vec<(&str, &str)> = email.map(|email| ("email", email)).into_iter().collect();
    Request::of(Call::get(with_query(&org.at("/users"), &pairs)))
}

/// `POST …/users`: invites someone; the link is mailed.
#[must_use]
pub fn invite(org: &OrgPath, invitation: &InviteMember) -> Request<MemberInvited> {
    Request::of(Call::post(org.at("/users")).json(invitation))
}

/// Provisions an active member with an unverified mailbox and a chosen password.
#[must_use]
pub fn create(org: &OrgPath, account: &CreateMember) -> Request<MemberJoined> {
    Request::of(Call::post(org.at("/users/create")).json(account))
}

/// Hands the signed-in owner's ownership to another active member.
#[must_use]
pub fn transfer_ownership(org: &OrgPath, heir: &str) -> Request<()> {
    Request::of(Call::post(
        org.at(&format!("/users/{heir}/transfer-ownership")),
    ))
}

/// `POST …/users/accept-invitation`: accepts with the mailed token.
#[must_use]
pub fn accept_invitation(org: &OrgPath, accept: &AcceptMemberInvitation) -> Request<MemberJoined> {
    Request::of(Call::post(org.at("/users/accept-invitation")).json(accept))
}

/// `PATCH …/users/{id}/role`.
#[must_use]
pub fn change_role(org: &OrgPath, member_id: &str, change: &ChangeRole) -> Request<()> {
    Request::of(Call::patch(org.at(&format!("/users/{member_id}/role"))).json(change))
}

/// `PATCH …/users/{id}/status`.
#[must_use]
pub fn change_status(org: &OrgPath, member_id: &str, change: &ChangeMemberStatus) -> Request<()> {
    Request::of(Call::patch(org.at(&format!("/users/{member_id}/status"))).json(change))
}

/// `PUT …/users/{id}/tenants/{tenant}`: the member's roles in one tenant.
#[must_use]
pub fn set_tenant_roles(
    org: &OrgPath,
    member_id: &str,
    tenant_slug: &str,
    roles: &TenantRoles,
) -> Request<()> {
    let path = org.at(&format!("/users/{member_id}/tenants/{tenant_slug}"));
    Request::of(Call::put(path).json(roles))
}

/// `GET …/tenants/{tenant}/grantable-roles`: the role names a member can be
/// given there.
#[must_use]
pub fn grantable_roles(org: &OrgPath, tenant_slug: &str) -> Request<Page<GrantableRole>> {
    Request::of(Call::get(
        org.at(&format!("/tenants/{tenant_slug}/grantable-roles")),
    ))
}

/// `GET …/users/{id}/access`: what the member reaches.
#[must_use]
pub fn access(org: &OrgPath, member_id: &str) -> Request<Reach> {
    Request::of(Call::get(org.at(&format!("/users/{member_id}/access"))))
}

/// `GET …/me/access`: what the calling member reaches, as their dashboard
/// is built from it.
#[must_use]
pub fn my_access(org: &OrgPath) -> Request<Reach> {
    Request::of(Call::get(org.at("/me/access")))
}

/// `DELETE …/users/{id}`.
#[must_use]
pub fn remove(org: &OrgPath, member_id: &str) -> Request<()> {
    Request::of(Call::delete(org.at(&format!("/users/{member_id}"))))
}

/// `GET …/me`: the caller's own account.
#[must_use]
pub fn me(org: &OrgPath) -> Request<Member> {
    Request::of(Call::get(org.at("/me")))
}

/// `POST …/password/change`: changes the caller's password with current proof.
#[must_use]
pub fn change_password(org: &OrgPath, change: &ChangeMemberPassword) -> Request<()> {
    Request::of(Call::post(org.at("/password/change")).json(change))
}

/// `POST …/users/{id}/reset-password`: resets another member's password.
#[must_use]
pub fn reset_password(
    org: &OrgPath,
    member_id: &str,
    reset: &ResetMemberPassword,
) -> Request<MemberPasswordReset> {
    Request::of(Call::post(org.at(&format!("/users/{member_id}/reset-password"))).json(reset))
}

/// `POST …/users/{id}/mfa/reset`: clears another member's lost second factor.
#[must_use]
pub fn reset_factor(org: &OrgPath, member_id: &str) -> Request<()> {
    Request::of(Call::post(org.at(&format!("/users/{member_id}/mfa/reset"))))
}

/// `PATCH …/users/{id}/email`: an administrator moves a member to a new
/// address, unverified, and mails a link to confirm it there.
#[must_use]
pub fn change_email(org: &OrgPath, member_id: &str, change: &ChangeMemberEmail) -> Request<()> {
    Request::of(Call::patch(org.at(&format!("/users/{member_id}/email"))).json(change))
}

/// `POST …/users/{id}/welcome`: mails a member a notice that an account
/// was made for them.
#[must_use]
pub fn welcome(org: &OrgPath, member_id: &str) -> Request<()> {
    Request::of(Call::post(org.at(&format!("/users/{member_id}/welcome"))))
}

/// `POST …/users/send-verification`: asks for another mailbox proof for
/// an address in this organization; nobody need be signed in.
#[must_use]
pub fn send_verification(org: &OrgPath, address: &MemberAddress) -> Request<()> {
    Request::of(Call::post(org.at("/users/send-verification")).json(address))
}

/// `POST /api/v1/users/send-verification`: the same request with no
/// organization named: every account at the address is asked for.
#[must_use]
pub fn send_verification_anywhere(address: &MemberAddress) -> Request<()> {
    Request::of(Call::post("/api/v1/users/send-verification").json(address))
}

/// `POST …/users/verify-email`: a provisioned member proves their mailbox
/// with the mailed token, once; nobody need be signed in.
#[must_use]
pub fn verify_email(org: &OrgPath, proof: &LinkToken) -> Request<()> {
    Request::of(Call::post(org.at("/users/verify-email")).json(proof))
}
