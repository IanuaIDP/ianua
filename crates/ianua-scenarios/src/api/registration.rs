//! Joining what exists: a tenant's public form and its mailbox proof, a
//! verified member founding another company, and what an administrator
//! or the invitee does with a pending invitation.

use serde::de::IgnoredAny;

use crate::api::{OrgPath, Request, TenantPath};
use crate::net::Call;
use crate::wire::onboarding::Founded;
use crate::wire::organization::InvitationRenewed;
use crate::wire::people::{LinkStatus, LinkToken};
use crate::wire::registration::{AnotherCompany, SignupRules, TenantSignup};

/// `GET …/auth/sign-up`: whether the tenant's public form is open, and
/// its password rules when it is.
#[must_use]
pub fn rules(tenant: &TenantPath) -> Request<SignupRules> {
    Request::of(Call::get(tenant.at("/auth/sign-up")))
}

/// `POST …/auth/sign-up`: a visitor asks for an account through the
/// tenant's public form; the proof is mailed.
#[must_use]
pub fn sign_up(tenant: &TenantPath, form: &TenantSignup) -> Request<()> {
    Request::of(Call::post(tenant.at("/auth/sign-up")).json(form))
}

/// `POST …/users/verify-email`: proves the mailbox from the mailed link;
/// no session is needed.
#[must_use]
pub fn verify(tenant: &TenantPath, proof: &LinkToken) -> Request<()> {
    Request::of(Call::post(tenant.at("/users/verify-email")).json(proof))
}

/// `POST …/users/verify-email/resend`: asks for another proof from the
/// link in hand, expired or not.
#[must_use]
pub fn resend_verification(tenant: &TenantPath, proof: &LinkToken) -> Request<IgnoredAny> {
    Request::of(Call::post(tenant.at("/users/verify-email/resend")).json(proof))
}

/// `POST /api/v1/organizations`: a verified member founds another company
/// from their own session.
#[must_use]
pub fn another_company(form: &AnotherCompany) -> Request<Founded> {
    Request::of(Call::post("/api/v1/organizations").json(form))
}

/// `POST …/users/{id}/revoke-invitation`: an administrator withdraws a
/// pending invitation into the organization.
#[must_use]
pub fn revoke_member(org: &OrgPath, id: &str) -> Request<()> {
    Request::of(Call::post(
        org.at(&format!("/users/{id}/revoke-invitation")),
    ))
}

/// `POST …/users/{id}/resend-invitation`: an administrator mails a
/// pending invitation into the organization again, with a fresh link.
#[must_use]
pub fn resend_member(org: &OrgPath, id: &str) -> Request<IgnoredAny> {
    Request::of(Call::post(
        org.at(&format!("/users/{id}/resend-invitation")),
    ))
}

/// `POST …/users/invitation-status`: what the holder of a mailed
/// invitation link has, without spending it; nobody need be signed in.
#[must_use]
pub fn member_invitation_status(org: &OrgPath, proof: &LinkToken) -> Request<LinkStatus> {
    Request::of(Call::post(org.at("/users/invitation-status")).json(proof))
}

/// `POST …/users/invitation-resend`: the holder of a link that ran out
/// asks for another; nobody need be signed in.
#[must_use]
pub fn renew_member_invitation(org: &OrgPath, proof: &LinkToken) -> Request<InvitationRenewed> {
    Request::of(Call::post(org.at("/users/invitation-resend")).json(proof))
}

/// `POST …/users/decline-invitation`: the invitee declines the
/// organization's invitation from the mailed link.
#[must_use]
pub fn decline_member(org: &OrgPath, proof: &LinkToken) -> Request<()> {
    Request::of(Call::post(org.at("/users/decline-invitation")).json(proof))
}

/// `POST …/tenants/{tenant}/users/{id}/revoke-invitation`: an
/// administrator withdraws a pending invitation into the tenant.
#[must_use]
pub fn revoke_user(tenant: &TenantPath, id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/users/{id}/revoke-invitation")),
    ))
}

/// `POST …/tenants/{tenant}/users/{id}/resend-invitation`: an
/// administrator mails a pending invitation into the tenant again, with
/// a fresh link.
#[must_use]
pub fn resend_user(tenant: &TenantPath, id: &str) -> Request<IgnoredAny> {
    Request::of(Call::post(
        tenant.at(&format!("/users/{id}/resend-invitation")),
    ))
}

/// `POST …/tenants/{tenant}/users/decline-invitation`: the invitee
/// declines the tenant's invitation from the mailed link.
#[must_use]
pub fn decline_user(tenant: &TenantPath, proof: &LinkToken) -> Request<()> {
    Request::of(Call::post(tenant.at("/users/decline-invitation")).json(proof))
}
