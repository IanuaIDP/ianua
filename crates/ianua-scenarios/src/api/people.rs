//! A tenant's users: listing and reading them, registering and inviting,
//! accepting an invitation, changing a record or a status, and removing
//! someone.

use super::{Request, TenantPath, with_query};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::audit::AuditEntry;
use crate::wire::people::{
    AcceptInvitation, ChangeUserStatus, FactorsCleared, ImportProgress, ImportStarted, ImportUsers,
    InviteUser, LinkStatus, LinkToken, User, UserChange, UserDetails, UserInvited, UserJoined,
    UserRecords,
};

/// `GET …/users`, those whose address contains `email` when one is named.
#[must_use]
pub fn list(tenant: &TenantPath, email: Option<&str>) -> Request<Page<User>> {
    let pairs: Vec<(&str, &str)> = email.map(|email| ("email", email)).into_iter().collect();
    Request::of(Call::get(with_query(&tenant.at("/users"), &pairs)))
}

/// `GET …/users/{id}`.
#[must_use]
pub fn get(tenant: &TenantPath, user_id: &str) -> Request<User> {
    Request::of(Call::get(tenant.at(&format!("/users/{user_id}"))))
}

/// `PUT …/users/{id}/details`: replaces a person's own details.
#[must_use]
pub fn change_details(tenant: &TenantPath, user_id: &str, details: &UserDetails) -> Request<()> {
    Request::of(Call::put(tenant.at(&format!("/users/{user_id}/details"))).json(details))
}

/// `PUT …/users/{id}/records`: replaces what the company's directory holds
/// about a person.
#[must_use]
pub fn change_records(tenant: &TenantPath, user_id: &str, records: &UserRecords) -> Request<()> {
    Request::of(Call::put(tenant.at(&format!("/users/{user_id}/records"))).json(records))
}

/// `POST …/users/import`: keeps an import of accounts and queues its
/// work.
#[must_use]
pub fn import(tenant: &TenantPath, batch: &ImportUsers) -> Request<ImportStarted> {
    Request::of(Call::post(tenant.at("/users/import")).json(batch))
}

/// `GET …/users/imports/{id}`: how far the import got.
#[must_use]
pub fn import_progress(tenant: &TenantPath, import_id: &str) -> Request<ImportProgress> {
    Request::of(Call::get(tenant.at(&format!("/users/imports/{import_id}"))))
}

/// `POST …/users/invite`: invites someone with one role; the link is
/// mailed.
#[must_use]
pub fn invite(tenant: &TenantPath, invitation: &InviteUser) -> Request<UserInvited> {
    Request::of(Call::post(tenant.at("/users/invite")).json(invitation))
}

/// `POST …/users/invitation-status`: what a mailed invitation is worth.
#[must_use]
pub fn invitation_status(tenant: &TenantPath, token: &LinkToken) -> Request<LinkStatus> {
    Request::of(Call::post(tenant.at("/users/invitation-status")).json(token))
}

/// `POST …/users/accept-invitation`: accepts with the mailed token.
#[must_use]
pub fn accept_invitation(tenant: &TenantPath, accept: &AcceptInvitation) -> Request<UserJoined> {
    Request::of(Call::post(tenant.at("/users/accept-invitation")).json(accept))
}

/// `PATCH …/users/{id}`.
#[must_use]
pub fn change(tenant: &TenantPath, user_id: &str, change: &UserChange) -> Request<()> {
    Request::of(Call::patch(tenant.at(&format!("/users/{user_id}"))).json(change))
}

/// `POST …/users/{id}/status`: locks, deactivates or lets back in.
#[must_use]
pub fn change_status(tenant: &TenantPath, user_id: &str, change: &ChangeUserStatus) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!("/users/{user_id}/status"))).json(change))
}

/// `DELETE …/users/{id}`.
#[must_use]
pub fn remove(tenant: &TenantPath, user_id: &str) -> Request<()> {
    Request::of(Call::delete(tenant.at(&format!("/users/{user_id}"))))
}

/// `GET …/me`: the signed-in user's own record.
#[must_use]
pub fn me(tenant: &TenantPath) -> Request<User> {
    Request::of(Call::get(tenant.at("/me")))
}

/// `POST …/users/{id}/send-reset-link`: mails the user a link to choose
/// their own password, so the administrator never learns it.
#[must_use]
pub fn send_reset_link(tenant: &TenantPath, user_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/users/{user_id}/send-reset-link"));
    Request::of(Call::post(path))
}

/// `POST …/users/{id}/send-welcome`: mails the user that their account
/// exists and where to sign in.
#[must_use]
pub fn send_welcome(tenant: &TenantPath, user_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/users/{user_id}/send-welcome"));
    Request::of(Call::post(path))
}

/// `POST …/users/{id}/reset-factors`: clears the second factor and
/// passkeys of someone who lost their device.
#[must_use]
pub fn reset_factors(tenant: &TenantPath, user_id: &str) -> Request<FactorsCleared> {
    let path = tenant.at(&format!("/users/{user_id}/reset-factors"));
    Request::of(Call::post(path))
}

/// `POST …/users/{id}/deactivate`: switches the account off and ends its
/// sessions.
#[must_use]
pub fn deactivate(tenant: &TenantPath, user_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/users/{user_id}/deactivate"));
    Request::of(Call::post(path))
}

/// `GET …/users/{id}/sign-ins`: the user's sign-ins and failed attempts,
/// newest first.
#[must_use]
pub fn sign_ins(tenant: &TenantPath, user_id: &str) -> Request<Page<AuditEntry>> {
    Request::of(Call::get(tenant.at(&format!("/users/{user_id}/sign-ins"))))
}
