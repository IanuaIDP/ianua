//! Notification inboxes: a tenant user's in their tenant and a member's
//! in their organization, each with its unread count, read marks and the
//! channel chosen per category.

use super::{OrgPath, Request, TenantPath, with_query};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::notifications::{
    MarkedRead, Notification, Preference, PreferencesChange, UnreadCount,
};

/// `GET …/tenants/{tenant}/notifications`: the caller's inbox, newest
/// first.
#[must_use]
pub fn inbox(tenant: &TenantPath) -> Request<Page<Notification>> {
    Request::of(Call::get(tenant.at("/notifications")))
}

/// `GET …/tenants/{tenant}/notifications?unread_only=true`: what the
/// caller has not read yet.
#[must_use]
pub fn unread(tenant: &TenantPath) -> Request<Page<Notification>> {
    let path = with_query(&tenant.at("/notifications"), &[("unread_only", "true")]);
    Request::of(Call::get(path))
}

/// `GET …/tenants/{tenant}/notifications/unread-count`.
#[must_use]
pub fn unread_count(tenant: &TenantPath) -> Request<UnreadCount> {
    Request::of(Call::get(tenant.at("/notifications/unread-count")))
}

/// `POST …/tenants/{tenant}/notifications/{id}/read`: one notice read.
#[must_use]
pub fn mark_read(tenant: &TenantPath, notification_id: &str) -> Request<()> {
    let path = tenant.at(&format!("/notifications/{notification_id}/read"));
    Request::of(Call::post(path))
}

/// `POST …/tenants/{tenant}/notifications/read-all`.
#[must_use]
pub fn mark_all_read(tenant: &TenantPath) -> Request<MarkedRead> {
    Request::of(Call::post(tenant.at("/notifications/read-all")))
}

/// `GET …/tenants/{tenant}/notifications/preferences`.
#[must_use]
pub fn preferences(tenant: &TenantPath) -> Request<Vec<Preference>> {
    Request::of(Call::get(tenant.at("/notifications/preferences")))
}

/// `PATCH …/tenants/{tenant}/notifications/preferences`.
#[must_use]
pub fn change_preferences(
    tenant: &TenantPath,
    change: &PreferencesChange,
) -> Request<Vec<Preference>> {
    let path = tenant.at("/notifications/preferences");
    Request::of(Call::patch(path).json(change))
}

/// `GET /organizations/{org}/notifications?unread_only=true`: what the
/// member has not read yet.
#[must_use]
pub fn member_unread(org: &OrgPath) -> Request<Page<Notification>> {
    let path = with_query(&org.at("/notifications"), &[("unread_only", "true")]);
    Request::of(Call::get(path))
}

/// `GET /organizations/{org}/notifications`: the member's inbox.
#[must_use]
pub fn member_inbox(org: &OrgPath) -> Request<Page<Notification>> {
    Request::of(Call::get(org.at("/notifications")))
}

/// `GET /organizations/{org}/notifications/unread-count`.
#[must_use]
pub fn member_unread_count(org: &OrgPath) -> Request<UnreadCount> {
    Request::of(Call::get(org.at("/notifications/unread-count")))
}

/// `POST /organizations/{org}/notifications/{id}/read`.
#[must_use]
pub fn member_mark_read(org: &OrgPath, notification_id: &str) -> Request<()> {
    let path = org.at(&format!("/notifications/{notification_id}/read"));
    Request::of(Call::post(path))
}

/// `POST /organizations/{org}/notifications/read-all`.
#[must_use]
pub fn member_mark_all_read(org: &OrgPath) -> Request<MarkedRead> {
    Request::of(Call::post(org.at("/notifications/read-all")))
}

/// `GET /organizations/{org}/notifications/preferences`.
#[must_use]
pub fn member_preferences(org: &OrgPath) -> Request<Vec<Preference>> {
    Request::of(Call::get(org.at("/notifications/preferences")))
}

/// `PATCH /organizations/{org}/notifications/preferences`.
#[must_use]
pub fn change_member_preferences(
    org: &OrgPath,
    change: &PreferencesChange,
) -> Request<Vec<Preference>> {
    let path = org.at("/notifications/preferences");
    Request::of(Call::patch(path).json(change))
}

/// `GET …/tenants/{tenant}/ws/notifications`: where a tenant user opens
/// the live stream of their own notifications.
#[must_use]
pub fn stream(tenant: &TenantPath) -> String {
    tenant.at("/ws/notifications")
}

/// `GET /organizations/{org}/ws/notifications`: where a member opens the
/// live stream of their own notifications.
#[must_use]
pub fn member_stream(org: &OrgPath) -> String {
    org.at("/ws/notifications")
}
