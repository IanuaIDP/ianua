//! API keys, of a tenant and of an organization: making them, reading,
//! changing and revoking them.

use super::{OrgPath, Request, TenantPath};
use crate::net::Call;
use crate::wire::Page;
use crate::wire::api_keys::{ApiKey, ApiKeyChange, ApiKeyMade, NewApiKey, NewEndingApiKey};
use crate::wire::organization::{NewEndingOrgApiKey, NewOrgApiKey, OrgApiKey, OrgApiKeyMade};

/// `GET …/oauth/api-keys`.
#[must_use]
pub fn list(tenant: &TenantPath) -> Request<Page<ApiKey>> {
    Request::of(Call::get(tenant.at("/oauth/api-keys")))
}

/// `POST …/oauth/api-keys`: makes a key, shown this once.
#[must_use]
pub fn create(tenant: &TenantPath, key: &NewApiKey) -> Request<ApiKeyMade> {
    Request::of(Call::post(tenant.at("/oauth/api-keys")).json(key))
}

/// `POST …/oauth/api-keys`: makes a key that stops working at its end,
/// shown this once.
#[must_use]
pub fn create_ending(tenant: &TenantPath, key: &NewEndingApiKey) -> Request<ApiKeyMade> {
    Request::of(Call::post(tenant.at("/oauth/api-keys")).json(key))
}

/// `GET …/oauth/api-keys/{id}`.
#[must_use]
pub fn get(tenant: &TenantPath, key_id: &str) -> Request<ApiKey> {
    Request::of(Call::get(tenant.at(&format!("/oauth/api-keys/{key_id}"))))
}

/// `PATCH …/oauth/api-keys/{id}`.
#[must_use]
pub fn change(tenant: &TenantPath, key_id: &str, change: &ApiKeyChange) -> Request<()> {
    Request::of(Call::patch(tenant.at(&format!("/oauth/api-keys/{key_id}"))).json(change))
}

/// `POST …/oauth/api-keys/{id}/revoke`.
#[must_use]
pub fn revoke(tenant: &TenantPath, key_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/oauth/api-keys/{key_id}/revoke")),
    ))
}

/// `POST …/oauth/api-keys/{id}/pause`: the key signs in nothing until it
/// is resumed.
#[must_use]
pub fn pause(tenant: &TenantPath, key_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/oauth/api-keys/{key_id}/pause")),
    ))
}

/// `POST …/oauth/api-keys/{id}/resume`: a paused key signs in again.
#[must_use]
pub fn resume(tenant: &TenantPath, key_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/oauth/api-keys/{key_id}/resume")),
    ))
}

/// `GET …/api-keys`: the organization's own keys.
#[must_use]
pub fn list_for_organization(org: &OrgPath) -> Request<Page<OrgApiKey>> {
    Request::of(Call::get(org.at("/api-keys")))
}

/// `POST …/api-keys`: makes an organization key, shown this once.
#[must_use]
pub fn create_for_organization(org: &OrgPath, key: &NewOrgApiKey) -> Request<OrgApiKeyMade> {
    Request::of(Call::post(org.at("/api-keys")).json(key))
}

/// `POST …/api-keys`: makes an organization key that stops working at its
/// end, shown this once.
#[must_use]
pub fn create_ending_for_organization(
    org: &OrgPath,
    key: &NewEndingOrgApiKey,
) -> Request<OrgApiKeyMade> {
    Request::of(Call::post(org.at("/api-keys")).json(key))
}
