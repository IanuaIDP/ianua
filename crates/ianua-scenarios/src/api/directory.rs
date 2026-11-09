//! A tenant's directory link over SCIM 2.0: the administrator switching
//! the endpoint on, rotating its token and switching it off, and the
//! directory itself making, changing, finding and removing users and
//! groups through the protocol at
//! `/scim/v2/organizations/{org}/tenants/{tenant}`, and the service
//! accounts applications bind to the LDAP directory as.

use serde::de::IgnoredAny;
use url::form_urlencoded;

use super::{Request, TenantPath, with_query};
use crate::net::Call;
use crate::wire::directory::{
    CertificateAsked, CertificateIssued, DirectoryGroup, DirectoryGroupListing,
    DirectoryGroupResource, DirectoryListing, DirectoryPatch, DirectoryRecord, DirectoryResource,
    DirectorySearch, DirectorySettings, DirectoryStatus, DirectoryToken, DirectoryUser,
    DiscoveryListing, NewServiceAccount, ProvisionedKind, ProvisionedSchema, ProvisioningAbilities,
    ServiceAccount, ServiceAccountMade, ServiceAccountScope, ServiceAccountSecret, ServiceAccounts,
};

/// `POST …/federation/scim`: switches the endpoint on, showing its token
/// this once.
#[must_use]
pub fn enable(tenant: &TenantPath) -> Request<DirectoryToken> {
    Request::of(Call::post(tenant.at("/federation/scim")))
}

/// `GET …/federation/scim`: whether the endpoint is set up.
#[must_use]
pub fn status(tenant: &TenantPath) -> Request<DirectoryStatus> {
    Request::of(Call::get(tenant.at("/federation/scim")))
}

/// `DELETE …/federation/scim`: switches the endpoint off.
#[must_use]
pub fn disable(tenant: &TenantPath) -> Request<()> {
    Request::of(Call::delete(tenant.at("/federation/scim")))
}

/// `POST …/federation/scim/rotate-token`: a new token, the old one dead.
#[must_use]
pub fn rotate_token(tenant: &TenantPath) -> Request<DirectoryToken> {
    Request::of(Call::post(tenant.at("/federation/scim/rotate-token")))
}

/// `PUT …/federation/scim/settings`: what the endpoint does with the
/// users the directory makes and removes.
#[must_use]
pub fn replace_settings(tenant: &TenantPath, settings: &DirectorySettings) -> Request<()> {
    Request::of(Call::put(tenant.at("/federation/scim/settings")).json(settings))
}

/// `POST /scim/v2/…/Users`: the directory makes a user.
#[must_use]
pub fn create_user(tenant: &TenantPath, user: &DirectoryUser) -> Request<DirectoryResource> {
    Request::of(Call::post(protocol_path(tenant, "/Users")).json(user))
}

/// `PATCH /scim/v2/…/Users/{id}`: the directory changes a user.
#[must_use]
pub fn patch_user(
    tenant: &TenantPath,
    user_id: &str,
    patch: &DirectoryPatch,
) -> Request<DirectoryResource> {
    let path = protocol_path(tenant, &format!("/Users/{user_id}"));
    Request::of(Call::patch(path).json(patch))
}

/// `GET /scim/v2/…/Users`: the directory lists the tenant's users.
#[must_use]
pub fn list_users(tenant: &TenantPath) -> Request<DirectoryListing> {
    Request::of(Call::get(protocol_path(tenant, "/Users")))
}

/// `GET /scim/v2/…/Users?filter=…`: the users matching `filter`.
#[must_use]
pub fn find_users(tenant: &TenantPath, filter: &str) -> Request<DirectoryListing> {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("filter", filter)
        .finish();
    Request::of(Call::get(protocol_path(tenant, &format!("/Users?{query}"))))
}

/// `GET /scim/v2/…/Users/{id}`.
#[must_use]
pub fn get_user(tenant: &TenantPath, user_id: &str) -> Request<DirectoryResource> {
    Request::of(Call::get(protocol_path(
        tenant,
        &format!("/Users/{user_id}"),
    )))
}

/// `DELETE /scim/v2/…/Users/{id}`: the directory removes a user.
#[must_use]
pub fn delete_user(tenant: &TenantPath, user_id: &str) -> Request<()> {
    Request::of(Call::delete(protocol_path(
        tenant,
        &format!("/Users/{user_id}"),
    )))
}

/// `POST /scim/v2/…/Groups`: the directory makes a group.
#[must_use]
pub fn create_group(
    tenant: &TenantPath,
    group: &DirectoryGroup,
) -> Request<DirectoryGroupResource> {
    Request::of(Call::post(protocol_path(tenant, "/Groups")).json(group))
}

/// `PATCH /scim/v2/…/Groups/{id}`: the directory changes a group.
#[must_use]
pub fn patch_group(
    tenant: &TenantPath,
    group_id: &str,
    patch: &DirectoryPatch,
) -> Request<IgnoredAny> {
    let path = protocol_path(tenant, &format!("/Groups/{group_id}"));
    Request::of(Call::patch(path).json(patch))
}

/// `DELETE /scim/v2/…/Groups/{id}`: the directory removes a group.
#[must_use]
pub fn delete_group(tenant: &TenantPath, group_id: &str) -> Request<()> {
    Request::of(Call::delete(protocol_path(
        tenant,
        &format!("/Groups/{group_id}"),
    )))
}

/// `POST …/auth/ldap-service-accounts`: an administrator makes an account
/// an application binds to the LDAP directory as.
#[must_use]
pub fn create_service_account(
    tenant: &TenantPath,
    account: &NewServiceAccount,
) -> Request<ServiceAccountMade> {
    Request::of(Call::post(tenant.at("/auth/ldap-service-accounts")).json(account))
}

/// `POST …/auth/ldap-certificates`: a person asks for a client
/// certificate to bind to the LDAP directory with.
#[must_use]
pub fn issue_ldap_certificate(
    tenant: &TenantPath,
    asked: &CertificateAsked,
) -> Request<CertificateIssued> {
    Request::of(Call::post(tenant.at("/auth/ldap-certificates")).json(asked))
}

/// `GET /scim/v2/…/ServiceProviderConfig`: what the endpoint supports,
/// readable before any token.
#[must_use]
pub fn abilities(tenant: &TenantPath) -> Request<ProvisioningAbilities> {
    Request::of(Call::get(protocol_path(tenant, "/ServiceProviderConfig")))
}

/// `GET /scim/v2/…/ResourceTypes`: the kinds of record it provisions.
#[must_use]
pub fn resource_types(tenant: &TenantPath) -> Request<DiscoveryListing<ProvisionedKind>> {
    Request::of(Call::get(protocol_path(tenant, "/ResourceTypes")))
}

/// `GET /scim/v2/…/Schemas`: the attributes it reads and returns.
#[must_use]
pub fn schemas(tenant: &TenantPath) -> Request<DiscoveryListing<ProvisionedSchema>> {
    Request::of(Call::get(protocol_path(tenant, "/Schemas")))
}

/// `GET /scim/v2/…/Me`: the signed-in subject, which a directory token
/// does not name.
#[must_use]
pub fn me(tenant: &TenantPath) -> Request<IgnoredAny> {
    Request::of(Call::get(protocol_path(tenant, "/Me")))
}

/// `POST /scim/v2/…/Users`: the directory makes a user from their whole
/// record, name parts and enterprise fields included.
#[must_use]
pub fn create_record(tenant: &TenantPath, record: &DirectoryRecord) -> Request<DirectoryResource> {
    Request::of(Call::post(protocol_path(tenant, "/Users")).json(record))
}

/// `POST /scim/v2/…/Users` with `text` as the body, sent as
/// `content_type`, whatever it holds.
#[must_use]
pub fn create_user_raw(
    tenant: &TenantPath,
    content_type: &str,
    text: &str,
) -> Request<DirectoryResource> {
    Request::of(Call::post(protocol_path(tenant, "/Users")).raw(content_type, text))
}

/// `PUT /scim/v2/…/Users/{id}`: the directory replaces a user's whole
/// record with `record`.
#[must_use]
pub fn replace_user(
    tenant: &TenantPath,
    user_id: &str,
    record: &DirectoryRecord,
) -> Request<DirectoryResource> {
    let path = protocol_path(tenant, &format!("/Users/{user_id}"));
    Request::of(Call::put(path).json(record))
}

/// `GET /scim/v2/…/Users?…`: the page of users `search` asks for.
#[must_use]
pub fn search_users(tenant: &TenantPath, search: &DirectorySearch) -> Request<DirectoryListing> {
    Request::of(Call::get(search_path(tenant, "/Users", search)))
}

/// `GET /scim/v2/…/Groups/{id}`: one group the directory keeps.
#[must_use]
pub fn get_group(tenant: &TenantPath, group_id: &str) -> Request<DirectoryGroupResource> {
    Request::of(Call::get(protocol_path(
        tenant,
        &format!("/Groups/{group_id}"),
    )))
}

/// `GET /scim/v2/…/Groups?…`: the page of groups `search` asks for.
#[must_use]
pub fn search_groups(
    tenant: &TenantPath,
    search: &DirectorySearch,
) -> Request<DirectoryGroupListing> {
    Request::of(Call::get(search_path(tenant, "/Groups", search)))
}

/// `PUT /scim/v2/…/Groups/{id}`: the directory gives a group the name and
/// the members it sends, and only those.
#[must_use]
pub fn replace_group(
    tenant: &TenantPath,
    group_id: &str,
    group: &DirectoryGroup,
) -> Request<DirectoryGroupResource> {
    let path = protocol_path(tenant, &format!("/Groups/{group_id}"));
    Request::of(Call::put(path).json(group))
}

/// `GET …/auth/ldap-service-accounts`: the tenant's service accounts,
/// with no secret.
#[must_use]
pub fn service_accounts(tenant: &TenantPath) -> Request<ServiceAccounts> {
    Request::of(Call::get(tenant.at("/auth/ldap-service-accounts")))
}

/// `GET …/auth/ldap-service-accounts/{id}`: one service account, with no
/// secret.
#[must_use]
pub fn service_account(tenant: &TenantPath, account_id: &str) -> Request<ServiceAccount> {
    Request::of(Call::get(service_account_path(tenant, account_id, "")))
}

/// `POST …/auth/ldap-service-accounts/{id}/rotate-secret`: a new secret,
/// the old one dead.
#[must_use]
pub fn rotate_service_secret(
    tenant: &TenantPath,
    account_id: &str,
) -> Request<ServiceAccountSecret> {
    Request::of(Call::post(service_account_path(
        tenant,
        account_id,
        "/rotate-secret",
    )))
}

/// `POST …/auth/ldap-service-accounts/{id}/disable`: the account binds no
/// more until it is switched on again.
#[must_use]
pub fn disable_service_account(tenant: &TenantPath, account_id: &str) -> Request<()> {
    Request::of(Call::post(service_account_path(
        tenant, account_id, "/disable",
    )))
}

/// `POST …/auth/ldap-service-accounts/{id}/activate`: the account binds
/// again with the secret it had.
#[must_use]
pub fn activate_service_account(tenant: &TenantPath, account_id: &str) -> Request<()> {
    Request::of(Call::post(service_account_path(
        tenant,
        account_id,
        "/activate",
    )))
}

/// `PUT …/auth/ldap-service-accounts/{id}/scope`: what the account may
/// reach from now on.
#[must_use]
pub fn change_service_scope(
    tenant: &TenantPath,
    account_id: &str,
    scope: &ServiceAccountScope,
) -> Request<()> {
    Request::of(Call::put(service_account_path(tenant, account_id, "/scope")).json(scope))
}

/// `DELETE …/auth/ldap-service-accounts/{id}`: the account is gone.
#[must_use]
pub fn delete_service_account(tenant: &TenantPath, account_id: &str) -> Request<()> {
    Request::of(Call::delete(service_account_path(tenant, account_id, "")))
}

/// `rest` under the service account `account_id`'s path in `tenant`.
fn service_account_path(tenant: &TenantPath, account_id: &str, rest: &str) -> String {
    tenant.at(&format!("/auth/ldap-service-accounts/{account_id}{rest}"))
}

/// The listing `kind` under the protocol's base for `tenant`, with the
/// query `search` asks for.
fn search_path(tenant: &TenantPath, kind: &str, search: &DirectorySearch) -> String {
    let pairs = search.pairs();
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    with_query(&protocol_path(tenant, kind), &borrowed)
}

/// `rest` under the protocol's base for `tenant`.
fn protocol_path(tenant: &TenantPath, rest: &str) -> String {
    format!(
        "/scim/v2/organizations/{}/tenants/{}{rest}",
        tenant.organization().slug(),
        tenant.slug()
    )
}
