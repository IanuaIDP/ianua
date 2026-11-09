//! Loading the OAuth client, API key, device authorization, pushed request
//! or initial access token a use case names, which most of the OAuth use
//! cases start with.

use ianua_domain::domains::oauth::clients::api_key::ApiKey;
use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::registration::InitialAccessToken;
use ianua_domain::domains::oauth::grants::device_authorization::DeviceAuthorization;
use ianua_domain::domains::oauth::grants::pushed_request::{PushedRequest, RequestUri};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    ApiKeyId, ClientId, DeviceUserCode, InitialAccessTokenId, OAuthClientId,
};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::oauth::{
    ApiKeyStore, DeviceAuthStore, InitialAccessTokenStore, OAuthClientStore, PushedRequestStore,
};
use crate::tenancy::ScopedTenant;

/// The tenant's OAuth client with `client_id`, whatever its status.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such client.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_client(
    store: &dyn OAuthClientStore,
    tenant: &ScopedTenant,
    client_id: &OAuthClientId,
) -> Result<OAuthClient<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, client_id)
        .await
        .or_internal()?
        .or_not_found(message!("oauth-client-not-found", "client not found"))
}

/// The tenant's OAuth client whose public client id is `client_id`, the
/// `cli_...` value it names itself by, whatever its status.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such client.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_client_by_client_id(
    store: &dyn OAuthClientStore,
    tenant: &ScopedTenant,
    client_id: &ClientId,
) -> Result<OAuthClient<ResolvedTenant>, AppError> {
    store
        .find_by_client_id_value(tenant, client_id)
        .await
        .or_internal()?
        .or_not_found(message!("oauth-client-not-found", "client not found"))
}

/// The tenant's pushed authorization request `request_uri` names, used or
/// not.
///
/// # Errors
///
/// - `AppError::NotFound` if no request has that `request_uri`, or it was
///   let go after it expired.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_pushed_request(
    store: &dyn PushedRequestStore,
    tenant: &ScopedTenant,
    request_uri: &RequestUri,
) -> Result<PushedRequest<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, request_uri.id())
        .await
        .or_internal()?
        .or_not_found(message!(
            "oauth-pushed-authorization-request-not-found",
            "pushed authorization request not found"
        ))
}

/// The tenant's initial access token with `id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such token.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_initial_access_token(
    store: &dyn InitialAccessTokenStore,
    tenant: &ScopedTenant,
    id: &InitialAccessTokenId,
) -> Result<InitialAccessToken<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "oauth-initial-access-token-not-found",
            "initial access token not found"
        ))
}

/// The tenant's device authorization behind the user-facing `user_code`.
///
/// # Errors
///
/// - `AppError::NotFound` if no authorization carries that code.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_device_authorization_for_user_code(
    store: &dyn DeviceAuthStore,
    tenant: &ScopedTenant,
    user_code: &DeviceUserCode,
) -> Result<DeviceAuthorization<ResolvedTenant>, AppError> {
    store
        .find_by_user_code(tenant, user_code)
        .await
        .or_internal()?
        .or_not_found(message!(
            "oauth-device-authorization-not-found",
            "device authorization not found"
        ))
}

/// The tenant's API key with `key_id`.
///
/// Revoked keys are deleted, so a revoked key reads as not found.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such key.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_api_key(
    store: &dyn ApiKeyStore,
    tenant: &ScopedTenant,
    key_id: &ApiKeyId,
) -> Result<ApiKey<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, key_id)
        .await
        .or_internal()?
        .or_not_found(message!("oauth-api-key-not-found", "API key not found"))
}

/// What a write to an API key that only lands while the key is kept
/// answers. A key revoked after it was read was not written back, and
/// reads as not found, as it would have a moment later.
///
/// # Errors
///
/// - `AppError::NotFound` when the key was revoked meanwhile.
/// - `AppError::Internal` when the write failed.
pub(super) fn ensure_key_still_kept(write: Result<bool, DomainError>) -> Result<(), AppError> {
    write
        .or_internal()?
        .then_some(())
        .or_not_found(message!("oauth-api-key-not-found", "API key not found"))
}
