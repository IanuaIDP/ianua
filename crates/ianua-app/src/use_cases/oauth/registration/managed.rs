//! A self-registered client proving, with its registration access token,
//! that a request to manage its registration comes from it (RFC 7592 2).

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::registration::SelfManagement;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::ClientId;

use crate::error::{AppError, OrInternal};
use crate::input::validate_token;
use crate::ports::oauth::{CodeHasher, OAuthClientStore};
use crate::tenancy::ScopedTenant;

/// The ports a client managing its own registration needs.
#[derive(ianua_macros::Fakes)]
pub struct SelfManagementPorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Hashes the presented registration access token.
    pub code_hasher: Arc<dyn CodeHasher>,
}

/// What a client brings to manage its registration.
pub struct ManagingClient {
    /// The client, by the public id it names itself by.
    pub client_id: ClientId,
    /// Its registration access token.
    pub registration_token: Secret,
}

/// The client `managing` names, with the proof it manages itself.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the client is unknown, revoked, did
///   not register itself, or the token is not its own: which of those is
///   never said.
/// - `AppError::Internal` when hashing or the lookup fails.
pub(super) async fn self_managed(
    ports: &SelfManagementPorts,
    tenant: &ScopedTenant,
    managing: &ManagingClient,
) -> Result<(OAuthClient<ResolvedTenant>, SelfManagement), AppError> {
    validate_token(
        "registration_access_token",
        managing.registration_token.expose(),
    )
    .map_err(|_| AppError::Unauthenticated)?;
    let client = ports
        .client_store
        .find_by_client_id_value(tenant, &managing.client_id)
        .await
        .or_internal()?
        .ok_or(AppError::Unauthenticated)?;
    let presented = ports
        .code_hasher
        .hash_code(&managing.registration_token)
        .await
        .or_internal()?;
    let proof = client
        .managed_by_itself(&presented)
        .map_err(|_| AppError::Unauthenticated)?;
    Ok((client, proof))
}
