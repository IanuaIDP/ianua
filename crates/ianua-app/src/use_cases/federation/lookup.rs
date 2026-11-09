//! Loading the connection, linked account or SCIM endpoint a caller names,
//! which the use cases that change one start with, and the key a SAML
//! assertion and the identity provider's metadata are signed with.

use ianua_domain::domains::crypto::signing_key::{SigningKey, SigningKeySet};
use ianua_domain::domains::federation::connection::FederatedIdpConnection;
use ianua_domain::domains::federation::link::FederatedLink;
use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{ConnectionId, SamlResponseId, UserId};
use uuid::Uuid;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::crypto::XmlSigningKey;
use crate::ports::federation::{ConnectionStore, FederatedLinkStore, ScimStore};
use crate::tenancy::ScopedTenant;

/// The key `key_set` signs with now.
///
/// # Errors
///
/// - `AppError::Internal` if the set holds no key that signs now, which a
///   set that exists never should.
pub(crate) fn active_signing_key(
    key_set: &SigningKeySet<ResolvedTenant>,
) -> Result<&SigningKey, AppError> {
    key_set
        .active_key(clock::now())
        .ok_or_else(|| AppError::internal_msg("no active signing key"))
}

/// A new, unique id for a SAML response this platform sends: an answer to
/// a SAML app's sign-in, or to a peer's logout request.
///
/// # Errors
///
/// - `AppError::Internal` if the id is refused, which it never is.
pub(super) fn fresh_response_id() -> Result<SamlResponseId, AppError> {
    SamlResponseId::new(format!("_r{}", Uuid::now_v7().simple())).or_internal()
}

/// `key` as the XML signing ports take it.
pub(crate) fn xml_signing_key(key: &SigningKey) -> XmlSigningKey<'_> {
    XmlSigningKey {
        kid: key.kid(),
        algorithm: key.algorithm(),
        private_key: key.private_key(),
        public_key: key.public_key(),
    }
}

/// The tenant's federation connection with `id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such connection.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_connection(
    store: &dyn ConnectionStore,
    tenant: &ScopedTenant,
    id: &ConnectionId,
) -> Result<FederatedIdpConnection<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "authentication-connection-not-found",
            "connection not found"
        ))
}

/// The link `user_id` holds at `connection_id`'s provider.
///
/// # Errors
///
/// - `AppError::NotFound` if the account is not linked there.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_link(
    store: &dyn FederatedLinkStore,
    tenant: &ScopedTenant,
    connection_id: &ConnectionId,
    user_id: &UserId,
) -> Result<FederatedLink<ResolvedTenant>, AppError> {
    store
        .find_by_user(tenant, connection_id, user_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "federation-the-account-is-not-linked-through",
            "the account is not linked through this connection"
        ))
}

/// The tenant's SCIM endpoint, enabled or not.
///
/// # Errors
///
/// - `AppError::NotFound` if SCIM was never set up for the tenant.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_scim_endpoint(
    store: &dyn ScimStore,
    tenant: &ScopedTenant,
) -> Result<ScimEndpoint<ResolvedTenant>, AppError> {
    store
        .find(tenant)
        .await
        .or_internal()?
        .or_not_found(message!(
            "federation-scim-is-not-set-up",
            "SCIM is not set up"
        ))
}
