//! Loading the connection a step names, and where its secrets are sealed.

use ianua_domain::domains::workflows::account::connection::PendingConnection;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::PendingConnectionId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{SealOwner, SealedField, SealedFor};
use crate::ports::workflows::PendingConnectionStore;
use crate::tenancy::ScopedTenant;

/// The tenant's connection `id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant keeps no such connection.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_connection(
    store: &dyn PendingConnectionStore,
    tenant: &ScopedTenant,
    id: &PendingConnectionId,
) -> Result<PendingConnection<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "workflows-account-connection",
            "account connection"
        ))
}

/// Where `tenant`'s connection `id` keeps its PKCE verifier.
pub(super) fn verifier_place(tenant: &ScopedTenant, id: &PendingConnectionId) -> SealedFor {
    SealedFor::new(SealOwner::from(tenant), SealedField::ConnectionVerifier, id)
}

/// Where `tenant`'s connection `id` keeps the credential its service
/// issued.
pub(super) fn issued_credential_place(
    tenant: &ScopedTenant,
    id: &PendingConnectionId,
) -> SealedFor {
    SealedFor::new(
        SealOwner::from(tenant),
        SealedField::ConnectionCredential,
        id,
    )
}
