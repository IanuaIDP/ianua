//! Loading the invitation, verification token, erasure request or declared
//! attribute an identity use case names, by id or by the link mailed for it,
//! failing with not-found when there is none.

use ianua_domain::domains::identity::attribute::{
    AttributeDefinition, AttributeKey, AttributeNamespace,
};
use ianua_domain::domains::identity::invitations::invitation::Invitation;
use ianua_domain::domains::identity::privacy::erasure::ErasureRequest;
use ianua_domain::domains::identity::privacy::export::DataExportRequest;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{DataExportId, ErasureRequestId, TokenHash, UserId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::identity::{
    DataExportStore, EmailVerificationToken, ErasureRequestStore, InvitationStore,
    UserAttributeStore, VerificationTokenStore,
};
use crate::tenancy::ScopedTenant;

/// The invitation `user_id` has not accepted yet.
///
/// # Errors
///
/// - `AppError::NotFound` if the user has no pending invitation.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_invitation(
    store: &dyn InvitationStore,
    tenant: &ScopedTenant,
    user_id: &UserId,
) -> Result<Invitation<ResolvedTenant>, AppError> {
    store
        .find_pending_by_user_id(tenant, user_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-no-pending-invitation",
            "no pending invitation"
        ))
}

/// The invitation whose link hashes to `token_hash`, whatever it stands at.
///
/// # Errors
///
/// - `AppError::NotFound` if no invitation carries that link.
/// - `AppError::Internal` on storage failure.
pub(super) async fn invitation_by_link(
    store: &dyn InvitationStore,
    tenant: &ScopedTenant,
    token_hash: &TokenHash,
) -> Result<Invitation<ResolvedTenant>, AppError> {
    store
        .find_by_token_hash(tenant, token_hash)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-invalid-invitation-token",
            "invalid invitation token"
        ))
}

/// The email verification token whose hash is `token_hash`, spent or not.
///
/// # Errors
///
/// - `AppError::NotFound` if no token has that hash.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_verification_token(
    store: &dyn VerificationTokenStore,
    tenant: &ScopedTenant,
    token_hash: &TokenHash,
) -> Result<EmailVerificationToken, AppError> {
    store
        .find_by_hash(tenant, token_hash)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-invalid-verification-token",
            "invalid verification token"
        ))
}

/// The erasure request with `request_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such request.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_erasure_request(
    store: &dyn ErasureRequestStore,
    tenant: &ScopedTenant,
    request_id: &ErasureRequestId,
) -> Result<ErasureRequest<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, request_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "identity-erasure-request-not-found",
            "erasure request not found"
        ))
}

/// The export with `export_id` of `user_id`'s data. Another person's export
/// answers the same as a missing one, so its existence is not revealed.
///
/// # Errors
///
/// - `AppError::NotFound` if there is no such export of `user_id`.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_export_of(
    store: &dyn DataExportStore,
    tenant: &ScopedTenant,
    export_id: &DataExportId,
    user_id: &UserId,
) -> Result<DataExportRequest<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, export_id)
        .await
        .or_internal()?
        .filter(|export| export.user_id() == user_id)
        .or_not_found(message!(
            "identity-data-export-not-found",
            "data export not found"
        ))
}

/// The attribute the tenant declared under `key` in `namespace`, archived or
/// not.
///
/// # Errors
///
/// - `AppError::NotFound` if no attribute carries that key.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_attribute(
    store: &dyn UserAttributeStore,
    tenant: &ScopedTenant,
    namespace: AttributeNamespace,
    key: &AttributeKey,
) -> Result<AttributeDefinition<ResolvedTenant>, AppError> {
    store
        .find(tenant, namespace, key)
        .await
        .or_internal()?
        .ok_or_else(|| {
            AppError::NotFound(message!(
                "identity-no-attribute-named",
                format!("no attribute named '{key}'")
            ))
        })
}
