//! Loading the SAML app a caller or a message names, and the keys its
//! messages are checked against.

use ianua_domain::domains::federation::service_provider::{
    RequestSigningRule, SamlServiceProvider,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{SamlEntityId, SamlServiceProviderId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::federation::{SamlServiceProviderStore, SignatureTrust};
use crate::tenancy::ScopedTenant;

/// The tenant's SAML app with `id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such app.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::federation) async fn existing_service_provider(
    store: &dyn SamlServiceProviderStore,
    tenant: &ScopedTenant,
    id: &SamlServiceProviderId,
) -> Result<SamlServiceProvider<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "federation-saml-app-not-found",
            "SAML app not found"
        ))
}

/// The tenant's SAML app whose entity id a message names as its issuer.
///
/// # Errors
///
/// - `AppError::Forbidden` if the tenant has no app of that name: a
///   message from a stranger is refused, not looked into.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::federation) async fn sending_service_provider(
    store: &dyn SamlServiceProviderStore,
    tenant: &ScopedTenant,
    issuer: &SamlEntityId,
) -> Result<SamlServiceProvider<ResolvedTenant>, AppError> {
    store
        .find_by_entity_id(tenant, issuer)
        .await
        .or_internal()?
        .ok_or_else(|| {
            AppError::Forbidden(message!(
                "federation-unknown-sp",
                format!("unknown SP: {}", issuer.as_str())
            ))
        })
}

/// The keys an app's messages are checked against: its registered
/// certificate when it signs, none when it was set up not to.
pub(in crate::use_cases::federation) fn signature_trust(
    rule: &RequestSigningRule,
) -> SignatureTrust {
    match rule {
        RequestSigningRule::NotRequired => SignatureTrust::NotRequired,
        RequestSigningRule::Required(certificate) => {
            SignatureTrust::SignedBy(vec![certificate.clone()])
        }
    }
}
