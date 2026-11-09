//! Reaching the tenant's own model provider for a person's request, such
//! as drafting workflow steps or writing a sandbox's code: the provider
//! must be the tenant's and active, and its key is opened for this call
//! only.

use ianua_domain::domains::agents::execution::model_provider::ModelProvider;
use ianua_domain::message;
use ianua_domain::types::ModelProviderId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::agents::{ModelProviderStore, ModelTarget};
use crate::ports::authentication::SecretEncryptor;
use crate::tenancy::ScopedTenant;
use crate::use_cases::agents::model_providers::connect::opened_key;

/// Where the tenant's active model provider `id` is reached.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant has no such active provider.
/// - `AppError::Internal` when the store or opening its key fails.
pub(crate) async fn active_model(
    providers: &dyn ModelProviderStore,
    encryptor: &dyn SecretEncryptor,
    tenant: &ScopedTenant,
    id: &ModelProviderId,
) -> Result<ModelTarget, AppError> {
    let provider = providers
        .find_by_id(tenant, id)
        .await
        .or_internal()?
        .filter(ModelProvider::is_active)
        .or_not_found(message!("workflows-model-provider", "model provider"))?;
    let api_key = opened_key(encryptor, tenant, &provider)
        .await
        .or_internal()?;
    Ok(ModelTarget {
        kind: provider.kind(),
        endpoint: provider.endpoint().clone(),
        model: provider.model().clone(),
        api_key,
    })
}
