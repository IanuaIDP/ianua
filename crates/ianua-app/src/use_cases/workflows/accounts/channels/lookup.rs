//! Finding an account's channel for the use cases that set it up.

use ianua_domain::domains::workflows::triggers::channel::AccountChannel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::IntegrationAccountId;

use crate::error::{AppError, OrInternal};
use crate::ports::workflows::AccountChannelStore;
use crate::tenancy::ScopedTenant;

/// The channel of `account`.
///
/// # Errors
///
/// - `AppError::NotFound` when no workflow has opened one yet.
/// - `AppError::Internal` when the store fails.
pub(super) async fn existing_channel(
    channels: &dyn AccountChannelStore,
    tenant: &ScopedTenant,
    account: &IntegrationAccountId,
) -> Result<AccountChannel<ResolvedTenant>, AppError> {
    channels
        .of_account(tenant, account)
        .await
        .or_internal()?
        .ok_or_else(|| {
            AppError::NotFound(message!(
                "workflows-integration-account-channel",
                "integration account channel"
            ))
        })
}
