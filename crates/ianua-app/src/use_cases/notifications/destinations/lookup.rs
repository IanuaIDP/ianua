//! Loading the destination a caller names.

use ianua_domain::domains::notifications::destination::NotificationDestination;
use ianua_domain::message;
use ianua_domain::types::{NotificationDestinationId, OrganizationId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::notifications::NotificationDestinationStore;

/// The organization's destination `id`.
///
/// # Errors
///
/// - `AppError::NotFound` when the organization has no such destination.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_destination(
    store: &dyn NotificationDestinationStore,
    organization_id: &OrganizationId,
    id: &NotificationDestinationId,
) -> Result<NotificationDestination, AppError> {
    store
        .find(organization_id, id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "notifications-notification-destination-not-found",
            "notification destination not found"
        ))
}
