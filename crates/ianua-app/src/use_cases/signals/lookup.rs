//! Loading the signal stream a caller names, which every use case that works
//! on one starts with.

use ianua_domain::domains::signals::stream::SignalStream;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::SignalStreamId;

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::signals::SignalStreamStore;
use crate::tenancy::ScopedTenant;

/// The tenant's signal stream with `stream_id`.
///
/// # Errors
///
/// - `AppError::NotFound` if the tenant has no such stream.
/// - `AppError::Internal` on storage failure.
pub(super) async fn existing_stream(
    store: &dyn SignalStreamStore,
    tenant: &ScopedTenant,
    stream_id: &SignalStreamId,
) -> Result<SignalStream<ResolvedTenant>, AppError> {
    store
        .find_by_id(tenant, stream_id)
        .await
        .or_internal()?
        .or_not_found(message!(
            "signals-signal-stream-not-found",
            "signal stream not found"
        ))
}
