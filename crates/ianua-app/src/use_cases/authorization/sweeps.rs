//! What the authorization sweeps share: keeping each change with its
//! record, one at a time, so one that fails is logged and tried on the next
//! run without stopping the rest. They walk the tenants a batch at a time
//! through `TenantBatches`.

use std::future::Future;

use crate::error::AppError;
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;

/// 1 when `work` was kept with its record, 0 when it failed and was
/// dropped, logged as `what` to be tried again on the next run.
pub(super) async fn swept(
    unit: &dyn UnitOfWork,
    what: &'static str,
    work: impl Future<Output = Result<(), AppError>> + Send,
) -> u64 {
    match kept_together(unit, work).await {
        Ok(()) => 1,
        Err(error) => {
            tracing::warn!(%error, sweep = what, "could not be swept; tried again next run");
            0
        }
    }
}
