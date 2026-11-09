//! Changing a stored log shipping target and recording what it raised.

use ianua_domain::domains::proxy::log_shipping::LogShippingTarget;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::LogShippingTargetId;

use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::proxy::LogShippingStore;
use crate::use_cases::proxy::log_shipping::lookup::existing_log_target;

/// A person changing one of their tenant's log shipping targets, and where
/// the change is recorded.
pub(super) struct TargetChange<'a> {
    caller: &'a CallerContext,
    auditor: &'a RequestAuditor,
}

impl<'a> TargetChange<'a> {
    /// A change by the person `caller` names, recorded through `auditor`.
    pub(super) fn by(caller: &'a CallerContext, auditor: &'a RequestAuditor) -> Self {
        Self { caller, auditor }
    }

    /// Loads the tenant's target, applies `change` to it, saves the result
    /// and records what the target raised. Nothing is saved or recorded when
    /// `change` refuses.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant has no such target.
    /// - What `AppError::from_domain` makes of the refusal.
    /// - `AppError::Internal` on storage or audit failure.
    pub(super) async fn target<F>(
        &self,
        store: &dyn LogShippingStore,
        target_id: &LogShippingTargetId,
        change: F,
    ) -> Result<(), AppError>
    where
        F: FnOnce(&mut LogShippingTarget<ResolvedTenant>) -> Result<(), DomainError>,
    {
        let tenant = self.caller.tenant();
        let mut target = existing_log_target(store, &tenant, target_id).await?;
        change(&mut target).map_err(AppError::from_domain)?;
        store.save(&tenant, &target).await.or_internal()?;
        self.auditor
            .dispatch_by(&self.caller.actor(), target.take_events(&tenant))
            .await
            .or_internal()
    }
}
