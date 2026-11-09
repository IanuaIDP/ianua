//! Get log target: one place the tenant ships its request records to.

use std::sync::Arc;

use ianua_domain::types::LogShippingTargetId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::proxy::LogShippingStore;
use crate::use_case::Query;
use crate::use_cases::proxy::log_shipping::lookup::existing_log_target;
use crate::use_cases::proxy::log_shipping::view::LogTargetView;
use crate::use_cases::routing::lookup::ensure_may_view_routing;

/// The ports [`GetLogTargetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetLogTargetPorts {
    /// Keeps the tenant's log shipping targets.
    pub log_shipping_store: Arc<dyn LogShippingStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one log shipping target.
pub struct GetLogTargetUseCase {
    ports: GetLogTargetPorts,
}

impl GetLogTargetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetLogTargetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetLogTargetUseCase {
    type Caller = CallerContext;
    type Input = LogShippingTargetId;
    type Output = Result<LogTargetView, AppError>;

    /// The target, showing whether it holds a credential but never the
    /// credential.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view routing.
    /// - `AppError::NotFound` when the tenant has no such target.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        target_id: LogShippingTargetId,
    ) -> Result<LogTargetView, AppError> {
        ensure_may_view_routing(self.ports.tenant_authorities.as_ref(), caller).await?;
        let store = self.ports.log_shipping_store.as_ref();
        let target = existing_log_target(store, &caller.tenant(), &target_id).await?;
        Ok(LogTargetView::from(&target))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{FakeLogShippingStore, log_target_name, test_log_target};
    use crate::test_support::{block_on, test_ctx};

    /// Reads `target_id`, as `authorities` allow, from `store`.
    fn get(
        store: FakeLogShippingStore,
        authorities: FakeTenantAuthorities,
        target_id: LogShippingTargetId,
    ) -> Result<LogTargetView, AppError> {
        let use_case = GetLogTargetUseCase::new(GetLogTargetPorts {
            log_shipping_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), target_id))
    }

    /// Bob, who may view routing, reads Ann's SIEM target.
    #[test]
    fn a_target_is_read() {
        let target = test_log_target();
        let id = *target.id();
        let store = FakeLogShippingStore::holding(test_ctx().tenant_id(), target);

        let view = get(store, FakeTenantAuthorities::holding_everything(), id).unwrap();

        assert_eq!(view.name, log_target_name("siem"));
    }

    /// Looking up a target stored for another tenant returns not found.
    #[test]
    fn another_tenants_target_is_not_found() {
        let target = test_log_target();
        let id = *target.id();
        let store = FakeLogShippingStore::holding(TenantId::new(), target);

        let result = get(store, FakeTenantAuthorities::holding_everything(), id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller without routing view rights cannot read the stored SIEM target.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let target = test_log_target();
        let id = *target.id();
        let store = FakeLogShippingStore::holding(test_ctx().tenant_id(), target);

        let result = get(store, FakeTenantAuthorities::holding(&[]), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading a target with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = get(
            FakeLogShippingStore::default(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            LogShippingTargetId::new(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
