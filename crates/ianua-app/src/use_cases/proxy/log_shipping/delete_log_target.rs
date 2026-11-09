//! Delete log target: stop shipping to a place for good and forget it.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::LogShippingTargetId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::proxy::LogShippingStore;
use crate::use_case::Command;
use crate::use_cases::proxy::log_shipping::lookup::existing_log_target;

/// The ports [`DeleteLogTargetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeleteLogTargetPorts {
    /// Keeps the tenant's log shipping targets.
    pub log_shipping_store: Arc<dyn LogShippingStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Deletes a log shipping target.
pub struct DeleteLogTargetUseCase {
    ports: DeleteLogTargetPorts,
}

impl DeleteLogTargetUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeleteLogTargetPorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteLogTargetUseCase {
    type Caller = CallerContext;
    type Input = LogShippingTargetId;
    type Output = Result<(), AppError>;

    /// Deletes the target once the domain agrees it may go, with its sealed
    /// credential, and records `proxy.log_target_deleted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not delete routing.
    /// - `AppError::NotFound` when the tenant has no such target.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        target_id: LogShippingTargetId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.log_shipping_store.as_ref();
        let mut target = existing_log_target(store, &tenant, &target_id).await?;
        target.delete(&control).map_err(AppError::from_domain)?;
        store.delete(&tenant, &target_id).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), target.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{FakeLogShippingStore, test_log_target};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store, the audit trail and the use case a test works with.
    struct Fixture {
        targets: Arc<FakeLogShippingStore>,
        audit: Arc<FakeEventDispatcher>,
        target_id: LogShippingTargetId,
        use_case: DeleteLogTargetUseCase,
    }

    /// A fixture holding Ann's SIEM target, whose caller holds what
    /// `authorities` say.
    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let target = test_log_target();
        let target_id = *target.id();
        let targets = Arc::new(FakeLogShippingStore::holding(
            test_ctx().tenant_id(),
            target,
        ));
        Fixture {
            use_case: DeleteLogTargetUseCase::new(DeleteLogTargetPorts {
                log_shipping_store: targets.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            targets,
            audit: Arc::new(FakeEventDispatcher::new()),
            target_id,
        }
    }

    /// Runs the use case for `target_id`.
    fn run(f: &Fixture, target_id: LogShippingTargetId) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), target_id),
        )
    }

    /// Ann deletes her SIEM target. It is gone and the deletion recorded.
    #[test]
    fn a_deleted_target_is_gone_and_recorded() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, f.target_id).unwrap();

        assert_eq!(f.targets.count(), 0);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["proxy.log_target_deleted"]
        );
    }

    /// Ann deletes a target the tenant does not have. It is not found.
    #[test]
    fn an_unknown_target_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(&f, LogShippingTargetId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A routing editor cannot delete the SIEM target; it stays stored and
    /// no deletion is audited.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let editor =
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::Update)]);
        let f = fixture(editor);

        let result = run(&f, f.target_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.targets.count(), 1);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot delete the target, which remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, f.target_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(f.targets.count(), 1);
    }
}
