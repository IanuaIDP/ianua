//! Pause log target: stop shipping to a log shipping target until it is
//! resumed.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::types::LogShippingTargetId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::proxy::LogShippingStore;
use crate::use_case::Command;
use crate::use_cases::proxy::log_shipping::target_changes::TargetChange;

/// The ports [`PauseLogTargetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PauseLogTargetPorts {
    /// Keeps the tenant's log shipping targets.
    pub log_shipping_store: Arc<dyn LogShippingStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Pauses a log shipping target.
pub struct PauseLogTargetUseCase {
    ports: PauseLogTargetPorts,
}

impl PauseLogTargetUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PauseLogTargetPorts) -> Self {
        Self { ports }
    }
}

impl Command for PauseLogTargetUseCase {
    type Caller = CallerContext;
    type Input = LogShippingTargetId;
    type Output = Result<(), AppError>;

    /// Stops shipping to the target and records `proxy.log_target_paused`.
    /// The security team watching the destination stops seeing traffic, so
    /// this is recorded like any other change.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` when the tenant has no such target.
    /// - `AppError::Domain` when it is already paused.
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
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        TargetChange::by(caller, auditor)
            .target(
                self.ports.log_shipping_store.as_ref(),
                &target_id,
                |target| target.pause(&control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::proxy::log_shipping::LogTargetStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{FakeLogShippingStore, test_log_target};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store, the audit trail and the use case a test works with.
    struct Fixture {
        targets: Arc<FakeLogShippingStore>,
        audit: Arc<FakeEventDispatcher>,
        target_id: LogShippingTargetId,
        use_case: PauseLogTargetUseCase,
    }

    /// A fixture holding Ann's active SIEM target, whose caller holds what
    /// `authorities` say.
    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let target = test_log_target();
        let target_id = *target.id();
        let targets = Arc::new(FakeLogShippingStore::holding(
            test_ctx().tenant_id(),
            target,
        ));
        Fixture {
            use_case: PauseLogTargetUseCase::new(PauseLogTargetPorts {
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

    /// The stored target's status.
    fn status(f: &Fixture) -> LogTargetStatus {
        f.targets
            .stored(test_ctx().tenant_id(), &f.target_id)
            .unwrap()
            .status()
    }

    /// Ann pauses her SIEM target during maintenance. It is paused and the
    /// pause is recorded.
    #[test]
    fn an_active_target_is_paused() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, f.target_id).unwrap();

        assert_eq!(status(&f), LogTargetStatus::Paused);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["proxy.log_target_paused"]
        );
    }

    /// Pausing a target that is already paused is refused.
    #[test]
    fn a_paused_target_is_not_paused_again() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        run(&f, f.target_id).unwrap();

        let again = run(&f, f.target_id);

        assert!(matches!(again, Err(AppError::Domain(_))));
    }

    /// Ann names a target the tenant does not have. It is not found.
    #[test]
    fn an_unknown_target_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(&f, LogShippingTargetId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A routing viewer cannot pause the SIEM target; it remains active and
    /// no pause is audited.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::View)]);
        let f = fixture(viewer);

        let result = run(&f, f.target_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status(&f), LogTargetStatus::Active);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot pause the target, which remains active.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, f.target_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status(&f), LogTargetStatus::Active);
    }
}
