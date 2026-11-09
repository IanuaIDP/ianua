//! Resume log target: start shipping to a paused log shipping target again.

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

/// The ports [`ResumeLogTargetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResumeLogTargetPorts {
    /// Keeps the tenant's log shipping targets.
    pub log_shipping_store: Arc<dyn LogShippingStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Resumes a paused log shipping target.
pub struct ResumeLogTargetUseCase {
    ports: ResumeLogTargetPorts,
}

impl ResumeLogTargetUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResumeLogTargetPorts) -> Self {
        Self { ports }
    }
}

impl Command for ResumeLogTargetUseCase {
    type Caller = CallerContext;
    type Input = LogShippingTargetId;
    type Output = Result<(), AppError>;

    /// Starts shipping to the target again and records
    /// `proxy.log_target_resumed`. Records of requests made while it was
    /// paused are not sent.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` when the tenant has no such target.
    /// - `AppError::Domain` when it is already active.
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
                |target| target.resume(&control),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::domains::proxy::log_shipping::LogTargetStatus;
    use ianua_domain::shared::events::raised::Raises as _;
    use ianua_domain::test_support::authority::anyone_holding;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::{FakeLogShippingStore, test_log_target};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store, the audit trail and the use case a test works with.
    struct Fixture {
        targets: Arc<FakeLogShippingStore>,
        audit: Arc<FakeEventDispatcher>,
        target_id: LogShippingTargetId,
        use_case: ResumeLogTargetUseCase,
    }

    /// A fixture holding Ann's SIEM target, paused, whose caller holds what
    /// `authorities` say.
    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let mut target = test_log_target();
        let admin = RoutingControl::new(anyone_holding(SystemPermission::all()));
        target.pause(&admin).unwrap();
        let _ = target.take_events(&test_ctx().tenant());
        let target_id = *target.id();
        let targets = Arc::new(FakeLogShippingStore::holding(
            test_ctx().tenant_id(),
            target,
        ));
        Fixture {
            use_case: ResumeLogTargetUseCase::new(ResumeLogTargetPorts {
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

    /// Ann resumes her SIEM target after maintenance. It ships again and
    /// the resumption is recorded.
    #[test]
    fn a_paused_target_is_resumed() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, f.target_id).unwrap();

        assert_eq!(status(&f), LogTargetStatus::Active);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["proxy.log_target_resumed"]
        );
    }

    /// Resuming a target that is already active is refused.
    #[test]
    fn an_active_target_is_not_resumed_again() {
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

    /// A routing viewer cannot resume the SIEM target; it stays paused and
    /// no resumption is audited.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Routing(RoutingAction::View)]);
        let f = fixture(viewer);

        let result = run(&f, f.target_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status(&f), LogTargetStatus::Paused);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot resume the target, which stays paused.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, f.target_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status(&f), LogTargetStatus::Paused);
    }
}
