//! Enable consumer: let a disabled consumer authenticate again.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::ConsumersAction;
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ConsumerId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::consumers::ConsumerStore;
use crate::use_case::Command;
use crate::use_cases::consumers::lookup::existing_consumer;

/// Ports needed by the enable consumer use case.
#[derive(ianua_macros::Fakes)]
pub struct EnablePorts {
    /// Port for loading and saving consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Restores authentication for a disabled machine identity.
pub struct EnableUseCase {
    ports: EnablePorts,
}

impl EnableUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: EnablePorts) -> Self {
        Self { ports }
    }
}

impl Command for EnableUseCase {
    type Caller = CallerContext;
    type Input = ConsumerId;
    type Output = Result<(), AppError>;

    /// Re-enables a disabled consumer and records
    /// `consumers.consumer_enabled`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update consumers,
    ///   whether or not the consumer exists.
    /// - `AppError::NotFound` if the consumer doesn't exist.
    /// - `AppError::Domain` when the consumer is already active.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        consumer_id: ConsumerId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = ConsumerControl::new(&authority);
        control
            .ensure_may(ConsumersAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut consumer =
            existing_consumer(self.ports.consumer_store.as_ref(), &tenant, &consumer_id).await?;
        consumer.enable(&control).map_err(AppError::from_domain)?;

        self.ports
            .consumer_store
            .save(&tenant, &consumer)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), consumer.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{
        FakeConsumerStore, consumers_of_test_tenant, disabled_billing_sync,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn run(
        use_case: &EnableUseCase,
        consumer_id: ConsumerId,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result =
            block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), consumer_id));
        (result, audit)
    }

    fn with_authorities(
        store: Arc<FakeConsumerStore>,
        authorities: FakeTenantAuthorities,
    ) -> EnableUseCase {
        EnableUseCase::new(EnablePorts {
            consumer_store: store,
            tenant_authorities: Arc::new(authorities),
            ..EnablePorts::fakes()
        })
    }

    /// Ann turns "billing-sync" back on once its key was replaced. It is
    /// active again, and that is on record.
    #[test]
    fn a_consumer_is_enabled_and_recorded() {
        let consumer = disabled_billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let use_case = with_authorities(store.clone(), FakeTenantAuthorities::holding_everything());

        let (result, audit) = run(&use_case, id);

        result.unwrap();
        assert!(store.find_by_id_direct(&id).unwrap().is_active());
        assert_eq!(
            audit.records.lock().unwrap()[0],
            "consumers.consumer_enabled"
        );
    }

    /// A viewer cannot enable billing-sync; it stays disabled and no event is recorded.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let consumer = disabled_billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Consumers(ConsumersAction::View)]);

        let (result, audit) = run(&with_authorities(store.clone(), viewer), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!store.find_by_id_direct(&id).unwrap().is_active());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Enabling a consumer requires a caller whose sign-in remains valid.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = disabled_billing_sync();
        let id = *consumer.id();
        let refusing = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let (result, _) = run(
            &with_authorities(consumers_of_test_tenant(consumer), refusing),
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A consumer the tenant does not have is not found, and nothing is
    /// recorded.
    #[test]
    fn enabling_an_unknown_consumer_is_not_found() {
        let use_case = with_authorities(
            Arc::new(FakeConsumerStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, audit) = run(&use_case, ConsumerId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Enabling an unknown consumer still returns forbidden when update rights are missing.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_consumer() {
        let use_case = with_authorities(
            Arc::new(FakeConsumerStore::empty()),
            FakeTenantAuthorities::holding(&[]),
        );

        let (result, _) = run(&use_case, ConsumerId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
