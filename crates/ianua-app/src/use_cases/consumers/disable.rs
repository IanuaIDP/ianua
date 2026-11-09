//! Disable consumer: stop a consumer from authenticating.

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

/// Ports needed by the disable consumer use case.
#[derive(ianua_macros::Fakes)]
pub struct DisablePorts {
    /// Port for loading and saving consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Stops a machine identity from authenticating with its credentials.
pub struct DisableUseCase {
    ports: DisablePorts,
}

impl DisableUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: DisablePorts) -> Self {
        Self { ports }
    }
}

impl Command for DisableUseCase {
    type Caller = CallerContext;
    type Input = ConsumerId;
    type Output = Result<(), AppError>;

    /// Disables a consumer, so every request using its credentials is
    /// denied, and records `consumers.consumer_disabled`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update consumers,
    ///   whether or not the consumer exists.
    /// - `AppError::NotFound` if the consumer doesn't exist.
    /// - `AppError::Domain` when the consumer is already disabled.
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
        consumer.disable(&control).map_err(AppError::from_domain)?;

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
        FakeConsumerStore, billing_sync, consumers_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn run(
        use_case: &DisableUseCase,
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
    ) -> DisableUseCase {
        DisableUseCase::new(DisablePorts {
            consumer_store: store,
            tenant_authorities: Arc::new(authorities),
            ..DisablePorts::fakes()
        })
    }

    /// Ann disables "billing-sync" after its key leaked. It is kept
    /// disabled, and that is on record.
    #[test]
    fn a_consumer_is_disabled_and_recorded() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let use_case = with_authorities(store.clone(), FakeTenantAuthorities::holding_everything());

        let (result, audit) = run(&use_case, id);

        result.unwrap();
        assert!(!store.find_by_id_direct(&id).unwrap().is_active());
        assert_eq!(
            audit.records.lock().unwrap()[0],
            "consumers.consumer_disabled"
        );
    }

    /// A viewer cannot disable billing-sync; it stays active and no event is recorded.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Consumers(ConsumersAction::View)]);

        let (result, audit) = run(&with_authorities(store.clone(), viewer), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(store.find_by_id_direct(&id).unwrap().is_active());
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot disable a consumer.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = billing_sync();
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
    fn disabling_an_unknown_consumer_is_not_found() {
        let use_case = with_authorities(
            Arc::new(FakeConsumerStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, audit) = run(&use_case, ConsumerId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A caller without update rights gets a forbidden response even for an unknown consumer.
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
