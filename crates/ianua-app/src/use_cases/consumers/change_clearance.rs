//! Change clearance: set the most sensitive data a consumer may receive.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::ConsumersAction;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ConsumerId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::consumers::ConsumerStore;
use crate::use_case::Command;
use crate::use_cases::consumers::lookup::existing_consumer;

/// Which consumer is cleared for what.
pub struct ChangeClearanceRequest {
    /// The consumer whose clearance changes.
    pub consumer_id: ConsumerId,
    /// The most sensitive data it may receive from now on.
    pub clearance: DataClassLevel,
}

/// Ports needed by the change clearance use case.
#[derive(ianua_macros::Fakes)]
pub struct ChangeClearancePorts {
    /// Port for loading and saving consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sets the most sensitive data a consumer may receive.
pub struct ChangeClearanceUseCase {
    ports: ChangeClearancePorts,
}

impl ChangeClearanceUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: ChangeClearancePorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeClearanceUseCase {
    type Caller = CallerContext;
    type Input = ChangeClearanceRequest;
    type Output = Result<Consumer<ResolvedTenant>, AppError>;

    /// Clears the consumer for `clearance` and returns it as saved.
    ///
    /// Raising it lets the consumer subscribe to topics it could not reach
    /// before, so it needs the full consumers right, and no one clears a
    /// consumer for more than they may see themselves. A change records
    /// `consumers.clearance_changed`; clearing a consumer for what it already
    /// has saves and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller does not manage consumers,
    ///   checked before the consumer is looked up so a made-up id is refused
    ///   the same as a real one.
    /// - `AppError::NotFound` if the consumer doesn't exist.
    /// - `AppError::Forbidden` when `clearance` is above the caller's own.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeClearanceRequest,
    ) -> Result<Consumer<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = ConsumerControl::new(&authority);
        ensure_manages_consumers(&control)?;
        let tenant = ctx.tenant();
        let mut consumer = existing_consumer(
            self.ports.consumer_store.as_ref(),
            &tenant,
            &request.consumer_id,
        )
        .await?;
        let previous = consumer.clearance();
        consumer
            .change_clearance(request.clearance, &control)
            .map_err(AppError::from_domain)?;
        if previous == consumer.clearance() {
            return Ok(consumer);
        }

        self.ports
            .consumer_store
            .save(&tenant, &consumer)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), consumer.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(consumer)
    }
}

/// Refuses a caller without the full consumers right, before any consumer
/// is read.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when the person `control` names may not
/// manage consumers.
fn ensure_manages_consumers(control: &ConsumerControl<'_>) -> Result<(), AppError> {
    control
        .ensure_may(ConsumersAction::Manage)
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        ConsumersAction, DataAccessAction, SystemPermission,
    };

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{
        FakeConsumerStore, billing_sync, consumers_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const CONFIDENTIAL: SystemPermission = SystemPermission::Data(DataAccessAction::Confidential);

    fn clearing(consumer_id: ConsumerId, clearance: DataClassLevel) -> ChangeClearanceRequest {
        ChangeClearanceRequest {
            consumer_id,
            clearance,
        }
    }

    fn holding(store: Arc<FakeConsumerStore>, held: &[SystemPermission]) -> ChangeClearanceUseCase {
        ChangeClearanceUseCase::new(ChangeClearancePorts {
            consumer_store: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
            ..ChangeClearancePorts::fakes()
        })
    }

    fn run(
        use_case: &ChangeClearanceUseCase,
        request: ChangeClearanceRequest,
    ) -> Result<Consumer<ResolvedTenant>, AppError> {
        run_recorded(use_case, request, &Arc::new(FakeEventDispatcher::new()))
    }

    fn run_recorded(
        use_case: &ChangeClearanceUseCase,
        request: ChangeClearanceRequest,
        sink: &Arc<FakeEventDispatcher>,
    ) -> Result<Consumer<ResolvedTenant>, AppError> {
        let auditor = test_auditor(sink.clone());
        block_on(use_case.execute(&test_ctx(), &auditor, request))
    }

    /// Fay clears "billing-sync" for confidential data. The change is
    /// recorded, so a review sees when it could reach more.
    #[test]
    fn a_clearance_change_is_recorded() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let fay = [SystemPermission::ManageConsumers, CONFIDENTIAL];
        let sink = Arc::new(FakeEventDispatcher::new());

        run_recorded(
            &holding(store, &fay),
            clearing(id, DataClassLevel::Confidential),
            &sink,
        )
        .unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["consumers.clearance_changed"]
        );
    }

    /// Fay clears "billing-sync" for internal data, which it already has.
    /// Nothing changed, so nothing is recorded.
    #[test]
    fn clearing_a_consumer_for_what_it_has_records_nothing() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let sink = Arc::new(FakeEventDispatcher::new());

        run_recorded(
            &holding(store, &[SystemPermission::ManageConsumers]),
            clearing(id, DataClassLevel::Internal),
            &sink,
        )
        .unwrap();

        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Fay manages consumers and may see confidential data. She clears
    /// "billing-sync" for confidential data, and it is kept so.
    #[test]
    fn a_manager_clears_a_consumer_for_what_she_sees() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let fay = [SystemPermission::ManageConsumers, CONFIDENTIAL];

        run(
            &holding(store.clone(), &fay),
            clearing(id, DataClassLevel::Confidential),
        )
        .unwrap();

        let saved = store.find_by_id_direct(&id).unwrap();
        assert_eq!(saved.clearance(), DataClassLevel::Confidential);
    }

    /// Update and confidential-data rights cannot raise a consumer's clearance
    /// without management rights; its internal clearance remains stored.
    #[test]
    fn the_update_right_does_not_change_a_clearance() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let sam = [
            SystemPermission::Consumers(ConsumersAction::Update),
            CONFIDENTIAL,
        ];

        let result = run(
            &holding(store.clone(), &sam),
            clearing(id, DataClassLevel::Confidential),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        let saved = store.find_by_id_direct(&id).unwrap();
        assert_eq!(saved.clearance(), DataClassLevel::Internal);
    }

    /// A consumer manager with only internal clearance cannot grant restricted clearance.
    #[test]
    fn a_consumer_is_cleared_for_no_more_than_the_person_clearing_it() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);

        let result = run(
            &holding(store, &[SystemPermission::ManageConsumers]),
            clearing(id, DataClassLevel::Restricted),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Changing consumer clearance with an invalidated sign-in returns unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let use_case = ChangeClearanceUseCase::new(ChangeClearancePorts {
            consumer_store: consumers_of_test_tenant(consumer),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ChangeClearancePorts::fakes()
        });

        let result = run(&use_case, clearing(id, DataClassLevel::Internal));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A consumer the tenant does not have is not found.
    #[test]
    fn an_unknown_consumer_is_not_found() {
        let use_case = holding(
            Arc::new(FakeConsumerStore::empty()),
            &[SystemPermission::ManageConsumers],
        );

        let result = run(
            &use_case,
            clearing(ConsumerId::new(), DataClassLevel::Internal),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
