//! Delete consumer: permanently remove a disabled consumer.

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

/// Ports needed by the delete consumer use case.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Port for loading and deleting consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Permanently removes a disabled machine identity from its tenant.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = ConsumerId;
    type Output = Result<(), AppError>;

    /// Permanently deletes a consumer and records `consumers.consumer_deleted`.
    /// Must be disabled first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not delete consumers,
    ///   whether or not the consumer exists.
    /// - `AppError::NotFound` if the consumer doesn't exist.
    /// - `AppError::Forbidden` when the consumer is still active.
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
            .ensure_may(ConsumersAction::Delete)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut consumer =
            existing_consumer(self.ports.consumer_store.as_ref(), &tenant, &consumer_id).await?;
        consumer.delete(&control).map_err(AppError::from_domain)?;

        self.ports
            .consumer_store
            .delete(&tenant, &consumer_id)
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
        FakeConsumerStore, billing_sync, consumers_of_test_tenant, disabled_billing_sync,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn run(
        use_case: &DeleteUseCase,
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
    ) -> DeleteUseCase {
        DeleteUseCase::new(DeletePorts {
            consumer_store: store,
            tenant_authorities: Arc::new(authorities),
            ..DeletePorts::fakes()
        })
    }

    /// Ann deletes "billing-sync", which she disabled. It is gone, and that
    /// is on record.
    #[test]
    fn a_disabled_consumer_is_deleted_and_recorded() {
        let consumer = disabled_billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let use_case = with_authorities(store.clone(), FakeTenantAuthorities::holding_everything());

        let (result, audit) = run(&use_case, id);

        result.unwrap();
        assert_eq!(store.count(), 0);
        assert_eq!(
            audit.records.lock().unwrap()[0],
            "consumers.consumer_deleted"
        );
    }

    /// An active consumer cannot be deleted; its record remains and no deletion is audited.
    #[test]
    fn an_active_consumer_is_not_deleted() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let use_case = with_authorities(store.clone(), FakeTenantAuthorities::holding_everything());

        let (result, audit) = run(&use_case, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Update rights do not permit deletion, so the disabled consumer remains stored.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let consumer = disabled_billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let updater =
            FakeTenantAuthorities::holding(&[SystemPermission::Consumers(ConsumersAction::Update)]);

        let (result, _) = run(&with_authorities(store.clone(), updater), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 1);
    }

    /// A signed-out caller is refused consumer deletion as unauthenticated.
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
    fn deleting_an_unknown_consumer_is_not_found() {
        let use_case = with_authorities(
            Arc::new(FakeConsumerStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let (result, audit) = run(&use_case, ConsumerId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Missing delete rights return forbidden for an unknown consumer instead of not found.
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
