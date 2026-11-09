//! Get consumer: retrieve a single consumer by ID.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ConsumersAction, SystemPermission};
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::ConsumerId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::consumers::ConsumerStore;
use crate::use_case::Query;
use crate::use_cases::consumers::lookup::existing_consumer;

/// Ports needed by the get consumer use case.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Port for loading consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a machine identity within the caller's tenant.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = ConsumerId;
    type Output = Result<Consumer<ResolvedTenant>, AppError>;

    /// Returns a consumer by ID.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view consumers.
    /// - `AppError::NotFound` if the consumer doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: ConsumerId,
    ) -> Result<Consumer<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Consumers(ConsumersAction::View))
            .map_err(AppError::from_domain)?;
        existing_consumer(self.ports.consumer_store.as_ref(), &ctx.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{
        FakeConsumerStore, billing_sync, consumers_of_test_tenant,
    };
    use crate::test_support::{block_on, test_ctx};

    fn with_authorities(
        store: Arc<FakeConsumerStore>,
        authorities: FakeTenantAuthorities,
    ) -> GetUseCase {
        GetUseCase::new(GetPorts {
            consumer_store: store,
            tenant_authorities: Arc::new(authorities),
            ..GetPorts::fakes()
        })
    }

    /// Ann may view consumers. She opens "billing-sync" and sees it.
    #[test]
    fn a_viewer_gets_the_consumer() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Consumers(ConsumersAction::View)]);
        let use_case = with_authorities(consumers_of_test_tenant(consumer), viewer);

        let found = block_on(use_case.execute(&test_ctx(), id)).unwrap();

        assert_eq!(found.name().as_str(), "billing-sync");
    }

    /// A consumer the tenant does not have is not found.
    #[test]
    fn an_unknown_consumer_is_not_found() {
        let use_case = with_authorities(
            Arc::new(FakeConsumerStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = block_on(use_case.execute(&test_ctx(), ConsumerId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading billing-sync is forbidden without consumer-view rights.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let use_case = with_authorities(
            consumers_of_test_tenant(consumer),
            FakeTenantAuthorities::holding(&[]),
        );

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading a consumer with an invalidated sign-in returns unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let use_case = with_authorities(
            consumers_of_test_tenant(consumer),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
