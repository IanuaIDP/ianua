//! Change quota: set how many requests a consumer may send per period.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::ConsumersAction;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::domains::consumers::quota::ConsumerQuota;
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

/// Which consumer may send how many requests.
pub struct ChangeQuotaRequest {
    /// The consumer whose quota changes.
    pub consumer_id: ConsumerId,
    /// How many requests it may send from now on.
    pub quota: ConsumerQuota,
}

/// Ports needed by the change quota use case.
#[derive(ianua_macros::Fakes)]
pub struct ChangeQuotaPorts {
    /// Port for loading and saving consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sets how many requests a consumer may send per period.
pub struct ChangeQuotaUseCase {
    ports: ChangeQuotaPorts,
}

impl ChangeQuotaUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: ChangeQuotaPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeQuotaUseCase {
    type Caller = CallerContext;
    type Input = ChangeQuotaRequest;
    type Output = Result<Consumer<ResolvedTenant>, AppError>;

    /// Gives the consumer `quota` and returns it as saved.
    ///
    /// A larger quota lets it send more than its contract paid for, so it
    /// needs the full consumers right. A change records
    /// `consumers.quota_changed`; setting the quota it already has saves and
    /// records nothing. Requests already counted in the current period
    /// still count against the new quota.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller does not manage consumers,
    ///   whether or not the consumer exists.
    /// - `AppError::NotFound` if the consumer doesn't exist.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeQuotaRequest,
    ) -> Result<Consumer<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = ConsumerControl::new(&authority);
        control
            .ensure_may(ConsumersAction::Manage)
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut consumer = existing_consumer(
            self.ports.consumer_store.as_ref(),
            &tenant,
            &request.consumer_id,
        )
        .await?;
        if consumer.quota() == request.quota {
            return Ok(consumer);
        }
        consumer
            .change_quota(request.quota, &control)
            .map_err(AppError::from_domain)?;

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

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::consumers::quota::{QuotaPeriod, RequestAllowance};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{
        FakeConsumerStore, billing_sync, consumers_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// A quota of `requests` a day.
    fn daily(requests: u64) -> ConsumerQuota {
        ConsumerQuota::Limited(RequestAllowance::new(requests, QuotaPeriod::Day).unwrap())
    }

    fn limiting(consumer_id: ConsumerId, quota: ConsumerQuota) -> ChangeQuotaRequest {
        ChangeQuotaRequest { consumer_id, quota }
    }

    fn holding(store: Arc<FakeConsumerStore>, held: &[SystemPermission]) -> ChangeQuotaUseCase {
        ChangeQuotaUseCase::new(ChangeQuotaPorts {
            consumer_store: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
            ..ChangeQuotaPorts::fakes()
        })
    }

    fn run(
        use_case: &ChangeQuotaUseCase,
        request: ChangeQuotaRequest,
    ) -> (
        Result<Consumer<ResolvedTenant>, AppError>,
        Arc<FakeEventDispatcher>,
    ) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request));
        (result, audit)
    }

    /// Fay manages consumers. The partner's contract pays for 10 000 calls
    /// a day, so she limits "billing-sync" to that. It is kept so, and the
    /// change is on record.
    #[test]
    fn the_quota_changes_and_it_is_recorded() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);

        let (result, audit) = run(
            &holding(store.clone(), &[SystemPermission::ManageConsumers]),
            limiting(id, daily(10_000)),
        );

        result.unwrap();
        assert_eq!(store.find_by_id_direct(&id).unwrap().quota(), daily(10_000));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["consumers.quota_changed"]
        );
    }

    /// Fay sets "billing-sync" to unlimited, which it already is. Nothing
    /// changed, so nothing is recorded.
    #[test]
    fn setting_the_quota_it_has_records_nothing() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);

        let (result, audit) = run(
            &holding(store, &[SystemPermission::ManageConsumers]),
            limiting(id, ConsumerQuota::Unlimited),
        );

        result.unwrap();
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Update rights cannot replace an unlimited quota with a daily cap;
    /// the original quota stays stored and no change is audited.
    #[test]
    fn the_update_right_does_not_change_a_quota() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let sam = [SystemPermission::Consumers(ConsumersAction::Update)];

        let (result, audit) = run(&holding(store.clone(), &sam), limiting(id, daily(5)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            store.find_by_id_direct(&id).unwrap().quota(),
            ConsumerQuota::Unlimited
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot change a consumer's quota.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let use_case = ChangeQuotaUseCase::new(ChangeQuotaPorts {
            consumer_store: consumers_of_test_tenant(consumer),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ChangeQuotaPorts::fakes()
        });

        let (result, _) = run(&use_case, limiting(id, daily(5)));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A consumer the tenant does not have is not found, and nothing is
    /// recorded.
    #[test]
    fn an_unknown_consumer_is_not_found() {
        let use_case = holding(
            Arc::new(FakeConsumerStore::empty()),
            &[SystemPermission::ManageConsumers],
        );

        let (result, audit) = run(&use_case, limiting(ConsumerId::new(), daily(5)));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A caller without management rights gets forbidden for an unknown consumer's quota.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_consumer() {
        let use_case = holding(Arc::new(FakeConsumerStore::empty()), &[]);

        let (result, _) = run(&use_case, limiting(ConsumerId::new(), daily(5)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
