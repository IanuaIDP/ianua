//! Change credential expiry: set when a consumer's current credential stops
//! working.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::ConsumersAction;
use ianua_domain::domains::consumers::consumer::Consumer;
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ConsumerId, Expiry};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::consumers::ConsumerStore;
use crate::use_case::Command;
use crate::use_cases::consumers::lookup::existing_consumer;

/// Which consumer's credential expires when.
pub struct ChangeCredentialExpiryRequest {
    /// The consumer whose credential's expiry changes.
    pub consumer_id: ConsumerId,
    /// When its current credential stops working from now on.
    pub expiry: Expiry,
}

/// Ports needed by the change credential expiry use case.
#[derive(ianua_macros::Fakes)]
pub struct ChangeCredentialExpiryPorts {
    /// Port for loading and saving consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sets when a machine identity's current credential stops working.
pub struct ChangeCredentialExpiryUseCase {
    ports: ChangeCredentialExpiryPorts,
}

impl ChangeCredentialExpiryUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: ChangeCredentialExpiryPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeCredentialExpiryUseCase {
    type Caller = CallerContext;
    type Input = ChangeCredentialExpiryRequest;
    type Output = Result<Consumer<ResolvedTenant>, AppError>;

    /// Sets when the consumer's current credential stops working, records
    /// `consumers.credential_expiry_changed` with both expiries, and returns
    /// the consumer as saved.
    ///
    /// A later expiry keeps a credential working that would have stopped,
    /// much as issuing it again would, so it needs the full consumers right.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller does not manage consumers,
    ///   whether or not the consumer exists.
    /// - `AppError::NotFound` if the consumer doesn't exist.
    /// - `AppError::Domain` when `expiry` has already passed.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: ChangeCredentialExpiryRequest,
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
        consumer
            .change_credential_expiry(request.expiry, &control)
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
    use ianua_domain::shared::clock;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{
        FakeConsumerStore, billing_sync, consumers_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// An expiry `days` from now, in the past when negative.
    fn in_days(days: i64) -> Expiry {
        Expiry::At(clock::now() + time::Duration::days(days))
    }

    fn expiring(consumer_id: ConsumerId, expiry: Expiry) -> ChangeCredentialExpiryRequest {
        ChangeCredentialExpiryRequest {
            consumer_id,
            expiry,
        }
    }

    fn holding(
        store: Arc<FakeConsumerStore>,
        held: &[SystemPermission],
    ) -> ChangeCredentialExpiryUseCase {
        ChangeCredentialExpiryUseCase::new(ChangeCredentialExpiryPorts {
            consumer_store: store,
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(held)),
            ..ChangeCredentialExpiryPorts::fakes()
        })
    }

    fn run(
        use_case: &ChangeCredentialExpiryUseCase,
        request: ChangeCredentialExpiryRequest,
    ) -> (
        Result<Consumer<ResolvedTenant>, AppError>,
        Arc<FakeEventDispatcher>,
    ) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request));
        (result, audit)
    }

    /// Fay manages consumers. The contractor's work ends in a month, so she
    /// makes the key of "billing-sync" stop then. It is kept so, and the
    /// change is on record.
    #[test]
    fn the_expiry_changes_and_it_is_recorded() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let in_a_month = in_days(30);

        let (result, audit) = run(
            &holding(store.clone(), &[SystemPermission::ManageConsumers]),
            expiring(id, in_a_month),
        );

        result.unwrap();
        let saved = store.find_by_id_direct(&id).unwrap();
        assert_eq!(saved.credentials().current().expiry(), in_a_month);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["consumers.credential_expiry_changed"]
        );
    }

    /// Fay sets the key to expire yesterday. It is refused, since an expiry
    /// lies ahead; a key that must stop now is stopped by disabling the
    /// consumer. Nothing is recorded.
    #[test]
    fn an_expiry_in_the_past_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);

        let (result, audit) = run(
            &holding(store.clone(), &[SystemPermission::ManageConsumers]),
            expiring(id, in_days(-1)),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Update rights cannot set a credential expiry; its unlimited lifetime
    /// remains stored and no event is recorded.
    #[test]
    fn the_update_right_does_not_change_an_expiry() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let sam = [SystemPermission::Consumers(ConsumersAction::Update)];

        let (result, audit) = run(&holding(store.clone(), &sam), expiring(id, in_days(3650)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        let saved = store.find_by_id_direct(&id).unwrap();
        assert_eq!(saved.credentials().current().expiry(), Expiry::Never);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller cannot change credential expiry.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let use_case = ChangeCredentialExpiryUseCase::new(ChangeCredentialExpiryPorts {
            consumer_store: consumers_of_test_tenant(consumer),
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ChangeCredentialExpiryPorts::fakes()
        });

        let (result, _) = run(&use_case, expiring(id, in_days(30)));

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

        let (result, audit) = run(&use_case, expiring(ConsumerId::new(), in_days(30)));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Missing management rights return forbidden for an unknown consumer's expiry change.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_consumer() {
        let use_case = holding(Arc::new(FakeConsumerStore::empty()), &[]);

        let (result, _) = run(&use_case, expiring(ConsumerId::new(), in_days(30)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
