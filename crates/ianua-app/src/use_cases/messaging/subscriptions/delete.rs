//! Delete subscription: remove a service's subscription to a topic.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::control::MessagingControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::MessageSubscriptionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{MessageConsumer, SubscriptionStore};
use crate::use_case::Command;
use crate::use_cases::messaging::bus::close_consumer;
use crate::use_cases::messaging::lookup::existing_subscription;

/// Ports needed by the delete subscription use case.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// Port for subscription persistence.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// The bus consumer the subscription reads through.
    pub message_consumer: Arc<dyn MessageConsumer>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Disconnects a service from a topic and closes its broker consumer.
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
    type Input = MessageSubscriptionId;
    type Output = Result<(), AppError>;

    /// Deletes a subscription and the bus consumer it reads through, with
    /// the messages waiting there; a consumer group's consumer stays while
    /// another subscription of the group reads through it. Records
    /// `messaging.subscription_deleted`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the subscription doesn't exist.
    /// - `AppError::Forbidden` when the caller may not delete in messaging.
    /// - `AppError::Internal` on persistence, bus or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        id: MessageSubscriptionId,
    ) -> Result<(), AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = MessagingControl::new(&authority);
        control
            .ensure_may(MessagingAction::Delete)
            .map_err(AppError::from_domain)?;
        let store = self.ports.subscription_store.as_ref();
        let mut sub = existing_subscription(store, &tenant, &id).await?;
        sub.delete(&control).map_err(AppError::from_domain)?;
        close_consumer(self.ports.message_consumer.as_ref(), store, &tenant, &sub).await?;

        store.delete(&tenant, &id).await.or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), sub.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::billing_sync;
    use crate::test_support::messaging::{
        FakeMessageConsumer, FakeSubscriptionStore, enrolled_subscription, grouped_subscription_of,
        topic_named,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::messaging::bus::consumer_name;

    struct Bench {
        use_case: DeleteUseCase,
        subscriptions: Arc<FakeSubscriptionStore>,
        bus: Arc<FakeMessageConsumer>,
        id: MessageSubscriptionId,
    }

    fn bench(people: FakeTenantAuthorities) -> Bench {
        let subscription = enrolled_subscription(&topic_named("orders.created"));
        let id = *subscription.id();
        let bus = Arc::new(FakeMessageConsumer::empty());
        bus.open(test_ctx().tenant_id(), &consumer_name(&subscription));
        let subscriptions = FakeSubscriptionStore::of_test_tenant([subscription]);
        let use_case = DeleteUseCase::new(DeletePorts {
            subscription_store: subscriptions.clone(),
            message_consumer: bus.clone(),
            tenant_authorities: Arc::new(people),
        });
        Bench {
            use_case,
            subscriptions,
            bus,
            id,
        }
    }

    fn run(
        use_case: &DeleteUseCase,
        id: MessageSubscriptionId,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id));
        (result, audit)
    }

    /// Ann deletes "billing-sync"'s subscription. It is gone, its bus
    /// consumer is removed, and that is on record.
    #[test]
    fn a_subscription_and_its_bus_consumer_are_deleted_and_recorded() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, audit) = run(&bench.use_case, bench.id);

        result.unwrap();
        assert_eq!(bench.subscriptions.count(), 0);
        assert!(bench.bus.open_in(test_ctx().tenant_id()).is_empty());
        assert_eq!(
            audit.records.lock().unwrap()[0],
            "messaging.subscription_deleted"
        );
    }

    /// Publishing rights do not permit deleting a subscription; the
    /// forbidden request keeps it and its bus consumer without recording
    /// a deletion event.
    #[test]
    fn a_caller_without_the_delete_right_is_refused() {
        let publisher = FakeTenantAuthorities::holding(&[SystemPermission::Messaging(
            MessagingAction::Publish,
        )]);
        let bench = bench(publisher);

        let (result, audit) = run(&bench.use_case, bench.id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.subscriptions.count(), 1);
        assert_eq!(bench.bus.open_in(test_ctx().tenant_id()).len(), 1);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller receives an unauthenticated error when deleting
    /// a subscription, which remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let bench = bench(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = run(&bench.use_case, bench.id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(bench.subscriptions.count(), 1);
    }

    fn group_bench(members: usize) -> Bench {
        let orders = topic_named("orders.created");
        let subscriptions: Vec<_> = (0..members)
            .map(|_| grouped_subscription_of(&billing_sync(), &orders, "payment-workers"))
            .collect();
        let id = *subscriptions[0].id();
        let bus = Arc::new(FakeMessageConsumer::empty());
        bus.open(test_ctx().tenant_id(), &consumer_name(&subscriptions[0]));
        let subscriptions = FakeSubscriptionStore::of_test_tenant(subscriptions);
        let use_case = DeleteUseCase::new(DeletePorts {
            subscription_store: subscriptions.clone(),
            message_consumer: bus.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        Bench {
            use_case,
            subscriptions,
            bus,
            id,
        }
    }

    /// Deleting one of two subscriptions in a group leaves the other
    /// subscription and their shared bus consumer in place.
    #[test]
    fn a_group_consumer_stays_while_the_group_reads() {
        let bench = group_bench(2);

        let (result, _) = run(&bench.use_case, bench.id);

        result.unwrap();
        assert_eq!(bench.subscriptions.count(), 1);
        assert_eq!(bench.bus.open_in(test_ctx().tenant_id()).len(), 1);
    }

    /// The last subscription of a group takes the group's consumer with it.
    #[test]
    fn the_last_of_a_group_removes_its_consumer() {
        let bench = group_bench(1);

        let (result, _) = run(&bench.use_case, bench.id);

        result.unwrap();
        assert!(bench.bus.open_in(test_ctx().tenant_id()).is_empty());
    }

    /// A subscription the tenant does not have is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, _) = run(&bench.use_case, MessageSubscriptionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
