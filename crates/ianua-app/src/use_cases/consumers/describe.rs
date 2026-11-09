//! Describe consumer: say in a few words what a consumer is for, or clear
//! what it said.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::ConsumersAction;
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ConsumerId, Label, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::consumers::ConsumerStore;
use crate::use_case::Command;
use crate::use_cases::consumers::lookup::existing_consumer;

/// The ports [`DescribeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DescribePorts {
    /// Where consumers are kept.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which consumer to describe, and how.
pub struct DescribeRequest {
    /// The consumer to describe.
    pub consumer_id: ConsumerId,
    /// What it is for, or unset to clear its description.
    pub description: Setting<Label>,
}

/// Changes the description of one of a tenant's consumers.
pub struct DescribeUseCase {
    ports: DescribePorts,
}

impl DescribeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DescribePorts) -> Self {
        Self { ports }
    }
}

impl Command for DescribeUseCase {
    type Caller = CallerContext;
    type Input = DescribeRequest;
    type Output = Result<(), AppError>;

    /// Gives the consumer the description `request` carries, or clears it,
    /// and records `consumers.description_changed`. The description it
    /// already has changes and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update consumers,
    ///   whether or not the consumer exists.
    /// - `AppError::NotFound` if the consumer doesn't exist.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: DescribeRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = ConsumerControl::new(&authority);
        control
            .ensure_may(ConsumersAction::Update)
            .map_err(AppError::from_domain)?;
        let store = self.ports.consumer_store.as_ref();
        let tenant = ctx.tenant();
        let mut consumer = existing_consumer(store, &tenant, &request.consumer_id).await?;
        consumer
            .change_description(request.description, &control)
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &consumer).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), consumer.take_events(&tenant))
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

    /// Runs the use case for `request`, for a caller holding `authorities`,
    /// recording into `audit`.
    fn describe(
        store: Arc<FakeConsumerStore>,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
        request: DescribeRequest,
    ) -> Result<(), AppError> {
        let use_case = DescribeUseCase::new(DescribePorts {
            consumer_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    /// "Syncs invoices to the ledger".
    fn invoices() -> Setting<Label> {
        Setting::Set(Label::new("description", "Syncs invoices to the ledger").unwrap())
    }

    fn description_of(store: &FakeConsumerStore, id: &ConsumerId) -> Option<String> {
        store
            .find_by_id_direct(id)
            .unwrap()
            .description()
            .map(|label| label.as_str().to_owned())
    }

    /// Ann says what "billing-sync" is for. It is stored and recorded.
    #[test]
    fn a_consumer_is_described_and_it_is_recorded() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let audit = Arc::new(FakeEventDispatcher::new());

        describe(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            &audit,
            DescribeRequest {
                consumer_id: id,
                description: invoices(),
            },
        )
        .unwrap();

        assert_eq!(
            description_of(&store, &id).as_deref(),
            Some("Syncs invoices to the ledger")
        );
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["consumers.description_changed"]
        );
    }

    /// Ann names a consumer the tenant does not have. It is not found.
    #[test]
    fn describing_an_unknown_consumer_is_not_found() {
        let result = describe(
            Arc::new(FakeConsumerStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &Arc::new(FakeEventDispatcher::new()),
            DescribeRequest {
                consumer_id: ConsumerId::new(),
                description: invoices(),
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A viewer cannot change the consumer's description; the stored text
    /// remains unchanged and no event is recorded.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let before = consumer
            .description()
            .map(|label| label.as_str().to_owned());
        let store = consumers_of_test_tenant(consumer);
        let audit = Arc::new(FakeEventDispatcher::new());
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Consumers(ConsumersAction::View)]);

        let result = describe(
            store.clone(),
            viewer,
            &audit,
            DescribeRequest {
                consumer_id: id,
                description: invoices(),
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(description_of(&store, &id), before);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// An invalidated sign-in is refused when changing a consumer's description.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();

        let result = describe(
            consumers_of_test_tenant(consumer),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
            DescribeRequest {
                consumer_id: id,
                description: invoices(),
            },
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
