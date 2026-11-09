//! Rename consumer: give a consumer another display name.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::ConsumersAction;
use ianua_domain::domains::consumers::control::ConsumerControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ConsumerId, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::consumers::ConsumerStore;
use crate::use_case::Command;
use crate::use_cases::consumers::lookup::existing_consumer;

/// The ports [`RenameUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenamePorts {
    /// Where consumers are kept.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which consumer to rename, and its new name.
pub struct RenameRequest {
    /// The consumer to rename.
    pub consumer_id: ConsumerId,
    /// The name it is to carry.
    pub name: Label,
}

/// Renames one of a tenant's consumers.
pub struct RenameUseCase {
    ports: RenamePorts,
}

impl RenameUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenamePorts) -> Self {
        Self { ports }
    }
}

impl Command for RenameUseCase {
    type Caller = CallerContext;
    type Input = RenameRequest;
    type Output = Result<(), AppError>;

    /// Renames the consumer and records `consumers.consumer_renamed` with
    /// both names. Its credential, clearance and status stay as they were.
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
        request: RenameRequest,
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
            .rename(request.name, &control)
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
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{
        FakeConsumerStore, billing_sync, consumers_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn rename(
        store: Arc<FakeConsumerStore>,
        authorities: FakeTenantAuthorities,
        consumer_id: ConsumerId,
    ) -> Result<(), AppError> {
        rename_recorded(
            store,
            authorities,
            consumer_id,
            &Arc::new(FakeEventDispatcher::new()),
        )
    }

    fn rename_recorded(
        store: Arc<FakeConsumerStore>,
        authorities: FakeTenantAuthorities,
        consumer_id: ConsumerId,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<(), AppError> {
        let use_case = RenameUseCase::new(RenamePorts {
            consumer_store: store,
            tenant_authorities: Arc::new(authorities),
        });
        let request = RenameRequest {
            consumer_id,
            name: Label::new("name", "invoice-sync").unwrap(),
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn name_of(store: &FakeConsumerStore, id: &ConsumerId) -> String {
        store
            .find_by_id_direct(id)
            .unwrap()
            .name()
            .as_str()
            .to_owned()
    }

    /// Ann renames "billing-sync" to "invoice-sync". It is stored under the
    /// new name and still active.
    #[test]
    fn a_consumer_is_renamed() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);

        rename(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            id,
        )
        .unwrap();

        assert_eq!(name_of(&store, &id), "invoice-sync");
        assert!(store.find_by_id_direct(&id).unwrap().is_active());
    }

    /// Ann renames "billing-sync" to "invoice-sync". The audit trail keeps
    /// both names.
    #[test]
    fn renaming_a_consumer_is_recorded_with_both_names() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let audit = Arc::new(FakeEventDispatcher::new());

        rename_recorded(
            consumers_of_test_tenant(consumer),
            FakeTenantAuthorities::holding_everything(),
            id,
            &audit,
        )
        .unwrap();

        let payload = audit.payload_of("consumers.consumer_renamed");
        let Some(FieldValue::Change(change)) = payload.value("name") else {
            panic!("name is not a change");
        };
        assert_eq!(
            (change.from(), change.to()),
            (Some("billing-sync"), Some("invoice-sync"))
        );
    }

    /// Ann names a consumer the tenant does not have. It is not found.
    #[test]
    fn renaming_an_unknown_consumer_is_not_found() {
        let result = rename(
            Arc::new(FakeConsumerStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            ConsumerId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Without update rights, renaming an unknown consumer returns forbidden.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_consumer() {
        let result = rename(
            Arc::new(FakeConsumerStore::empty()),
            FakeTenantAuthorities::holding(&[]),
            ConsumerId::new(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A consumer viewer cannot rename billing-sync, which retains its stored name.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Consumers(ConsumersAction::View)]);

        let result = rename(store.clone(), viewer, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(name_of(&store, &id), "billing-sync");
    }

    /// A signed-out caller cannot rename a consumer.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = billing_sync();
        let id = *consumer.id();

        let result = rename(
            consumers_of_test_tenant(consumer),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            id,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
