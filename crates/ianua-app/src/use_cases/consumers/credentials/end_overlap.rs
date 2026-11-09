//! End credential overlap: stop the credential a rotation kept working,
//! once every caller moved to the new one.

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

/// Ports needed by the end credential overlap use case.
#[derive(ianua_macros::Fakes)]
pub struct EndCredentialOverlapPorts {
    /// Port for loading and saving consumers.
    pub consumer_store: Arc<dyn ConsumerStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Stops a consumer's previous credential before its overlap
/// runs out.
pub struct EndCredentialOverlapUseCase {
    ports: EndCredentialOverlapPorts,
}

impl EndCredentialOverlapUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: EndCredentialOverlapPorts) -> Self {
        Self { ports }
    }
}

impl Command for EndCredentialOverlapUseCase {
    type Caller = CallerContext;
    type Input = ConsumerId;
    type Output = Result<(), AppError>;

    /// Stops the credential the consumer's last rotation kept, so only the
    /// new one works, and records `consumers.credential_overlap_ended`.
    ///
    /// It only takes access away, so the update right is enough.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update consumers,
    ///   whether or not the consumer exists.
    /// - `AppError::NotFound` if the consumer doesn't exist.
    /// - `AppError::Domain` when no previous credential is kept.
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
        consumer
            .end_credential_overlap(&control)
            .map_err(AppError::from_domain)?;

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
        FakeConsumerStore, billing_sync, billing_sync_overlapping, consumers_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const UPDATE: SystemPermission = SystemPermission::Consumers(ConsumersAction::Update);

    fn run(
        use_case: &EndCredentialOverlapUseCase,
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
    ) -> EndCredentialOverlapUseCase {
        EndCredentialOverlapUseCase::new(EndCredentialOverlapPorts {
            consumer_store: store,
            tenant_authorities: Arc::new(authorities),
            ..EndCredentialOverlapPorts::fakes()
        })
    }

    /// Sam may update consumers. Every caller of "billing-sync" moved to
    /// its new key, so he stops the old one early. Only the new key works,
    /// and that is on record.
    #[test]
    fn the_old_credential_stops_and_it_is_recorded() {
        let consumer = billing_sync_overlapping();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let use_case = with_authorities(store.clone(), FakeTenantAuthorities::holding(&[UPDATE]));

        let (result, audit) = run(&use_case, id);

        result.unwrap();
        let saved = store.find_by_id_direct(&id).unwrap();
        assert_eq!(saved.credentials().live().count(), 1);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["consumers.credential_overlap_ended"]
        );
    }

    /// "billing-sync" keeps no old key. Ending the overlap is refused, and
    /// nothing is recorded.
    #[test]
    fn a_consumer_without_an_old_credential_has_no_overlap_to_end() {
        let consumer = billing_sync();
        let id = *consumer.id();
        let use_case = with_authorities(
            consumers_of_test_tenant(consumer),
            FakeTenantAuthorities::holding(&[UPDATE]),
        );

        let (result, audit) = run(&use_case, id);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A viewer cannot end credential overlap; both credentials remain live
    /// and no event is recorded.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let consumer = billing_sync_overlapping();
        let id = *consumer.id();
        let store = consumers_of_test_tenant(consumer);
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Consumers(ConsumersAction::View)]);

        let (result, audit) = run(&with_authorities(store.clone(), viewer), id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        let saved = store.find_by_id_direct(&id).unwrap();
        assert_eq!(saved.credentials().live().count(), 2);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ending an overlap requires a caller whose sign-in is still valid.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let consumer = billing_sync_overlapping();
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
    fn an_unknown_consumer_is_not_found() {
        let use_case = with_authorities(
            Arc::new(FakeConsumerStore::empty()),
            FakeTenantAuthorities::holding(&[UPDATE]),
        );

        let (result, audit) = run(&use_case, ConsumerId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Without update rights, ending overlap returns forbidden even for an unknown consumer.
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
