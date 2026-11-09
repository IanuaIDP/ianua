//! Pause subscription: stop delivering webhook events for now.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WebhooksAction;
use ianua_domain::domains::webhooks::control::WebhookControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WebhookSubscriptionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::webhooks::WebhookStore;
use crate::use_case::Command;
use crate::use_cases::webhooks::lookup::existing_subscription;

/// The ports [`PauseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PausePorts {
    /// Where subscriptions are kept.
    pub webhook_store: Arc<dyn WebhookStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Pauses a webhook subscription.
pub struct PauseUseCase {
    ports: PausePorts,
}

impl PauseUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: PausePorts) -> Self {
        Self { ports }
    }
}

impl Command for PauseUseCase {
    type Caller = CallerContext;
    type Input = WebhookSubscriptionId;
    type Output = Result<(), AppError>;

    /// Pauses the subscription and records `webhooks.subscription_paused`.
    /// Events raised while it is paused are not delivered, then or later.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update webhooks.
    /// - `AppError::NotFound` when the tenant has no such subscription.
    /// - `AppError::Domain` when the subscription is already paused or
    ///   disabled.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        subscription_id: WebhookSubscriptionId,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = WebhookControl::new(&authority);
        control
            .ensure_may(WebhooksAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut subscription =
            existing_subscription(self.ports.webhook_store.as_ref(), &tenant, &subscription_id)
                .await?;
        subscription
            .pause(&control)
            .map_err(AppError::from_domain)?;

        self.ports
            .webhook_store
            .save(&tenant, &subscription)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), subscription.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::webhooks::{FakeWebhookStore, test_subscription};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded(status: WebhookSubscriptionStatus) -> (Arc<FakeWebhookStore>, WebhookSubscriptionId) {
        let subscription = test_subscription("https://hooks.acme.com/events", status);
        let store = FakeWebhookStore::holding(test_ctx().tenant_id(), &subscription);
        (Arc::new(store), *subscription.id())
    }

    fn use_case(store: Arc<FakeWebhookStore>, authorities: FakeTenantAuthorities) -> PauseUseCase {
        PauseUseCase::new(PausePorts {
            webhook_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn pause(
        use_case: &PauseUseCase,
        audit: &Arc<FakeEventDispatcher>,
        id: WebhookSubscriptionId,
    ) -> Result<(), AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id))
    }

    fn status_of(
        store: &FakeWebhookStore,
        id: &WebhookSubscriptionId,
    ) -> WebhookSubscriptionStatus {
        store.stored(test_ctx().tenant_id(), id).unwrap().status()
    }

    /// Ann pauses an active webhook while its server is being moved. It is
    /// stored paused and the pause recorded.
    #[test]
    fn an_active_subscription_is_paused() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        pause(&use_case, &audit, id).unwrap();

        assert_eq!(status_of(&store, &id), WebhookSubscriptionStatus::Paused);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["webhooks.subscription_paused"]
        );
    }

    /// Ann pauses a webhook that is already paused. It is refused as a move
    /// the subscription cannot make.
    #[test]
    fn a_paused_subscription_cannot_be_paused_again() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Paused);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::holding_everything());

        let result = pause(&use_case, &audit, id);

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann names a subscription the tenant does not have. It is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeWebhookStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = pause(&use_case, &audit, WebhookSubscriptionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Pausing an unknown subscription without webhook update rights
    /// returns forbidden rather than exposing its absence.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_subscription() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeWebhookStore::empty()),
            FakeTenantAuthorities::holding(&[]),
        );

        let result = pause(&use_case, &audit, WebhookSubscriptionId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A caller with only webhook viewing rights cannot pause a subscription;
    /// it stays active and no event is recorded.
    #[test]
    fn a_caller_without_the_webhooks_right_is_refused() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::View)]),
        );

        let result = pause(&use_case, &audit, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status_of(&store, &id), WebhookSubscriptionStatus::Active);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Pausing a subscription with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = pause(&use_case, &audit, id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
