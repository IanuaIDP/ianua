//! Update subscription: change a webhook's address, events, description or
//! retry policy.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WebhooksAction;
use ianua_domain::domains::webhooks::control::WebhookControl;
use ianua_domain::domains::webhooks::subscription::{WebhookSubscription, WebhookUpdate};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::WebhookSubscriptionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::webhooks::WebhookStore;
use crate::use_case::Command;
use crate::use_cases::webhooks::keeping::keep_subscription;
use crate::use_cases::webhooks::lookup::existing_subscription;

/// Which subscription to change, and what to change about it.
pub struct UpdateRequest {
    /// The subscription to change.
    pub subscription_id: WebhookSubscriptionId,
    /// The parts to change. A part left `None` stays as it is.
    pub update: WebhookUpdate,
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Where subscriptions are kept.
    pub webhook_store: Arc<dyn WebhookStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a webhook subscription.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<WebhookSubscription<ResolvedTenant>, AppError>;

    /// Applies the update and records one `webhooks.subscription_updated`
    /// naming the parts that changed. An update that changes nothing is
    /// neither saved nor recorded. New event types are checked against what
    /// the caller may see, and a new address starts with no failures
    /// counted. Gives back the subscription as it now stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update webhooks, or
    ///   names an event they may not see.
    /// - `AppError::NotFound` when the tenant has no such subscription.
    /// - `AppError::Domain` when the subscription is disabled, or the new
    ///   events name the webhook delivery event.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRequest,
    ) -> Result<WebhookSubscription<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = WebhookControl::new(&authority);
        control
            .ensure_may(WebhooksAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut subscription = existing_subscription(
            self.ports.webhook_store.as_ref(),
            &tenant,
            &request.subscription_id,
        )
        .await?;
        subscription
            .update(request.update, &control)
            .map_err(AppError::from_domain)?;
        let events = subscription.take_events(&tenant);
        if events.is_empty() {
            return Ok(subscription);
        }

        keep_subscription(self.ports.webhook_store.as_ref(), &tenant, &subscription).await?;
        auditor
            .dispatch_by(&caller.actor(), events)
            .await
            .or_internal()?;

        Ok(subscription)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
    use ianua_domain::types::event_type::{CryptoEvent, IdentityEvent};
    use ianua_domain::types::{EventType, PublicHttpsUrl, Setting, Text};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::webhooks::{
        FakeWebhookStore, failing_test_subscription, test_subscription,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// What lets Ann change webhooks for user events.
    const WEBHOOKS_AND_USERS: [SystemPermission; 2] = [
        SystemPermission::Webhooks(WebhooksAction::Update),
        SystemPermission::Users(UserAction::View),
    ];

    /// A store holding Ann's webhook in `status`, which has failed
    /// `failures` times in a row, and its id.
    fn seeded(
        status: WebhookSubscriptionStatus,
        failures: u32,
    ) -> (Arc<FakeWebhookStore>, WebhookSubscriptionId) {
        let subscription =
            failing_test_subscription("https://hooks.acme.com/events", status, failures);
        let store = FakeWebhookStore::holding(test_ctx().tenant_id(), &subscription);
        (Arc::new(store), *subscription.id())
    }

    /// A use case on `store`, for a caller holding what `authorities` says.
    fn use_case(store: Arc<FakeWebhookStore>, authorities: FakeTenantAuthorities) -> UpdateUseCase {
        UpdateUseCase::new(UpdatePorts {
            webhook_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    /// An update that changes nothing.
    fn nothing() -> WebhookUpdate {
        WebhookUpdate {
            url: None,
            event_types: None,
            description: None,
            retry: None,
        }
    }

    /// An update moving deliveries to Ann's new server.
    fn new_address() -> WebhookUpdate {
        WebhookUpdate {
            url: Some(PublicHttpsUrl::new("https://hooks.acme.com/v2").unwrap()),
            ..nothing()
        }
    }

    /// Applies `update` to subscription `id`.
    fn update(
        use_case: &UpdateUseCase,
        audit: &Arc<FakeEventDispatcher>,
        id: WebhookSubscriptionId,
        update: WebhookUpdate,
    ) -> Result<WebhookSubscription<ResolvedTenant>, AppError> {
        let request = UpdateRequest {
            subscription_id: id,
            update,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    /// The subscription as the store holds it now.
    fn stored(
        store: &FakeWebhookStore,
        id: &WebhookSubscriptionId,
    ) -> WebhookSubscription<ResolvedTenant> {
        store.stored(test_ctx().tenant_id(), id).unwrap()
    }

    /// Ann moves her webhook to a new server, whose failures so far do not
    /// count against it. The change is stored and recorded.
    #[test]
    fn a_new_address_is_stored_with_no_failures_counted() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Active, 4);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding(&WEBHOOKS_AND_USERS),
        );

        update(&use_case, &audit, id, new_address()).unwrap();

        let stored = stored(&store, &id);
        assert_eq!(stored.url().as_str(), "https://hooks.acme.com/v2");
        assert_eq!(stored.consecutive_failures(), 0);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["webhooks.subscription_updated"]
        );
    }

    /// Ann gives her webhook a description and the patient retry policy.
    /// Both are kept.
    #[test]
    fn a_description_and_retry_policy_are_changed() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Active, 0);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding(&WEBHOOKS_AND_USERS),
        );
        let change = WebhookUpdate {
            description: Some(Setting::Set(Text::new("description", "CRM sync").unwrap())),
            retry: Some(RetryPreset::Patient),
            ..nothing()
        };

        update(&use_case, &audit, id, change).unwrap();

        let stored = stored(&store, &id);
        assert_eq!(stored.description().map(Text::as_str), Some("CRM sync"));
        assert_eq!(stored.retry(), RetryPreset::Patient);
    }

    /// Ann saves her webhook without changing anything. Nothing is recorded.
    #[test]
    fn an_update_that_changes_nothing_records_nothing() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Active, 0);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::holding(&WEBHOOKS_AND_USERS));

        update(&use_case, &audit, id, nothing()).unwrap();

        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Changing a subscription to include an event the caller cannot view
    /// is forbidden, preserves its event types and records no event.
    #[test]
    fn an_event_the_caller_may_not_see_is_refused() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Active, 0);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding(&WEBHOOKS_AND_USERS),
        );
        let change = WebhookUpdate {
            event_types: Some(vec![CryptoEvent::ALL[0].0.into()]),
            ..nothing()
        };

        let result = update(&use_case, &audit, id, change);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            stored(&store, &id).event_types(),
            [EventType::from(IdentityEvent::UserRegistered)]
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann edits a webhook that was switched off for failing. It is refused:
    /// a disabled webhook is replaced, not changed.
    #[test]
    fn a_disabled_subscription_is_not_changed() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Disabled, 0);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::holding(&WEBHOOKS_AND_USERS));

        let result = update(&use_case, &audit, id, new_address());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a subscription the tenant does not have. It is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeWebhookStore::empty()),
            FakeTenantAuthorities::holding(&WEBHOOKS_AND_USERS),
        );

        let result = update(
            &use_case,
            &audit,
            WebhookSubscriptionId::new(),
            new_address(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A caller with only webhook viewing rights cannot change its address;
    /// the request is forbidden, the address stays and no event is recorded.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let subscription = test_subscription(
            "https://hooks.acme.com/events",
            WebhookSubscriptionStatus::Active,
        );
        let store = Arc::new(FakeWebhookStore::holding(
            test_ctx().tenant_id(),
            &subscription,
        ));
        let id = *subscription.id();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::View)]),
        );

        let result = update(&use_case, &audit, id, new_address());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            stored(&store, &id).url().as_str(),
            "https://hooks.acme.com/events"
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Updating a subscription with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded(WebhookSubscriptionStatus::Active, 0);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = update(&use_case, &audit, id, new_address());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
