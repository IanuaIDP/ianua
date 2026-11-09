//! Get subscription: read one webhook subscription.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{SystemPermission, WebhooksAction};
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::WebhookSubscriptionId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::webhooks::WebhookStore;
use crate::use_case::Query;
use crate::use_cases::webhooks::lookup::existing_subscription;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Where subscriptions are kept.
    pub webhook_store: Arc<dyn WebhookStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one of the tenant's webhook subscriptions.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = WebhookSubscriptionId;
    type Output = Result<WebhookSubscription<ResolvedTenant>, AppError>;

    /// The tenant's subscription `id`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view webhooks.
    /// - `AppError::NotFound` when the tenant has no such subscription.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        id: WebhookSubscriptionId,
    ) -> Result<WebhookSubscription<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(caller)
            .await?
            .ensure_holds(SystemPermission::Webhooks(WebhooksAction::View))
            .map_err(AppError::from_domain)?;
        existing_subscription(self.ports.webhook_store.as_ref(), &caller.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::webhooks::{FakeWebhookStore, test_subscription};
    use crate::test_support::{block_on, test_ctx};

    fn seeded() -> (Arc<FakeWebhookStore>, WebhookSubscriptionId) {
        let subscription = test_subscription(
            "https://hooks.acme.com/events",
            WebhookSubscriptionStatus::Active,
        );
        let store = FakeWebhookStore::holding(test_ctx().tenant_id(), &subscription);
        (Arc::new(store), *subscription.id())
    }

    fn use_case(store: Arc<FakeWebhookStore>, authorities: FakeTenantAuthorities) -> GetUseCase {
        GetUseCase::new(GetPorts {
            webhook_store: store,
            tenant_authorities: Arc::new(authorities),
        })
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::View)])
    }

    /// Ann may view webhooks and opens one of the tenant's. She sees it.
    #[test]
    fn a_viewer_reads_a_subscription() {
        let (store, id) = seeded();

        let found = block_on(use_case(store, viewer()).execute(&test_ctx(), id)).unwrap();

        assert_eq!(found.id(), &id);
    }

    /// Ann names a subscription the tenant does not have. It is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let use_case = use_case(Arc::new(FakeWebhookStore::empty()), viewer());

        let result = block_on(use_case.execute(&test_ctx(), WebhookSubscriptionId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading a subscription without webhook viewing rights returns forbidden.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let (store, id) = seeded();

        let result =
            block_on(use_case(store, FakeTenantAuthorities::holding(&[])).execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Reading a subscription with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();

        let result = block_on(
            use_case(store, FakeTenantAuthorities::refusing(Refusal::SignedOut))
                .execute(&test_ctx(), id),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
