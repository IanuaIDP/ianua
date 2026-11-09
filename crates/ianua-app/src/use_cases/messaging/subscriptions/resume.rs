//! Resume subscription: deliver a paused subscription's messages again.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::types::MessageSubscriptionId;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::messaging::SubscriptionStore;
use crate::use_case::Command;
use crate::use_cases::messaging::changes::MessagingChange;

/// The ports [`ResumeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResumePorts {
    /// Where subscriptions are kept.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Resumes a paused subscription.
pub struct ResumeUseCase {
    ports: ResumePorts,
}

impl ResumeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResumePorts) -> Self {
        Self { ports }
    }
}

impl Command for ResumeUseCase {
    type Caller = CallerContext;
    type Input = MessageSubscriptionId;
    type Output = Result<(), AppError>;

    /// Resumes a paused subscription, so its messages are delivered again.
    /// Records `messaging.subscription_resumed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` if the tenant has no such subscription.
    /// - `AppError::Forbidden` when the caller does not manage messaging.
    /// - `AppError::Domain` when the subscription is already active.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        subscription_id: MessageSubscriptionId,
    ) -> Result<(), AppError> {
        MessagingChange::by(caller, auditor, self.ports.tenant_authorities.as_ref())
            .subscription(
                self.ports.subscription_store.as_ref(),
                &subscription_id,
                MessagingAction::Manage,
                Subscription::resume,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
    use ianua_domain::domains::messaging::subscription::{Subscription, SubscriptionStatus};
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::billing_sync;
    use crate::test_support::messaging::{
        FakeSubscriptionStore, enrolled_subscription, paused_subscription_of, stored_subscription,
        topic_named,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn paused() -> Subscription<ResolvedTenant> {
        paused_subscription_of(&billing_sync(), &topic_named("orders.created"))
    }

    fn resume(
        subscription: Subscription<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> (Result<(), AppError>, SubscriptionStatus, Vec<String>) {
        let id = *subscription.id();
        let store = FakeSubscriptionStore::of_test_tenant([subscription]);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = ResumeUseCase::new(ResumePorts {
            subscription_store: store.clone(),
            tenant_authorities: Arc::new(authorities),
        });

        let result = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), id));

        let records = audit.records.lock().unwrap().clone();
        (result, stored_subscription(&store, &id).status(), records)
    }

    /// billing-sync is back from maintenance. Ann resumes its subscription,
    /// its waiting messages are delivered again, and that is on record.
    #[test]
    fn a_paused_subscription_is_resumed_and_recorded() {
        let (result, status, records) = resume(
            paused(),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Manage)]),
        );

        result.unwrap();
        assert_eq!(status, SubscriptionStatus::Active);
        assert_eq!(records, ["messaging.subscription_resumed"]);
    }

    /// Resuming an already active subscription returns a domain error,
    /// leaves it active and records no event.
    #[test]
    fn an_active_subscription_is_not_resumed() {
        let (result, status, records) = resume(
            enrolled_subscription(&topic_named("orders.created")),
            FakeTenantAuthorities::holding_everything(),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(status, SubscriptionStatus::Active);
        assert!(records.is_empty());
    }

    /// Messaging creation rights do not permit resuming a subscription;
    /// the forbidden request leaves it paused.
    #[test]
    fn a_caller_who_does_not_manage_messaging_is_refused() {
        let (result, status, _) = resume(
            paused(),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Create)]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(status, SubscriptionStatus::Paused);
    }

    /// A signed-out caller receives an unauthenticated error when resuming
    /// a subscription, which stays paused.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (result, status, _) = resume(
            paused(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(status, SubscriptionStatus::Paused);
    }

    /// Ann names a subscription the tenant does not have. It is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let use_case = ResumeUseCase::new(ResumePorts {
            subscription_store: Arc::new(FakeSubscriptionStore::empty()),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
        });
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(audit),
            MessageSubscriptionId::new(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
