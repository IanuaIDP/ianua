//! Rotate push secret: replace the secret a push subscription signs its
//! messages with.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::control::MessagingControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{MessageSubscriptionId, RotationOverlap};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::messaging::{PushSecretGenerator, SubscriptionStore};
use crate::use_case::Command;
use crate::use_cases::messaging::lookup::existing_subscription;
use crate::use_cases::messaging::push_secret::{fresh_push_secret, push_secret_place};

/// Which subscription's push secret to replace, and how long the old one
/// keeps signing.
pub struct RotatePushSecretRequest {
    /// The push subscription whose secret is replaced.
    pub subscription_id: MessageSubscriptionId,
    /// How long the old secret keeps signing beside the new one: not at all
    /// after a leak, or up to seven days while the service moves over.
    pub overlap: RotationOverlap,
}

/// The ports [`RotatePushSecretUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotatePushSecretPorts {
    /// Where subscriptions are kept.
    pub subscription_store: Arc<dyn SubscriptionStore>,
    /// Makes push signing secrets.
    pub push_secrets: Arc<dyn PushSecretGenerator>,
    /// Seals the secret before it is stored.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Replaces a push subscription's signing secret.
pub struct RotatePushSecretUseCase {
    ports: RotatePushSecretPorts,
}

impl RotatePushSecretUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RotatePushSecretPorts) -> Self {
        Self { ports }
    }
}

impl Command for RotatePushSecretUseCase {
    type Caller = CallerContext;
    type Input = RotatePushSecretRequest;
    type Output = Result<Secret, AppError>;

    /// Gives the push subscription a new signing secret and records
    /// `messaging.subscription_secret_rotated`. The raw secret comes back
    /// once; only its sealed form is stored and the record never holds it.
    /// The old one keeps signing for the overlap asked for, and a secret
    /// from an earlier rotation stops at once.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without messaging-management rights.
    /// - `AppError::NotFound` for a missing tenant subscription; `Conflict` for a pulled subscription.
    /// - `AppError::Domain` for overlap beyond seven days; `Internal` on storage, secret or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: RotatePushSecretRequest,
    ) -> Result<Secret, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = MessagingControl::new(&authority);
        control
            .ensure_may(MessagingAction::Manage)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.subscription_store.as_ref();
        let mut subscription =
            existing_subscription(store, &tenant, &request.subscription_id).await?;
        let secret = fresh_push_secret(
            self.ports.push_secrets.as_ref(),
            self.ports.encryptor.as_ref(),
            &push_secret_place(&tenant, subscription.id()),
        )
        .await?;
        subscription
            .rotate_push_secret(secret.sealed, request.overlap, &control)
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &subscription).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), subscription.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(secret.raw)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::messaging::delivery::{PushEndpoint, SubscriptionDelivery};
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Lifetime, SealedSecret};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::consumers::billing_sync;
    use crate::test_support::messaging::{
        FakeSubscriptionStore, TEST_PUSH_SECRET, push_secret_place, push_subscription_of,
        stored_subscription, subscription_of, topic_named,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// `secret` as the fake seals it for the test tenant's subscription
    /// `id`.
    fn sealed_as(id: &MessageSubscriptionId, secret: &str) -> SealedSecret {
        FakeEncryptor::sealed_for(secret, &push_secret_place(id))
    }

    fn seeded() -> (Arc<FakeSubscriptionStore>, MessageSubscriptionId) {
        let subscription = push_subscription_of(&billing_sync(), &topic_named("orders.created"));
        let id = *subscription.id();
        (FakeSubscriptionStore::of_test_tenant([subscription]), id)
    }

    fn use_case(
        store: Arc<FakeSubscriptionStore>,
        authorities: FakeTenantAuthorities,
    ) -> RotatePushSecretUseCase {
        RotatePushSecretUseCase::new(RotatePushSecretPorts {
            subscription_store: store,
            tenant_authorities: Arc::new(authorities),
            ..RotatePushSecretPorts::fakes()
        })
    }

    fn rotate_with(
        use_case: &RotatePushSecretUseCase,
        audit: &Arc<FakeEventDispatcher>,
        subscription_id: MessageSubscriptionId,
        overlap: RotationOverlap,
    ) -> Result<Secret, AppError> {
        let request = RotatePushSecretRequest {
            subscription_id,
            overlap,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    fn rotate(
        use_case: &RotatePushSecretUseCase,
        audit: &Arc<FakeEventDispatcher>,
        id: MessageSubscriptionId,
    ) -> Result<Secret, AppError> {
        rotate_with(use_case, audit, id, RotationOverlap::Immediate)
    }

    fn stored_endpoint(store: &FakeSubscriptionStore, id: &MessageSubscriptionId) -> PushEndpoint {
        let SubscriptionDelivery::Push(endpoint) =
            stored_subscription(store, id).delivery().clone()
        else {
            panic!("the subscription is pushed");
        };
        endpoint
    }

    fn stored_secret(store: &FakeSubscriptionStore, id: &MessageSubscriptionId) -> SealedSecret {
        stored_endpoint(store, id).signing_secret().clone()
    }

    /// Ann fears "billing-sync"'s push secret leaked and rotates it at once.
    /// She is shown the new one, the subscription keeps it sealed, the old
    /// one signs nothing more, and the rotation is recorded.
    #[test]
    fn a_rotated_push_secret_is_shown_once_and_stored_sealed() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        let secret = rotate(&use_case, &audit, id).unwrap();

        assert_eq!(secret.expose(), "push-secret-1");
        assert_eq!(stored_secret(&store, &id), sealed_as(&id, "push-secret-1"));
        assert_eq!(
            stored_endpoint(&store, &id)
                .signing_secrets(clock::now())
                .len(),
            1
        );
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["messaging.subscription_secret_rotated"]
        );
    }

    /// Ann rotates the secret with a day's overlap while "billing-sync"
    /// moves over. Both secrets sign pushes until the day is out.
    #[test]
    fn an_overlap_keeps_the_old_push_secret_signing() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());
        let day = RotationOverlap::For(Lifetime::seconds(86_400).unwrap());

        rotate_with(&use_case, &audit, id, day).unwrap();

        let endpoint = stored_endpoint(&store, &id);
        assert_eq!(
            endpoint.signing_secrets(clock::now()),
            [
                &sealed_as(&id, "push-secret-1"),
                &sealed_as(&id, TEST_PUSH_SECRET)
            ]
        );
    }

    /// Rotating with a month's overlap returns a domain error, keeps the
    /// existing push secret and records no event.
    #[test]
    fn an_overlap_over_seven_days_is_refused() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());
        let month = RotationOverlap::For(Lifetime::seconds(2_592_000).unwrap());

        let result = rotate_with(&use_case, &audit, id, month);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(stored_secret(&store, &id), sealed_as(&id, TEST_PUSH_SECRET));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A pulled subscription signs nothing. Rotating its secret is refused
    /// as a conflict, and nothing is recorded.
    #[test]
    fn a_pulled_subscription_has_no_secret_to_rotate() {
        let subscription = subscription_of(&billing_sync(), &topic_named("orders.created"));
        let id = *subscription.id();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            FakeSubscriptionStore::of_test_tenant([subscription]),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = rotate(&use_case, &audit, id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann names a subscription the tenant does not have. It is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeSubscriptionStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = rotate(&use_case, &audit, MessageSubscriptionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Messaging creation rights do not permit rotating a push secret;
    /// the forbidden request keeps the existing secret and records no event.
    #[test]
    fn rotating_needs_the_full_messaging_right() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::Create)]),
        );

        let result = rotate(&use_case, &audit, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stored_secret(&store, &id), sealed_as(&id, TEST_PUSH_SECRET));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out caller receives an unauthenticated error when rotating
    /// a push secret.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = rotate(&use_case, &audit, id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
