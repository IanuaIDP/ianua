//! Rotate secret: replace a webhook subscription's signing secret.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WebhooksAction;
use ianua_domain::domains::webhooks::control::WebhookControl;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{RotationOverlap, WebhookSubscriptionId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealedFor, SecretEncryptor};
use crate::ports::webhooks::{WebhookSecretGenerator, WebhookStore};
use crate::use_case::Command;
use crate::use_cases::webhooks::keeping::keep_subscription;
use crate::use_cases::webhooks::lookup::existing_subscription;
use crate::use_cases::webhooks::signing_secret::{FreshSecret, fresh_secret, secret_place};

/// Which subscription's secret to replace, and how long the old one keeps
/// signing.
pub struct RotateSecretRequest {
    /// The subscription whose secret is replaced.
    pub subscription_id: WebhookSubscriptionId,
    /// How long the old secret keeps signing beside the new one: not at all
    /// after a leak, or up to seven days while the receiving servers move
    /// over.
    pub overlap: RotationOverlap,
}

/// The ports [`RotateSecretUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RotateSecretPorts {
    /// Where subscriptions are kept.
    pub webhook_store: Arc<dyn WebhookStore>,
    /// Makes signing secrets.
    pub secret_generator: Arc<dyn WebhookSecretGenerator>,
    /// Seals the signing secret before it is stored.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Replaces a webhook subscription's signing secret.
pub struct RotateSecretUseCase {
    ports: RotateSecretPorts,
}

impl RotateSecretUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RotateSecretPorts) -> Self {
        Self { ports }
    }

    /// A new random signing secret, with its form sealed for `place`.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when no secret can be made or it cannot be sealed.
    async fn new_secret(&self, place: &SealedFor) -> Result<FreshSecret, AppError> {
        fresh_secret(
            self.ports.secret_generator.as_ref(),
            self.ports.encryptor.as_ref(),
            place,
        )
        .await
    }
}

impl Command for RotateSecretUseCase {
    type Caller = CallerContext;
    type Input = RotateSecretRequest;
    type Output = Result<Secret, AppError>;

    /// Gives the subscription a new signing secret and records
    /// `webhooks.secret_rotated`. The raw secret comes back once; only its
    /// sealed form is stored. The old one keeps signing for the overlap
    /// asked for, and a secret from an earlier rotation stops at once.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller does not manage webhooks.
    /// - `AppError::NotFound` when the tenant has no such subscription.
    /// - `AppError::Domain` when the overlap is longer than seven days.
    /// - `AppError::Internal` on storage, secret or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: RotateSecretRequest,
    ) -> Result<Secret, AppError> {
        let RotateSecretRequest {
            subscription_id,
            overlap,
        } = request;
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = WebhookControl::new(&authority);
        control
            .ensure_may(WebhooksAction::Manage)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut subscription =
            existing_subscription(self.ports.webhook_store.as_ref(), &tenant, &subscription_id)
                .await?;
        let secret = self
            .new_secret(&secret_place(&tenant, subscription.id()))
            .await?;
        subscription
            .rotate_secret(secret.sealed, overlap, &control)
            .map_err(AppError::from_domain)?;

        keep_subscription(self.ports.webhook_store.as_ref(), &tenant, &subscription).await?;
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
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
    use ianua_domain::types::{Lifetime, SealedSecret};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::webhooks::{
        FakeWebhookStore, TEST_SIGNING_SECRET, signing_secret_place, test_subscription,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn seeded() -> (Arc<FakeWebhookStore>, WebhookSubscriptionId) {
        let subscription = test_subscription(
            "https://hooks.acme.com/events",
            WebhookSubscriptionStatus::Active,
        );
        let store = FakeWebhookStore::holding(test_ctx().tenant_id(), &subscription);
        (Arc::new(store), *subscription.id())
    }

    fn use_case(
        store: Arc<FakeWebhookStore>,
        authorities: FakeTenantAuthorities,
    ) -> RotateSecretUseCase {
        RotateSecretUseCase::new(RotateSecretPorts {
            webhook_store: store,
            tenant_authorities: Arc::new(authorities),
            ..RotateSecretPorts::fakes()
        })
    }

    /// Rotates `id`'s secret, the old one stopping at once.
    fn rotate(
        use_case: &RotateSecretUseCase,
        audit: &Arc<FakeEventDispatcher>,
        id: WebhookSubscriptionId,
    ) -> Result<Secret, AppError> {
        rotate_keeping(use_case, audit, id, RotationOverlap::Immediate)
    }

    /// Rotates `id`'s secret, the old one signing for `overlap`.
    fn rotate_keeping(
        use_case: &RotateSecretUseCase,
        audit: &Arc<FakeEventDispatcher>,
        subscription_id: WebhookSubscriptionId,
        overlap: RotationOverlap,
    ) -> Result<Secret, AppError> {
        let request = RotateSecretRequest {
            subscription_id,
            overlap,
        };
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    /// An overlap of `count` days.
    fn days(count: i64) -> RotationOverlap {
        RotationOverlap::For(Lifetime::new(time::Duration::days(count)).unwrap())
    }

    /// Ann's servers need a day to move to the new secret. She rotates with
    /// a day's overlap: deliveries are signed with both secrets until then.
    #[test]
    fn an_overlap_keeps_the_old_secret_signing() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        rotate_keeping(&use_case, &audit, id, days(1)).unwrap();

        let stored = store.stored(test_ctx().tenant_id(), &id).unwrap();
        assert_eq!(
            stored.signing_secrets(),
            [
                &sealed_as(&id, "raw-secret-1"),
                &sealed_as(&id, TEST_SIGNING_SECRET)
            ]
        );
    }

    /// Ann's secret leaked. She rotates with no overlap, and only the new
    /// secret signs from then on.
    #[test]
    fn a_rotation_after_a_leak_ends_the_old_secret_at_once() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        rotate(&use_case, &audit, id).unwrap();

        let stored = store.stored(test_ctx().tenant_id(), &id).unwrap();
        assert_eq!(stored.signing_secrets(), [&sealed_as(&id, "raw-secret-1")]);
    }

    /// A thirty-day rotation overlap returns a domain error, preserves the
    /// stored signing secret and records no event.
    #[test]
    fn an_overlap_past_seven_days_is_refused() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        let result = rotate_keeping(&use_case, &audit, id, days(30));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(
            stored_secret(&store, &id),
            sealed_as(&id, TEST_SIGNING_SECRET)
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// `secret` as the fake seals it for the test tenant's subscription
    /// `id`.
    fn sealed_as(id: &WebhookSubscriptionId, secret: &str) -> SealedSecret {
        FakeEncryptor::sealed_for(secret, &signing_secret_place(id))
    }

    fn stored_secret(store: &FakeWebhookStore, id: &WebhookSubscriptionId) -> SealedSecret {
        store
            .stored(test_ctx().tenant_id(), id)
            .unwrap()
            .signing_secret()
            .clone()
    }

    /// Ann fears the secret leaked and rotates it. She is shown the new one,
    /// the subscription keeps it sealed, and the rotation is recorded.
    #[test]
    fn a_rotated_secret_is_shown_once_and_stored_sealed() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), FakeTenantAuthorities::holding_everything());

        let secret = rotate(&use_case, &audit, id).unwrap();

        assert_eq!(secret.expose(), "raw-secret-1");
        assert_eq!(stored_secret(&store, &id), sealed_as(&id, "raw-secret-1"));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["webhooks.secret_rotated"]
        );
    }

    /// Ann names a subscription the tenant does not have. It is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeWebhookStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = rotate(&use_case, &audit, WebhookSubscriptionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Rotating an unknown subscription's secret without webhook management
    /// rights returns forbidden rather than exposing its absence.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_subscription() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeWebhookStore::empty()),
            FakeTenantAuthorities::holding(&[]),
        );

        let result = rotate(&use_case, &audit, WebhookSubscriptionId::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Webhook update rights do not permit rotating a signing secret; the
    /// request is forbidden, the old secret stays and no event is recorded.
    #[test]
    fn rotating_needs_the_full_webhooks_right() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::Update)]),
        );

        let result = rotate(&use_case, &audit, id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            stored_secret(&store, &id),
            sealed_as(&id, TEST_SIGNING_SECRET)
        );
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Rotating a secret with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let (store, id) = seeded();
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store, FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = rotate(&use_case, &audit, id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
