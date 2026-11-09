//! Create subscription: register a new webhook endpoint for event delivery.

use std::sync::Arc;

use ianua_domain::domains::authorization::authority::TenantAuthority;
use ianua_domain::domains::webhooks::control::WebhookControl;
use ianua_domain::domains::webhooks::retry_policy::RetryPreset;
use ianua_domain::domains::webhooks::subscription::{CreateWebhookParams, WebhookSubscription};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{EventType, PublicHttpsUrl, SealedSecret, Text, WebhookSubscriptionId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::webhooks::{WebhookSecretGenerator, WebhookStore};
use crate::services::limits::room::ensure_room_in_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::webhooks::signing_secret::{FreshSecret, fresh_secret, secret_place};

/// Request to create a new webhook subscription.
pub struct CreateRequest {
    /// The public HTTPS URL to deliver events to.
    pub url: PublicHttpsUrl,
    /// Event types to subscribe to. Empty means every event the creator may
    /// see now.
    pub event_types: Vec<EventType>,
    /// Optional description.
    pub description: Option<Text>,
    /// How hard failed deliveries are retried.
    pub retry: RetryPreset,
}

/// A subscription just created, with its secret.
///
/// No `Debug`: it carries the raw signing secret.
pub struct CreatedSubscription {
    /// The subscription's unique identifier.
    pub subscription_id: WebhookSubscriptionId,
    /// The raw signing secret, shown once and stored only sealed.
    pub signing_secret: Secret,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Where subscriptions are kept.
    pub webhook_store: Arc<dyn WebhookStore>,
    /// Makes signing secrets.
    pub secret_generator: Arc<dyn WebhookSecretGenerator>,
    /// Seals the signing secret before it is stored.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// The tenant's plan limits.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Creates a webhook subscription for the person acting, who is kept as its
/// creator.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// A new signing secret for `tenant`'s subscription `id`, with its form
    /// sealed for it.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when no secret can be made or it cannot be
    /// sealed.
    async fn new_secret(
        &self,
        tenant: &ScopedTenant,
        id: &WebhookSubscriptionId,
    ) -> Result<FreshSecret, AppError> {
        fresh_secret(
            self.ports.secret_generator.as_ref(),
            self.ports.encryptor.as_ref(),
            &secret_place(tenant, id),
        )
        .await
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<CreatedSubscription, AppError>;

    /// Creates the subscription `request` describes and records
    /// `webhooks.subscription_created`. The raw signing secret comes back
    /// once; only its sealed form is stored.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update webhooks,
    ///   names an event they may not see, or the plan's webhook limit is
    ///   reached.
    /// - `AppError::Domain` when the request names the webhook delivery
    ///   event, or the caller may see no event at all.
    /// - `AppError::Internal` on storage, secret or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<CreatedSubscription, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        ensure_room_in_tenant(
            self.ports.limit_enforcer.as_ref(),
            caller,
            ResourceKind::Webhooks,
        )
        .await?;
        let tenant = caller.tenant();
        let id = WebhookSubscriptionId::new();
        let secret = self.new_secret(&tenant, &id).await?;
        let mut subscription = new_subscription(id, request, secret.sealed, &authority)?;
        self.ports
            .webhook_store
            .save(&tenant, &subscription)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), subscription.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(CreatedSubscription {
            subscription_id: *subscription.id(),
            signing_secret: secret.raw,
        })
    }
}

/// The subscription `id` that `request` describes, signed with
/// `signing_secret` and made by the person `authority` names, as the
/// domain allows it.
fn new_subscription(
    id: WebhookSubscriptionId,
    request: CreateRequest,
    signing_secret: SealedSecret,
    authority: &TenantAuthority,
) -> Result<WebhookSubscription<ResolvedTenant>, AppError> {
    WebhookSubscription::create(
        CreateWebhookParams {
            id,
            url: request.url,
            signing_secret,
            event_types: request.event_types,
            description: request.description,
            retry: request.retry,
        },
        &WebhookControl::new(authority),
    )
    .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{
        SystemPermission, UserAction, WebhooksAction,
    };
    use ianua_domain::types::event_type::{CryptoEvent, IdentityEvent, WebhooksEvent};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::webhooks::{FakeWebhookStore, signing_secret_place};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    /// What lets Ann make webhooks for user events.
    const WEBHOOKS_AND_USERS: [SystemPermission; 2] = [
        SystemPermission::Webhooks(WebhooksAction::Update),
        SystemPermission::Users(UserAction::View),
    ];

    fn request(event_types: Vec<EventType>) -> CreateRequest {
        CreateRequest {
            url: PublicHttpsUrl::new("https://hooks.acme.com/events").unwrap(),
            event_types,
            description: None,
            retry: RetryPreset::Standard,
        }
    }

    fn user_registrations() -> CreateRequest {
        request(vec![IdentityEvent::UserRegistered.into()])
    }

    fn holding(rights: &[SystemPermission]) -> Arc<dyn TenantAuthorities> {
        Arc::new(FakeTenantAuthorities::holding(rights))
    }

    fn use_case(
        store: Arc<FakeWebhookStore>,
        authorities: Arc<dyn TenantAuthorities>,
    ) -> CreateUseCase {
        CreateUseCase::new(CreatePorts {
            webhook_store: store,
            tenant_authorities: authorities,
            ..CreatePorts::fakes()
        })
    }

    fn create(
        use_case: &CreateUseCase,
        audit: &Arc<FakeEventDispatcher>,
        request: CreateRequest,
    ) -> Result<CreatedSubscription, AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    /// Ann may make webhooks and see user events. She subscribes her server
    /// to user registrations. The subscription is stored and the creation
    /// recorded.
    #[test]
    fn a_webhook_admin_creates_a_subscription() {
        let store = Arc::new(FakeWebhookStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), holding(&WEBHOOKS_AND_USERS));

        create(&use_case, &audit, user_registrations()).unwrap();

        assert_eq!(store.count(), 1);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["webhooks.subscription_created"]
        );
    }

    /// Ann is shown the secret her server checks deliveries with. The store
    /// keeps only its sealed form.
    #[test]
    fn the_raw_secret_is_shown_once_and_stored_sealed() {
        let store = Arc::new(FakeWebhookStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), holding(&WEBHOOKS_AND_USERS));

        let created = create(&use_case, &audit, user_registrations()).unwrap();

        let stored = store
            .stored(test_ctx().tenant_id(), &created.subscription_id)
            .unwrap();
        assert_eq!(created.signing_secret.expose(), "raw-secret-1");
        assert_eq!(
            stored.signing_secret(),
            &FakeEncryptor::sealed_for(
                "raw-secret-1",
                &signing_secret_place(&created.subscription_id)
            )
        );
    }

    /// Ann's endpoint is often down, so she picks the patient retry policy.
    /// The subscription keeps it.
    #[test]
    fn the_chosen_retry_policy_is_kept() {
        let store = Arc::new(FakeWebhookStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), holding(&WEBHOOKS_AND_USERS));
        let patient = CreateRequest {
            retry: RetryPreset::Patient,
            ..user_registrations()
        };

        let created = create(&use_case, &audit, patient).unwrap();

        let stored = store
            .stored(test_ctx().tenant_id(), &created.subscription_id)
            .unwrap();
        assert_eq!(stored.retry(), RetryPreset::Patient);
    }

    /// Ann names no event. Her subscription receives every event she may
    /// see, and no other.
    #[test]
    fn an_empty_list_subscribes_to_what_the_creator_may_see() {
        let store = Arc::new(FakeWebhookStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), holding(&WEBHOOKS_AND_USERS));

        let created = create(&use_case, &audit, request(Vec::new())).unwrap();

        let stored = store
            .stored(test_ctx().tenant_id(), &created.subscription_id)
            .unwrap();
        let key_event: EventType = CryptoEvent::ALL[0].0.into();
        assert!(
            stored
                .event_types()
                .contains(&IdentityEvent::UserRegistered.into())
        );
        assert!(!stored.event_types().contains(&key_event));
    }

    /// A webhook creator without access to signing key events cannot
    /// subscribe to them; the request is forbidden and nothing is stored.
    #[test]
    fn an_event_the_creator_may_not_see_is_refused() {
        let store = Arc::new(FakeWebhookStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(store.clone(), holding(&WEBHOOKS_AND_USERS));

        let result = create(
            &use_case,
            &audit,
            request(vec![CryptoEvent::ALL[0].0.into()]),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Ann subscribes to the record of webhook deliveries. It is refused,
    /// since every delivery would raise one more.
    #[test]
    fn a_subscription_to_its_own_deliveries_is_refused() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeWebhookStore::empty()),
            holding(SystemPermission::all()),
        );

        let result = create(
            &use_case,
            &audit,
            request(vec![WebhooksEvent::DeliveryAttempted.into()]),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Viewing webhooks and users does not permit creating a subscription;
    /// the request is forbidden without storing or recording a creation.
    #[test]
    fn a_caller_without_the_webhooks_right_is_refused() {
        let store = Arc::new(FakeWebhookStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store.clone(),
            holding(&[
                SystemPermission::Webhooks(WebhooksAction::View),
                SystemPermission::Users(UserAction::View),
            ]),
        );

        let result = create(&use_case, &audit, user_registrations());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Creating a subscription with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            Arc::new(FakeWebhookStore::empty()),
            Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
        );

        let result = create(&use_case, &audit, user_registrations());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Ann's tenant already holds as many webhooks as its plan allows. Her
    /// new one is refused and nothing is stored.
    #[test]
    fn a_subscription_past_the_plan_limit_is_refused() {
        let store = Arc::new(FakeWebhookStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = CreateUseCase::new(CreatePorts {
            webhook_store: store.clone(),
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            tenant_authorities: holding(&WEBHOOKS_AND_USERS),
            ..CreatePorts::fakes()
        });

        let result = create(&use_case, &audit, user_registrations());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }
}
