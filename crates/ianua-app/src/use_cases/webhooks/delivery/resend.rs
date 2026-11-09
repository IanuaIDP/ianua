//! Resend delivery: send a message a webhook was sent before again, under
//! its own message id, as a new attempt.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WebhooksAction;
use ianua_domain::domains::webhooks::control::WebhookControl;
use ianua_domain::domains::webhooks::delivery::DeliveryAttempt;
use ianua_domain::domains::webhooks::subscription::WebhookSubscription;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{WebhookDeliveryId, WebhookSubscriptionId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::AccessRecordStore;
use crate::ports::identity::UserStore;
use crate::ports::organization::{OrgTenantGrantStore, OrgUserStore, OrganizationStore};
use crate::ports::webhooks::{WebhookMessage, WebhookSendThrottle};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::webhooks::delivery::creator::{Audience, CreatorStores};
use crate::use_cases::webhooks::delivery::sending::{
    SendingPorts, SentBy, Try, ensure_not_disabled, ensure_send_admitted,
};
use crate::use_cases::webhooks::lookup::existing_subscription;

/// Which earlier try to send again.
pub struct ResendRequest {
    /// The subscription it was sent to.
    pub subscription_id: WebhookSubscriptionId,
    /// The earlier attempt whose message is sent again.
    pub delivery_id: WebhookDeliveryId,
}

/// The ports [`ResendUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ResendPorts {
    /// Signs and sends the try, keeps it, counts it and records it.
    pub sending: SendingPorts,
    /// Lets each webhook be resent to only now and then.
    pub throttle: Arc<dyn WebhookSendThrottle>,
    /// Who holds what in the tenant, for what the creator may see now.
    pub access: Arc<dyn AccessRecordStore>,
    /// The tenant's users, for a creator who is one.
    pub users: Arc<dyn UserStore>,
    /// Organization members, for a creator who is one.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organizations, for a member creator's organization.
    pub organizations: Arc<dyn OrganizationStore>,
    /// A member creator's tenant grants.
    pub org_grants: Arc<dyn OrgTenantGrantStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sends a message a webhook was sent before again.
pub struct ResendUseCase {
    ports: ResendPorts,
}

impl ResendUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ResendPorts) -> Self {
        Self { ports }
    }

    /// The message attempt `delivery_id` of the subscription carried.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the subscription has no such attempt, or
    ///   its message is no longer kept.
    /// - `AppError::Internal` on storage failure.
    async fn earlier_message(
        &self,
        tenant: &ScopedTenant,
        request: &ResendRequest,
    ) -> Result<(DeliveryAttempt, WebhookMessage), AppError> {
        let store = self.ports.sending.webhook_store.as_ref();
        let attempt = store
            .find_delivery_attempt(tenant, &request.subscription_id, &request.delivery_id)
            .await
            .or_internal()?
            .or_not_found(message!(
                "webhooks-webhook-delivery-not-found",
                "webhook delivery not found"
            ))?;
        let message = store
            .find_message(tenant, &request.subscription_id, &attempt.message_id)
            .await
            .or_internal()?
            .or_not_found(message!(
                "webhooks-webhook-message-not-found",
                "webhook message not found"
            ))?;
        Ok((attempt, message))
    }

    /// Refuses the resend unless the domain says the subscription's creator
    /// may still see the message's event.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when they may no longer see it.
    /// - `AppError::Internal` when a store cannot be read.
    async fn ensure_still_received(
        &self,
        tenant: &ScopedTenant,
        subscription: &WebhookSubscription<ResolvedTenant>,
        message: &WebhookMessage,
    ) -> Result<(), AppError> {
        let audience = Audience {
            creators: CreatorStores {
                users: self.ports.users.as_ref(),
                org_users: self.ports.org_users.as_ref(),
                organizations: self.ports.organizations.as_ref(),
                org_grants: self.ports.org_grants.as_ref(),
            },
            access: self.ports.access.as_ref(),
        };
        if audience
            .receives_now(tenant, subscription, &message.event_type)
            .await?
        {
            return Ok(());
        }
        Err(AppError::Forbidden(message!(
            "webhooks-the-webhook-no-longer-receives-this",
            "the webhook no longer receives this event"
        )))
    }
}

impl Command for ResendUseCase {
    type Caller = CallerContext;
    type Input = ResendRequest;
    type Output = Result<DeliveryAttempt, AppError>;

    /// Sends the earlier attempt's message again, with the same message id
    /// so a receiver that handled it drops it, signed with every secret the
    /// subscription signs with now. The new attempt is kept, counted on the
    /// endpoint's failure streak and recorded as
    /// `webhooks.delivery_attempted` by the caller. It is not retried.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without webhook-update rights or when the creator cannot see the event.
    /// - `AppError::NotFound` for a missing tenant subscription/attempt/message; `Conflict` for a disabled subscription.
    /// - `AppError::Domain` for a forbidden destination address; `TooManyRequests` for a recent send.
    /// - `AppError::Internal` on storage, secret or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: ResendRequest,
    ) -> Result<DeliveryAttempt, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        WebhookControl::new(&authority)
            .ensure_may(WebhooksAction::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let store = self.ports.sending.webhook_store.as_ref();
        let subscription = existing_subscription(store, &tenant, &request.subscription_id).await?;
        ensure_not_disabled(&subscription)?;
        let (earlier, message) = self.earlier_message(&tenant, &request).await?;
        self.ensure_still_received(&tenant, &subscription, &message)
            .await?;
        ensure_send_admitted(
            self.ports.throttle.as_ref(),
            &tenant,
            &request.subscription_id,
        )
        .await?;
        let attempt = Try {
            message: &message,
            attempt_number: earlier.attempt_number.saturating_add(1),
        };
        let actor = caller.actor();
        let sender = self
            .ports
            .sending
            .sender(&tenant, auditor, SentBy::Person(&actor));
        Ok(sender.send(&subscription, attempt).await?.attempt)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
    use ianua_domain::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::{Label, PrincipalRef, RoleId, UserId};

    use super::*;
    use crate::ports::authorization::AccessRecords;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeAccessRecordStore;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::webhooks::{
        FakeWebhookDeliverer, FakeWebhookStore, ShutWebhookSendThrottle, test_attempt,
        test_message, test_subscription, test_subscription_creator,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann, who made the webhook.
    fn ann() -> UserId {
        match test_subscription_creator() {
            PrincipalRef::User(user_id) => Some(user_id),
            _ => None,
        }
        .unwrap()
    }

    /// The tenant's records, where Ann holds one role granting `system`.
    fn records_where_ann_holds(system: &[SystemPermission]) -> AccessRecords {
        let role = Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("role_name", "user viewer").unwrap(),
            system_permissions: system.to_vec(),
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        });
        let assignment = RoleAssignment::create(
            PrincipalRef::User(ann()),
            &role,
            anyone_holding(SystemPermission::all()),
        )
        .unwrap();
        AccessRecords {
            roles: vec![role],
            assignments: vec![assignment],
            ..AccessRecords::default()
        }
    }

    /// A webhook in `status` that was sent one registration, which failed.
    struct Sent {
        store: Arc<FakeWebhookStore>,
        deliverer: Arc<FakeWebhookDeliverer>,
        message: WebhookMessage,
        request: ResendRequest,
    }

    /// Ann's webhook in `status`, sent one registration its server
    /// answered 503.
    fn sent_once(status: WebhookSubscriptionStatus) -> Sent {
        let subscription = test_subscription("https://hooks.acme.com/events", status);
        let tenant = test_ctx().tenant_id();
        let store = Arc::new(FakeWebhookStore::holding(tenant, &subscription));
        let message = test_message(*subscription.id());
        let attempt = test_attempt(&message, 503);
        let request = ResendRequest {
            subscription_id: *subscription.id(),
            delivery_id: attempt.id,
        };
        store.sent(tenant, message.clone(), attempt);
        Sent {
            store,
            deliverer: Arc::new(FakeWebhookDeliverer::new()),
            message,
            request,
        }
    }

    /// A use case resending from `sent`, for a caller holding what
    /// `authorities` says, while Ann holds `ann_holds`.
    fn use_case(
        sent: &Sent,
        authorities: FakeTenantAuthorities,
        ann_holds: &[SystemPermission],
    ) -> ResendUseCase {
        ResendUseCase::new(ResendPorts {
            sending: SendingPorts {
                webhook_store: sent.store.clone(),
                deliverer: sent.deliverer.clone(),
                ..SendingPorts::fakes()
            },
            access: Arc::new(FakeAccessRecordStore::holding(
                test_ctx().tenant_id(),
                records_where_ann_holds(ann_holds),
            )),
            users: Arc::new(FakeUserStore::with_user(ann(), "ann@acme.com")),
            tenant_authorities: Arc::new(authorities),
            ..ResendPorts::fakes()
        })
    }

    /// The right to see user events.
    fn user_viewer() -> [SystemPermission; 1] {
        [SystemPermission::Users(UserAction::View)]
    }

    /// The right to update webhooks.
    fn updater() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::Update)])
    }

    /// Resends `request`.
    fn resend(
        use_case: &ResendUseCase,
        audit: &Arc<FakeEventDispatcher>,
        request: ResendRequest,
    ) -> Result<DeliveryAttempt, AppError> {
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), request))
    }

    /// The same request again.
    fn again(request: &ResendRequest) -> ResendRequest {
        ResendRequest {
            subscription_id: request.subscription_id,
            delivery_id: request.delivery_id,
        }
    }

    /// Ann's server was down when a registration was sent. Once it is back
    /// she resends it: the same body under the same message id, recorded as
    /// a new attempt.
    #[test]
    fn a_failed_delivery_is_sent_again_under_its_message_id() {
        let sent = sent_once(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&sent, updater(), &user_viewer());

        let attempt = resend(&use_case, &audit, again(&sent.request)).unwrap();

        let delivered = sent.deliverer.deliveries();
        assert_eq!(delivered[0].signed.message_id(), &sent.message.id);
        assert_eq!(delivered[0].payload, sent.message.payload);
        assert_eq!(attempt.message_id, sent.message.id);
        assert_eq!(attempt.attempt_number, 1);
        assert_eq!(sent.store.attempts_in(test_ctx().tenant_id()).len(), 2);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["webhooks.delivery_attempted"]
        );
    }

    /// A resend rejected by the webhook throttle returns too many requests
    /// without calling the deliverer or recording an event.
    #[test]
    fn a_webhook_resent_to_a_moment_ago_is_refused() {
        let sent = sent_once(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let mut use_case = use_case(&sent, updater(), &user_viewer());
        use_case.ports.throttle = Arc::new(ShutWebhookSendThrottle);

        let result = resend(&use_case, &audit, again(&sent.request));

        assert!(matches!(result, Err(AppError::TooManyRequests(_))));
        assert_eq!(*sent.deliverer.calls.lock().unwrap(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Resending an event the subscription's creator cannot view is forbidden
    /// without calling the deliverer or recording an event.
    #[test]
    fn an_event_the_creator_may_no_longer_see_is_not_resent() {
        let sent = sent_once(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&sent, updater(), &[]);

        let result = resend(&use_case, &audit, again(&sent.request));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(*sent.deliverer.calls.lock().unwrap(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Ann resends to a webhook switched off for failing. It is refused: a
    /// disabled webhook is replaced.
    #[test]
    fn a_disabled_subscription_is_not_resent_to() {
        let sent = sent_once(WebhookSubscriptionStatus::Disabled);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&sent, updater(), &user_viewer());

        let result = resend(&use_case, &audit, again(&sent.request));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(*sent.deliverer.calls.lock().unwrap(), 0);
    }

    /// Ann names an attempt the webhook never made. It is not found.
    #[test]
    fn an_unknown_attempt_is_not_found() {
        let sent = sent_once(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&sent, updater(), &user_viewer());
        let request = ResendRequest {
            subscription_id: sent.request.subscription_id,
            delivery_id: WebhookDeliveryId::new(),
        };

        let result = resend(&use_case, &audit, request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Ann names a subscription the tenant does not have. It is not found.
    #[test]
    fn an_unknown_subscription_is_not_found() {
        let sent = sent_once(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(&sent, updater(), &user_viewer());
        let request = ResendRequest {
            subscription_id: WebhookSubscriptionId::new(),
            delivery_id: sent.request.delivery_id,
        };

        let result = resend(&use_case, &audit, request);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Webhook viewing rights do not permit resending a delivery; the request
    /// is forbidden without calling the deliverer or recording an event.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let sent = sent_once(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            &sent,
            FakeTenantAuthorities::holding(&[SystemPermission::Webhooks(WebhooksAction::View)]),
            &user_viewer(),
        );

        let result = resend(&use_case, &audit, again(&sent.request));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(*sent.deliverer.calls.lock().unwrap(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Resending a delivery with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let sent = sent_once(WebhookSubscriptionStatus::Active);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            &sent,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &user_viewer(),
        );

        let result = resend(&use_case, &audit, again(&sent.request));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
