mod changes;

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAccess;
use crate::domains::authorization::permission::WebhooksAction;
use crate::domains::notifications::category::VisibleTo;
use crate::domains::webhooks::catalog::{DELIVERY, subscribed};
use crate::domains::webhooks::control::WebhookControl;
use crate::domains::webhooks::creator::CreatorNow;
use crate::domains::webhooks::delivery::DeliveryAttempt;
use crate::domains::webhooks::events::{
    WebhookDeliveryAttempted, WebhookSubscriptionCreated, WebhookSubscriptionDeleted,
    WebhookSubscriptionDisabled, WebhookSubscriptionPaused, WebhookSubscriptionResumed,
};
use crate::domains::webhooks::retry_policy::RetryPreset;
use crate::domains::webhooks::subscription_status::WebhookSubscriptionStatus;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    EventType, EventVisibility, FailureLimit, FailureOutcome, FailureStreak, PreviousSigningSecret,
    PrincipalRef, PublicHttpsUrl, SealedSecret, Setting, Text, Threshold, WebhookSubscriptionId,
};

/// A tenant's subscription to events, delivered by HTTP callback.
///
/// When an event of a subscribed type occurs, the infrastructure layer
/// sends a signed HTTP POST to the URL. Failed deliveries are retried with
/// a growing delay.
///
/// Read and written only through stores opened for the resolved tenant.
/// See [`crate::isolation`].
#[derive(Debug)]
pub struct WebhookSubscription<T: TenantScope> {
    /// Unique subscription identifier.
    id: WebhookSubscriptionId,
    /// The HTTPS URL to deliver events to.
    url: PublicHttpsUrl,
    /// The secret deliveries are signed with, sealed at rest.
    signing_secret: SealedSecret,
    /// The secret before the last rotation, while it still signs.
    previous_secret: PreviousSigningSecret,
    /// Event types this subscription receives. Never empty.
    event_types: Vec<EventType>,
    /// Current delivery status.
    status: WebhookSubscriptionStatus,
    /// Optional description of this subscription's purpose.
    description: Option<Text>,
    /// How hard failed deliveries are retried.
    retry: RetryPreset,
    /// Who created it. Every delivery asks again what they may see.
    created_by: PrincipalRef,
    /// Number of consecutive delivery failures.
    failures: FailureStreak,
    /// When the last successful delivery occurred.
    last_delivered_at: Option<OffsetDateTime>,
    /// When this subscription was created.
    created_at: OffsetDateTime,
    /// When this subscription was last modified.
    updated_at: OffsetDateTime,
    /// The events raised since they were last taken.
    raised: Raised<T>,
    /// Which plane this belongs to. See [`crate::isolation`].
    _scope: PhantomData<T>,
}

/// What a new webhook subscription is created from.
pub struct CreateWebhookParams {
    /// The id the subscription is kept under, chosen before it is made so
    /// its signing secret can be sealed for it.
    pub id: WebhookSubscriptionId,
    /// The HTTPS URL to deliver events to.
    pub url: PublicHttpsUrl,
    /// The secret deliveries are signed with, sealed. The raw secret is
    /// shown to the tenant once, at creation.
    pub signing_secret: SealedSecret,
    /// Event types to subscribe to. Empty means every event the creator
    /// may see, as of creation.
    pub event_types: Vec<EventType>,
    /// Optional description of this subscription's purpose.
    pub description: Option<Text>,
    /// How hard failed deliveries are retried.
    pub retry: RetryPreset,
}

/// What an update changes about a webhook. `None` leaves a part as it is.
pub struct WebhookUpdate {
    /// A new address to deliver to.
    pub url: Option<PublicHttpsUrl>,
    /// New event types. Empty means every event the person updating may
    /// see.
    pub event_types: Option<Vec<EventType>>,
    /// A new description, or none.
    pub description: Option<Setting<Text>>,
    /// A new retry policy.
    pub retry: Option<RetryPreset>,
}

/// A webhook subscription as storage holds it.
pub struct WebhookSubscriptionRow {
    /// Unique subscription identifier.
    pub id: WebhookSubscriptionId,
    /// The HTTPS URL to deliver events to.
    pub url: PublicHttpsUrl,
    /// The secret deliveries are signed with, sealed.
    pub signing_secret: SealedSecret,
    /// The secret before the last rotation, while it still signs.
    pub previous_secret: PreviousSigningSecret,
    /// Event types this subscription receives.
    pub event_types: Vec<EventType>,
    /// Current delivery status.
    pub status: WebhookSubscriptionStatus,
    /// Optional description of this subscription's purpose.
    pub description: Option<Text>,
    /// How hard failed deliveries are retried.
    pub retry: RetryPreset,
    /// Who created it.
    pub created_by: PrincipalRef,
    /// Number of consecutive delivery failures.
    pub consecutive_failures: u32,
    /// When the last successful delivery occurred.
    pub last_delivered_at: Option<OffsetDateTime>,
    /// When this subscription was created.
    pub created_at: OffsetDateTime,
    /// When this subscription was last modified.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> WebhookSubscription<T> {
    /// Creates an active webhook subscription for the person `control`
    /// names, who is kept as its creator. What they may see is read from
    /// the same `control`, so it is never someone else's.
    ///
    /// The URL is already a [`PublicHttpsUrl`], which refuses plain HTTP,
    /// `localhost`, internal names and internal addresses. An empty list of
    /// event types is resolved here to every event the creator may see, never
    /// to everything. Raises `webhooks.subscription_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update webhooks.
    /// - [`DomainError::Validation`] when the list names the webhook
    ///   delivery event, or the creator may see no event at all.
    /// - [`DomainError::Forbidden`] when the list names an event the
    ///   creator may not see.
    pub fn create(
        params: CreateWebhookParams,
        control: &WebhookControl<'_>,
    ) -> Result<Self, DomainError> {
        control.ensure_may(WebhooksAction::Update)?;
        let event_types = subscribed(params.event_types, &control.visibility())?;
        let now = crate::shared::clock::now();
        let mut subscription = Self {
            id: params.id,
            url: params.url,
            signing_secret: params.signing_secret,
            previous_secret: PreviousSigningSecret::Retired,
            event_types,
            status: WebhookSubscriptionStatus::Active,
            description: params.description,
            retry: params.retry,
            created_by: control.by().principal(),
            failures: FailureStreak::default(),
            last_delivered_at: None,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        subscription.raised.raise(WebhookSubscriptionCreated {
            subscription_id: subscription.id,
            endpoint: subscription.url.origin(),
            occurred_at: now,
        });
        Ok(subscription)
    }

    /// Rebuilds a webhook subscription from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row subscribes to nothing.
    /// - [`DomainError::Infrastructure`] when the row subscribes to its own
    ///   deliveries.
    /// - [`DomainError::Infrastructure`] when the row changed before it was
    ///   created.
    /// - [`DomainError::Infrastructure`] when the row was delivered to before
    ///   it was created, or after it last changed.
    /// - [`DomainError::Infrastructure`] when the row's old secret stops
    ///   signing before the subscription was created.
    pub fn reconstitute(row: WebhookSubscriptionRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            url: row.url,
            signing_secret: row.signing_secret,
            previous_secret: row.previous_secret,
            event_types: row.event_types,
            status: row.status,
            description: row.description,
            retry: row.retry,
            created_by: row.created_by,
            failures: FailureStreak::from_stored(row.consecutive_failures),
            last_delivered_at: row.last_delivered_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &WebhookSubscriptionRow) -> Result<(), DomainError> {
        RowCheck::of("webhook subscription")
            .holds(!row.event_types.is_empty(), "subscribed to nothing")
            .holds(
                !row.event_types.contains(&DELIVERY),
                "subscribed to its own deliveries",
            )
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was created",
            )
            .in_order_if(
                row.created_at,
                row.last_delivered_at,
                "delivered to before it was created",
            )
            .holds(
                row.last_delivered_at
                    .is_none_or(|delivered| delivered <= row.updated_at),
                "delivered to after its last change",
            )
            .holds(
                row.previous_secret.ends_after(row.created_at),
                "old secret stops before it was created",
            )
            .finish()
    }

    /// Unique subscription identifier.
    #[must_use]
    pub fn id(&self) -> &WebhookSubscriptionId {
        &self.id
    }

    /// The delivery target URL.
    #[must_use]
    pub fn url(&self) -> &PublicHttpsUrl {
        &self.url
    }

    /// The secret deliveries are signed with, sealed.
    ///
    /// It is sealed, not hashed, because an HMAC needs the secret itself.
    /// Only delivery opens it.
    #[must_use]
    pub fn signing_secret(&self) -> &SealedSecret {
        &self.signing_secret
    }

    /// The secret before the last rotation, with when it stops signing.
    #[must_use]
    pub fn previous_secret(&self) -> &PreviousSigningSecret {
        &self.previous_secret
    }

    /// Every secret a delivery sent now is signed with: the current one
    /// first, then the one before it while its overlap lasts. The delivery
    /// carries one signature per secret, so a receiver still on the old
    /// secret accepts it.
    #[must_use]
    pub fn signing_secrets(&self) -> Vec<&SealedSecret> {
        let now = crate::shared::clock::now();
        std::iter::once(&self.signing_secret)
            .chain(self.previous_secret.signing_at(now))
            .collect()
    }

    /// How hard failed deliveries are retried.
    #[must_use]
    pub fn retry(&self) -> RetryPreset {
        self.retry
    }

    /// Event types this subscription receives. Never empty.
    #[must_use]
    pub fn event_types(&self) -> &[EventType] {
        &self.event_types
    }

    /// Current delivery status.
    #[must_use]
    pub fn status(&self) -> WebhookSubscriptionStatus {
        self.status
    }

    /// Optional description of this subscription's purpose.
    #[must_use]
    pub fn description(&self) -> Option<&Text> {
        self.description.as_ref()
    }

    /// Who created it.
    ///
    /// [`receives`](Self::receives) works out what they may see now from
    /// the tenant's records.
    #[must_use]
    pub fn created_by(&self) -> &PrincipalRef {
        &self.created_by
    }

    /// Number of consecutive delivery failures.
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.failures.count()
    }

    /// When the last successful delivery occurred.
    #[must_use]
    pub fn last_delivered_at(&self) -> Option<OffsetDateTime> {
        self.last_delivered_at
    }

    /// When this subscription was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this subscription was last modified.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Whether this subscription is currently receiving deliveries.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == WebhookSubscriptionStatus::Active
    }

    /// Whether an event of `event_type` is delivered to this subscription
    /// now, with what its creator holds worked out from `access`, the
    /// tenant's records as they stand.
    ///
    /// The event must be one it subscribed to, and one its creator may still
    /// see. Sam creates a webhook for key events while he may read them.
    /// Then he loses that right. From then on no key event is sent to his
    /// server. A creator who left, was shut out, or whose organization no
    /// longer lets them in holds nothing, so nothing is sent.
    ///
    /// `creator` is the account that made it, as the records hold it now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `creator` is not the account that
    ///   made this webhook.
    /// - [`DomainError::Infrastructure`] when the records name a role or
    ///   group that is not there.
    pub fn receives(
        &self,
        event_type: &EventType,
        creator: &CreatorNow<'_, T>,
        access: &TenantAccess<'_, T>,
    ) -> Result<bool, DomainError> {
        if creator.principal() != self.created_by {
            return Err(DomainError::forbidden(message!(
                "webhooks-the-account-given-is-not-the",
                "the account given is not the one that made the webhook"
            )));
        }
        if !self.event_types.contains(event_type) {
            return Ok(false);
        }
        let Some(standing) = creator.standing_in(access)? else {
            return Ok(false);
        };
        let creator_sees = VisibleTo(standing.handout().system);
        Ok(EventVisibility::may_see(&creator_sees, event_type))
    }

    /// Records a successful delivery.
    pub fn record_success(&mut self) {
        self.failures.reset();
        self.last_delivered_at = Some(crate::shared::clock::now());
        self.touch();
    }

    /// Records a failed delivery, and disables the subscription after
    /// `disable_after` consecutive failures.
    ///
    /// Only an `Active` subscription is disabled. A paused or disabled one
    /// only counts the failure. The result says which happened. Only when
    /// the endpoint has just stopped receiving events is
    /// [`report_switched_off`](Self::report_switched_off) called.
    #[must_use = "a subscription the failure disabled must be reported"]
    pub fn record_failure(&mut self, disable_after: FailureLimit) -> FailureOutcome {
        let threshold = self.failures.record(disable_after);
        self.touch();
        if threshold == Threshold::Below || !self.status.is_active() {
            return FailureOutcome::Counted;
        }
        let Ok(disabled) = self
            .status
            .try_transition(WebhookSubscriptionStatus::Disabled)
        else {
            return FailureOutcome::Counted;
        };
        self.status = disabled;
        FailureOutcome::Disabled
    }

    /// Raises `webhooks.delivery_attempted` for `attempt`, a send of an
    /// event to this subscription's endpoint, whatever its outcome. Nothing
    /// stored changes: the store counted the attempt already.
    pub fn report_attempt(&mut self, attempt: &DeliveryAttempt) {
        self.raised.raise(WebhookDeliveryAttempted {
            subscription_id: attempt.subscription_id,
            endpoint: self.url.origin(),
            delivered_event: attempt.event_type,
            status: attempt.status(),
            occurred_at: attempt.attempted_at,
        });
    }

    /// Raises `webhooks.subscription_disabled`, with the failure streak
    /// that switched the subscription off. Called once, when counting a
    /// failure answered [`FailureOutcome::Disabled`], so the switch-off is
    /// recorded once. A subscription that is not disabled raises nothing.
    pub fn report_switched_off(&mut self) {
        if self.status != WebhookSubscriptionStatus::Disabled {
            return;
        }
        self.raised.raise(WebhookSubscriptionDisabled {
            subscription_id: self.id,
            endpoint: self.url.origin(),
            consecutive_failures: self.failures.count(),
            occurred_at: self.updated_at,
        });
    }

    /// Pauses delivery without resetting the failure counter. Raises
    /// `webhooks.subscription_paused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update webhooks.
    /// - [`DomainError::InvalidTransition`] when the subscription is already
    ///   paused or disabled.
    pub fn pause(&mut self, control: &WebhookControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(WebhooksAction::Update)?;
        self.status = self
            .status
            .try_transition(WebhookSubscriptionStatus::Paused)?;
        self.touch();
        self.raised.raise(WebhookSubscriptionPaused {
            subscription_id: self.id,
            endpoint: self.url.origin(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Resumes delivery and resets the failure counter. Raises
    /// `webhooks.subscription_resumed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update webhooks.
    /// - [`DomainError::InvalidTransition`] when the subscription is active
    ///   or disabled. A disabled subscription is never resumed.
    pub fn resume(&mut self, control: &WebhookControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(WebhooksAction::Update)?;
        self.status = self
            .status
            .try_transition(WebhookSubscriptionStatus::Active)?;
        self.failures.reset();
        self.touch();
        self.raised.raise(WebhookSubscriptionResumed {
            subscription_id: self.id,
            endpoint: self.url.origin(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Deletes this webhook once the person may update webhooks and it no
    /// longer delivers. Raises `webhooks.subscription_deleted`, taken once
    /// the subscription is removed from storage.
    ///
    /// Deleting it takes its delivery history with it. Sam may only view
    /// webhooks. Without this check, he deletes the one that feeds the
    /// security team's alerting, and its record of what it sent goes too.
    /// An active webhook is paused or disabled first, so nobody deletes one
    /// still in use by mistake.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update webhooks.
    /// - [`DomainError::Conflict`] while the webhook is active.
    pub fn delete(&mut self, control: &WebhookControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(WebhooksAction::Update)?;
        if self.is_active() {
            return Err(DomainError::conflict(message!(
                "webhooks-an-active-webhook-is-paused-or",
                "an active webhook is paused or disabled before it is deleted"
            )));
        }
        self.raised.raise(WebhookSubscriptionDeleted {
            subscription_id: self.id,
            endpoint: self.url.origin(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Bumps the `updated_at` timestamp.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }
}

impl<T: TenantScope> Raises for WebhookSubscription<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// A webhook subscription is an aggregate root of one tenant. It says where
/// and how events reach an outside system.
impl<T: TenantScope> Aggregate for WebhookSubscription<T> {
    /// The subscription's unique identifier type.
    type Id = WebhookSubscriptionId;

    /// The subscription's unique identifier within the tenant.
    fn id(&self) -> &Self::Id {
        &self.id
    }

    /// When this subscription was created.
    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When this subscription was last modified.
    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{
        AuthConfigAction, SystemPermission, UserAction,
    };
    use crate::domains::consumers::fixtures::{ConsumerRecords, acme};
    use crate::domains::identity::account::user::User;
    use crate::domains::identity::account::user::tests::control_over;
    use crate::domains::organization::access::session::tests::{acme_with, plain_member};
    use crate::domains::organization::lifecycle::Organization;
    use crate::domains::organization::members::org_user::OrgUser;
    use crate::domains::organization::members::tenant_grant::{OrgTenantGrant, OrgTenantGrantRow};
    use crate::domains::organization::status::OrganizationStatus;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::builders::user;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::event_type::{AuthenticationEvent, CryptoEvent, IdentityEvent};
    use crate::types::{
        ActedBy, Human, HumanAccount, Lifetime, PersonKey, RoleId, RotationOverlap, UserId,
    };

    /// What lets someone see user and login events, and no signing key
    /// event.
    const USERS_AND_LOGINS: [SystemPermission; 2] = [
        SystemPermission::Users(UserAction::View),
        SystemPermission::AuthConfig(AuthConfigAction::View),
    ];

    fn limit(count: u32) -> FailureLimit {
        FailureLimit::new(count).unwrap()
    }

    fn sam() -> Human {
        Human::new(
            HumanAccount::User(UserId::from_uuid(uuid::Uuid::from_u128(0x5a))),
            PersonKey::new("sam@acme.test").unwrap(),
        )
    }

    /// Sam, holding `system` and no custom permission.
    fn holding(system: &[SystemPermission]) -> WebhookControl<'static> {
        WebhookControl::new(assumed_authority(&sam(), acme(), system, &[]))
    }

    /// Acme's records as they stand now, where Sam holds `system`.
    fn sam_now(system: &[SystemPermission]) -> ConsumerRecords {
        ConsumerRecords::where_holding(sam().principal(), system)
    }

    /// Sam, managing webhooks and seeing user and login events.
    fn webhook_admin() -> WebhookControl<'static> {
        holding(&[
            SystemPermission::ManageWebhooks,
            USERS_AND_LOGINS[0],
            USERS_AND_LOGINS[1],
        ])
    }

    /// Sam, who may only view webhooks.
    fn webhook_viewer() -> WebhookControl<'static> {
        holding(&[SystemPermission::Webhooks(WebhooksAction::View)])
    }

    /// Sam, who may create, pause and resume webhooks.
    fn webhook_editor() -> WebhookControl<'static> {
        holding(&[SystemPermission::Webhooks(WebhooksAction::Update)])
    }

    fn params(event_types: Vec<EventType>) -> CreateWebhookParams {
        CreateWebhookParams {
            id: WebhookSubscriptionId::new(),
            url: PublicHttpsUrl::new("https://hooks.acme.com/events").unwrap(),
            signing_secret: SealedSecret::new("v1.c2VjcmV0").unwrap(),
            event_types,
            description: None,
            retry: RetryPreset::Standard,
        }
    }

    fn create(
        event_types: Vec<EventType>,
    ) -> Result<WebhookSubscription<ResolvedTenant>, DomainError> {
        WebhookSubscription::create(params(event_types), &webhook_admin())
    }

    fn test_webhook() -> WebhookSubscription<ResolvedTenant> {
        WebhookSubscription::create(
            CreateWebhookParams {
                description: Some(Text::new("description", "User sync").unwrap()),
                ..params(vec![IdentityEvent::UserRegistered.into()])
            },
            &webhook_admin(),
        )
        .unwrap()
    }

    /// A viewer cannot create a webhook for user registrations.
    #[test]
    fn a_viewer_cannot_create_a_webhook() {
        let result = WebhookSubscription::<ResolvedTenant>::create(
            params(vec![IdentityEvent::UserRegistered.into()]),
            &webhook_viewer(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A viewer cannot pause a webhook, which remains active.
    #[test]
    fn a_viewer_cannot_pause_a_webhook() {
        let mut wh = test_webhook();

        let result = wh.pause(&webhook_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(wh.is_active());
    }

    /// A viewer cannot resume a webhook paused by an administrator. Its
    /// status remains paused.
    #[test]
    fn a_viewer_cannot_resume_a_webhook() {
        let mut wh = test_webhook();
        wh.pause(&webhook_admin()).unwrap();

        let result = wh.resume(&webhook_viewer());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(wh.status(), WebhookSubscriptionStatus::Paused);
    }

    /// Webhook update permission does not allow secret rotation. The refused
    /// rotation preserves the existing signing secret.
    #[test]
    fn rotating_a_secret_needs_the_full_webhooks_right() {
        let mut wh = test_webhook();

        let result = wh.rotate_secret(
            SealedSecret::new("v1.c2Ftcw").unwrap(),
            RotationOverlap::Immediate,
            &webhook_editor(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(wh.signing_secret().as_str(), "v1.c2VjcmV0");
    }

    /// Removing the creator's key-event access makes the webhook ineligible
    /// for that event. It remains eligible for user registrations the creator
    /// can still see.
    #[test]
    fn an_event_its_creator_can_no_longer_see_is_not_delivered() {
        let key_event: EventType = CryptoEvent::ALL[0].0.into();
        let registered: EventType = IdentityEvent::UserRegistered.into();
        let everything = holding(SystemPermission::all());
        let wh = WebhookSubscription::<ResolvedTenant>::create(
            params(vec![key_event, registered]),
            &everything,
        )
        .unwrap();
        let (before, after) = (sam_now(SystemPermission::all()), sam_now(&USERS_AND_LOGINS));
        let account = sams_account();
        let sam = CreatorNow::User(&account);

        assert!(wh.receives(&key_event, &sam, &before.access()).unwrap());
        assert!(!wh.receives(&key_event, &sam, &after.access()).unwrap());
        assert!(wh.receives(&registered, &sam, &after.access()).unwrap());
    }

    /// A webhook is ineligible for user registrations when its creator has
    /// no roles in the current tenant records.
    #[test]
    fn a_creator_who_holds_nothing_now_receives_nothing() {
        let wh = test_webhook();
        let registered: EventType = IdentityEvent::UserRegistered.into();
        let account = sams_account();

        let receives = wh
            .receives(
                &registered,
                &CreatorNow::User(&account),
                &ConsumerRecords::empty().access(),
            )
            .unwrap();

        assert!(!receives);
    }

    /// Deactivating the creator's account makes the webhook ineligible for
    /// user registrations even while the creator's role remains assigned.
    #[test]
    fn a_creator_who_may_no_longer_sign_in_receives_nothing() {
        let wh = test_webhook();
        let registered: EventType = IdentityEvent::UserRegistered.into();
        let mut account = sams_account();
        account.deactivate(&control_over(&account)).unwrap();

        let receives = wh
            .receives(
                &registered,
                &CreatorNow::User(&account),
                &sam_now(&USERS_AND_LOGINS).access(),
            )
            .unwrap();

        assert!(!receives);
    }

    /// Checking a webhook with an account other than its creator is forbidden.
    #[test]
    fn a_creator_account_other_than_the_webhooks_is_refused() {
        let wh = test_webhook();
        let registered: EventType = IdentityEvent::UserRegistered.into();
        let ann = user(UserId::new(), "ann@acme.test");

        let receives = wh.receives(
            &registered,
            &CreatorNow::User(&ann),
            &ConsumerRecords::empty().access(),
        );

        assert!(matches!(receives, Err(DomainError::Forbidden(_))));
    }

    /// Sam, a plain member of Acme's organization, made a webhook for user
    /// events, which his grant in the tenant lets him see. They reach his
    /// server. Once the platform suspends Acme, they stop.
    #[test]
    fn a_member_creator_receives_what_their_grant_lets_them_see() {
        let (mut organization, founder) = acme_with(acme());
        let member = plain_member(&organization, &founder);
        let records = ConsumerRecords::unassigned(&USERS_AND_LOGINS);
        let grants = [grant_of(&member, records.first_role())];
        let registered: EventType = IdentityEvent::UserRegistered.into();
        let wh = member_webhook(&member, registered);
        let receives = |organization: &Organization| {
            let creator = CreatorNow::Member {
                member: &member,
                organization,
                grants: &grants,
            };
            wh.receives(&registered, &creator, &records.access())
                .unwrap()
        };

        let while_active = receives(&organization);
        organization
            .change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();
        let once_suspended = receives(&organization);

        assert!(while_active);
        assert!(!once_suspended);
    }

    /// A member's webhook created with user visibility and webhook management.
    fn member_webhook(member: &OrgUser, event: EventType) -> WebhookSubscription<ResolvedTenant> {
        let as_member = Human::new(
            HumanAccount::OrgUser(*member.id()),
            PersonKey::of(member.email()),
        );
        let made_by = WebhookControl::new(assumed_authority(
            &as_member,
            acme(),
            &[SystemPermission::ManageWebhooks, USERS_AND_LOGINS[0]],
            &[],
        ));
        WebhookSubscription::create(params(vec![event]), &made_by).unwrap()
    }

    /// Sam's active tenant account.
    fn sams_account() -> User<ResolvedTenant> {
        let HumanAccount::User(id) = sam().account() else {
            unreachable!("Sam acts through a tenant account")
        };
        let mut account = user(id, "sam@acme.test");
        account.activate(&control_over(&account)).unwrap();
        account
    }

    /// A grant of `role` in Acme to `member`.
    fn grant_of(member: &OrgUser, role: RoleId) -> OrgTenantGrant {
        OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: *member.id(),
            tenant_id: acme(),
            role_id: role,
            granted_by: ActedBy::Platform,
            granted_at: crate::shared::clock::now(),
        })
        .unwrap()
    }

    /// A viewer cannot delete a webhook, and an editor cannot delete it while
    /// active. The editor can delete it after pausing it.
    #[test]
    fn deleting_a_webhook_needs_the_right_and_a_stopped_webhook() {
        let mut wh = test_webhook();

        let by_viewer = wh.delete(&webhook_viewer());
        let while_active = wh.delete(&webhook_editor());
        wh.pause(&webhook_editor()).unwrap();

        assert!(matches!(by_viewer, Err(DomainError::Forbidden(_))));
        assert!(matches!(while_active, Err(DomainError::Conflict(_))));
        assert!(wh.delete(&webhook_editor()).is_ok());
    }

    /// A webhook keeps who created it, so delivery can ask what they may
    /// see now.
    #[test]
    fn a_subscription_keeps_who_created_it() {
        let wh = test_webhook();

        assert_eq!(wh.created_by(), &sam().principal());
    }

    /// A new subscription starts active, with no failures and no delivery
    /// yet.
    #[test]
    fn create_active_subscription() {
        let wh = test_webhook();
        assert!(wh.is_active());
        assert_eq!(wh.consecutive_failures(), 0);
        assert!(wh.last_delivered_at().is_none());
    }

    /// A subscription to user registrations matches a registration. It does
    /// not match a failed login it never asked for.
    #[test]
    fn matches_subscribed_event() {
        let wh = test_webhook();
        assert!(
            wh.event_types()
                .contains(&IdentityEvent::UserRegistered.into())
        );
        assert!(!wh.event_types().contains(&EventType::from(
            crate::types::event_type::AuthenticationEvent::LoginFailed
        )));
    }

    /// An empty event list expands to include visible user registrations and
    /// successful logins, excluding a hidden signing key event and delivery
    /// records.
    #[test]
    fn empty_event_types_match_what_the_creator_may_see() {
        let wh = create(vec![]).unwrap();

        assert!(
            wh.event_types()
                .contains(&IdentityEvent::UserRegistered.into())
        );
        assert!(
            wh.event_types()
                .contains(&AuthenticationEvent::LoginSucceeded.into())
        );
        assert!(!wh.event_types().contains(&CryptoEvent::ALL[0].0.into()));
        assert!(!wh.event_types().contains(&DELIVERY));
    }

    /// Creating a webhook for a signing key event the creator cannot see
    /// is forbidden.
    #[test]
    fn a_subscription_to_events_its_creator_may_not_see_is_refused() {
        let result = create(vec![CryptoEvent::ALL[0].0.into()]);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A webhook that names the delivery event is refused. Each delivery
    /// would raise another one to deliver, without end.
    #[test]
    fn a_subscription_to_its_own_deliveries_is_refused() {
        assert!(matches!(
            create(vec![DELIVERY]),
            Err(DomainError::Validation(_))
        ));
    }

    /// With a limit of five, the first four failures are only counted and
    /// the subscription stays active. The fifth disables it.
    #[test]
    fn record_failure_disables_after_threshold() {
        let mut wh = test_webhook();

        for _ in 0..4 {
            assert_eq!(wh.record_failure(limit(5)), FailureOutcome::Counted);
            assert!(wh.is_active());
        }
        assert_eq!(wh.record_failure(limit(5)), FailureOutcome::Disabled);
        assert_eq!(wh.status(), WebhookSubscriptionStatus::Disabled);
    }

    /// With a limit of one, the first failure disables the subscription.
    /// The next failure is only counted, so the disable is reported once.
    #[test]
    fn a_failure_after_the_disable_reports_no_second_disable() {
        let mut wh = test_webhook();
        assert_eq!(wh.record_failure(limit(1)), FailureOutcome::Disabled);

        assert_eq!(wh.record_failure(limit(1)), FailureOutcome::Counted);
    }

    /// Two failures are followed by a success. The failure count drops to
    /// zero and the delivery time is set.
    #[test]
    fn record_success_resets_failures() {
        let mut wh = test_webhook();
        assert_eq!(wh.record_failure(limit(10)), FailureOutcome::Counted);
        assert_eq!(wh.record_failure(limit(10)), FailureOutcome::Counted);
        assert_eq!(wh.consecutive_failures(), 2);

        wh.record_success();
        assert_eq!(wh.consecutive_failures(), 0);
        assert!(wh.last_delivered_at().is_some());
    }

    /// A subscription with one failure is paused and keeps the count. Once
    /// resumed it is active and the count is back to zero.
    #[test]
    fn pause_and_resume() {
        let mut wh = test_webhook();
        assert_eq!(wh.record_failure(limit(10)), FailureOutcome::Counted);
        let editor = webhook_editor();

        wh.pause(&editor).unwrap();
        assert_eq!(wh.status(), WebhookSubscriptionStatus::Paused);
        assert_eq!(wh.consecutive_failures(), 1);

        wh.resume(&editor).unwrap();
        assert!(wh.is_active());
        assert_eq!(wh.consecutive_failures(), 0);
    }

    /// A subscription is created with no description. It is accepted and
    /// reports none.
    #[test]
    fn a_subscription_may_have_no_description() {
        let wh = create(vec![]).unwrap();

        assert!(wh.description().is_none());
    }

    /// Delivery target validation rejects localhost and a hostname under
    /// `.internal`.
    #[test]
    fn a_webhook_cannot_target_a_local_or_internal_host() {
        for url in [
            "https://localhost:9000/admin",
            "https://payroll.internal/run",
        ] {
            assert!(PublicHttpsUrl::new(url).is_err(), "{url} was accepted");
        }
    }

    /// A subscription is created for `https://hooks.acme.com/events` and
    /// user registrations. It keeps that URL, its sealed secret, its event
    /// list and description, and gets a fresh id.
    #[test]
    fn a_subscription_carries_the_url_secret_and_events_it_was_created_with() {
        let wh = test_webhook();

        assert_eq!(wh.url().as_str(), "https://hooks.acme.com/events");
        assert_eq!(wh.signing_secret().as_str(), "v1.c2VjcmV0");
        assert_eq!(
            wh.event_types(),
            &[EventType::from(IdentityEvent::UserRegistered)]
        );
        assert_eq!(wh.description().map(Text::as_str), Some("User sync"));
        assert!(!wh.id().as_uuid().is_nil());
        assert_eq!(Aggregate::id(&wh), wh.id());
    }

    /// A tenant rotates the secret after the old one leaks. The new secret
    /// replaces the old, the last change time moves to the rotation and the
    /// creation time stays.
    #[test]
    fn rotating_the_secret_replaces_it_and_moves_the_timestamp() {
        let mut wh = test_webhook();
        let created = wh.created_at();
        let later = wh.updated_at() + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        wh.rotate_secret(
            SealedSecret::new("v1.cm90YXRlZA").unwrap(),
            RotationOverlap::Immediate,
            &webhook_admin(),
        )
        .unwrap();

        assert_eq!(wh.signing_secret().as_str(), "v1.cm90YXRlZA");
        assert_eq!(wh.signing_secrets().len(), 1);
        assert_eq!(wh.updated_at(), later);
        assert_eq!(wh.created_at(), created);
    }

    /// Ann rotates the secret with a day's overlap, so the receiver can
    /// move over. Deliveries are signed with the new secret and the old
    /// one, until the day is up; then with the new one only.
    #[test]
    fn an_old_secret_signs_beside_the_new_one_for_the_overlap() {
        let mut wh = test_webhook();
        let start = crate::shared::clock::now();
        let _frozen = crate::shared::clock::freeze(start);
        let day = RotationOverlap::For(Lifetime::seconds(86_400).unwrap());

        wh.rotate_secret(SealedSecret::new("v1.bmV3").unwrap(), day, &webhook_admin())
            .unwrap();
        let during: Vec<String> = signed_with(&wh);
        let _later = crate::shared::clock::freeze(start + time::Duration::days(1));
        let after: Vec<String> = signed_with(&wh);

        assert_eq!(during, ["v1.bmV3", "v1.c2VjcmV0"]);
        assert_eq!(after, ["v1.bmV3"]);
    }

    /// After two rotations with a day's overlap, the signing secrets are
    /// the newest secret and the one it just replaced. The original is absent.
    #[test]
    fn a_second_rotation_retires_the_oldest_secret() {
        let mut wh = test_webhook();
        let day = || RotationOverlap::For(Lifetime::seconds(86_400).unwrap());

        wh.rotate_secret(
            SealedSecret::new("v1.c2Vjb25k").unwrap(),
            day(),
            &webhook_admin(),
        )
        .unwrap();
        wh.rotate_secret(
            SealedSecret::new("v1.dGhpcmQ").unwrap(),
            day(),
            &webhook_admin(),
        )
        .unwrap();

        assert_eq!(signed_with(&wh), ["v1.dGhpcmQ", "v1.c2Vjb25k"]);
    }

    /// The sealed secrets `webhook` signs a delivery sent now with.
    fn signed_with(webhook: &WebhookSubscription<ResolvedTenant>) -> Vec<String> {
        webhook
            .signing_secrets()
            .into_iter()
            .map(|secret| secret.as_str().to_owned())
            .collect()
    }

    /// Ann moves Sam's webhook to a new address, narrows it to logins,
    /// clears its description and picks the patient retry policy. Each
    /// part changes, the failures counted against the old address are
    /// dropped, and one update is raised.
    #[test]
    fn an_update_changes_each_part_it_names_and_is_raised_once() {
        let mut wh = test_webhook();
        assert_eq!(wh.record_failure(limit(10)), FailureOutcome::Counted);
        raised_names(&mut wh);
        let login: EventType = AuthenticationEvent::LoginSucceeded.into();

        wh.update(
            WebhookUpdate {
                url: Some(PublicHttpsUrl::new("https://hooks.acme.com/v2").unwrap()),
                event_types: Some(vec![login]),
                description: Some(Setting::Unset),
                retry: Some(RetryPreset::Patient),
            },
            &webhook_editor_seeing_logins(),
        )
        .unwrap();

        assert_eq!(wh.url().as_str(), "https://hooks.acme.com/v2");
        assert_eq!(wh.event_types(), &[login]);
        assert!(wh.description().is_none());
        assert_eq!(wh.retry(), RetryPreset::Patient);
        assert_eq!(wh.consecutive_failures(), 0);
        assert_eq!(raised_names(&mut wh), ["webhooks.subscription_updated"]);
    }

    /// An update that names only what the webhook already has changes
    /// nothing and raises nothing.
    #[test]
    fn an_update_to_the_same_values_raises_nothing() {
        let mut wh = test_webhook();
        raised_names(&mut wh);

        wh.update(
            WebhookUpdate {
                url: Some(wh.url().clone()),
                event_types: None,
                description: None,
                retry: Some(RetryPreset::Standard),
            },
            &webhook_admin(),
        )
        .unwrap();

        assert!(raised_names(&mut wh).is_empty());
    }

    /// A viewer cannot change a webhook's endpoint, which retains its
    /// existing URL.
    #[test]
    fn a_viewer_cannot_update_a_webhook() {
        let mut wh = test_webhook();

        let result = wh.update(
            WebhookUpdate {
                url: Some(PublicHttpsUrl::new("https://sam.example.com/hook").unwrap()),
                event_types: None,
                description: None,
                retry: None,
            },
            &webhook_viewer(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(wh.url().as_str(), "https://hooks.acme.com/events");
    }

    /// An update refuses an event the editor cannot see and rejects the
    /// webhook delivery event. Both refusals preserve the registration-only
    /// event list.
    #[test]
    fn an_update_adds_no_event_the_person_may_not_see() {
        let mut wh = test_webhook();
        let editor = webhook_editor_seeing_logins();
        let with = |event: EventType| WebhookUpdate {
            url: None,
            event_types: Some(vec![event]),
            description: None,
            retry: None,
        };

        let key_event = wh.update(with(CryptoEvent::ALL[0].0.into()), &editor);
        let own_record = wh.update(with(DELIVERY), &editor);

        assert!(matches!(key_event, Err(DomainError::Forbidden(_))));
        assert!(matches!(own_record, Err(DomainError::Validation(_))));
        assert_eq!(
            wh.event_types(),
            &[EventType::from(IdentityEvent::UserRegistered)]
        );
    }

    /// A webhook switched off after failing is changed. It is refused: a
    /// disabled webhook is replaced, not brought back by an edit.
    #[test]
    fn a_disabled_webhook_is_not_updated() {
        let mut wh = test_webhook();
        assert_eq!(wh.record_failure(limit(1)), FailureOutcome::Disabled);

        let result = wh.update(
            WebhookUpdate {
                url: None,
                event_types: None,
                description: None,
                retry: Some(RetryPreset::Patient),
            },
            &webhook_admin(),
        );

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
    }

    /// Sam, who may create, pause and resume webhooks and see logins.
    fn webhook_editor_seeing_logins() -> WebhookControl<'static> {
        holding(&[
            SystemPermission::Webhooks(WebhooksAction::Update),
            USERS_AND_LOGINS[1],
        ])
    }

    /// A stored subscription says its old secret stopped signing before the
    /// subscription was made. It is refused as corrupt.
    #[test]
    fn a_stored_old_secret_ending_before_creation_is_refused() {
        let mut row = stored(test_webhook());
        row.previous_secret = PreviousSigningSecret::SignsUntil {
            secret: SealedSecret::new("v1.b2xk").unwrap(),
            until: row.created_at - time::Duration::hours(1),
        };

        assert!(refused_as_corrupt(
            &WebhookSubscription::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A tenant pauses an active subscription. It then reads as inactive,
    /// so nothing is posted to the endpoint.
    #[test]
    fn a_paused_subscription_does_not_read_as_active() {
        let mut wh = test_webhook();
        assert!(wh.is_active());

        wh.pause(&webhook_admin()).unwrap();

        assert!(!wh.is_active());
        assert_eq!(wh.status(), WebhookSubscriptionStatus::Paused);
    }

    /// An endpoint fails once with a limit of one. The subscription is
    /// disabled and reads as inactive, so nothing more is sent.
    #[test]
    fn a_disabled_subscription_does_not_read_as_active() {
        let mut wh = test_webhook();

        assert_eq!(wh.record_failure(limit(1)), FailureOutcome::Disabled);

        assert_eq!(wh.status(), WebhookSubscriptionStatus::Disabled);
        assert!(!wh.is_active());
    }

    /// `webhook` as storage would hold it.
    fn stored(webhook: WebhookSubscription<ResolvedTenant>) -> WebhookSubscriptionRow {
        let consecutive_failures = webhook.consecutive_failures();
        WebhookSubscriptionRow {
            id: webhook.id,
            url: webhook.url,
            signing_secret: webhook.signing_secret,
            previous_secret: webhook.previous_secret,
            event_types: webhook.event_types,
            status: webhook.status,
            description: webhook.description,
            retry: webhook.retry,
            created_by: webhook.created_by,
            consecutive_failures,
            last_delivered_at: webhook.last_delivered_at,
            created_at: webhook.created_at,
            updated_at: webhook.updated_at,
        }
    }

    /// A subscription that delivered once, stored as it is, reads back.
    #[test]
    fn a_stored_subscription_that_delivered_reads_back() {
        let mut wh = test_webhook();
        wh.record_success();

        assert!(WebhookSubscription::<ResolvedTenant>::reconstitute(stored(wh)).is_ok());
    }

    /// A stored subscription whose last delivery follows its last change
    /// by an hour is refused as corrupt.
    #[test]
    fn a_stored_subscription_delivered_to_after_its_last_change_is_refused() {
        let mut row = stored(test_webhook());
        row.last_delivered_at = Some(row.updated_at + time::Duration::hours(1));

        assert!(refused_as_corrupt(
            &WebhookSubscription::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// The text of `key` in `event`'s payload.
    fn text_of(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// Sam creates a webhook for user registrations. Its creation is
    /// raised.
    #[test]
    fn creating_raises_webhooks_subscription_created() {
        let mut wh = test_webhook();

        assert_eq!(raised_names(&mut wh), ["webhooks.subscription_created"]);
    }

    /// Sam pauses his webhook, resumes it, rotates its secret, pauses it
    /// again and deletes it. Each step is raised, in order.
    #[test]
    fn each_change_to_a_webhook_is_raised_in_order() {
        let mut wh = test_webhook();
        raised_names(&mut wh);
        let admin = webhook_admin();

        wh.pause(&admin).unwrap();
        wh.resume(&admin).unwrap();
        wh.rotate_secret(
            SealedSecret::new("v1.cm90YXRlZA").unwrap(),
            RotationOverlap::Immediate,
            &admin,
        )
        .unwrap();
        wh.pause(&admin).unwrap();
        wh.delete(&admin).unwrap();

        assert_eq!(
            raised_names(&mut wh),
            [
                "webhooks.subscription_paused",
                "webhooks.subscription_resumed",
                "webhooks.secret_rotated",
                "webhooks.subscription_paused",
                "webhooks.subscription_deleted",
            ]
        );
    }

    /// A user registration is sent to Sam's webhook and times out. The
    /// attempt is raised with the event sent and how it ended.
    #[test]
    fn reporting_an_attempt_raises_the_event_sent_and_its_outcome() {
        let mut wh = test_webhook();
        raised_names(&mut wh);
        let attempt = DeliveryAttempt {
            id: crate::types::WebhookDeliveryId::new(),
            message_id: crate::types::WebhookMessageId::new(),
            subscription_id: *wh.id(),
            event_type: IdentityEvent::UserRegistered.into(),
            outcome: crate::types::DeliveryOutcome::TimedOut,
            duration_ms: 10_000,
            attempt_number: 0,
            attempted_at: crate::shared::clock::now(),
        };

        wh.report_attempt(&attempt);

        let events = raised(&mut wh);
        assert_eq!(
            events[0].event_type().to_string(),
            "webhooks.delivery_attempted"
        );
        assert_eq!(text_of(&events[0], "status"), "timeout");
    }

    /// Sam's endpoint fails once with a limit of one, which switches the
    /// webhook off. The switch-off is raised with the one failure behind
    /// it.
    #[test]
    fn reporting_a_switch_off_raises_it_with_the_failures_behind_it() {
        let mut wh = test_webhook();
        raised_names(&mut wh);
        assert_eq!(wh.record_failure(limit(1)), FailureOutcome::Disabled);

        wh.report_switched_off();

        let events = raised(&mut wh);
        assert_eq!(
            events[0].event_type().to_string(),
            "webhooks.subscription_disabled"
        );
        assert_eq!(text_of(&events[0], "consecutive_failures"), "1");
    }

    /// A switch-off is reported for Sam's endpoint while it is still
    /// active. Nothing switched it off, so nothing is raised.
    #[test]
    fn a_switch_off_of_an_active_webhook_raises_nothing() {
        let mut wh = test_webhook();
        raised_names(&mut wh);

        wh.report_switched_off();

        assert!(raised_names(&mut wh).is_empty());
    }

    /// Counting a delivery only keeps the streak; it raises nothing of its
    /// own.
    #[test]
    fn counting_a_delivery_raises_nothing() {
        let mut wh = test_webhook();
        raised_names(&mut wh);

        wh.record_success();
        let _ = wh.record_failure(limit(1));

        assert!(raised_names(&mut wh).is_empty());
    }

    /// A viewer's pause, secret rotation and delete attempts all fail
    /// without raising events.
    #[test]
    fn a_refused_webhook_change_raises_nothing() {
        let mut wh = test_webhook();
        raised_names(&mut wh);
        let viewer = webhook_viewer();

        let paused = wh.pause(&viewer);
        let rotated = wh.rotate_secret(
            SealedSecret::new("v1.c2Ftcw").unwrap(),
            RotationOverlap::Immediate,
            &viewer,
        );
        let deleted = wh.delete(&viewer);

        assert!(paused.is_err());
        assert!(rotated.is_err());
        assert!(deleted.is_err());
        assert!(raised_names(&mut wh).is_empty());
    }

    /// A webhook read back from storage has raised nothing; only a change
    /// made after loading is recorded.
    #[test]
    fn a_webhook_read_back_from_storage_has_raised_nothing() {
        let mut stored =
            WebhookSubscription::<ResolvedTenant>::reconstitute(stored(test_webhook())).unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }
}
