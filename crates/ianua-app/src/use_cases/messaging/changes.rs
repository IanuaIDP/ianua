//! Changing one of the tenant's topics or subscriptions on a person's order.
//!
//! Every such change goes the same way: the person's standing is read and
//! checked for the right the change needs, the topic or subscription is
//! loaded, the domain changes it with what the person holds and raises the
//! event, it is saved, and then what it raised is recorded.

use ianua_domain::domains::authorization::permission::MessagingAction;
use ianua_domain::domains::messaging::control::MessagingControl;
use ianua_domain::domains::messaging::subscription::Subscription;
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{MessageSubscriptionId, TopicId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{SubscriptionStore, TopicStore};
use crate::use_cases::messaging::lookup::{existing_subscription, existing_topic};

/// A person changing a topic or a subscription of their tenant, and where
/// the change is recorded.
pub(super) struct MessagingChange<'a> {
    caller: &'a CallerContext,
    auditor: &'a RequestAuditor,
    authorities: &'a dyn TenantAuthorities,
}

impl<'a> MessagingChange<'a> {
    /// A change by the person `caller` names, holding what `authorities`
    /// says, recorded through `auditor`.
    pub(super) fn by(
        caller: &'a CallerContext,
        auditor: &'a RequestAuditor,
        authorities: &'a dyn TenantAuthorities,
    ) -> Self {
        Self {
            caller,
            auditor,
            authorities,
        }
    }

    /// Checks the person may take `needs`, then loads the topic, applies
    /// `change` with the person's messaging control, saves it and records
    /// what the topic raised. Nothing is saved or recorded when `change`
    /// refuses.
    ///
    /// The right is checked before the topic is read, so a person without
    /// it is refused the same for a topic that exists and one that does
    /// not.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the person does not hold `needs`.
    /// - `AppError::NotFound` if the tenant has no such topic.
    /// - What `AppError::from_domain` makes of the domain's refusal.
    /// - `AppError::Internal` on storage or audit failure.
    pub(super) async fn topic<F>(
        &self,
        store: &dyn TopicStore,
        topic_id: &TopicId,
        needs: MessagingAction,
        change: F,
    ) -> Result<(), AppError>
    where
        F: FnOnce(&mut Topic<ResolvedTenant>, &MessagingControl<'_>) -> Result<(), DomainError>,
    {
        let authority = self.authorities.authority(self.caller).await?;
        let control = MessagingControl::new(&authority);
        control.ensure_may(needs).map_err(AppError::from_domain)?;
        let tenant = self.caller.tenant();
        let mut topic = existing_topic(store, &tenant, topic_id).await?;
        change(&mut topic, &control).map_err(AppError::from_domain)?;

        store.save(&tenant, &topic).await.or_internal()?;

        self.record(topic.take_events(&tenant)).await
    }

    /// Checks the person may take `needs`, then loads the subscription,
    /// applies `change` with the person's messaging control, saves it and
    /// records what the subscription raised. Nothing is saved or recorded
    /// when `change` refuses.
    ///
    /// The right is checked before the subscription is read, so a person
    /// without it is refused the same for one that exists and one that
    /// does not.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the person does not hold `needs`.
    /// - `AppError::NotFound` if the tenant has no such subscription.
    /// - What `AppError::from_domain` makes of the domain's refusal.
    /// - `AppError::Internal` on storage or audit failure.
    pub(super) async fn subscription<F>(
        &self,
        store: &dyn SubscriptionStore,
        subscription_id: &MessageSubscriptionId,
        needs: MessagingAction,
        change: F,
    ) -> Result<(), AppError>
    where
        F: FnOnce(
            &mut Subscription<ResolvedTenant>,
            &MessagingControl<'_>,
        ) -> Result<(), DomainError>,
    {
        let authority = self.authorities.authority(self.caller).await?;
        let control = MessagingControl::new(&authority);
        control.ensure_may(needs).map_err(AppError::from_domain)?;
        let tenant = self.caller.tenant();
        let mut subscription = existing_subscription(store, &tenant, subscription_id).await?;
        change(&mut subscription, &control).map_err(AppError::from_domain)?;

        store.save(&tenant, &subscription).await.or_internal()?;

        self.record(subscription.take_events(&tenant)).await
    }

    /// Records `events` as done by the person who changed it.
    async fn record(&self, events: Vec<DomainEvent>) -> Result<(), AppError> {
        self.auditor
            .dispatch_by(&self.caller.actor(), events)
            .await
            .or_internal()
    }
}
