/// Delivery status of a webhook subscription.
///
/// The allowed moves:
/// - `Active` to `Paused`. An admin pauses delivery.
/// - `Paused` to `Active`. An admin resumes delivery.
/// - `Active` or `Paused` to `Disabled`. The subscription
///   [`WebhookSubscription`](crate::domains::webhooks::subscription::WebhookSubscription)
///   disables itself only from `Active`, after too many failures in a row.
///
/// `Disabled` is final. A disabled subscription is replaced with a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum WebhookSubscriptionStatus {
    /// Receiving deliveries.
    Active,

    /// Paused. Events raised while paused are not delivered.
    Paused,

    /// Switched off for good. Nothing more is delivered.
    Disabled,
}

/// A status move that is not allowed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a webhook subscription from {from:?} to {to:?}")]
pub struct InvalidWebhookSubscriptionTransition {
    /// The current state.
    pub from: WebhookSubscriptionStatus,
    /// The attempted target state.
    pub to: WebhookSubscriptionStatus,
}

impl WebhookSubscriptionStatus {
    /// Moves to `to` when the move is one of those listed on the type.
    ///
    /// # Errors
    ///
    /// - [`InvalidWebhookSubscriptionTransition`] when the move is not
    ///   listed, including any move out of `Disabled` and any move to the
    ///   current state.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidWebhookSubscriptionTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Active, Self::Paused | Self::Disabled)
                | (Self::Paused, Self::Active | Self::Disabled)
        );

        if allowed {
            Ok(to)
        } else {
            Err(InvalidWebhookSubscriptionTransition { from: self, to })
        }
    }

    /// Whether this subscription is receiving deliveries.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }

    /// Whether this subscription is paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        *self == Self::Paused
    }

    /// Whether this subscription is permanently disabled.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        *self == Self::Disabled
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidWebhookSubscriptionTransition);

#[cfg(test)]
mod tests {
    use super::*;

    /// Each status answers yes to its own question only. A disabled
    /// subscription never reads as active, so nothing is delivered to it.
    #[test]
    fn each_predicate_answers_for_exactly_the_states_it_names() {
        let cases = [
            (WebhookSubscriptionStatus::Active, (true, false, false)),
            (WebhookSubscriptionStatus::Paused, (false, true, false)),
            (WebhookSubscriptionStatus::Disabled, (false, false, true)),
        ];

        for (status, (active, paused, disabled)) in cases {
            assert_eq!(status.is_active(), active, "{status:?}");
            assert_eq!(status.is_paused(), paused, "{status:?}");
            assert_eq!(status.is_disabled(), disabled, "{status:?}");
        }
    }

    /// An admin pauses an active subscription. The move is allowed.
    #[test]
    fn active_to_paused() {
        assert!(
            WebhookSubscriptionStatus::Active
                .try_transition(WebhookSubscriptionStatus::Paused)
                .is_ok()
        );
    }

    /// An active subscription that keeps failing is disabled. The move is
    /// allowed.
    #[test]
    fn active_to_disabled() {
        assert!(
            WebhookSubscriptionStatus::Active
                .try_transition(WebhookSubscriptionStatus::Disabled)
                .is_ok()
        );
    }

    /// An admin resumes a paused subscription. The move is allowed.
    #[test]
    fn paused_to_active() {
        assert!(
            WebhookSubscriptionStatus::Paused
                .try_transition(WebhookSubscriptionStatus::Active)
                .is_ok()
        );
    }

    /// A paused subscription moves to disabled. The status allows it.
    #[test]
    fn paused_to_disabled() {
        assert!(
            WebhookSubscriptionStatus::Paused
                .try_transition(WebhookSubscriptionStatus::Disabled)
                .is_ok()
        );
    }

    /// A disabled subscription cannot move to active, to paused, or to
    /// disabled again. The tenant creates a new one instead.
    #[test]
    fn disabled_is_terminal() {
        for to in [
            WebhookSubscriptionStatus::Active,
            WebhookSubscriptionStatus::Paused,
            WebhookSubscriptionStatus::Disabled,
        ] {
            assert!(
                WebhookSubscriptionStatus::Disabled
                    .try_transition(to)
                    .is_err()
            );
        }
    }

    /// Moving an active subscription to active, or a paused one to paused,
    /// is refused. A repeated pause is reported, not ignored.
    #[test]
    fn no_self_transitions() {
        assert!(
            WebhookSubscriptionStatus::Active
                .try_transition(WebhookSubscriptionStatus::Active)
                .is_err()
        );
        assert!(
            WebhookSubscriptionStatus::Paused
                .try_transition(WebhookSubscriptionStatus::Paused)
                .is_err()
        );
    }

    /// Each status is written to JSON as `"Active"`, `"Paused"` or
    /// `"Disabled"` and read back from it. Renaming a variant fails here
    /// before it changes saved data.
    #[cfg(feature = "serde")]
    #[test]
    fn webhook_subscription_status_is_stored_under_its_variant_name() {
        assert_eq!(
            serde_json::to_string(&WebhookSubscriptionStatus::Active).unwrap(),
            r#""Active""#
        );
        assert_eq!(
            serde_json::to_string(&WebhookSubscriptionStatus::Paused).unwrap(),
            r#""Paused""#
        );
        assert_eq!(
            serde_json::to_string(&WebhookSubscriptionStatus::Disabled).unwrap(),
            r#""Disabled""#
        );
        assert_eq!(
            serde_json::from_str::<WebhookSubscriptionStatus>(r#""Active""#).unwrap(),
            WebhookSubscriptionStatus::Active
        );
        assert_eq!(
            serde_json::from_str::<WebhookSubscriptionStatus>(r#""Paused""#).unwrap(),
            WebhookSubscriptionStatus::Paused
        );
        assert_eq!(
            serde_json::from_str::<WebhookSubscriptionStatus>(r#""Disabled""#).unwrap(),
            WebhookSubscriptionStatus::Disabled
        );
    }
}
