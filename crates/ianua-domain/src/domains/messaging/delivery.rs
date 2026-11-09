//! How a subscription's messages reach its service, and what becomes of a
//! message the service does not acknowledge.
//!
//! The transport counts deliveries and keeps the dead letters. The domain
//! decides where a push goes, what signs it, how long a message waits for
//! its acknowledgement and when it is set aside.

use time::OffsetDateTime;

use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::types::{PreviousSigningSecret, PublicHttpsUrl, RotationOverlap, SealedSecret, Seconds};

/// The shortest wait for an acknowledgement.
const SHORTEST_DEADLINE_SECONDS: u32 = 5;
/// The longest wait for an acknowledgement: ten minutes.
const LONGEST_DEADLINE_SECONDS: u32 = 600;
/// The most deliveries one message gets.
const MOST_DELIVERIES: u32 = 100;

/// Where a push subscription posts its messages, and the secrets it signs
/// them with.
///
/// The address is a [`PublicHttpsUrl`], so a push never reaches the
/// platform's own network. The secrets are sealed at rest; only delivery
/// opens them, and `Debug` never shows them. After a rotation the old
/// secret signs beside the new one for the overlap asked for, so the
/// service can move to the new one without refusing a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushEndpoint {
    url: PublicHttpsUrl,
    signing_secret: SealedSecret,
    previous_secret: PreviousSigningSecret,
}

impl PushEndpoint {
    /// Pushes to `url`, signed with `signing_secret` alone.
    #[must_use]
    pub fn new(url: PublicHttpsUrl, signing_secret: SealedSecret) -> Self {
        Self::restored(url, signing_secret, PreviousSigningSecret::Retired)
    }

    /// Pushes to `url`, signed with `signing_secret` and, while its overlap
    /// lasts, with `previous_secret`, as storage holds it.
    #[must_use]
    pub fn restored(
        url: PublicHttpsUrl,
        signing_secret: SealedSecret,
        previous_secret: PreviousSigningSecret,
    ) -> Self {
        Self {
            url,
            signing_secret,
            previous_secret,
        }
    }

    /// Where messages are posted.
    #[must_use]
    pub fn url(&self) -> &PublicHttpsUrl {
        &self.url
    }

    /// The secret each push is signed with now, sealed.
    #[must_use]
    pub fn signing_secret(&self) -> &SealedSecret {
        &self.signing_secret
    }

    /// The secret before the last rotation, with when it stops signing.
    #[must_use]
    pub fn previous_secret(&self) -> &PreviousSigningSecret {
        &self.previous_secret
    }

    /// Every secret a push sent at `now` is signed with: the current one
    /// first, then the one before it while its overlap lasts. The push
    /// carries one signature per secret, so a service still on the old
    /// secret accepts it.
    #[must_use]
    pub fn signing_secrets(&self, now: OffsetDateTime) -> Vec<&SealedSecret> {
        std::iter::once(&self.signing_secret)
            .chain(self.previous_secret.signing_at(now))
            .collect()
    }

    /// The same address, signed with `signing_secret` from `now` on, the
    /// secret it replaces signing beside it for `overlap`. A secret from an
    /// earlier rotation stops at once.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the overlap is longer than seven
    ///   days.
    pub(crate) fn rotated(
        &self,
        signing_secret: SealedSecret,
        overlap: RotationOverlap,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let previous =
            PreviousSigningSecret::after_rotation(overlap, self.signing_secret.clone(), now)?;
        Ok(Self::restored(self.url.clone(), signing_secret, previous))
    }
}

/// How a subscription's messages reach its service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionDelivery {
    /// The service asks for new messages.
    Pull,
    /// Messages are posted to the service's endpoint.
    Push(PushEndpoint),
}

/// What becomes of a message its service did not acknowledge in time, or
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageFate {
    /// It is delivered again.
    Redeliver,
    /// It is set aside as a dead letter, kept for the tenant to read and
    /// replay, and not delivered again.
    DeadLetter,
}

/// How long a delivered message waits for its acknowledgement, and how
/// many deliveries it gets before it is set aside.
///
/// Without a limit, one message the service always fails on would be
/// delivered forever and hold up every message behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckPolicy {
    ack_deadline: Seconds,
    max_deliveries: u32,
}

impl AckPolicy {
    /// A policy waiting `ack_deadline` for each acknowledgement and setting
    /// a message aside after `max_deliveries`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the deadline is under five
    ///   seconds or over ten minutes.
    /// - [`DomainError::Validation`] when the deliveries are none or more
    ///   than a hundred.
    pub fn new(ack_deadline: Seconds, max_deliveries: u32) -> Result<Self, DomainError> {
        validate_range(
            "ack_deadline_seconds",
            ack_deadline.get(),
            SHORTEST_DEADLINE_SECONDS..=LONGEST_DEADLINE_SECONDS,
        )?;
        validate_range("max_deliveries", max_deliveries, 1..=MOST_DELIVERIES)?;
        Ok(Self {
            ack_deadline,
            max_deliveries,
        })
    }

    /// The default: thirty seconds for each acknowledgement, set aside
    /// after five deliveries.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            ack_deadline: Seconds::new(30),
            max_deliveries: 5,
        }
    }

    /// How long a delivered message waits for its acknowledgement before it
    /// counts as not acknowledged.
    #[must_use]
    pub fn ack_deadline(&self) -> Seconds {
        self.ack_deadline
    }

    /// How many deliveries a message gets.
    #[must_use]
    pub fn max_deliveries(&self) -> u32 {
        self.max_deliveries
    }

    /// What becomes of a message not acknowledged after `delivered`
    /// deliveries so far.
    #[must_use]
    pub fn fate_after(&self, delivered: u32) -> MessageFate {
        if delivered >= self.max_deliveries {
            return MessageFate::DeadLetter;
        }
        MessageFate::Redeliver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Lifetime;

    /// "billing-sync"'s push endpoint, signed with `secret`.
    fn endpoint(secret: &str) -> PushEndpoint {
        PushEndpoint::new(
            PublicHttpsUrl::new("https://hooks.acme.com/orders").unwrap(),
            SealedSecret::new(secret).unwrap(),
        )
    }

    /// An overlap of `count` days.
    fn days(count: i64) -> RotationOverlap {
        RotationOverlap::For(Lifetime::new(time::Duration::days(count)).unwrap())
    }

    /// With the default policy, a message the payment workers fail on is
    /// delivered again after its first four deliveries and set aside after
    /// the fifth.
    #[test]
    fn a_message_is_set_aside_after_its_last_delivery() {
        let policy = AckPolicy::standard();

        let fates: Vec<MessageFate> = (1..=5).map(|n| policy.fate_after(n)).collect();

        assert_eq!(fates[..4], [MessageFate::Redeliver; 4]);
        assert_eq!(fates[4], MessageFate::DeadLetter);
    }

    /// A deadline of a minute and ten deliveries are accepted.
    #[test]
    fn a_sensible_ack_policy_is_accepted() {
        let policy = AckPolicy::new(Seconds::new(60), 10).unwrap();

        assert_eq!(policy.ack_deadline(), Seconds::new(60));
        assert_eq!(policy.max_deliveries(), 10);
    }

    /// Acknowledgement policies reject zero or 101 deliveries, and reject
    /// deadlines just below five seconds or above ten minutes.
    #[test]
    fn an_ack_policy_past_its_bounds_is_refused() {
        for (deadline, deliveries) in [(30, 0), (30, 101), (4, 5), (601, 5)] {
            let result = AckPolicy::new(Seconds::new(deadline), deliveries);

            assert!(
                matches!(result, Err(DomainError::Validation(_))),
                "{deadline}s, {deliveries} deliveries"
            );
        }
    }

    /// Formatting a push endpoint for debugging conceals its sealed secret.
    #[test]
    fn a_push_endpoint_never_prints_its_secret() {
        let push = PushEndpoint::new(
            PublicHttpsUrl::new("https://hooks.acme.com/orders").unwrap(),
            SealedSecret::new("v1.c2VjcmV0").unwrap(),
        );

        assert!(!format!("{push:?}").contains("c2VjcmV0"));
    }

    /// Ann rotates the push secret with a day's overlap. For that day each
    /// push carries both secrets, so "billing-sync" can move over without
    /// refusing one; after it only the new one signs.
    #[test]
    fn the_old_push_secret_signs_beside_the_new_one_for_the_overlap() {
        let now = crate::shared::clock::now();

        let rotated = endpoint("v1.b2xk")
            .rotated(SealedSecret::new("v1.bmV3").unwrap(), days(1), now)
            .unwrap();

        let during = rotated.signing_secrets(now + time::Duration::hours(23));
        let after = rotated.signing_secrets(now + time::Duration::hours(24));
        assert_eq!(during.len(), 2);
        assert_eq!(during[0].as_str(), "v1.bmV3");
        assert_eq!(after.len(), 1);
    }

    /// An immediate rotation retires the previous push secret and leaves
    /// one signing secret.
    #[test]
    fn an_immediate_rotation_stops_the_old_push_secret() {
        let now = crate::shared::clock::now();

        let rotated = endpoint("v1.b2xk")
            .rotated(
                SealedSecret::new("v1.bmV3").unwrap(),
                RotationOverlap::Immediate,
                now,
            )
            .unwrap();

        assert_eq!(rotated.signing_secrets(now).len(), 1);
        assert_eq!(rotated.previous_secret(), &PreviousSigningSecret::Retired);
    }

    /// Ann rotates twice within one overlap. Only the secret just replaced
    /// keeps signing; the first one stops.
    #[test]
    fn a_second_rotation_ends_the_oldest_push_secret() {
        let now = crate::shared::clock::now();
        let once = endpoint("v1.Zmlyc3Q")
            .rotated(SealedSecret::new("v1.c2Vjb25k").unwrap(), days(1), now)
            .unwrap();

        let twice = once
            .rotated(SealedSecret::new("v1.dGhpcmQ").unwrap(), days(1), now)
            .unwrap();

        let signing: Vec<&str> = twice
            .signing_secrets(now)
            .into_iter()
            .map(SealedSecret::as_str)
            .collect();
        assert_eq!(signing, ["v1.dGhpcmQ", "v1.c2Vjb25k"]);
    }
}
