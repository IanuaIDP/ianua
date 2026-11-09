//! The certificate a connector holds its link to the gateway with: whose
//! key it carries, and how long it is good for.
//!
//! The certificate is short-lived on purpose. The platform's connector
//! authority signs it for a day, and the connector asks for a new one in
//! the last eight hours of that day, always for the same key. So the key
//! pinned at enrollment names the connector for as long as it lives, and
//! a certificate copied off a disk is worth a day at most.

use time::{Duration, OffsetDateTime};

use crate::types::PublicKeyPin;

/// How long one certificate is good for.
pub(crate) const CERTIFICATE_LIFETIME: Duration = Duration::hours(24);

/// How long before its end a certificate is due to be renewed.
pub(crate) const RENEWAL_WINDOW: Duration = Duration::hours(8);

/// The certificate a connector holds now: the key it carries and when it
/// stops being good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorCertificate {
    key: PublicKeyPin,
    expires_at: OffsetDateTime,
}

impl ConnectorCertificate {
    /// A certificate for `key`, issued at `issued_at`, good for
    /// `CERTIFICATE_LIFETIME`.
    pub(crate) fn issued(key: PublicKeyPin, issued_at: OffsetDateTime) -> Self {
        Self {
            key,
            expires_at: issued_at.saturating_add(CERTIFICATE_LIFETIME),
        }
    }

    /// The certificate for `key` good until `expires_at`, as the connector
    /// holding it was rebuilt with, its dates checked there.
    pub(crate) fn held(key: PublicKeyPin, expires_at: OffsetDateTime) -> Self {
        Self { key, expires_at }
    }

    /// The pin of the key it carries.
    #[must_use]
    pub fn key(&self) -> &PublicKeyPin {
        &self.key
    }

    /// When it stops being good.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// From when the connector asks for the next one.
    #[must_use]
    pub fn renew_after(&self) -> OffsetDateTime {
        self.expires_at.saturating_sub(RENEWAL_WINDOW)
    }

    /// Whether a new certificate may be issued at `now`: within the
    /// renewal window, or once this one has run out, as it has for a
    /// connector that was switched off for a weekend.
    #[must_use]
    pub fn is_due(&self, now: OffsetDateTime) -> bool {
        now >= self.renew_after()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate() -> ConnectorCertificate {
        ConnectorCertificate::issued(
            PublicKeyPin::from_digest([7; 32]),
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    /// A certificate issued at midnight is good until the next midnight
    /// and is renewed from four in the afternoon.
    #[test]
    fn a_certificate_lasts_a_day_and_is_renewed_in_its_last_eight_hours() {
        let certificate = certificate();

        assert_eq!(
            certificate.expires_at(),
            OffsetDateTime::UNIX_EPOCH + Duration::hours(24)
        );
        assert_eq!(
            certificate.renew_after(),
            OffsetDateTime::UNIX_EPOCH + Duration::hours(16)
        );
    }

    /// A certificate is not due for renewal one hour after issuance. It is
    /// due within the renewal window and after expiration.
    #[test]
    fn a_certificate_is_due_only_in_its_window_or_after_it() {
        let certificate = certificate();
        let start = OffsetDateTime::UNIX_EPOCH;

        assert!(!certificate.is_due(start + Duration::hours(1)));
        assert!(certificate.is_due(start + Duration::hours(17)));
        assert!(certificate.is_due(start + Duration::days(3)));
    }
}
