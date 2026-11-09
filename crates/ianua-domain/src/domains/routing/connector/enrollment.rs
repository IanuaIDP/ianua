//! How a connector's agent proves who it is: once with the one-time code
//! an admin was shown, then with the key it enrolled.
//!
//! The agent sends the code with a certificate signing request. The
//! request names its public key and is signed by the private one, so the
//! agent shows it holds that key; the connector pins the key, and the
//! platform's connector authority signs a certificate for it that lasts a
//! day. From then on the agent asks for the next certificate with a new
//! request for the same key, and a request for any other key is refused,
//! so a stolen code or a copied certificate never becomes a connector of
//! its own.

use time::{Duration, OffsetDateTime};

use crate::domains::routing::connector::certificate::{CERTIFICATE_LIFETIME, ConnectorCertificate};
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{PublicKeyPin, TokenHash};

/// How long an enrollment code stays good.
pub(crate) const ENROLLMENT_WINDOW: Duration = Duration::hours(1);

/// Where a connector's enrollment stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorEnrollment {
    /// Waiting for the agent to present its one-time code.
    Awaiting {
        /// The digest of the code. The code itself is shown once and never
        /// kept.
        code_hash: TokenHash,
        /// When the code stops being good.
        expires_at: OffsetDateTime,
    },
    /// Enrolled. The code is spent, and the link is held with a
    /// certificate for this key.
    Enrolled {
        /// The pin of the key the agent enrolled with.
        key: PublicKeyPin,
        /// When the certificate issued last stops being good.
        certificate_expires_at: OffsetDateTime,
        /// When it enrolled.
        enrolled_at: OffsetDateTime,
    },
}

impl ConnectorEnrollment {
    /// Whether a stored enrollment keeps its rules against the connector's
    /// dates: a code good for an hour at most after the connector was
    /// made, and a certificate that ends after the enrollment and no later
    /// than a day after the connector last changed, when it was issued.
    pub(crate) fn fits(&self, created_at: OffsetDateTime, updated_at: OffsetDateTime) -> bool {
        match self {
            Self::Awaiting { expires_at, .. } => {
                *expires_at <= created_at.saturating_add(ENROLLMENT_WINDOW)
            }
            Self::Enrolled {
                certificate_expires_at,
                enrolled_at,
                ..
            } => {
                *enrolled_at >= created_at
                    && *certificate_expires_at > *enrolled_at
                    && *certificate_expires_at <= updated_at.saturating_add(CERTIFICATE_LIFETIME)
            }
        }
    }

    /// The certificate the connector holds now, once enrolled.
    pub(crate) fn certificate(&self) -> Option<ConnectorCertificate> {
        let Self::Enrolled {
            key,
            certificate_expires_at,
            ..
        } = self
        else {
            return None;
        };
        Some(ConnectorCertificate::held(*key, *certificate_expires_at))
    }
}

/// The refusal of an enrollment. It names no detail.
pub(crate) fn enrollment_refused() -> DomainError {
    DomainError::forbidden(message!(
        "routing-the-enrollment-code-is-not-good",
        "the enrollment code is not good"
    ))
}

/// The refusal of a renewal. It names no detail.
pub(crate) fn renewal_refused() -> DomainError {
    DomainError::forbidden(message!(
        "routing-the-connector-may-not-renew-with",
        "the connector may not renew with this key"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrolled(certificate_expires_at: OffsetDateTime) -> ConnectorEnrollment {
        ConnectorEnrollment::Enrolled {
            key: PublicKeyPin::from_digest([1; 32]),
            certificate_expires_at,
            enrolled_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// A stored certificate good for a day from its last change keeps the
    /// rule; one good for two days breaks the rule the authority signs by.
    #[test]
    fn a_stored_certificate_lasts_a_day_at_most() {
        let at = OffsetDateTime::UNIX_EPOCH;

        assert!(enrolled(at + Duration::days(1)).fits(at, at));
        assert!(!enrolled(at + Duration::days(2)).fits(at, at));
    }

    /// A stored certificate ending before the enrollment breaks the rule.
    #[test]
    fn a_stored_certificate_ends_after_the_enrollment() {
        let at = OffsetDateTime::UNIX_EPOCH;

        assert!(!enrolled(at).fits(at, at));
    }
}
