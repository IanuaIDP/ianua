//! When the gateway last saw a connector's link.
//!
//! The gateway notes it when a link opens and every few minutes while it
//! stays open. It is a sighting, not a change: no right is needed to note
//! it, nothing is raised for it, and it moves no other date of the
//! connector.

use time::OffsetDateTime;

use crate::domains::routing::connector::ConnectorEnrollment;

/// When the gateway last saw a connector's link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastSeen {
    /// No link of it has opened yet.
    Never,
    /// A link of it was open at this time.
    At(OffsetDateTime),
}

impl LastSeen {
    /// Whether a stored sighting fits a connector whose enrollment stands
    /// as `enrollment`: seen only once it enrolled, and never before.
    pub(crate) fn fits(self, enrollment: &ConnectorEnrollment) -> bool {
        match (self, enrollment) {
            (Self::Never, _) => true,
            (Self::At(seen), ConnectorEnrollment::Enrolled { enrolled_at, .. }) => {
                seen >= *enrolled_at
            }
            (Self::At(_), ConnectorEnrollment::Awaiting { .. }) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::types::{PublicKeyPin, TokenHash};

    fn enrolled(enrolled_at: OffsetDateTime) -> ConnectorEnrollment {
        ConnectorEnrollment::Enrolled {
            key: PublicKeyPin::from_digest([1; 32]),
            certificate_expires_at: enrolled_at + Duration::days(1),
            enrolled_at,
        }
    }

    /// A connector seen before it enrolled, or seen while still awaiting
    /// its agent, breaks the rule; one seen after it enrolled keeps it.
    #[test]
    fn a_connector_is_seen_only_after_it_enrolled() {
        let at = OffsetDateTime::UNIX_EPOCH;
        let awaiting = ConnectorEnrollment::Awaiting {
            code_hash: TokenHash::from_stored("code".to_owned()),
            expires_at: at,
        };

        assert!(LastSeen::Never.fits(&awaiting));
        assert!(LastSeen::At(at + Duration::minutes(1)).fits(&enrolled(at)));
        assert!(!LastSeen::At(at - Duration::minutes(1)).fits(&enrolled(at)));
        assert!(!LastSeen::At(at).fits(&awaiting));
    }
}
