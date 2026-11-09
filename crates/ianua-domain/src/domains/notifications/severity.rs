//! How urgent a notification is.

use std::fmt;

use crate::shared::errors::DomainError;
use crate::types::EventType;
use crate::types::event_type::{
    AuthenticationEvent, CryptoEvent, OAuthEvent, OrganizationEvent, TenantEvent,
};

/// Severity level for notifications and dashboard events.
///
/// Used by the security dashboard for filtering and by the
/// notification UI for visual priority indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NotificationSeverity {
    /// Routine work, such as a user registering or a key rotating.
    Info,
    /// Needs attention, such as a failed login or a revoked session or key.
    Warning,
    /// Needs action now, such as break-glass access granted or an account
    /// locked out.
    Critical,
}

impl NotificationSeverity {
    /// The string key used for persistence and filtering.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    /// The severity's rank, from 0 for info to 2 for critical, so a list
    /// sorted by severity runs by urgency, not by the alphabet.
    ///
    /// It is stored where the database sorts by severity.
    #[must_use]
    pub fn rank(self) -> i16 {
        match self {
            Self::Info => 0,
            Self::Warning => 1,
            Self::Critical => 2,
        }
    }

    /// The severity at `rank`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for a rank no severity has. Only a
    ///   corrupt row holds one.
    pub fn from_rank(rank: i16) -> Result<Self, DomainError> {
        match rank {
            0 => Ok(Self::Info),
            1 => Ok(Self::Warning),
            2 => Ok(Self::Critical),
            _ => Err(DomainError::corrupt_row(
                "notification severity",
                "an unknown rank",
            )),
        }
    }

    /// Parses a severity from its string key.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "info" => Some(Self::Info),
            "warning" => Some(Self::Warning),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    /// The severity of an event type.
    ///
    /// - Critical: break-glass access granted, account locked out, account
    ///   under attack.
    /// - Warning: organization status changed, a payment failed, ownership
    ///   handed over, login failed, session
    ///   revoked, break-glass access revoked, key revoked, client or API key
    ///   revoked, domain verification lost, an uploaded certificate nearing
    ///   its end.
    /// - Info: everything else.
    ///
    /// The catch-all arm is the rule. A new event is informational until it
    /// is named here.
    #[must_use]
    #[allow(clippy::wildcard_enum_match_arm)]
    pub fn from_event_type(event_type: &EventType) -> Self {
        match event_type {
            EventType::Authentication(AuthenticationEvent::BreakGlassGranted) => Self::Critical,
            EventType::Authentication(AuthenticationEvent::AccountLockedOut) => Self::Critical,
            EventType::Authentication(AuthenticationEvent::AccountUnderAttack) => Self::Critical,
            EventType::Organization(OrganizationEvent::OrgAccountUnderAttack) => Self::Critical,
            EventType::Organization(OrganizationEvent::StatusChanged) => Self::Warning,
            EventType::Organization(OrganizationEvent::PaymentFailed) => Self::Warning,
            EventType::Organization(OrganizationEvent::OwnershipTransferred) => Self::Warning,

            EventType::Authentication(AuthenticationEvent::LoginFailed) => Self::Warning,
            EventType::Authentication(AuthenticationEvent::SessionRevoked) => Self::Warning,
            EventType::Authentication(AuthenticationEvent::BreakGlassRevoked) => Self::Warning,

            EventType::Crypto(CryptoEvent::KeyRevoked) => Self::Warning,
            EventType::OAuth(OAuthEvent::ClientRevoked) => Self::Warning,
            EventType::OAuth(OAuthEvent::ApiKeyRevoked) => Self::Warning,

            EventType::Tenant(TenantEvent::DomainVerificationLost) => Self::Warning,
            EventType::Tenant(TenantEvent::DomainCertificateExpiring) => Self::Warning,

            _ => Self::Info,
        }
    }
}

impl fmt::Display for NotificationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::event_type::IdentityEvent;

    /// Ranks run by urgency, as the order does, and each reads back as its
    /// severity; a rank no severity has is refused as corrupt.
    #[test]
    fn ranks_follow_urgency_and_round_trip() {
        let all = [
            NotificationSeverity::Info,
            NotificationSeverity::Warning,
            NotificationSeverity::Critical,
        ];

        let ranks: Vec<i16> = all.iter().map(|s| s.rank()).collect();

        assert_eq!(ranks, [0, 1, 2]);
        for severity in all {
            assert_eq!(
                NotificationSeverity::from_rank(severity.rank()).unwrap(),
                severity
            );
        }
        assert!(matches!(
            NotificationSeverity::from_rank(3),
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Sorting by severity puts info first, then warning, then critical. A
    /// filter for "warning and above" relies on this order.
    #[test]
    fn severities_rank_info_below_warning_below_critical() {
        assert!(NotificationSeverity::Info < NotificationSeverity::Warning);
        assert!(NotificationSeverity::Warning < NotificationSeverity::Critical);
    }

    /// Each severity's stored key parses back to the same severity.
    #[test]
    fn roundtrip_via_parse() {
        for s in &[
            NotificationSeverity::Info,
            NotificationSeverity::Warning,
            NotificationSeverity::Critical,
        ] {
            assert_eq!(NotificationSeverity::parse(s.as_str()), Some(*s));
        }
    }

    /// The key `urgent` is not a severity, so it parses to nothing.
    #[test]
    fn parse_unknown_returns_none() {
        assert_eq!(NotificationSeverity::parse("urgent"), None);
    }

    /// Someone is granted break-glass access. The notification is critical,
    /// since an administrator must act on it now.
    #[test]
    fn break_glass_is_critical() {
        let et = EventType::Authentication(AuthenticationEvent::BreakGlassGranted);
        assert_eq!(
            NotificationSeverity::from_event_type(&et),
            NotificationSeverity::Critical
        );
    }

    /// An account is locked out after too many tries. The notification is
    /// critical.
    #[test]
    fn account_lockout_is_critical() {
        let et = EventType::Authentication(AuthenticationEvent::AccountLockedOut);
        assert_eq!(
            NotificationSeverity::from_event_type(&et),
            NotificationSeverity::Critical
        );
    }

    /// A botnet's guesses put Ann's account under attack, in a tenant or in
    /// her organization. The alert is critical.
    #[test]
    fn an_account_under_attack_is_critical() {
        let tenant = EventType::Authentication(AuthenticationEvent::AccountUnderAttack);
        let organization = EventType::Organization(OrganizationEvent::OrgAccountUnderAttack);

        assert_eq!(
            NotificationSeverity::from_event_type(&tenant),
            NotificationSeverity::Critical
        );
        assert_eq!(
            NotificationSeverity::from_event_type(&organization),
            NotificationSeverity::Critical
        );
    }

    /// A login fails. The notification is a warning, not routine.
    #[test]
    fn login_failed_is_warning() {
        let et = EventType::Authentication(AuthenticationEvent::LoginFailed);
        assert_eq!(
            NotificationSeverity::from_event_type(&et),
            NotificationSeverity::Warning
        );
    }

    /// A signing key is revoked. The notification is a warning.
    #[test]
    fn key_revoked_is_warning() {
        let et = EventType::Crypto(CryptoEvent::KeyRevoked);
        assert_eq!(
            NotificationSeverity::from_event_type(&et),
            NotificationSeverity::Warning
        );
    }

    /// A user registers. The notification is routine info.
    #[test]
    fn user_registered_is_info() {
        let et = EventType::Identity(IdentityEvent::UserRegistered);
        assert_eq!(
            NotificationSeverity::from_event_type(&et),
            NotificationSeverity::Info
        );
    }

    /// A key is rotated on schedule. The notification is routine info,
    /// unlike a revoked key.
    #[test]
    fn key_rotated_is_info() {
        let et = EventType::Crypto(CryptoEvent::KeyRotated);
        assert_eq!(
            NotificationSeverity::from_event_type(&et),
            NotificationSeverity::Info
        );
    }

    /// An organization's status changes, a session or client is revoked, or
    /// a domain loses its verification. Each is a warning, so an
    /// administrator sees it above the routine ones.
    #[test]
    fn every_event_an_administrator_must_look_at_is_at_least_a_warning() {
        let must_be_seen = [
            EventType::Organization(OrganizationEvent::StatusChanged),
            EventType::Authentication(AuthenticationEvent::SessionRevoked),
            EventType::Authentication(AuthenticationEvent::BreakGlassRevoked),
            EventType::OAuth(OAuthEvent::ClientRevoked),
            EventType::OAuth(OAuthEvent::ApiKeyRevoked),
            EventType::Tenant(TenantEvent::DomainVerificationLost),
        ];

        for event_type in must_be_seen {
            assert_eq!(
                NotificationSeverity::from_event_type(&event_type),
                NotificationSeverity::Warning,
                "{} must not be filed as routine",
                event_type.as_str()
            );
        }
    }

    /// Each severity prints as its stored key, such as `critical`. That
    /// printed name parses back to the same severity.
    #[test]
    fn a_severity_displays_as_the_name_it_parses_back_from() {
        for severity in [
            NotificationSeverity::Info,
            NotificationSeverity::Warning,
            NotificationSeverity::Critical,
        ] {
            assert_eq!(severity.to_string(), severity.as_str());
            assert_eq!(
                NotificationSeverity::parse(&severity.to_string()),
                Some(severity)
            );
        }
        assert_eq!(NotificationSeverity::Critical.to_string(), "critical");
    }
}
