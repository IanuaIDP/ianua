//! Broad activity categories for the activity calendar.
//!
//! Each audit event belongs to exactly one [`ActivityCategory`]. The
//! category comes from the typed [`EventType`] when the event is written.
//! It is stored on the `audit_log` table, so the calendar reader groups by
//! an indexed column. It does not work it out again from `event_type` on
//! every query.
//!
//! [`EventType`]: crate::types::event_type::EventType

use crate::types::event_type::EventType;

/// A broad group of audit events for the activity calendar.
///
/// Each category covers one or more [`EventType`] contexts. The calendar's
/// category picker offers these few groups, not every event type. The set
/// is fixed. Events outside a named group count as [`Other`](Self::Other).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ActivityCategory {
    /// Logins, sessions, tokens, MFA, password changes.
    Authentication,
    /// Proxy access decisions and routing.
    Access,
    /// Role, permission, group, impersonation and agent changes.
    Administration,
    /// User lifecycle, invitations, email, status.
    Identity,
    /// Organization and tenant lifecycle, plan changes.
    Provisioning,
    /// Federation, OAuth, webhooks, messaging, consumers, branding,
    /// crypto, signals and notifications.
    Other,
}

impl ActivityCategory {
    /// Every category, in display order.
    ///
    /// The calendar shows only the categories that occurred in its range.
    /// They appear in this order.
    pub const ALL: [Self; 6] = [
        Self::Authentication,
        Self::Access,
        Self::Administration,
        Self::Identity,
        Self::Provisioning,
        Self::Other,
    ];

    /// The activity category an event belongs to.
    ///
    /// Every [`EventType`] context has a category, so there is no fallback.
    /// [`Other`](Self::Other) is a normal category, not an error case. An
    /// unknown stored value is refused by [`parse`](Self::parse).
    #[must_use]
    pub fn from_event_type(event_type: &EventType) -> Self {
        match event_type {
            EventType::Authentication(_) => Self::Authentication,
            EventType::Proxy(_) | EventType::Routing(_) => Self::Access,
            EventType::Authorization(_)
            | EventType::Operator(_)
            | EventType::Agents(_)
            | EventType::Workflows(_) => Self::Administration,
            EventType::Identity(_) => Self::Identity,
            EventType::Organization(_) | EventType::Tenant(_) => Self::Provisioning,
            EventType::Federation(_)
            | EventType::OAuth(_)
            | EventType::Webhooks(_)
            | EventType::Messaging(_)
            | EventType::Consumers(_)
            | EventType::Signals(_)
            | EventType::Branding(_)
            | EventType::Crypto(_)
            | EventType::Notifications(_) => Self::Other,
        }
    }

    /// The category's lowercase name, which the calendar orders cells by
    /// and caches and transports use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Access => "access",
            Self::Administration => "administration",
            Self::Identity => "identity",
            Self::Provisioning => "provisioning",
            Self::Other => "other",
        }
    }

    /// Reads a name written by [`as_str`](Self::as_str).
    ///
    /// Gives `None` for an unknown name. The calendar reader treats that
    /// as corrupt storage. It never puts the event in some other category.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "authentication" => Some(Self::Authentication),
            "access" => Some(Self::Access),
            "administration" => Some(Self::Administration),
            "identity" => Some(Self::Identity),
            "provisioning" => Some(Self::Provisioning),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::event_type::{
        AuthenticationEvent, AuthorizationEvent, CryptoEvent, FederationEvent, IdentityEvent,
        OAuthEvent, OrganizationEvent, ProxyEvent, RoutingEvent, TenantEvent,
    };

    /// A login lands in authentication, a route change in access and a role
    /// change in administration. User and tenant events land in identity
    /// and provisioning.
    #[test]
    fn from_event_type_classifies_each_bucket() {
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(
                AuthenticationEvent::LoginSucceeded
            )),
            ActivityCategory::Authentication
        );
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(ProxyEvent::PipelineCreated)),
            ActivityCategory::Access
        );
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(RoutingEvent::RouteCreated)),
            ActivityCategory::Access
        );
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(AuthorizationEvent::RoleAssigned)),
            ActivityCategory::Administration
        );
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(IdentityEvent::UserRegistered)),
            ActivityCategory::Identity
        );
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(OrganizationEvent::Created)),
            ActivityCategory::Provisioning
        );
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(TenantEvent::Provisioned)),
            ActivityCategory::Provisioning
        );
    }

    /// A new OAuth client, a federation connection and a rotated key have
    /// no group of their own. Each one counts as other.
    #[test]
    fn from_event_type_buckets_long_tail_contexts_as_other() {
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(OAuthEvent::ClientCreated)),
            ActivityCategory::Other
        );
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(FederationEvent::ConnectionCreated)),
            ActivityCategory::Other
        );
        assert_eq!(
            ActivityCategory::from_event_type(&EventType::from(CryptoEvent::KeyRotated)),
            ActivityCategory::Other
        );
    }

    /// Each category's stored name reads back as the same category. A row
    /// written today stays readable tomorrow.
    #[test]
    fn as_str_parse_roundtrip_every_variant() {
        for category in ActivityCategory::ALL {
            assert_eq!(ActivityCategory::parse(category.as_str()), Some(category));
        }
    }

    /// A stored name of "nonsense" or an empty string reads as no category.
    /// The reader can then report the row as corrupt.
    #[test]
    fn parse_returns_none_for_unknown_string() {
        assert_eq!(ActivityCategory::parse("nonsense"), None);
        assert_eq!(ActivityCategory::parse(""), None);
    }

    /// The display list is already sorted by the enum order. The calendar
    /// sorts categories that way, so both orders agree.
    #[test]
    fn all_is_in_canonical_order() {
        let mut sorted = ActivityCategory::ALL;
        sorted.sort_unstable();
        assert_eq!(sorted, ActivityCategory::ALL);
    }
}
