//! Session lifecycle events: revocation, suspension, resumption and token
//! rotation.

use time::OffsetDateTime;

use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, SessionId, UserId};

/// A session was revoked, by a logout, an admin or a detected token theft.
///
/// Handlers of this event should drop any cached session state and refuse
/// further requests with this session's tokens.
#[derive(Debug)]
pub struct SessionRevoked {
    /// The session that was revoked.
    pub(crate) session_id: SessionId,
    /// The user whose session was revoked.
    pub(crate) user_id: UserId,
    /// That user's readable label, taken when the event is written. It is set
    /// when someone else is the actor, because an admin or the platform may
    /// revoke a user's session.
    ///
    /// `None` when the user logs themselves out. The user is then the actor,
    /// and the audit record already names them. Naming them again in the
    /// payload would break the actor rule and cost a label lookup on the
    /// request path.
    pub(crate) user_label: Option<EventLabel>,
    /// Why the session was revoked.
    pub(crate) reason: RevocationReason,
    /// When the revocation occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

/// Why a session was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    /// The user logged out.
    Logout,
    /// The user chose "log out everywhere."
    LogoutAll,
    /// An admin revoked the session.
    AdminAction,
    /// Reuse of a rotated refresh token was detected.
    TokenTheft,
    /// The user's account was locked or deactivated.
    AccountStateChange,
    /// The tenant was suspended.
    TenantSuspended,
    /// Its use stopped looking like the person who signed in, and they
    /// hold no factor that could lift a freeze.
    SuspectedTakeover,
}

impl RevocationReason {
    /// The name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Logout => "logout",
            Self::LogoutAll => "logout_all",
            Self::AdminAction => "admin_action",
            Self::TokenTheft => "token_theft",
            Self::AccountStateChange => "account_state_change",
            Self::TenantSuspended => "tenant_suspended",
            Self::SuspectedTakeover => "suspected_takeover",
        }
    }
}

tenant_event! {
    SessionRevoked => crate::types::event_type::AuthenticationEvent::SessionRevoked,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("session_id", self.session_id.to_string())
            .optional_reference(
                "user",
                self.user_label.as_ref().map(|label| {
                    Reference::new(RefKind::USER, self.user_id.to_string(), label.as_str())
                }),
            )
            .field("reason", self.reason.as_str())
    }
}

/// A session was paused.
///
/// A binding violation or a rise in risk causes it. Requests on the session
/// are refused until the user proves a second factor again.
#[derive(Debug)]
pub struct SessionSuspended {
    /// The suspended session.
    pub(crate) session_id: SessionId,
    /// The user whose session was suspended.
    pub(crate) user_id: UserId,
    /// That user's readable label, taken when the event is written. The
    /// platform suspends the session, so the user is not the actor.
    pub(crate) user_label: EventLabel,
    /// Why the session was suspended.
    pub(crate) reason: SuspensionReason,
    /// When the suspension occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SessionSuspended => crate::types::event_type::AuthenticationEvent::SessionSuspended,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("session_id", self.session_id.to_string())
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("reason", self.reason.as_str())
    }
}

/// Why a session was paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspensionReason {
    /// A request did not match what the session is bound to.
    BindingViolation,
    /// The session's risk rose past the level it may go on at.
    RiskEscalation,
    /// Two uses of it were further apart than anyone could travel in the
    /// time between them, across a border.
    FastTravel,
}

impl SuspensionReason {
    /// The name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BindingViolation => "binding violation",
            Self::RiskEscalation => "risk escalation",
            Self::FastTravel => "fast travel",
        }
    }
}

/// A suspended session was resumed after the user proved a second factor
/// again.
#[derive(Debug)]
pub struct SessionResumed {
    /// The resumed session.
    pub(crate) session_id: SessionId,
    /// When the session was resumed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SessionResumed => crate::types::event_type::AuthenticationEvent::SessionResumed,
    fn payload(&self) -> EventData {
        EventData::new().field("session_id", self.session_id.to_string())
    }
}

/// A refresh token was used to obtain a new access token.
///
/// The old session is rotated out and a new session takes its place. If the
/// old session's token is used again after this, someone stole it, and the
/// whole chain should be revoked.
#[derive(Debug)]
pub struct TokenRefreshed {
    /// The old session that was rotated out.
    pub(crate) session_id: SessionId,
    /// The new session that replaced it.
    pub(crate) new_session_id: SessionId,
    /// When the refresh occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TokenRefreshed => crate::types::event_type::AuthenticationEvent::TokenRefreshed,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("session_id", self.session_id.to_string())
            .field("new_session_id", self.new_session_id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    /// Alice's session is revoked after a reused refresh token. The payload
    /// gives the reason as `token_theft`.
    #[test]
    fn session_revoked_payload_captures_reason() {
        let event = SessionRevoked {
            session_id: SessionId::new(),
            user_id: UserId::new(),
            user_label: Some(EventLabel::of("alice@corp.com")),
            reason: RevocationReason::TokenTheft,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("reason"), Some("token_theft"));
    }

    /// An admin revokes Alice's session. The payload links to Alice by id and
    /// label, because the admin, not Alice, is the actor.
    #[test]
    fn session_revoked_references_the_subject_user() {
        let user_id = UserId::new();
        let event = SessionRevoked {
            session_id: SessionId::new(),
            user_id,
            user_label: Some(EventLabel::of("alice@corp.com")),
            reason: RevocationReason::AdminAction,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected a user reference");
        };
        assert_eq!(user.kind(), RefKind::USER);
        assert_eq!(user.id(), user_id.to_string());
        assert_eq!(user.label(), "alice@corp.com");
    }

    /// Ann refreshes her token. The payload does not name Ann, because she is
    /// the actor on the envelope.
    #[test]
    fn token_refreshed_omits_the_actor() {
        let event = TokenRefreshed {
            session_id: SessionId::new(),
            new_session_id: SessionId::new(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert!(payload.value("user").is_none());
        assert!(payload.value("user_id").is_none());
    }

    /// A refresh rotates session A into session B. The payload carries both
    /// ids, so a later reuse of A can be traced to B.
    #[test]
    fn token_refreshed_captures_both_session_ids() {
        let old = SessionId::new();
        let new = SessionId::new();

        let event = TokenRefreshed {
            session_id: old,
            new_session_id: new,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("session_id").unwrap(), old.to_string());
        assert_eq!(payload.get("new_session_id").unwrap(), new.to_string());
    }
}
