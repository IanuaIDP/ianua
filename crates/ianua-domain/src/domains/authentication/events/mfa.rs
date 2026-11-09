//! MFA events: enrollment, unenrollment, verification and failed attempts.

use time::OffsetDateTime;

use crate::domains::authentication::events::changed_account;
use crate::domains::authentication::keeper::ChangedBy;
use crate::domains::authentication::mfa::enrollment::MfaMethod;
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::shared::model::two_cases::two_cases;
use crate::types::{SessionId, UserId};

/// A user completed MFA enrollment.
///
/// The user entered a correct code from their authenticator app, or one
/// sent to the address or number the factor uses. MFA is active on their
/// account.
#[derive(Debug)]
pub struct MfaEnrolled {
    /// When the enrollment completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MfaEnrolled => crate::types::event_type::AuthenticationEvent::MfaEnrolled,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A user proved a second factor on a session, at sign-in or later for a
/// sensitive action.
///
/// The session counts as having passed MFA. The user can reach resources
/// that require it.
#[derive(Debug)]
pub struct MfaVerified {
    /// The session that was upgraded.
    pub(crate) session_id: SessionId,
    /// The assurance level the session stands at once the factor counted,
    /// so a relying party hears how far it may now trust the session.
    pub(crate) assurance: AssuranceLevel,
    /// When the verification completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MfaVerified => crate::types::event_type::AuthenticationEvent::MfaVerified,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("session_id", self.session_id.to_string())
            .field("assurance", self.assurance.acr())
    }
}

/// MFA was removed from a user's account.
///
/// The user or an admin turned MFA off. When the tenant's policy requires
/// MFA, the user is asked to enroll again at the next login.
#[derive(Debug)]
pub struct MfaUnenrolled {
    /// Whose doing it was. The record names the account only when someone
    /// other than its holder, an admin resetting it, turned the factor off.
    pub(crate) by: ChangedBy<UserId>,
    /// When the unenrollment occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MfaUnenrolled => crate::types::event_type::AuthenticationEvent::MfaUnenrolled,
    fn payload(&self) -> EventData {
        EventData::new().optional_reference("user", changed_account(self.by))
    }
}

/// A user began enrolling a second factor.
#[derive(Debug)]
pub struct MfaEnrollmentStarted {
    /// The user enrolling.
    pub(crate) user_id: UserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MfaEnrollmentStarted => crate::types::event_type::AuthenticationEvent::MfaEnrollmentStarted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "user",
            Reference::new(
                RefKind::USER,
                self.user_id.to_string(),
                self.user_id.to_string(),
            ),
        )
    }
}

/// Which second factor a failed attempt was made with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailedFactor {
    /// A code from an authenticator app.
    Totp,
    /// A code mailed to the account's address.
    EmailCode,
    /// A code texted to the factor's number.
    SmsCode,
    /// A saved backup proof presented instead of the enrolled factor.
    RecoveryCode,
}

impl FailedFactor {
    /// The stable name the record carries.
    fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::EmailCode => "email_code",
            Self::SmsCode => "sms_code",
            Self::RecoveryCode => "recovery_code",
        }
    }
}

impl From<MfaMethod> for FailedFactor {
    fn from(method: MfaMethod) -> Self {
        match method {
            MfaMethod::Totp => Self::Totp,
            MfaMethod::EmailCode => Self::EmailCode,
            MfaMethod::SmsCode => Self::SmsCode,
        }
    }
}

two_cases! {
    /// Whether a wrong answer to a second factor locked it.
    pub enum FactorLock {
        /// This failure locked the factor.
        Locked => true,
        /// The factor still takes answers.
        StillOpen => false,
    }
}

/// A wrong second-factor code was given.
///
/// Repeated failures across separate requests are the sign of someone
/// guessing codes. So each one is recorded, with whether it locked the
/// factor.
#[derive(Debug)]
pub struct MfaFailed {
    /// What was tried.
    pub(crate) factor: FailedFactor,
    /// Whether this failure locked the factor.
    pub(crate) locked: FactorLock,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MfaFailed => crate::types::event_type::AuthenticationEvent::MfaFailed,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("factor", self.factor.as_str())
            .field("locked", bool::from(self.locked).to_string())
    }
}

/// A one-time code was sent for a second factor: mailed to the account's
/// address or texted to the factor's number.
///
/// Each send is recorded, since a run of them is the sign of someone
/// guessing, or of texts being sent at the tenant's cost.
#[derive(Debug)]
pub struct MfaCodeSent {
    /// The kind of factor the code was sent for.
    pub(crate) method: MfaMethod,
    /// When the code lapses.
    pub(crate) expires_at: OffsetDateTime,
    /// When it was sent.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MfaCodeSent => crate::types::event_type::AuthenticationEvent::MfaCodeSent,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("factor", self.method.as_str())
            .field("expires_at", self.expires_at.to_string())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    /// Ann finishes enrolling TOTP. The payload is empty, because the
    /// envelope already names Ann as the actor.
    #[test]
    fn mfa_enrolled_payload_omits_the_enrolling_user() {
        let event = MfaEnrolled {
            occurred_at: crate::shared::clock::now(),
        };

        assert!(
            event.payload().is_empty(),
            "the enrolling user is the record's actor, not payload data"
        );
    }

    /// Ann proves her second factor on a session. The payload names that
    /// session and the level it stands at now, and does not repeat her user
    /// id.
    #[test]
    fn mfa_verified_payload_names_the_session_and_its_level() {
        let session_id = SessionId::new();
        let event = MfaVerified {
            session_id,
            assurance: AssuranceLevel::Aal2,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert!(payload.get("user_id").is_none());
        assert_eq!(payload.get("session_id").unwrap(), session_id.to_string());
        assert_eq!(payload.get("assurance"), Some("aal2"));
    }

    /// Ann turns MFA off. The payload is empty, because the envelope already
    /// says who and where.
    #[test]
    fn mfa_unenrolled_payload_omits_the_user() {
        let event = MfaUnenrolled {
            by: ChangedBy::Holder,
            occurred_at: crate::shared::clock::now(),
        };

        assert!(event.payload().is_empty());
    }

    /// An admin resets Ann's factor. The payload names Ann, since the
    /// record's actor is the admin, not the account that lost the factor.
    #[test]
    fn mfa_turned_off_by_an_admin_names_the_account() {
        let ann = UserId::new();
        let event = MfaUnenrolled {
            by: ChangedBy::SomeoneElse(ann),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected the account to be named");
        };
        assert_eq!(user.id(), ann.to_string());
    }
}
