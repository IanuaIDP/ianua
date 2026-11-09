//! Login events: successful and failed sign-in attempts.

use time::OffsetDateTime;

use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::risk_engine::origin::AttemptOrigin;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{CountryCode, EventLabel, Fact, IpAddress, SessionId, UntrustedText, UserId};

/// A user successfully authenticated and a session was created.
///
/// It follows the password check, any MFA that was required, and the new
/// session. The audit log and security monitoring read it.
#[derive(Debug)]
pub struct LoginSucceeded {
    /// The newly created session.
    pub(crate) session_id: SessionId,
    /// How the user authenticated, such as password, SAML or OIDC.
    pub(crate) auth_method: AuthMethod,
    /// The client's IP address, if available.
    pub(crate) ip_address: Fact<IpAddress>,
    /// How long the authentication took in milliseconds, when the
    /// application measured it. Domain operations that build this event
    /// leave it unknown. The value feeds the "average authentication time"
    /// metric.
    pub(crate) auth_duration_ms: Fact<u32>,
    /// When the authentication completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    LoginSucceeded => crate::types::event_type::AuthenticationEvent::LoginSucceeded,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("session_id", self.session_id.to_string())
            .field("auth_method", self.auth_method.as_str())
            .optional(
                "ip_address",
                self.ip_address.known().map(ToString::to_string),
            )
            .optional(
                "auth_duration_ms",
                self.auth_duration_ms.known().map(ToString::to_string),
            )
    }
}

/// A login attempt failed.
///
/// Records the email and the reason. It records the email, not a user ID,
/// because the user may not exist. Rate limiting, lockout decisions and
/// security monitoring read it.
#[derive(Debug)]
pub struct LoginFailed {
    /// The email the caller submitted, as [`UntrustedText`]. It is not held
    /// to `Email::new()`, because a failed login must record what was typed.
    /// That includes typos, injection payloads and malformed addresses. It is
    /// still made safe to store and show.
    pub(crate) email: UntrustedText,
    /// Why the login was rejected.
    pub(crate) reason: LoginFailureReason,
    /// The client's IP address, if available.
    pub(crate) ip_address: Fact<IpAddress>,
    /// When the failed attempt occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

/// Why a login attempt was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFailureReason {
    /// The email does not belong to any user in this tenant.
    UserNotFound,
    /// The password did not match the stored hash.
    BadPassword,
    /// Sign-in is blocked by account standing or an active attempt lockout.
    AccountLocked,
    /// The account has been deactivated.
    AccountDeactivated,
    /// The account is closed while its erasure waits.
    AccountClosing,
    /// The user's email address has not been verified.
    EmailNotVerified,
    /// The account never finished joining.
    AccountNotActive,
    /// MFA challenge was required but not completed.
    MfaRequired,
    /// MFA verification code was incorrect.
    MfaFailed,
    /// The authentication method used is not enabled for this tenant.
    MethodDisabled,
    /// The request came from an IP not in the tenant's allowlist.
    IpBlocked,
    /// The sign-in looked too risky to allow, by the tenant's rules.
    RiskTooHigh,
}

impl LoginFailureReason {
    /// The name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserNotFound => "user_not_found",
            Self::BadPassword => "bad_password",
            Self::AccountLocked => "account_locked",
            Self::AccountDeactivated => "account_deactivated",
            Self::AccountClosing => "account_closing",
            Self::EmailNotVerified => "email_not_verified",
            Self::AccountNotActive => "account_not_active",
            Self::MfaRequired => "mfa_required",
            Self::MfaFailed => "mfa_failed",
            Self::MethodDisabled => "method_disabled",
            Self::IpBlocked => "ip_blocked",
            Self::RiskTooHigh => "risk_too_high",
        }
    }
}

tenant_event! {
    LoginFailed => crate::types::event_type::AuthenticationEvent::LoginFailed,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("email", self.email.to_string())
            .field("reason", self.reason.as_str())
            .optional(
                "ip_address",
                self.ip_address.known().map(ToString::to_string),
            )
    }
}

/// The network failed sign-ins came from was locked out of an account after
/// exceeding the failed login threshold.
///
/// Sign-ins from that network cannot reach the account until the lockout
/// ends; the person, from anywhere else, still signs in. Security
/// monitoring should flag repeated lockouts of the same account as a
/// possible brute-force attack.
#[derive(Debug)]
pub struct AccountLockedOut {
    /// The account the attempts named, or a record of attempts against an
    /// address with no account. That address locks out too, so guessing
    /// cannot go on there either.
    pub(crate) user_id: LockedAddress,
    /// How the account is named in the audit entry. It is the address the
    /// attempts used, kept here so the entry stays readable after the
    /// account is renamed or deleted.
    pub(crate) user_label: EventLabel,
    /// Number of failed attempts that triggered the lockout.
    pub(crate) failed_attempts: u32,
    /// When the lockout expires.
    pub(crate) locked_until: OffsetDateTime,
    /// The network locked out of the account.
    pub(crate) origin: AttemptOrigin,
    /// The client's IP address, if available.
    pub(crate) ip_address: Fact<IpAddress>,
    /// When the lockout was triggered.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountLockedOut => crate::types::event_type::AuthenticationEvent::AccountLockedOut,
    fn payload(&self) -> EventData {
        let (user, unknown_address) = match self.user_id {
            LockedAddress::Account(id) => (
                Some(Reference::new(RefKind::USER, id.to_string(), self.user_label.as_str())),
                None,
            ),
            LockedAddress::NoAccount => (None, Some(self.user_label.as_str())),
        };
        EventData::new()
            .optional_reference("user", user)
            .optional("email", unknown_address)
            .field("failed_attempts", self.failed_attempts.to_string())
            .field("locked_until", self.locked_until.to_string())
            .field("origin", self.origin.to_string())
            .optional(
                "ip_address",
                self.ip_address.known().map(ToString::to_string),
            )
    }
}

/// Failed sign-ins against one account came from so many networks within
/// the lockout's window that the account counts as under attack.
///
/// Until the attack is over, a right password from a device the person did
/// not trust also needs their second factor or a link mailed to them, and a
/// directory bind from a network that failed is refused. It is recorded
/// once each time the account comes under attack, and told to the people
/// who run the tenant as a security alert. It names how many networks
/// failed, never which, and never a password.
#[derive(Debug)]
pub struct AccountUnderAttack {
    /// The account the attempts named, or a record of attempts against an
    /// address with no account.
    pub(crate) user_id: LockedAddress,
    /// How the account is named in the audit entry: the address the
    /// attempts used.
    pub(crate) user_label: EventLabel,
    /// How many networks had failed on the account when the attack was
    /// found.
    pub(crate) networks: u64,
    /// Until when the account counts as under attack.
    pub(crate) until: OffsetDateTime,
    /// When the attack was found.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AccountUnderAttack => crate::types::event_type::AuthenticationEvent::AccountUnderAttack,
    fn payload(&self) -> EventData {
        let (user, unknown_address) = match self.user_id {
            LockedAddress::Account(id) => (
                Some(Reference::new(RefKind::USER, id.to_string(), self.user_label.as_str())),
                None,
            ),
            LockedAddress::NoAccount => (None, Some(self.user_label.as_str())),
        };
        EventData::new()
            .optional_reference("user", user)
            .optional("email", unknown_address)
            .field("networks", self.networks.to_string())
            .field("under_attack_until", self.until.to_string())
    }
}

/// Whose account a lockout locked. Either one that exists, or an address
/// with none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockedAddress {
    /// The attempts named an address no account has.
    NoAccount,
    /// An existing user's identity, retained without recording their address.
    Account(UserId),
}

/// A browser was sent to an identity provider to sign in.
#[derive(Debug)]
pub struct SingleSignOnStarted {
    /// The connection it was sent through.
    pub(crate) connection: EventLabel,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SingleSignOnStarted => crate::types::event_type::AuthenticationEvent::SingleSignOnStarted,
    fn payload(&self) -> EventData {
        EventData::new().field("connection", self.connection.to_string())
    }
}

/// The one-time code from a finished single sign-on was exchanged for a session token.
#[derive(Debug)]
pub struct SignInCodeExchanged {
    /// The user who signed in.
    pub(crate) user_id: UserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignInCodeExchanged => crate::types::event_type::AuthenticationEvent::SignInCodeExchanged,
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

/// A passkey sign-in was started for a user who has passkeys.
#[derive(Debug)]
pub struct PasskeySignInStarted {
    /// The user the sign-in is for.
    pub(crate) user_id: UserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasskeySignInStarted => crate::types::event_type::AuthenticationEvent::PasskeySignInStarted,
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

/// A discoverable passkey challenge was issued. Nobody is known until it is
/// answered.
#[derive(Debug)]
pub struct PasskeyChallengeIssued {
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasskeyChallengeIssued => crate::types::event_type::AuthenticationEvent::PasskeyChallengeIssued,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A sign-in link was emailed to a user.
#[derive(Debug)]
pub struct MagicLinkRequested {
    /// The user it was sent to.
    pub(crate) user_id: UserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MagicLinkRequested => crate::types::event_type::AuthenticationEvent::MagicLinkRequested,
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

/// A check that runs on a sign-in whose password was proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignInCheck {
    /// Whether the password appears in known breaches.
    Breach,
    /// Where the request came from.
    Location,
}

impl SignInCheck {
    /// The name the audit record uses for the check.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Breach => "breach",
            Self::Location => "location",
        }
    }
}

/// A sign-in went ahead without one of its checks, because the service that
/// answers it could not be reached.
///
/// The sign-in is not refused for this, because an outage at an outside
/// service should not lock everyone out. The record shows the sign-in was
/// judged on less than usual.
#[derive(Debug)]
pub struct SignInCheckUnavailable {
    /// The user signing in.
    pub(crate) user_id: UserId,
    /// That user's address, captured at write time.
    pub(crate) user_label: EventLabel,
    /// The check that could not run.
    pub(crate) check: SignInCheck,
    /// When the sign-in happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignInCheckUnavailable => crate::types::event_type::AuthenticationEvent::SignInCheckUnavailable,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .field("check", self.check.as_str())
    }
}

/// What made a sign-in look risky.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskSign {
    /// A country the person never signed in from before.
    NewCountry,
    /// A journey from their last sign-in faster than a traveller makes
    /// lightly, though not impossible.
    FastTravel,
    /// Both: a fast journey into a country they never signed in from.
    FastTravelToNewCountry,
}

impl RiskSign {
    /// The sign as the event names it, such as `new_country`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewCountry => "new_country",
            Self::FastTravel => "fast_travel",
            Self::FastTravelToNewCountry => "fast_travel_to_new_country",
        }
    }
}

/// A sign-in went ahead though it looked risky: a new country, or travel
/// faster than a journey is lightly made.
///
/// Pat signs in from a country he never signed in from. The sign-in goes
/// on, perhaps after a second factor, and a workflow can start from this:
/// ask him whether it was him, or sign him out. Colleagues are not told:
/// it records his own sign-in.
#[derive(Debug)]
pub struct RiskySignIn {
    /// The person who signed in.
    pub(crate) user_id: UserId,
    /// Their readable label, taken when the event is written.
    pub(crate) user_label: EventLabel,
    /// The country it came from, when it could be placed.
    pub(crate) country: Fact<CountryCode>,
    /// What made it look risky.
    pub(crate) sign: RiskSign,
    /// When the sign-in happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RiskySignIn => crate::types::event_type::AuthenticationEvent::RiskySignIn,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_label.as_str(),
                ),
            )
            .optional("country", self.country.known().map(ToString::to_string))
            .field("sign", self.sign.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    /// Alice signs in while the breach service is down. The event is filed
    /// as `sign_in_check_unavailable` and names the skipped check, "breach".
    #[test]
    fn an_unavailable_check_names_the_check_and_the_user() {
        let user_id = UserId::new();
        let event = SignInCheckUnavailable {
            user_id,
            user_label: EventLabel::of("alice@acme.com"),
            check: SignInCheck::Breach,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("check"), Some("breach"));
        assert_eq!(
            event.event_type().as_str(),
            "authentication.sign_in_check_unavailable"
        );
    }

    /// Ann signs in through SAML from `10.0.0.1` in 42 ms. The payload holds
    /// the session, address and duration, but not Ann's id, which the
    /// envelope already carries.
    #[test]
    fn login_succeeded_payload_omits_the_authenticating_user() {
        let session_id = SessionId::new();

        let event = LoginSucceeded {
            session_id,
            auth_method: AuthMethod::Saml,
            ip_address: Fact::Known(IpAddress::new("10.0.0.1").unwrap()),
            auth_duration_ms: Fact::Known(42),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert!(
            payload.get("user_id").is_none(),
            "the authenticating user is the record's actor, not payload data"
        );
        assert_eq!(payload.get("session_id").unwrap(), session_id.to_string());
        assert_eq!(payload.get("ip_address"), Some("10.0.0.1"));
        assert_eq!(payload.get("auth_duration_ms"), Some("42"));
    }

    /// A sign-in as alice@example.com fails because the account is locked.
    /// The payload carries the typed address and the reason
    /// `account_locked`.
    #[test]
    fn login_failed_payload_captures_reason() {
        let event = LoginFailed {
            email: crate::types::UntrustedText::record("alice@example.com"),
            reason: LoginFailureReason::AccountLocked,
            ip_address: Fact::Known(IpAddress::new("192.168.1.1").unwrap()),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("email"), Some("alice@example.com"));
        assert_eq!(payload.get("reason"), Some("account_locked"));
    }

    /// Someone tries unknown@example.com, which has no account. The payload
    /// records the typed address and no user id, since there is no user.
    #[test]
    fn login_failed_uses_email_not_user_id() {
        let event = LoginFailed {
            email: crate::types::UntrustedText::record("unknown@example.com"),
            reason: LoginFailureReason::UserNotFound,
            ip_address: Fact::Unknown,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("email"), Some("unknown@example.com"));
        assert!(payload.get("user_id").is_none());
    }

    /// Alice's account locks after 5 wrong passwords. The payload links to
    /// Alice as a user and records the 5 attempts.
    #[test]
    fn account_locked_out_references_the_locked_user() {
        let user_id = UserId::new();
        let event = AccountLockedOut {
            user_id: LockedAddress::Account(user_id),
            user_label: EventLabel::of("alice@example.com"),
            failed_attempts: 5,
            locked_until: crate::shared::clock::now(),
            origin: AttemptOrigin::of(Fact::Known(&IpAddress::new("203.0.113.7").unwrap())),
            ip_address: Fact::Unknown,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected a user reference");
        };
        assert_eq!(user.kind(), RefKind::USER);
        assert_eq!(user.id(), user_id.to_string());
        assert_eq!(user.label(), "alice@example.com");
        assert_eq!(payload.get("failed_attempts"), Some("5"));
        assert_eq!(payload.get("origin"), Some("203.0.113.7"));
    }

    /// Someone guesses passwords for nobody@example.com, which has no
    /// account, and that address locks. The payload names the address and
    /// links to no user, so the audit trail points at nobody made up.
    #[test]
    fn a_lockout_of_an_unknown_address_names_the_address_and_no_user() {
        let event = AccountLockedOut {
            user_id: LockedAddress::NoAccount,
            user_label: EventLabel::of("nobody@example.com"),
            failed_attempts: 5,
            locked_until: crate::shared::clock::now(),
            origin: AttemptOrigin::of(Fact::Unknown),
            ip_address: Fact::Unknown,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert!(payload.value("user").is_none());
        assert_eq!(payload.get("email"), Some("nobody@example.com"));
    }

    /// Pat signs in from Brazil for the first time. The event names the
    /// country and why the sign-in looked risky, so a workflow can tell a
    /// new country from a fast journey.
    #[test]
    fn a_risky_sign_in_names_its_country_and_its_sign() {
        let event = RiskySignIn {
            user_id: UserId::new(),
            user_label: EventLabel::of("pat@acme.com"),
            country: Fact::Known(CountryCode::new("BR").unwrap()),
            sign: RiskSign::NewCountry,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("country"), Some("BR"));
        assert_eq!(payload.get("sign"), Some("new_country"));
    }
}
