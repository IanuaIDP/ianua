//! Credential events: password changes and breaches, passkey registration,
//! renaming and removal, and an admin clearing an account's factors.

use time::OffsetDateTime;

use crate::domains::authentication::credentials::passkey::AuthenticatorType;
use crate::domains::authentication::events::changed_account;
use crate::domains::authentication::keeper::ChangedBy;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{EventLabel, PasskeyCredentialId, UserId};

/// A user changed their password.
///
/// The event records only that the password changed. It carries neither the
/// old nor the new hash. The audit log names who made the change through
/// [`ActorRef`](crate::types::ActorRef).
#[derive(Debug)]
pub struct PasswordChanged {
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasswordChanged => crate::types::event_type::AuthenticationEvent::PasswordChanged,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A passkey was registered for a user.
///
/// A passkey is a `WebAuthn` credential, such as Touch ID, a `YubiKey` or
/// Windows Hello. The user can sign in with it from now on.
#[derive(Debug)]
pub struct PasskeyRegistered {
    /// The `WebAuthn` credential ID of the new passkey.
    pub(crate) credential_id: PasskeyCredentialId,
    /// Where the browser said the passkey lives.
    pub(crate) authenticator: AuthenticatorType,
    /// When the registration occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasskeyRegistered => crate::types::event_type::AuthenticationEvent::PasskeyRegistered,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("credential_id", self.credential_id.to_string())
            .field("authenticator", self.authenticator.as_str())
    }
}

/// A passkey was removed from a user's account.
///
/// The passkey does not sign the user in any more. If it was their only
/// passkey and MFA is required, they must enroll a new one.
#[derive(Debug)]
pub struct PasskeyRemoved {
    /// The `WebAuthn` credential ID of the removed passkey.
    pub(crate) credential_id: PasskeyCredentialId,
    /// Where the browser said the passkey lived.
    pub(crate) authenticator: AuthenticatorType,
    /// Whose doing the removal was. The record names the account only when
    /// someone other than its holder removed the passkey.
    pub(crate) by: ChangedBy<UserId>,
    /// When the removal occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasskeyRemoved => crate::types::event_type::AuthenticationEvent::PasskeyRemoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("credential_id", self.credential_id.to_string())
            .field("authenticator", self.authenticator.as_str())
            .optional_reference("user", changed_account(self.by))
    }
}

/// A user authenticated with a password found in a known data breach.
///
/// The password was correct, so the login goes on as the policy allows. The
/// password is compromised, though, and the user should be asked to change
/// it.
#[derive(Debug)]
pub struct PasswordBreachDetected {
    /// The user whose password is breached.
    pub(crate) user_id: UserId,
    /// That user's readable label, taken when the event is written. The
    /// platform detects the breach, so the user is not the actor.
    pub(crate) user_label: EventLabel,
    /// How many times the password appears in breach corpora.
    pub(crate) occurrence_count: u64,
    /// When the breach was detected.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasswordBreachDetected => crate::types::event_type::AuthenticationEvent::PasswordBreachDetected,
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
            .field("occurrence_count", self.occurrence_count.to_string())
    }
}

/// An admin cleared every second factor of a user's account: the
/// enrollment in force and every passkey.
///
/// The user lost their device and codes. Their next sign-in sets up a new
/// factor if the tenant asks for one. Colleagues hear of it, since whoever
/// clears a factor could sign in in its place.
#[derive(Debug)]
pub struct FactorsReset {
    /// The user whose factors were cleared.
    pub(crate) user_id: UserId,
    /// That user's readable label, taken when the event is written. The
    /// admin is the actor.
    pub(crate) user_label: EventLabel,
    /// How many enrollments in force were turned off: none or one.
    pub(crate) enrollments_turned_off: usize,
    /// How many passkeys were removed.
    pub(crate) passkeys_removed: usize,
    /// When the factors were cleared.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    FactorsReset => crate::types::event_type::AuthenticationEvent::FactorsReset,
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
            .field("enrollments_turned_off", self.enrollments_turned_off.to_string())
            .field("passkeys_removed", self.passkeys_removed.to_string())
    }
}

/// A user began registering a passkey.
#[derive(Debug)]
pub struct PasskeyRegistrationStarted {
    /// The user registering.
    pub(crate) user_id: UserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasskeyRegistrationStarted => crate::types::event_type::AuthenticationEvent::PasskeyRegistrationStarted,
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

/// A user renamed one of their passkeys.
#[derive(Debug)]
pub struct PasskeyRenamed {
    /// The passkey's owner.
    pub(crate) user_id: UserId,
    /// The WebAuthn credential id.
    pub(crate) credential_id: PasskeyCredentialId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    PasskeyRenamed => crate::types::event_type::AuthenticationEvent::PasskeyRenamed,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.user_id.to_string(),
                ),
            )
            .field("credential_id", self.credential_id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    /// Ann changes her password. The payload is empty, because the envelope
    /// already names Ann as the actor and no hash belongs in the event.
    #[test]
    fn password_changed_payload_does_not_duplicate_the_actor() {
        let event = PasswordChanged {
            occurred_at: crate::shared::clock::now(),
        };

        assert!(event.payload().is_empty());
    }

    /// The platform finds Alice's password in 42 breaches. The payload links
    /// to Alice by id and label and carries the count, because she is not the
    /// actor.
    #[test]
    fn breach_detection_references_the_affected_user() {
        let user_id = UserId::new();
        let event = PasswordBreachDetected {
            user_id,
            user_label: EventLabel::of("alice@corp.com"),
            occurrence_count: 42,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected a user reference");
        };
        assert_eq!(user.kind(), RefKind::USER);
        assert_eq!(user.id(), user_id.to_string());
        assert_eq!(user.label(), "alice@corp.com");
        assert_eq!(payload.get("occurrence_count"), Some("42"));
    }

    /// Ann registers a passkey. The payload holds its credential id in hex,
    /// `0001020304`, and where it lives, and does not name Ann again.
    #[test]
    fn passkey_registration_records_only_the_credential() {
        let event = PasskeyRegistered {
            credential_id: PasskeyCredentialId::new(vec![0, 1, 2, 3, 4]).unwrap(),
            authenticator: AuthenticatorType::Platform,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        assert_eq!(payload.get("credential_id"), Some("0001020304"));
        assert_eq!(payload.get("authenticator"), Some("platform"));
        assert!(payload.value("user").is_none());
        assert!(payload.value("user_id").is_none());
    }

    /// An admin removes Ann's security key. The payload names Ann, since
    /// the record's actor is the admin: without it, a receiver would end
    /// the admin's sessions and leave Ann's open.
    #[test]
    fn a_passkey_removed_by_an_admin_names_the_account() {
        let ann = UserId::new();
        let event = PasskeyRemoved {
            credential_id: PasskeyCredentialId::new(vec![9]).unwrap(),
            authenticator: AuthenticatorType::CrossPlatform,
            by: ChangedBy::SomeoneElse(ann),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("user") else {
            panic!("expected the account to be named");
        };
        assert_eq!(user.id(), ann.to_string());
    }

    /// Ann removes her own passkey. The payload does not name her again:
    /// the record's actor does.
    #[test]
    fn a_passkey_removed_by_its_holder_names_no_account() {
        let event = PasskeyRemoved {
            credential_id: PasskeyCredentialId::new(vec![9]).unwrap(),
            authenticator: AuthenticatorType::Platform,
            by: ChangedBy::Holder,
            occurred_at: crate::shared::clock::now(),
        };

        assert!(event.payload().value("user").is_none());
    }
}
