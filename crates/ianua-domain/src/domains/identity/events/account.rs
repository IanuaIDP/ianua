//! Events about a person's account: registration, status, address and profile.

use time::OffsetDateTime;

use crate::domains::identity::account::user_status::UserStatus;
use crate::domains::identity::attribute::key::AttributeKey;
use crate::domains::identity::attribute::namespace::AttributeNamespace;
use crate::domains::identity::events::user_reference;
use crate::shared::events::data::EventData;
use crate::shared::events::event::{platform_event, tenant_event};
use crate::types::{
    DisplayName, Email, EventLabel, Locale, Preference, PrincipalId, Timezone, UserId,
};

/// A person registered themselves in a tenant.
///
/// The account starts in `PendingVerification` with an unverified email.
/// Confirming the address activates it, so a verification link is sent
/// next.
#[derive(Debug)]
pub struct UserRegistered {
    /// The email address the user registered with.
    pub(crate) email: Email,
    /// When the user registered.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserRegistered => crate::types::event_type::IdentityEvent::UserRegistered,
    fn payload(&self) -> EventData {
        EventData::new().field("email", self.email.as_str())
    }
}

/// A user's email address was verified.
///
/// A `PendingVerification` user became `Active` with it. Any other status
/// stayed as it was.
#[derive(Debug)]
pub(crate) struct UserEmailVerified {
    /// When it was verified.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserEmailVerified => crate::types::event_type::IdentityEvent::EmailVerified,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A user's account status changed.
///
/// It covers activating, locking, unlocking and deactivating. Handlers read
/// `to` to decide what to do, such as ending sessions on a lock.
#[derive(Debug)]
pub struct UserStatusChanged {
    /// The user whose status changed.
    pub(crate) user_id: UserId,
    /// The user's label at the time of the change.
    pub(crate) user_label: EventLabel,
    /// The status before.
    pub(crate) from: UserStatus,
    /// The status after.
    pub(crate) to: UserStatus,
    /// When the status changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserStatusChanged => crate::types::event_type::IdentityEvent::UserStatusChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("user", user_reference(&self.user_id, self.user_label.as_str()))
            .change("status", self.from.to_string(), self.to.to_string())
    }
}

/// A user's email address changed.
///
/// The old address is kept for the audit trail. Whether the new one still
/// needs verifying depends on how it arrived. See `new_email`.
#[derive(Debug)]
pub(crate) struct UserEmailChanged {
    /// The account whose address changed.
    ///
    /// It is named even when its holder made the change. An admin, a
    /// directory sync or a trusted provider changes it as often, and then
    /// the record's actor is not the account: a receiver reading the actor
    /// would tell the admin's apps that the admin's address moved.
    pub(crate) user_id: UserId,
    /// The account's label at the time of the change.
    pub(crate) user_label: EventLabel,
    /// The address before, for the audit trail.
    pub(crate) old_email: Email,
    /// The new address.
    ///
    /// It is unverified when set directly, as by an admin correction or a
    /// directory sync. It is already verified when it comes from a confirmed
    /// email change.
    pub(crate) new_email: Email,
    /// When the address changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserEmailChanged => crate::types::event_type::IdentityEvent::EmailChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("user", user_reference(&self.user_id, self.user_label.as_str()))
            .change("email", self.old_email.as_str(), self.new_email.as_str())
    }
}

/// An admin reset a user's password.
///
/// The use case ends all of the user's sessions, so they must sign in again
/// with the new password.
#[derive(Debug)]
pub(crate) struct UserPasswordReset {
    /// The user whose password was reset.
    pub(crate) user_id: UserId,
    /// The user's label at the time of the reset.
    pub(crate) user_label: EventLabel,
    /// When the password was reset.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserPasswordReset => crate::types::event_type::IdentityEvent::PasswordReset,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.user_label.as_str()))
    }
}

/// A user was deleted from the tenant for good.
///
/// The use case revokes the user's sessions and the delegations they gave
/// before deleting the account. A deletion cannot be undone.
#[derive(Debug)]
pub struct UserDeleted {
    /// The deleted user.
    pub(crate) user_id: UserId,
    /// The user's email when deleted, which labels them in the audit log.
    pub(crate) email: Email,
    /// When the user was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserDeleted => crate::types::event_type::IdentityEvent::UserDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.email.as_str()))
    }
}

/// A user's display name changed.
#[derive(Debug)]
pub struct UserRenamed {
    /// The name before.
    pub(crate) old_name: DisplayName,
    /// The name after.
    pub(crate) new_name: DisplayName,
    /// When the user was renamed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserRenamed => crate::types::event_type::IdentityEvent::UserRenamed,
    fn payload(&self) -> EventData {
        EventData::new().change("name", self.old_name.to_string(), self.new_name.to_string())
    }
}

/// A user changed their locale or timezone.
///
/// It carries both settings as they are after the change. Each is either
/// the person's own choice or follows the tenant's. Only own choices go in
/// the payload.
#[derive(Debug)]
pub struct UserPreferencesUpdated {
    /// The locale after the change.
    pub(crate) locale: Preference<Locale>,
    /// The timezone after the change.
    pub(crate) timezone: Preference<Timezone>,
    /// When the preferences changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserPreferencesUpdated => crate::types::event_type::IdentityEvent::UserPreferencesUpdated,
    fn payload(&self) -> EventData {
        EventData::new()
            .optional("locale", self.locale.value().map(Locale::as_str))
            .optional("timezone", self.timezone.value().map(Timezone::as_str))
    }
}

/// One of a user's custom attributes was set, in the user or app namespace.
#[derive(Debug)]
pub(crate) struct UserMetadataUpdated {
    /// The user whose attribute changed.
    pub(crate) user_id: UserId,
    /// The user's label at the time of the change.
    pub(crate) user_label: EventLabel,
    /// Which namespace the attribute is in.
    pub(crate) namespace: AttributeNamespace,
    /// The attribute's key.
    pub(crate) key: AttributeKey,
    /// When the attribute was set.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserMetadataUpdated => crate::types::event_type::IdentityEvent::MetadataUpdated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("user", user_reference(&self.user_id, self.user_label.as_str()))
            .field("namespace", self.namespace.as_str())
            .field("key", self.key.as_str())
    }
}

/// All of a user's custom attributes were deleted.
#[derive(Debug)]
pub(crate) struct UserMetadataDeleted {
    /// The user whose attributes were deleted.
    pub(crate) user_id: UserId,
    /// The user's label at the time of the deletion.
    pub(crate) user_label: EventLabel,
    /// When the attributes were deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserMetadataDeleted => crate::types::event_type::IdentityEvent::MetadataDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, self.user_label.as_str()))
    }
}

/// A user asked to move their account to a new address. A confirmation link
/// was sent there.
#[derive(Debug)]
pub struct EmailChangeRequested {
    /// Whose address is changing.
    pub(crate) principal: PrincipalId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    EmailChangeRequested => crate::types::event_type::IdentityEvent::EmailChangeRequested,
    fn payload(&self) -> EventData {
        EventData::new().field("principal", self.principal.to_string())
    }
}

/// An email change was cancelled from the link sent to the old address.
///
/// It notifies, since it usually means someone else asked for the change.
#[derive(Debug)]
pub struct EmailChangeCancelled {
    /// Whose address was to change.
    pub(crate) principal: PrincipalId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    EmailChangeCancelled => crate::types::event_type::IdentityEvent::EmailChangeCancelled,
    fn payload(&self) -> EventData {
        EventData::new().field("principal", self.principal.to_string())
    }
}

/// Another confirmation link was sent to the address a pending email change
/// waits on.
#[derive(Debug)]
pub struct EmailChangeLinkResent {
    /// Whose address is changing.
    pub(crate) principal: PrincipalId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    EmailChangeLinkResent => crate::types::event_type::IdentityEvent::EmailChangeLinkResent,
    fn payload(&self) -> EventData {
        EventData::new().field("principal", self.principal.to_string())
    }
}

/// An org user or operator asked to move their account to a new address. A
/// confirmation link was sent there.
#[derive(Debug)]
pub struct ManagementEmailChangeRequested {
    /// Whose address is changing.
    pub(crate) principal: PrincipalId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    ManagementEmailChangeRequested => crate::types::event_type::IdentityEvent::ManagementEmailChangeRequested,
    fn payload(&self) -> EventData {
        EventData::new().field("principal", self.principal.to_string())
    }
}

/// An org user's or operator's email change was cancelled from the link
/// sent to the old address.
#[derive(Debug)]
pub struct ManagementEmailChangeCancelled {
    /// Whose address was to change.
    pub(crate) principal: PrincipalId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    ManagementEmailChangeCancelled => crate::types::event_type::IdentityEvent::ManagementEmailChangeCancelled,
    fn payload(&self) -> EventData {
        EventData::new().field("principal", self.principal.to_string())
    }
}

/// Another confirmation link was sent for an org user's or operator's email
/// change.
#[derive(Debug)]
pub struct ManagementEmailChangeLinkResent {
    /// Whose address is changing.
    pub(crate) principal: PrincipalId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    ManagementEmailChangeLinkResent => crate::types::event_type::IdentityEvent::ManagementEmailChangeLinkResent,
    fn payload(&self) -> EventData {
        EventData::new().field("principal", self.principal.to_string())
    }
}

/// A link to confirm a user's address was emailed to them.
#[derive(Debug)]
pub struct VerificationEmailSent {
    /// The user it was sent to.
    pub(crate) user_id: UserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    VerificationEmailSent => crate::types::event_type::IdentityEvent::VerificationEmailSent,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, &self.user_id.to_string()))
    }
}

/// A user was emailed that their account exists and where to sign in.
#[derive(Debug)]
pub struct WelcomeEmailSent {
    /// The user it was sent to.
    pub(crate) user_id: UserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WelcomeEmailSent => crate::types::event_type::IdentityEvent::WelcomeEmailSent,
    fn payload(&self) -> EventData {
        EventData::new().reference("user", user_reference(&self.user_id, &self.user_id.to_string()))
    }
}

/// The link for an org user's or operator's email change was followed, so
/// the change can be made.
#[derive(Debug)]
pub struct ManagementEmailChangeConfirmed {
    /// Whose address is changing.
    pub(crate) principal: PrincipalId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    ManagementEmailChangeConfirmed => crate::types::event_type::IdentityEvent::ManagementEmailChangeConfirmed,
    fn payload(&self) -> EventData {
        EventData::new().field("principal", self.principal.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::{FieldValue, RefKind, Reference};
    use crate::shared::events::event::DomainEventCore;

    fn expect_reference(payload: &EventData, key: &str) -> Reference {
        let Some(FieldValue::Reference(reference)) = payload.value(key) else {
            panic!("expected a reference at {key}");
        };
        reference.clone()
    }

    fn expect_change(payload: &EventData, key: &str) -> (Option<String>, Option<String>) {
        let Some(FieldValue::Change(change)) = payload.value(key) else {
            panic!("expected a change at {key}");
        };
        (
            change.from().map(str::to_owned),
            change.to().map(str::to_owned),
        )
    }

    /// Alice registers. The event's type is "identity.user_registered".
    #[test]
    fn registered_event_has_correct_type() {
        let event = UserRegistered {
            email: Email::new("alice@example.com").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(event.event_type().as_str(), "identity.user_registered");
    }

    /// Alice registers. The payload holds only her email. She is the actor,
    /// and the audit record already names her.
    #[test]
    fn registered_event_records_the_email_without_repeating_the_actor() {
        let event = UserRegistered {
            email: Email::new("alice@example.com").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(payload.get("email"), Some("alice@example.com"));
        assert_eq!(payload.len(), 1, "the self-registering user is the actor");
    }

    /// An admin locks Alice. The event refers to Alice by id and label and
    /// records the change from active to locked.
    #[test]
    fn status_changed_event_records_the_transition_and_the_affected_user() {
        let target = UserId::new();
        let event = UserStatusChanged {
            user_id: target,
            user_label: EventLabel::of("Alice (alice@example.com)"),
            from: UserStatus::Active,
            to: UserStatus::Locked,
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(event.event_type().as_str(), "identity.user_status_changed");

        let payload = event.payload();
        let reference = expect_reference(&payload, "user");

        assert_eq!(reference.id(), target.to_string());
        assert_eq!(reference.label(), "Alice (alice@example.com)");
        assert_eq!(
            expect_change(&payload, "status"),
            (Some("active".to_owned()), Some("locked".to_owned()))
        );
    }

    /// A user moves from old@example.com to new@example.com. The payload
    /// names the account and holds one change with both addresses.
    #[test]
    fn email_changed_event_records_both_addresses_as_one_change() {
        let event = UserEmailChanged {
            user_id: UserId::new(),
            user_label: EventLabel::of("Ann (new@example.com)"),
            old_email: Email::new("old@example.com").unwrap(),
            new_email: Email::new("new@example.com").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(
            expect_change(&payload, "email"),
            (
                Some("old@example.com".to_owned()),
                Some("new@example.com".to_owned())
            )
        );
        assert_eq!(payload.len(), 2, "the account and the change");
    }

    /// Alice renames herself Alice Cooper. The payload holds that one name
    /// change and nothing else.
    #[test]
    fn renamed_event_records_the_display_name_change_only() {
        let limits = crate::shared::config::DisplayNameLimits::default();
        let event = UserRenamed {
            old_name: DisplayName::new("Alice", &limits).expect("valid display name"),
            new_name: DisplayName::new("Alice Cooper", &limits).expect("valid display name"),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(
            expect_change(&payload, "name"),
            (Some("Alice".to_owned()), Some("Alice Cooper".to_owned()))
        );
        assert_eq!(payload.len(), 1);
    }

    /// gone@example.com is deleted. The event refers to that user by id,
    /// labelled with the email they had when deleted.
    #[test]
    fn deleted_event_labels_the_user_by_their_email_at_deletion_time() {
        let deleted = UserId::new();
        let event = UserDeleted {
            user_id: deleted,
            email: Email::new("gone@example.com").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        let reference = expect_reference(&event.payload(), "user");

        assert_eq!(reference.id(), deleted.to_string());
        assert_eq!(reference.label(), "gone@example.com");
    }

    /// An admin resets Bob's password. The event refers to Bob as a user by
    /// his id.
    #[test]
    fn password_reset_event_references_the_user_the_admin_acted_on() {
        let target = UserId::new();
        let event = UserPasswordReset {
            user_id: target,
            user_label: EventLabel::of("Bob (bob@example.com)"),
            occurred_at: crate::shared::clock::now(),
        };

        let reference = expect_reference(&event.payload(), "user");

        assert_eq!(reference.kind(), RefKind::USER);
        assert_eq!(reference.id(), target.to_string());
    }

    /// An admin sets Dave's `feature_flags` in the app namespace. The event
    /// refers to Dave and names the namespace and key.
    #[test]
    fn metadata_updated_event_references_the_target_user_and_names_the_key() {
        let target = UserId::new();
        let event = UserMetadataUpdated {
            user_id: target,
            user_label: EventLabel::of("Dave (dave@example.com)"),
            namespace: AttributeNamespace::App,
            key: AttributeKey::new("feature_flags").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(expect_reference(&payload, "user").id(), target.to_string());
        assert_eq!(payload.get("namespace"), Some("app"));
        assert_eq!(payload.get("key"), Some("feature_flags"));
    }

    /// A user verifies their own address. The event has an empty payload,
    /// since the user is the actor.
    #[test]
    fn verifying_an_address_records_no_payload() {
        let event = UserEmailVerified {
            occurred_at: crate::shared::clock::now(),
        };

        assert!(event.payload().is_empty());
    }

    /// A user's own en-US and Europe/Berlin both go in the payload. A
    /// setting that follows the tenant is left out, so with neither set the
    /// payload is empty.
    #[test]
    fn preference_changes_record_only_the_settings_that_were_given() {
        let both = UserPreferencesUpdated {
            locale: Preference::Own(Locale::new("en-US").unwrap()),
            timezone: Preference::Own(Timezone::new("Europe/Berlin").unwrap()),
            occurred_at: crate::shared::clock::now(),
        };
        let locale_only = UserPreferencesUpdated {
            locale: Preference::Own(Locale::new("en-US").unwrap()),
            timezone: Preference::Inherited,
            occurred_at: crate::shared::clock::now(),
        };
        let neither = UserPreferencesUpdated {
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(both.payload().get("locale"), Some("en-US"));
        assert_eq!(both.payload().get("timezone"), Some("Europe/Berlin"));

        assert_eq!(locale_only.payload().get("locale"), Some("en-US"));
        assert_eq!(locale_only.payload().get("timezone"), None);

        assert!(neither.payload().is_empty());
    }

    /// Setting Ada's `employee_number` records the namespace and key.
    /// Deleting all her attributes records only her account, by id and
    /// label.
    #[test]
    fn the_metadata_events_name_the_account_and_what_changed() {
        let user = UserId::new();

        let updated = UserMetadataUpdated {
            user_id: user,
            user_label: EventLabel::of("ada@acme.com"),
            namespace: AttributeNamespace::App,
            key: AttributeKey::new("employee_number").unwrap(),
            occurred_at: crate::shared::clock::now(),
        };
        let deleted = UserMetadataDeleted {
            user_id: user,
            user_label: EventLabel::of("ada@acme.com"),
            occurred_at: crate::shared::clock::now(),
        };

        assert_eq!(updated.payload().get("namespace"), Some("app"));
        assert_eq!(updated.payload().get("key"), Some("employee_number"));

        let reference = expect_reference(&deleted.payload(), "user");
        assert_eq!(reference.id(), user.to_string());
        assert_eq!(reference.label(), "ada@acme.com");
    }
}
