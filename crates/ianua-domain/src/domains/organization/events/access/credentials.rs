//! Events about the credentials members sign in with: passwords, API keys, second factors, trusted devices and passkeys.

use time::OffsetDateTime;

use crate::domains::authentication::credentials::passkey::PasskeyCredential;
use crate::domains::organization::access::session::OrgSession;
use crate::domains::organization::members::org_user::OrgUser;
use crate::isolation::organization::scope::ResolvedOrganization;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEvent, organization_event};
use crate::types::{
    EventLabel, Label, OrgApiKeyId, OrgUserId, OrganizationId, PasskeyCredentialId,
};

/// An org user's password was reset by an admin.
#[derive(Debug)]
pub struct OrgUserPasswordReset {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The org user whose password was reset.
    pub(crate) org_user_id: OrgUserId,
    /// The org user's human label as it was when the event fired.
    pub(crate) org_user_label: EventLabel,
    /// When the password reset occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserPasswordReset => crate::types::event_type::OrganizationEvent::OrgUserPasswordReset,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "org_user",
            Reference::new(
                RefKind::ORG_USER,
                self.org_user_id.to_string(),
                self.org_user_label.as_str(),
            ),
        )
    }
}

/// An org user asked for a password reset link.
#[derive(Debug)]
pub struct OrgUserPasswordResetRequested {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// When the request was made.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgUserPasswordResetRequested {
    /// The record of `member` asking for a reset link, once it is kept.
    ///
    /// Nothing of the member's changes: the link is its own record, kept
    /// by the address it goes to, and names no organization.
    #[must_use]
    pub fn observed(member: &OrgUser) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgUserPasswordResetRequested => crate::types::event_type::OrganizationEvent::OrgUserPasswordResetRequested,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// An org user changed their own password.
#[derive(Debug)]
pub struct OrgUserPasswordChanged {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// When the password change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserPasswordChanged => crate::types::event_type::OrganizationEvent::OrgUserPasswordChanged,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// An org-level API key was created.
#[derive(Debug)]
pub struct OrgApiKeyCreated {
    /// The organization the key belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The unique identifier for the API key.
    pub(crate) key_id: OrgApiKeyId,
    /// The human-readable name for the key.
    pub(crate) name: Label,
    /// When the key was created.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgApiKeyCreated => crate::types::event_type::OrganizationEvent::OrgApiKeyCreated,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(RefKind::KEY, self.key_id.to_string(), self.name.as_str()),
        )
    }
}

/// An org-level API key was revoked.
#[derive(Debug)]
pub struct OrgApiKeyRevoked {
    /// The organization the key belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The unique identifier for the revoked API key.
    pub(crate) key_id: OrgApiKeyId,
    /// The key's human label as it was when the event fired.
    pub(crate) key_label: EventLabel,
    /// When the key was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgApiKeyRevoked => crate::types::event_type::OrganizationEvent::OrgApiKeyRevoked,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "key",
            Reference::new(
                RefKind::KEY,
                self.key_id.to_string(),
                self.key_label.as_str(),
            ),
        )
    }
}

/// An org user enrolled in multi-factor authentication.
#[derive(Debug)]
pub struct OrgMfaEnrolled {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// When the enrollment occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgMfaEnrolled => crate::types::event_type::OrganizationEvent::OrgMfaEnrolled,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// An org user replaced their recovery codes with a fresh set. Every
/// earlier code stopped working.
#[derive(Debug)]
pub struct OrgRecoveryCodesGenerated {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// How many codes the new set holds.
    pub(crate) count: u8,
    /// When the codes were made.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgRecoveryCodesGenerated => crate::types::event_type::OrganizationEvent::OrgRecoveryCodesGenerated,
    fn payload(&self) -> EventData {
        EventData::new().field("count", self.count.to_string())
    }
}

/// An org user trusted a device, letting it skip MFA on later sign-ins.
#[derive(Debug)]
pub struct OrgDeviceTrusted {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// When the device was trusted.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgDeviceTrusted {
    /// The record of `member` trusting a device, once it is kept. The
    /// device is kept under the member, not the organization, so no
    /// organization aggregate changes.
    #[must_use]
    pub fn observed(member: &OrgUser) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgDeviceTrusted => crate::types::event_type::OrganizationEvent::OrgDeviceTrusted,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// An org user revoked a trusted device.
#[derive(Debug)]
pub struct OrgDeviceRevoked {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// When the device was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgDeviceRevoked {
    /// The record of `member` revoking a device they trusted, once it is
    /// kept. The device is kept under the member, so no organization
    /// aggregate changes.
    #[must_use]
    pub fn observed(member: &OrgUser) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgDeviceRevoked => crate::types::event_type::OrganizationEvent::OrgDeviceRevoked,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// An org user began enrolling an authenticator app.
#[derive(Debug)]
pub struct OrgMfaEnrollmentStarted {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user enrolling.
    pub(crate) org_user_id: OrgUserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgMfaEnrollmentStarted {
    /// The record of `member` beginning to set up an authenticator app,
    /// once the unconfirmed setup is kept. The setup is kept under the
    /// member, so no organization aggregate changes.
    #[must_use]
    pub fn observed(member: &OrgUser) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgMfaEnrollmentStarted =>crate::types::event_type::OrganizationEvent::OrgMfaEnrollmentStarted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "org_user",
            Reference::new(
                RefKind::ORG_USER,
                self.org_user_id.to_string(),
                self.org_user_id.to_string(),
            ),
        )
    }
}

/// An org user proved their second factor and their session was raised.
#[derive(Debug)]
pub struct OrgMfaVerified {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user who verified.
    pub(crate) org_user_id: OrgUserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgMfaVerified {
    /// The record of `session`'s member answering the second factor their
    /// sign-in owed, by a code or a mailbox link, once the session is kept.
    ///
    /// Answering is a step of signing in, which records itself the way it
    /// finishes: a passkey records the sign-in, a factor just set up its
    /// enrolment. So only the answers that are a verification are recorded
    /// as one, and the session raises none of them.
    #[must_use]
    pub fn observed(session: &OrgSession) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *session.organization_id(),
            org_user_id: *session.org_user_id(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgMfaVerified =>crate::types::event_type::OrganizationEvent::OrgMfaVerified,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "org_user",
            Reference::new(
                RefKind::ORG_USER,
                self.org_user_id.to_string(),
                self.org_user_id.to_string(),
            ),
        )
    }
}

/// An org user switched MFA off.
#[derive(Debug)]
pub struct OrgMfaUnenrolled {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user who disabled it.
    pub(crate) org_user_id: OrgUserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgMfaUnenrolled => crate::types::event_type::OrganizationEvent::OrgMfaUnenrolled,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "org_user",
            Reference::new(
                RefKind::ORG_USER,
                self.org_user_id.to_string(),
                self.org_user_id.to_string(),
            ),
        )
    }
}

/// An owner reset a member's second factor, for a member who lost theirs.
#[derive(Debug)]
pub struct OrgMemberMfaReset {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The member whose factor was reset.
    pub(crate) org_user_id: OrgUserId,
    /// The member's label as it was when the event fired.
    pub(crate) org_user_label: EventLabel,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgMemberMfaReset => crate::types::event_type::OrganizationEvent::OrgMemberMfaReset,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "org_user",
            Reference::new(
                RefKind::ORG_USER,
                self.org_user_id.to_string(),
                self.org_user_label.as_str(),
            ),
        )
    }
}

/// An org user began registering a passkey.
#[derive(Debug)]
pub struct OrgPasskeyRegistrationStarted {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user registering.
    pub(crate) org_user_id: OrgUserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgPasskeyRegistrationStarted {
    /// The record of `member` beginning to register a passkey, once the
    /// ceremony is kept. A ceremony names the member alone, so no
    /// organization aggregate changes.
    #[must_use]
    pub fn observed(member: &OrgUser) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgPasskeyRegistrationStarted =>crate::types::event_type::OrganizationEvent::OrgPasskeyRegistrationStarted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "org_user",
            Reference::new(
                RefKind::ORG_USER,
                self.org_user_id.to_string(),
                self.org_user_id.to_string(),
            ),
        )
    }
}

/// An org user registered a passkey.
#[derive(Debug)]
pub struct OrgPasskeyRegistered {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user who registered it.
    pub(crate) org_user_id: OrgUserId,
    /// The WebAuthn credential id.
    pub(crate) credential_id: PasskeyCredentialId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgPasskeyRegistered => crate::types::event_type::OrganizationEvent::OrgPasskeyRegistered,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "org_user",
                Reference::new(
                    RefKind::ORG_USER,
                    self.org_user_id.to_string(),
                    self.org_user_id.to_string(),
                ),
            )
            .field("credential_id", self.credential_id.to_string())
    }
}

/// An org user renamed one of their passkeys.
#[derive(Debug)]
pub struct OrgPasskeyRenamed {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The passkey's owner.
    pub(crate) org_user_id: OrgUserId,
    /// The WebAuthn credential id.
    pub(crate) credential_id: PasskeyCredentialId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgPasskeyRenamed {
    /// The record of `member` renaming their `passkey`, once it is kept.
    /// The passkey is kept under the member, so no organization aggregate
    /// changes.
    #[must_use]
    pub fn observed(
        member: &OrgUser,
        passkey: &PasskeyCredential<ResolvedOrganization>,
    ) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            credential_id: passkey.credential_id().clone(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgPasskeyRenamed =>crate::types::event_type::OrganizationEvent::OrgPasskeyRenamed,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "org_user",
                Reference::new(
                    RefKind::ORG_USER,
                    self.org_user_id.to_string(),
                    self.org_user_id.to_string(),
                ),
            )
            .field("credential_id", self.credential_id.to_string())
    }
}

/// An org user removed one of their passkeys.
#[derive(Debug)]
pub struct OrgPasskeyRemoved {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The passkey's owner.
    pub(crate) org_user_id: OrgUserId,
    /// The WebAuthn credential id.
    pub(crate) credential_id: PasskeyCredentialId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgPasskeyRemoved => crate::types::event_type::OrganizationEvent::OrgPasskeyRemoved,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "org_user",
                Reference::new(
                    RefKind::ORG_USER,
                    self.org_user_id.to_string(),
                    self.org_user_id.to_string(),
                ),
            )
            .field("credential_id", self.credential_id.to_string())
    }
}
