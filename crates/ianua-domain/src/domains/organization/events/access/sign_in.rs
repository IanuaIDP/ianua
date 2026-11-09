//! Events about how members sign in to the management plane.

use time::OffsetDateTime;

use crate::domains::authentication::risk_engine::attack::AttackBegun;
use crate::domains::authentication::sessions::session::Session;
use crate::domains::organization::access::session::SessionPlace;
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::linked_identity::TenantSwitch;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::tenant::lifecycle::Tenant;
use crate::isolation::scope::TenantScope;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEvent, organization_event, platform_event};
use crate::types::{EventLabel, OrgUserId, OrganizationId, SessionId, TenantId, UserId};

/// How a member of an organization tried to sign in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgSignInMethod {
    /// Email and password.
    Password,
    /// A registered passkey.
    Passkey,
    /// The organization's own identity provider.
    SingleSignOn,
    /// A sign-in link mailed to the member.
    MagicLink,
}

impl OrgSignInMethod {
    /// The name recorded in the audit payload.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Passkey => "passkey",
            Self::SingleSignOn => "single_sign_on",
            Self::MagicLink => "magic_link",
        }
    }
}

/// Why an organization sign-in was refused, in terms safe to record. It never
/// says which half of a credential was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgSignInRefusal {
    /// The email, password or passkey did not match.
    InvalidCredentials,
    /// The member may not sign in this way.
    Refused,
    /// The account is locked after too many failures.
    Locked,
    /// The email address is not verified yet.
    EmailNotVerified,
    /// Too many attempts in too short a time.
    RateLimited,
    /// The tenant the sign-in was for is not available.
    TenantUnavailable,
}

impl OrgSignInRefusal {
    /// The name recorded in the audit payload.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::Refused => "refused",
            Self::Locked => "locked",
            Self::EmailNotVerified => "email_not_verified",
            Self::RateLimited => "rate_limited",
            Self::TenantUnavailable => "tenant_unavailable",
        }
    }
}

/// An organization's sign-in settings were replaced.
///
/// Carries no payload. The audit record says who changed the settings and
/// when. Copying the allowlist and lockout limits into the event would put
/// them in every log that stores it.
#[derive(Debug)]
pub(crate) struct OrganizationAuthConfigUpdated {
    /// The organization whose sign-in settings changed.
    pub(crate) organization_id: OrganizationId,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrganizationAuthConfigUpdated => crate::types::event_type::OrganizationEvent::AuthConfigUpdated,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A user switched between tenants via a linked identity.
#[derive(Debug)]
pub struct TenantSwitched {
    /// The organization containing both tenants.
    pub(crate) organization_id: OrganizationId,
    /// The tenant the user switched from.
    pub(crate) source_tenant_id: TenantId,
    /// The source tenant's human label as it was when the event fired.
    pub(crate) source_tenant_label: EventLabel,
    /// The tenant the user switched to.
    pub(crate) target_tenant_id: TenantId,
    /// The target tenant's human label as it was when the event fired.
    pub(crate) target_tenant_label: EventLabel,
    /// The user's ID in the target tenant.
    pub(crate) target_user_id: UserId,
    /// The target identity's human label as it was when the event fired.
    pub(crate) target_user_label: EventLabel,
    /// The new session ID in the target tenant.
    pub(crate) new_session_id: SessionId,
    /// When the switch occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

impl TenantSwitched {
    /// The record of the switch `switch` described, from the tenant
    /// `source`, once the `session` it opened is kept. It names both
    /// tenants and the account switched to as they are called now.
    ///
    /// The session opened is the target tenant's, kept under the linked
    /// account, and the group of linked accounts does not change, so no
    /// organization aggregate raises it.
    #[must_use]
    pub fn recorded<S: TenantScope, T: TenantScope>(
        switch: &TenantSwitch<'_, S, T>,
        source: &Tenant,
        session: &Session<T>,
    ) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *switch.organization.id(),
            source_tenant_id: *source.id(),
            source_tenant_label: EventLabel::of(source.display_name().as_str()),
            target_tenant_id: *switch.target_tenant.id(),
            target_tenant_label: EventLabel::of(switch.target_tenant.display_name().as_str()),
            target_user_id: *switch.to.user.id(),
            target_user_label: EventLabel::of(switch.to.user.display_name().as_str()),
            new_session_id: *session.id(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    TenantSwitched =>crate::types::event_type::OrganizationEvent::TenantSwitched,
    fn payload(&self) -> EventData {
        let source = self.source_tenant_id.to_string();
        let target = self.target_tenant_id.to_string();
        let user = self.target_user_id.to_string();
        let session = self.new_session_id.to_string();
        EventData::new()
            .field("organization_id", self.organization_id.to_string())
            .reference(
                "source_tenant",
                Reference::new(RefKind::TENANT, source, self.source_tenant_label.as_str()),
            )
            .reference(
                "target_tenant",
                Reference::new(RefKind::TENANT, target, self.target_tenant_label.as_str()),
            )
            .reference(
                "target_user",
                Reference::new(RefKind::USER, user, self.target_user_label.as_str()),
            )
            .reference(
                "new_session",
                Reference::new(RefKind::SESSION, session.clone(), session),
            )
    }
}

/// A member moved their organization session into a tenant of the
/// organization, without signing in again.
///
/// The old session ended and a new one opened in the tenant. Olivia is let
/// into `staging` and `production`. Without this record, nothing shows
/// when she began working in `production`, or from which session.
#[derive(Debug)]
pub struct OrgSessionMoved {
    /// The organization owning the tenants.
    pub(crate) organization_id: OrganizationId,
    /// The member who moved.
    pub(crate) org_user_id: OrgUserId,
    /// Where the old session worked: a tenant, or the organization alone.
    pub(crate) source: SessionPlace,
    /// The tenant the new session works in.
    pub(crate) target_tenant_id: TenantId,
    /// The replacement login scoped to the destination tenant.
    pub(crate) new_session_id: SessionId,
    /// When the move happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgSessionMoved => crate::types::event_type::OrganizationEvent::OrgSessionMoved,
    fn payload(&self) -> EventData {
        let member = self.org_user_id.to_string();
        let source = match self.source {
            SessionPlace::Tenant(tenant) => {
                let id = tenant.to_string();
                Some(Reference::new(RefKind::TENANT, id.clone(), id))
            }
            SessionPlace::Organization => None,
        };
        let target = self.target_tenant_id.to_string();
        let session = self.new_session_id.to_string();
        EventData::new()
            .reference(
                "org_user",
                Reference::new(RefKind::ORG_USER, member.clone(), member),
            )
            .optional_reference("source_tenant", source)
            .reference(
                "target_tenant",
                Reference::new(RefKind::TENANT, target.clone(), target),
            )
            .reference(
                "new_session",
                Reference::new(RefKind::SESSION, session.clone(), session),
            )
    }
}

/// An org user signed in to the management plane.
#[derive(Debug)]
pub struct OrgLoginSucceeded {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user who signed in.
    pub(crate) org_user_id: OrgUserId,
    /// How they proved who they are: password or passkey.
    pub(crate) method: OrgSignInMethod,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgLoginSucceeded {
    /// The record of `member` signing in by `method`. A sign-in is an
    /// attempt, not a change of the member, so it is observed rather than
    /// raised.
    #[must_use]
    pub fn observed(member: &OrgUser, method: OrgSignInMethod) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            method,
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgLoginSucceeded =>crate::types::event_type::OrganizationEvent::OrgLoginSucceeded,
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
            .field("method", self.method.as_str())
    }
}

/// A sign-in for a known org user was refused.
#[derive(Debug)]
pub struct OrgLoginFailed {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user the attempt named.
    pub(crate) org_user_id: OrgUserId,
    /// How they tried to sign in: password or passkey.
    pub(crate) method: OrgSignInMethod,
    /// Why it was refused.
    pub(crate) reason: OrgSignInRefusal,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgLoginFailed {
    /// The record of a sign-in by `method` for `member` refused for
    /// `reason`. A refused attempt changes nothing, so it is observed.
    #[must_use]
    pub fn observed(
        member: &OrgUser,
        method: OrgSignInMethod,
        reason: OrgSignInRefusal,
    ) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            method,
            reason,
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgLoginFailed =>crate::types::event_type::OrganizationEvent::OrgLoginFailed,
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
            .field("method", self.method.as_str())
            .field("reason", self.reason.as_str())
    }
}

/// Failed sign-ins against an org user's account came from so many
/// networks within the lockout's window that the account counts as under
/// attack.
///
/// Until the attack is over, a right password from a device the member did
/// not trust also needs their second factor or a link mailed to them. It is
/// recorded once each time the account comes under attack, and told to the
/// organization's admins and owners as a security alert. It names how many
/// networks failed, never which, and never a password.
#[derive(Debug)]
pub struct OrgAccountUnderAttack {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user whose account is under attack.
    pub(crate) org_user_id: OrgUserId,
    /// How many networks had failed on the account when the attack was
    /// found.
    pub(crate) networks: u64,
    /// Until when the account counts as under attack.
    pub(crate) until: OffsetDateTime,
    /// When the attack was found.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgAccountUnderAttack {
    /// The record of `begun`, the attack a sign-in found on `member`'s
    /// account. The account changes nothing it keeps, so it is observed.
    #[must_use]
    pub fn observed(member: &OrgUser, begun: AttackBegun) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            networks: begun.networks().get(),
            until: begun.until(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgAccountUnderAttack => crate::types::event_type::OrganizationEvent::OrgAccountUnderAttack,
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
            .field("networks", self.networks.to_string())
            .field("under_attack_until", self.until.to_string())
    }
}

/// An org session was ended by signing out.
#[derive(Debug)]
pub struct OrgSessionRevoked {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The session's owner.
    pub(crate) org_user_id: OrgUserId,
    /// The ended session.
    pub(crate) session_id: SessionId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgSessionRevoked => crate::types::event_type::OrganizationEvent::OrgSessionRevoked,
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
            .field("session_id", self.session_id.to_string())
    }
}

/// A passkey sign-in was started for an org user who has passkeys.
#[derive(Debug)]
pub struct OrgPasskeySignInStarted {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user the sign-in is for.
    pub(crate) org_user_id: OrgUserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgPasskeySignInStarted {
    /// The record of a passkey sign-in begun for `member`, once its
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
    OrgPasskeySignInStarted =>crate::types::event_type::OrganizationEvent::OrgPasskeySignInStarted,
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

/// A member asked for a sign-in link, and one was mailed to them.
///
/// Mailing a link changes nothing the organization keeps, but a link is a
/// way in. Without this record, nothing shows that Mallory, holding Ann's
/// mailbox, asked for the link she later signed in with.
#[derive(Debug)]
pub struct OrgMagicLinkRequested {
    /// The member's organization.
    pub(crate) organization_id: OrganizationId,
    /// The member the link was mailed to.
    pub(crate) org_user_id: OrgUserId,
    /// When it was mailed.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgMagicLinkRequested {
    /// The record of a sign-in link mailed to `member`, once it is kept.
    /// The link is kept under the member alone, so no organization
    /// aggregate changes.
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
    OrgMagicLinkRequested =>crate::types::event_type::OrganizationEvent::OrgMagicLinkRequested,
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

/// A sign-in through the organization's identity provider was started.
/// Nobody is known until the provider answers.
#[derive(Debug)]
pub struct OrgSsoSignInStarted {
    /// The organization whose provider the sign-in goes to.
    pub(crate) organization_id: OrganizationId,
    /// When it was started.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgSsoSignInStarted {
    /// The record of a sign-in sent to `organization`'s provider, once the
    /// state it returns to is kept. Starting changes nothing the
    /// organization keeps.
    #[must_use]
    pub fn observed(organization: &Organization) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *organization.id(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

organization_event! {
    OrgSsoSignInStarted =>crate::types::event_type::OrganizationEvent::OrgSsoSignInStarted,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A discoverable passkey challenge was issued. Nobody is known until it is answered.
#[derive(Debug)]
pub struct OrgPasskeyChallengeIssued {
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgPasskeyChallengeIssued {
    /// The record of a discoverable passkey challenge, once its ceremony is
    /// kept. Nobody and no organization is known yet, so it is a platform
    /// record.
    #[must_use]
    pub fn observed() -> DomainEvent {
        DomainEvent::platform(Box::new(Self {
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

platform_event! {
    OrgPasskeyChallengeIssued =>crate::types::event_type::OrganizationEvent::OrgPasskeyChallengeIssued,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}
