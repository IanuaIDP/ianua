//! Events about the people who administer an organization.

use time::OffsetDateTime;

use crate::domains::authorization::role::Role;
use crate::domains::organization::members::membership::OrgRole;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::org_user_status::OrgUserStatus;
use crate::domains::tenant::lifecycle::Tenant;
use crate::isolation::scope::ResolvedTenant;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{
    DomainEvent, DomainEventCore, OrganizationDomainEvent, organization_event,
};
use crate::types::{
    DisplayName, Email, EventLabel, Label, Locale, OrgUserId, OrganizationId, Preference, TenantId,
    Timezone, UserId,
};

/// A user identity was linked to a tenant within the organization.
#[derive(Debug)]
pub struct IdentityLinked {
    /// The organization containing the linked tenants.
    pub(crate) organization_id: OrganizationId,
    /// The email that was linked.
    pub(crate) email: Email,
    /// The tenant the identity was linked to.
    pub(crate) tenant_id: TenantId,
    /// The tenant's human label as it was when the event fired.
    pub(crate) tenant_label: EventLabel,
    /// The user ID in that tenant.
    pub(crate) user_id: UserId,
    /// When the link was created.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    IdentityLinked => crate::types::event_type::OrganizationEvent::IdentityLinked,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("organization_id", self.organization_id.to_string())
            .field("email", self.email.to_string())
            .reference(
                "tenant",
                Reference::new(
                    RefKind::TENANT,
                    self.tenant_id.to_string(),
                    self.tenant_label.as_str(),
                ),
            )
            .reference(
                "user",
                Reference::new(
                    RefKind::USER,
                    self.user_id.to_string(),
                    self.email.to_string(),
                ),
            )
    }
}

/// A user identity was unlinked from a tenant within the organization.
#[derive(Debug)]
pub struct IdentityUnlinked {
    /// The organization containing the linked tenants.
    pub(crate) organization_id: OrganizationId,
    /// The email that was unlinked.
    pub(crate) email: Email,
    /// The tenant the identity was unlinked from.
    pub(crate) tenant_id: TenantId,
    /// The tenant's human label as it was when the event fired.
    pub(crate) tenant_label: EventLabel,
    /// When the unlink occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    IdentityUnlinked => crate::types::event_type::OrganizationEvent::IdentityUnlinked,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("organization_id", self.organization_id.to_string())
            .field("email", self.email.to_string())
            .reference(
                "tenant",
                Reference::new(
                    RefKind::TENANT,
                    self.tenant_id.to_string(),
                    self.tenant_label.as_str(),
                ),
            )
    }
}

/// An org user was created.
#[derive(Debug)]
pub struct OrgUserCreated {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The new org user's ID.
    pub(crate) org_user_id: OrgUserId,
    /// The org user's email.
    pub(crate) email: Email,
    /// When the user was created.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserCreated => crate::types::event_type::OrganizationEvent::OrgUserCreated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "org_user",
                Reference::new(
                    RefKind::ORG_USER,
                    self.org_user_id.to_string(),
                    self.email.to_string(),
                ),
            )
            .field("email", self.email.to_string())
    }
}

/// An org user was deleted from the organization.
#[derive(Debug)]
pub struct OrgUserDeleted {
    /// The organization the user was deleted from.
    pub(crate) organization_id: OrganizationId,
    /// The deleted org user's ID.
    pub(crate) org_user_id: OrgUserId,
    /// The org user's human label as it was when the event fired.
    pub(crate) org_user_label: EventLabel,
    /// When the deletion occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserDeleted => crate::types::event_type::OrganizationEvent::OrgUserDeleted,
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

/// An org user's status was changed, such as deactivated, reactivated,
/// locked or unlocked.
#[derive(Debug)]
pub struct OrgUserStatusChanged {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The org user whose status changed.
    pub(crate) org_user_id: OrgUserId,
    /// The org user's human label as it was when the event fired.
    pub(crate) org_user_label: EventLabel,
    /// The previous status.
    pub(crate) from: OrgUserStatus,
    /// The new status.
    pub(crate) to: OrgUserStatus,
    /// When the status change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserStatusChanged => crate::types::event_type::OrganizationEvent::OrgUserStatusChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "org_user",
                Reference::new(
                    RefKind::ORG_USER,
                    self.org_user_id.to_string(),
                    self.org_user_label.as_str(),
                ),
            )
            .change("status", self.from.to_string(), self.to.to_string())
    }
}

/// An org user's organization role was changed, up or down.
#[derive(Debug)]
pub struct OrgUserRoleChanged {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The org user whose role changed.
    pub(crate) org_user_id: OrgUserId,
    /// The org user's human label as it was when the event fired.
    pub(crate) org_user_label: EventLabel,
    /// The previous role.
    pub(crate) from: OrgRole,
    /// The new role.
    pub(crate) to: OrgRole,
    /// When the role change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserRoleChanged => crate::types::event_type::OrganizationEvent::OrgUserRoleChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "org_user",
                Reference::new(
                    RefKind::ORG_USER,
                    self.org_user_id.to_string(),
                    self.org_user_label.as_str(),
                ),
            )
            .change("role", self.from.to_string(), self.to.to_string())
    }
}

/// An owner handed the organization's ownership to another member, and
/// stayed on as an admin.
///
/// The two role changes are recorded too. This record ties them together,
/// so a reviewer sees one hand-over, not a promotion and a demotion that
/// happened to fall in the same second.
#[derive(Debug)]
pub(crate) struct OrgOwnershipTransferred {
    /// The organization whose ownership moved.
    pub(crate) organization_id: OrganizationId,
    /// The owner who handed it over.
    pub(crate) from: OrgUserId,
    /// How the record names them.
    pub(crate) from_label: EventLabel,
    /// The member who took it over.
    pub(crate) to: OrgUserId,
    /// How the record names them.
    pub(crate) to_label: EventLabel,
    /// When it moved.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgOwnershipTransferred => crate::types::event_type::OrganizationEvent::OwnershipTransferred,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "from",
                Reference::new(RefKind::ORG_USER, self.from.to_string(), self.from_label.as_str()),
            )
            .reference(
                "to",
                Reference::new(RefKind::ORG_USER, self.to.to_string(), self.to_label.as_str()),
            )
    }
}

/// An org user's set of roles in one tenant was replaced.
///
/// Covers both directions. A non-empty `to_roles` is a grant, and an empty
/// one is a full withdrawal. The previous set is recorded so a narrowing
/// shows in the audit trail.
#[derive(Debug)]
pub struct OrgUserTenantAccessChanged {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The org user whose access changed.
    pub(crate) org_user_id: OrgUserId,
    /// The org user's human label as it was when the event fired.
    pub(crate) org_user_label: EventLabel,
    /// The tenant the access covers.
    pub(crate) tenant_id: TenantId,
    /// The tenant's human label as it was when the event fired.
    pub(crate) tenant_label: EventLabel,
    /// The role names held before. Empty when there were none.
    pub(crate) from_roles: Vec<Label>,
    /// The role names held after. Empty on a full withdrawal.
    pub(crate) to_roles: Vec<Label>,
    /// When the access changed.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgUserTenantAccessChanged {
    /// The record of `member`'s roles in `tenant` replaced: the names of
    /// those `held` before, and `now_held`, once the grants are stored.
    ///
    /// The member holds one grant per role, each its own record, and the
    /// roles belong to the tenant. So the replacement as a whole has no
    /// aggregate of its own to raise it.
    #[must_use]
    pub fn replaced(
        member: &OrgUser,
        tenant: &Tenant,
        held: Vec<Label>,
        now_held: &[Role<ResolvedTenant>],
    ) -> DomainEvent {
        DomainEvent::organization(Box::new(Self {
            organization_id: *member.organization_id(),
            org_user_id: *member.id(),
            org_user_label: member.label(),
            tenant_id: *tenant.id(),
            tenant_label: EventLabel::of(tenant.display_name().as_str()),
            from_roles: held,
            to_roles: now_held.iter().map(|role| role.name().clone()).collect(),
            occurred_at: crate::shared::clock::now(),
        }))
    }
}

impl DomainEventCore for OrgUserTenantAccessChanged {
    fn event_type(&self) -> crate::types::EventType {
        if self.to_roles.is_empty() {
            return crate::types::event_type::OrganizationEvent::OrgUserTenantAccessRevoked.into();
        }
        crate::types::event_type::OrganizationEvent::OrgUserTenantAccessGranted.into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "org_user",
                Reference::new(
                    RefKind::ORG_USER,
                    self.org_user_id.to_string(),
                    self.org_user_label.as_str(),
                ),
            )
            .reference(
                "tenant",
                Reference::new(
                    RefKind::TENANT,
                    self.tenant_id.to_string(),
                    self.tenant_label.as_str(),
                ),
            )
            .change(
                "roles",
                role_list(&self.from_roles),
                role_list(&self.to_roles),
            )
    }
}

impl OrganizationDomainEvent for OrgUserTenantAccessChanged {
    fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }
}

/// An org user confirmed their email address.
#[derive(Debug)]
pub struct OrgUserEmailVerified {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// When the address was confirmed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserEmailVerified => crate::types::event_type::OrganizationEvent::OrgUserEmailVerified,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// An org user's email was changed.
#[derive(Debug)]
pub struct OrgUserEmailChanged {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The previous email.
    pub(crate) old_email: Email,
    /// The replacement mailbox captured in the audit record.
    pub(crate) new_email: Email,
    /// When the email change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserEmailChanged => crate::types::event_type::OrganizationEvent::OrgUserEmailChanged,
    fn payload(&self) -> EventData {
        EventData::new().change("email", self.old_email.as_str(), self.new_email.as_str())
    }
}

/// An org user's display name was changed.
#[derive(Debug)]
pub struct OrgUserDisplayNameChanged {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The previous display name.
    pub(crate) old_display_name: DisplayName,
    /// The replacement person label captured in the audit record.
    pub(crate) new_display_name: DisplayName,
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserDisplayNameChanged => crate::types::event_type::OrganizationEvent::OrgUserDisplayNameChanged,
    fn payload(&self) -> EventData {
        EventData::new().change(
            "display_name",
            self.old_display_name.as_str(),
            self.new_display_name.as_str(),
        )
    }
}

/// An org user updated their locale and timezone preferences.
///
/// Carries the preferences as they stand after the update, each either the
/// person's own choice or inherited.
#[derive(Debug)]
pub struct OrgUserPreferencesUpdated {
    /// The organization the user belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The locale as it now stands.
    pub(crate) locale: Preference<Locale>,
    /// The timezone as it now stands.
    pub(crate) timezone: Preference<Timezone>,
    /// When the update occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    OrgUserPreferencesUpdated => crate::types::event_type::OrganizationEvent::OrgUserPreferencesUpdated,
    fn payload(&self) -> EventData {
        EventData::new()
            .optional("locale", self.locale.value().map(Locale::as_str))
            .optional("timezone", self.timezone.value().map(Timezone::as_str))
    }
}

/// A link to confirm an org user's address was emailed to them.
#[derive(Debug)]
pub struct OrgVerificationEmailSent {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user it was sent to.
    pub(crate) org_user_id: OrgUserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgVerificationEmailSent {
    /// The record of a link to confirm `member`'s address that the mail
    /// service accepted. Mailing changes nothing kept, so it is observed.
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
    OrgVerificationEmailSent =>crate::types::event_type::OrganizationEvent::OrgVerificationEmailSent,
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

/// An org user was emailed that their account exists and where to sign in.
#[derive(Debug)]
pub struct OrgWelcomeEmailSent {
    /// The organization it happened in.
    pub(crate) organization_id: OrganizationId,
    /// The org user it was sent to.
    pub(crate) org_user_id: OrgUserId,
    /// When it happened.
    pub(crate) occurred_at: OffsetDateTime,
}

impl OrgWelcomeEmailSent {
    /// The record of a welcome to `member` that the mail service accepted.
    /// Mailing changes nothing kept, so it is observed.
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
    OrgWelcomeEmailSent =>crate::types::event_type::OrganizationEvent::OrgWelcomeEmailSent,
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

/// Role names as one comma-separated list, the form the audit record shows.
fn role_list(roles: &[Label]) -> String {
    roles
        .iter()
        .map(Label::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::config::DisplayNameLimits;
    use crate::shared::events::data::FieldValue;

    fn role(name: &str) -> Label {
        Label::new("role", name).unwrap()
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    fn entity(payload: &EventData, key: &str) -> (RefKind, String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => (
                reference.kind(),
                reference.id().to_owned(),
                reference.label().to_owned(),
            ),
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    fn change(payload: &EventData, key: &str) -> (Option<String>, Option<String>) {
        match payload.value(key) {
            Some(FieldValue::Change(change)) => (
                change.from().map(str::to_owned),
                change.to().map(str::to_owned),
            ),
            other => panic!("{key} is not a change: {other:?}"),
        }
    }

    /// An owner locks Ada's account. The record names Ada's account by its id
    /// and the label "Ada Lovelace (ada@acme.com)".
    #[test]
    fn org_user_status_changed_references_the_target_user() {
        let org_user_id = OrgUserId::new();
        let event = OrgUserStatusChanged {
            organization_id: OrganizationId::new(),
            org_user_id,
            org_user_label: EventLabel::of("Ada Lovelace (ada@acme.com)"),
            from: OrgUserStatus::Active,
            to: OrgUserStatus::Locked,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Reference(user)) = payload.value("org_user") else {
            panic!("expected an org user reference");
        };
        assert_eq!(user.kind(), RefKind::ORG_USER);
        assert_eq!(user.id(), org_user_id.to_string());
        assert_eq!(user.label(), "Ada Lovelace (ada@acme.com)");
    }

    /// Ada's address is linked to her account in Production and later
    /// unlinked. Both records name her address and Production, and the link
    /// also names the account it reaches.
    #[test]
    fn linking_and_unlinking_an_identity_name_the_address_and_the_tenant() {
        let org = OrganizationId::new();
        let tenant = TenantId::new();
        let user = UserId::new();

        let linked = IdentityLinked {
            organization_id: org,
            email: Email::new("ada@acme.com").unwrap(),
            tenant_id: tenant,
            tenant_label: EventLabel::of("Production"),
            user_id: user,
            occurred_at: now(),
        };
        let unlinked = IdentityUnlinked {
            organization_id: org,
            email: Email::new("ada@acme.com").unwrap(),
            tenant_id: tenant,
            tenant_label: EventLabel::of("Production"),
            occurred_at: now(),
        };

        for event in [&linked as &dyn OrganizationDomainEvent, &unlinked] {
            assert_link_ends(event, org, tenant);
        }

        assert_eq!(
            entity(&linked.payload(), "user"),
            (RefKind::USER, user.to_string(), "ada@acme.com".to_owned()),
            "the link names the account in the tenant it reaches"
        );
    }

    /// A link change must name Ada's address, its organization and Production tenant.
    fn assert_link_ends(
        event: &dyn OrganizationDomainEvent,
        org: OrganizationId,
        tenant: TenantId,
    ) {
        let kind = event.event_type();
        let payload = event.payload();
        assert_eq!(event.organization_id(), &org, "{kind}");
        assert_eq!(payload.get("email"), Some("ada@acme.com"), "{kind}");
        assert_eq!(
            entity(&payload, "tenant"),
            (RefKind::TENANT, tenant.to_string(), "Production".to_owned()),
            "{kind}"
        );
    }

    /// A member at `new@acme.com` is created. The record names that member
    /// and that address.
    #[test]
    fn a_created_member_is_named_with_their_address() {
        let org = OrganizationId::new();
        let member = OrgUserId::new();
        let email = "new@acme.com";

        let event = OrgUserCreated {
            organization_id: org,
            org_user_id: member,
            email: Email::new(email).unwrap(),
            occurred_at: now(),
        };

        let payload = event.payload();
        assert_eq!(event.organization_id(), &org);
        assert_eq!(
            entity(&payload, "org_user"),
            (RefKind::ORG_USER, member.to_string(), email.to_owned())
        );
        assert_eq!(payload.get("email"), Some(email));
    }

    /// Making Ada an owner records her member reference and both roles.
    #[test]
    fn the_member_changes_record_what_they_moved_from_and_to() {
        let org = OrganizationId::new();
        let member = OrgUserId::new();

        let role = OrgUserRoleChanged {
            organization_id: org,
            org_user_id: member,
            org_user_label: EventLabel::of("ada@acme.com"),
            from: OrgRole::Member,
            to: OrgRole::Owner,
            occurred_at: now(),
        };
        assert_eq!(role.organization_id(), &org);
        assert_eq!(
            change(&role.payload(), "role"),
            (Some("Member".to_owned()), Some("Owner".to_owned()))
        );
        assert_eq!(
            entity(&role.payload(), "org_user"),
            (
                RefKind::ORG_USER,
                member.to_string(),
                "ada@acme.com".to_owned()
            )
        );
    }

    /// Moving Ada's mailbox records the organization and both email addresses.
    #[test]
    fn a_member_email_change_keeps_both_addresses() {
        let org = OrganizationId::new();
        let email = OrgUserEmailChanged {
            organization_id: org,
            old_email: Email::new("ada@acme.com").unwrap(),
            new_email: Email::new("ada@globex.com").unwrap(),
            occurred_at: now(),
        };
        assert_eq!(email.organization_id(), &org);
        assert_eq!(
            change(&email.payload(), "email"),
            (
                Some("ada@acme.com".to_owned()),
                Some("ada@globex.com".to_owned())
            )
        );
    }

    /// Expanding Ada's display name records the organization and both names.
    #[test]
    fn a_member_display_name_change_keeps_both_names() {
        let org = OrganizationId::new();
        let display_name = OrgUserDisplayNameChanged {
            organization_id: org,
            old_display_name: DisplayName::new("Ada", &DisplayNameLimits::default()).unwrap(),
            new_display_name: DisplayName::new("Ada Lovelace", &DisplayNameLimits::default())
                .unwrap(),
            occurred_at: now(),
        };
        assert_eq!(display_name.organization_id(), &org);
        assert_eq!(
            change(&display_name.payload(), "display_name"),
            (Some("Ada".to_owned()), Some("Ada Lovelace".to_owned()))
        );
    }

    /// Ada sets her own locale and timezone, and Bob inherits both. Ada's
    /// record carries both values. Bob's carries none.
    #[test]
    fn a_member_preference_change_records_only_what_was_set() {
        let org = OrganizationId::new();

        let both = OrgUserPreferencesUpdated {
            organization_id: org,
            locale: Preference::Own(Locale::new("en-US").unwrap()),
            timezone: Preference::Own(Timezone::new("Europe/Berlin").unwrap()),
            occurred_at: now(),
        };
        let neither = OrgUserPreferencesUpdated {
            organization_id: org,
            locale: Preference::Inherited,
            timezone: Preference::Inherited,
            occurred_at: now(),
        };

        assert_eq!(both.organization_id(), &org);
        assert_eq!(both.payload().get("locale"), Some("en-US"));
        assert_eq!(both.payload().get("timezone"), Some("Europe/Berlin"));
        assert!(neither.payload().is_empty());
    }

    /// Giving Ada Editor and Viewer records a grant naming her, Production and both roles.
    #[test]
    fn a_tenant_access_grant_names_the_member_tenant_and_roles() {
        let granted = granted_access();
        let org = granted.organization_id;
        let member = granted.org_user_id;
        let tenant = granted.tenant_id;

        assert_eq!(
            granted.event_type().as_str(),
            "organization.org_user_tenant_access_granted"
        );
        let payload = granted.payload();
        assert_eq!(granted.organization_id(), &org);
        assert_eq!(
            entity(&payload, "org_user"),
            (
                RefKind::ORG_USER,
                member.to_string(),
                "ada@acme.com".to_owned()
            )
        );
        assert_eq!(
            entity(&payload, "tenant"),
            (RefKind::TENANT, tenant.to_string(), "Production".to_owned())
        );
        assert_eq!(
            change(&payload, "roles"),
            (Some(String::new()), Some("Editor, Viewer".to_owned()))
        );
    }

    /// Removing Ada's Editor and Viewer roles records a withdrawal when none remain.
    #[test]
    fn removing_all_tenant_roles_records_a_withdrawal() {
        let mut withdrawn = granted_access();
        withdrawn.from_roles = std::mem::take(&mut withdrawn.to_roles);
        assert_eq!(
            withdrawn.event_type().as_str(),
            "organization.org_user_tenant_access_revoked"
        );
    }

    /// Ada's first grant of Editor and Viewer in Production at the epoch.
    fn granted_access() -> OrgUserTenantAccessChanged {
        OrgUserTenantAccessChanged {
            organization_id: OrganizationId::new(),
            org_user_id: OrgUserId::new(),
            org_user_label: EventLabel::of("ada@acme.com"),
            tenant_id: TenantId::new(),
            tenant_label: EventLabel::of("Production"),
            from_roles: Vec::new(),
            to_roles: vec![role("Editor"), role("Viewer")],
            occurred_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// Ada's access changes, and the record is read an hour later. It still
    /// gives the time of the change, not the time it was read.
    #[test]
    fn a_tenant_access_change_keeps_the_time_it_happened() {
        let happened = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let changed = OrgUserTenantAccessChanged {
            organization_id: OrganizationId::new(),
            org_user_id: OrgUserId::new(),
            org_user_label: EventLabel::of("ada@acme.com"),
            tenant_id: TenantId::new(),
            tenant_label: EventLabel::of("Production"),
            from_roles: Vec::new(),
            to_roles: vec![role("Viewer")],
            occurred_at: happened,
        };

        let _later = crate::shared::clock::freeze(happened + time::Duration::hours(1));

        assert_eq!(changed.occurred_at(), happened);
    }

    /// Ada's account goes from active to locked. The record holds both
    /// states, "Active" and "Locked".
    #[test]
    fn a_member_status_change_records_the_transition() {
        let org = OrganizationId::new();

        let event = OrgUserStatusChanged {
            organization_id: org,
            org_user_id: OrgUserId::new(),
            org_user_label: EventLabel::of("ada@acme.com"),
            from: OrgUserStatus::Active,
            to: OrgUserStatus::Locked,
            occurred_at: now(),
        };

        assert_eq!(event.organization_id(), &org);
        assert_eq!(
            change(&event.payload(), "status"),
            (Some("Active".to_owned()), Some("Locked".to_owned()))
        );
    }
}
