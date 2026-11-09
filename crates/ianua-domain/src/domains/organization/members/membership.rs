//! Organization roles, which decide how far an org user reaches across tenants.

use std::fmt;

use crate::domains::organization::members::permission::{
    MemberAction, OrgAuditAction, OrgBillingAction, OrgBrandingAction, OrgMetricsAction,
    OrgNotificationAction, OrgPermission, OrgSessionAction, OrganizationAction, TenantAction,
};

/// What a plain member may do on the organization plane: look around, and
/// keep their own notifications. Every change is an owner's or an admin's.
const MEMBER_RIGHTS: [OrgPermission; 10] = [
    OrgPermission::Organization(OrganizationAction::View),
    OrgPermission::Tenants(TenantAction::View),
    OrgPermission::Members(MemberAction::View),
    OrgPermission::AuditLog(OrgAuditAction::View),
    OrgPermission::AuditLog(OrgAuditAction::Export),
    OrgPermission::Notifications(OrgNotificationAction::View),
    OrgPermission::Notifications(OrgNotificationAction::Update),
    OrgPermission::Sessions(OrgSessionAction::View),
    OrgPermission::Metrics(OrgMetricsAction::View),
    OrgPermission::Branding(OrgBrandingAction::View),
];

/// What a viewer may do: read everything a member reads, and the bill too.
const VIEWER_RIGHTS: [OrgPermission; 11] = [
    OrgPermission::Organization(OrganizationAction::View),
    OrgPermission::Tenants(TenantAction::View),
    OrgPermission::Members(MemberAction::View),
    OrgPermission::AuditLog(OrgAuditAction::View),
    OrgPermission::AuditLog(OrgAuditAction::Export),
    OrgPermission::Notifications(OrgNotificationAction::View),
    OrgPermission::Notifications(OrgNotificationAction::Update),
    OrgPermission::Sessions(OrgSessionAction::View),
    OrgPermission::Metrics(OrgMetricsAction::View),
    OrgPermission::Branding(OrgBrandingAction::View),
    OrgPermission::Billing(OrgBillingAction::View),
];

/// What a billing contact may do: run the subscription, and read what they
/// need to see the bill is right.
const BILLING_RIGHTS: [OrgPermission; 5] = [
    OrgPermission::Organization(OrganizationAction::View),
    OrgPermission::Billing(OrgBillingAction::Manage),
    OrgPermission::Metrics(OrgMetricsAction::View),
    OrgPermission::Notifications(OrgNotificationAction::View),
    OrgPermission::Notifications(OrgNotificationAction::Update),
];

/// What only an owner may do, of everything an admin otherwise may: close
/// the organization, and change what it pays.
const OWNER_ONLY: [OrgPermission; 2] = [
    OrgPermission::Organization(OrganizationAction::Close),
    OrgPermission::Billing(OrgBillingAction::Update),
];

/// The role an org user holds within an organization.
///
/// Each membership stores one role. An `Owner` runs the organization and
/// reaches every tenant in it. An `Admin` runs it day to day and reaches
/// every tenant too, but neither closes it nor changes what it pays. A
/// `Billing` contact runs the subscription and reaches no tenant. A `Member`
/// reads the organization and reaches the tenants granted to them. A `Viewer`
/// reads the organization, its bill included, and reaches no tenant.
///
/// The order runs from the least to the most authority, so a role left
/// unset is the least.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgRole {
    /// Reads the organization, its bill included. Reaches no tenant.
    #[default]
    Viewer,

    /// Runs the subscription and its payment. Reaches no tenant.
    Billing,

    /// Can see the org dashboard and switch between tenants.
    /// Tenant access is controlled by per-tenant roles.
    Member,

    /// Runs the organization day to day, with implicit full access to every
    /// tenant, but does not close it or change what it pays.
    Admin,

    /// Full control over the organization and implicit full
    /// access to every tenant within it.
    Owner,
}

/// How far a role reaches into the organization's tenants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantReach {
    /// Every tenant of the organization, with no grant needed.
    Every,
    /// The tenants the member was granted, one by one.
    Granted,
    /// No tenant at all, granted or not.
    Nothing,
}

impl OrgRole {
    /// Every role, from the least authority to the most.
    pub const ALL: [Self; 5] = [
        Self::Viewer,
        Self::Billing,
        Self::Member,
        Self::Admin,
        Self::Owner,
    ];

    /// Whether this role has implicit full access to all tenants.
    #[must_use]
    pub fn has_implicit_tenant_access(&self) -> bool {
        self.tenant_reach() == TenantReach::Every
    }

    /// How far this role reaches into the organization's tenants.
    ///
    /// Bob is the billing contact. Without this, a tenant grant handed to
    /// him by mistake lets the person who pays the bill read every user's
    /// sessions.
    #[must_use]
    pub fn tenant_reach(self) -> TenantReach {
        match self {
            Self::Owner | Self::Admin => TenantReach::Every,
            Self::Member => TenantReach::Granted,
            Self::Billing | Self::Viewer => TenantReach::Nothing,
        }
    }

    /// Whether this role lets its holder do `permission`.
    ///
    /// An owner may do everything. An admin may do everything but close the
    /// organization or change what it pays. A billing contact runs the
    /// subscription. A member and a viewer only read, and mark their own
    /// notifications read. Sam is a member. Without this table, he resets
    /// another member's password because nothing says he may not.
    #[must_use]
    pub fn grants(self, permission: &OrgPermission) -> bool {
        match self {
            Self::Owner => true,
            Self::Admin => !OWNER_ONLY.iter().any(|kept| permission.implies(kept)),
            Self::Billing => carried_by(&BILLING_RIGHTS, permission),
            Self::Member => carried_by(&MEMBER_RIGHTS, permission),
            Self::Viewer => carried_by(&VIEWER_RIGHTS, permission),
        }
    }

    /// Whether a holder of this role may give `role` to someone, take it
    /// away, or act on someone who holds it.
    ///
    /// Only an owner makes an owner or a billing contact: one reaches every
    /// tenant, the other decides what the organization pays. An admin makes
    /// admins. Anyone with the member right makes members and viewers.
    #[must_use]
    pub fn may_hand_out(self, role: Self) -> bool {
        match role {
            Self::Owner | Self::Billing => self == Self::Owner,
            Self::Admin => matches!(self, Self::Owner | Self::Admin),
            Self::Member | Self::Viewer => true,
        }
    }

    /// Whether a holder of this role still acts while the organization is
    /// suspended: owners, to settle what caused it, and the billing contact,
    /// to pay what is owed.
    #[must_use]
    pub fn acts_while_suspended(self) -> bool {
        matches!(self, Self::Owner | Self::Billing)
    }

    /// The stable wire/storage name of this role.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "Viewer",
            Self::Billing => "Billing",
            Self::Member => "Member",
            Self::Admin => "Admin",
            Self::Owner => "Owner",
        }
    }

    /// Parses a stored role name.
    ///
    /// Returns `None` for anything the domain does not define, which the
    /// storage adapter reports as corrupted data rather than bad input.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == value)
    }
}

impl fmt::Display for OrgRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether one of `rights` implies `permission`.
fn carried_by(rights: &[OrgPermission], permission: &OrgPermission) -> bool {
    rights.iter().any(|right| right.implies(permission))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::organization::members::permission::OrgApiKeyAction;

    /// An owner reaches every tenant of the organization without a role in
    /// each.
    #[test]
    fn owner_has_full_access() {
        assert!(OrgRole::Owner.has_implicit_tenant_access());
    }

    /// An admin reaches every tenant too, as the person who runs the
    /// organization day to day.
    #[test]
    fn an_admin_reaches_every_tenant() {
        assert_eq!(OrgRole::Admin.tenant_reach(), TenantReach::Every);
    }

    /// A member reaches no tenant by their org role alone. They need a role
    /// in each tenant.
    #[test]
    fn member_has_no_implicit_access() {
        assert!(!OrgRole::Member.has_implicit_tenant_access());
        assert_eq!(OrgRole::Member.tenant_reach(), TenantReach::Granted);
    }

    /// Billing and viewer roles both have no tenant reach.
    #[test]
    fn billing_and_viewer_reach_no_tenant() {
        assert_eq!(OrgRole::Billing.tenant_reach(), TenantReach::Nothing);
        assert_eq!(OrgRole::Viewer.tenant_reach(), TenantReach::Nothing);
    }

    /// Members lack update, invitation, key creation and sign-in settings
    /// rights that owners have. Reading members and updating notifications
    /// remain permitted for members.
    #[test]
    fn a_member_role_grants_reading_but_no_changes() {
        let changes = [
            OrgPermission::Members(MemberAction::Update),
            OrgPermission::Members(MemberAction::Invite),
            OrgPermission::ApiKeys(OrgApiKeyAction::Create),
            OrgPermission::Organization(OrganizationAction::AuthConfig),
        ];

        for change in changes {
            assert!(!OrgRole::Member.grants(&change), "{change}");
            assert!(OrgRole::Owner.grants(&change), "{change}");
        }
        assert!(OrgRole::Member.grants(&OrgPermission::Members(MemberAction::View)));
        assert!(
            OrgRole::Member.grants(&OrgPermission::Notifications(OrgNotificationAction::Update))
        );
    }

    /// Ann, an admin, invites people, mints keys and changes the sign-in
    /// settings, as an owner would.
    #[test]
    fn an_admin_runs_the_organization() {
        for right in [
            OrgPermission::Members(MemberAction::Invite),
            OrgPermission::ApiKeys(OrgApiKeyAction::Create),
            OrgPermission::Organization(OrganizationAction::AuthConfig),
            OrgPermission::Billing(OrgBillingAction::View),
        ] {
            assert!(OrgRole::Admin.grants(&right), "{right}");
        }
    }

    /// Admins lack closure and billing-update rights, including their
    /// broader manage rights; owners hold all four.
    #[test]
    fn an_admin_neither_closes_nor_changes_what_it_pays() {
        for right in [
            OrgPermission::Organization(OrganizationAction::Close),
            OrgPermission::Organization(OrganizationAction::Manage),
            OrgPermission::Billing(OrgBillingAction::Update),
            OrgPermission::Billing(OrgBillingAction::Manage),
        ] {
            assert!(!OrgRole::Admin.grants(&right), "{right}");
            assert!(OrgRole::Owner.grants(&right), "{right}");
        }
    }

    /// Bob, the billing contact, chooses a plan, but may neither list the
    /// members nor change one.
    #[test]
    fn a_billing_contact_runs_only_the_bill() {
        assert!(OrgRole::Billing.grants(&OrgPermission::Billing(OrgBillingAction::Update)));
        assert!(!OrgRole::Billing.grants(&OrgPermission::Members(MemberAction::View)));
        assert!(!OrgRole::Billing.grants(&OrgPermission::Members(MemberAction::Update)));
    }

    /// Vera, a viewer, reads the bill and the audit log, and changes
    /// neither the plan nor any member.
    #[test]
    fn a_viewer_reads_and_changes_nothing() {
        assert!(OrgRole::Viewer.grants(&OrgPermission::Billing(OrgBillingAction::View)));
        assert!(OrgRole::Viewer.grants(&OrgPermission::AuditLog(OrgAuditAction::View)));
        assert!(!OrgRole::Viewer.grants(&OrgPermission::Billing(OrgBillingAction::Update)));
        assert!(!OrgRole::Viewer.grants(&OrgPermission::Members(MemberAction::Update)));
    }

    /// Every role that reads the organization's audit log exports it too,
    /// as each did before exporting needed a right of its own. The billing
    /// contact, who reads no log, exports none.
    #[test]
    fn every_role_reading_the_audit_log_exports_it() {
        let view = OrgPermission::AuditLog(OrgAuditAction::View);
        let export = OrgPermission::AuditLog(OrgAuditAction::Export);

        for role in OrgRole::ALL {
            assert_eq!(role.grants(&export), role.grants(&view), "{role}");
        }
        assert!(!OrgRole::Billing.grants(&export));
    }

    /// Admins cannot assign owner or billing roles, but may assign admin
    /// and viewer roles. Owners may assign owner and billing roles.
    #[test]
    fn only_an_owner_hands_out_owner_and_billing() {
        assert!(!OrgRole::Admin.may_hand_out(OrgRole::Owner));
        assert!(!OrgRole::Admin.may_hand_out(OrgRole::Billing));
        assert!(OrgRole::Admin.may_hand_out(OrgRole::Admin));
        assert!(OrgRole::Admin.may_hand_out(OrgRole::Viewer));
        assert!(OrgRole::Owner.may_hand_out(OrgRole::Owner));
        assert!(OrgRole::Owner.may_hand_out(OrgRole::Billing));
    }

    /// The member role permits handing out member status, but not admin
    /// status.
    #[test]
    fn a_member_hands_out_no_admin() {
        assert!(!OrgRole::Member.may_hand_out(OrgRole::Admin));
        assert!(OrgRole::Member.may_hand_out(OrgRole::Member));
    }

    /// While Acme is suspended, its owners and its billing contact still act,
    /// so the bill can be paid. Admins, members and viewers wait.
    #[test]
    fn only_owners_and_billing_act_while_suspended() {
        assert!(OrgRole::Owner.acts_while_suspended());
        assert!(OrgRole::Billing.acts_while_suspended());
        assert!(!OrgRole::Admin.acts_while_suspended());
        assert!(!OrgRole::Member.acts_while_suspended());
        assert!(!OrgRole::Viewer.acts_while_suspended());
    }

    /// Owner ranks above admin, and admin above member, which the access
    /// check compares against.
    #[test]
    fn roles_are_ordered() {
        assert!(OrgRole::Owner > OrgRole::Admin);
        assert!(OrgRole::Admin > OrgRole::Member);
    }

    /// A role left unset starts as viewer, never as owner.
    #[test]
    fn default_is_the_least_privileged_role() {
        assert_eq!(OrgRole::default(), OrgRole::Viewer);
    }

    /// Each role is written by its stored name and read back. It comes back
    /// as the same role.
    #[test]
    fn parse_round_trips_every_variant() {
        for role in OrgRole::ALL {
            assert_eq!(OrgRole::parse(role.as_str()), Some(role));
        }
    }

    /// A stored role of `Superuser`, or `owner` in lower case, reads as no
    /// role. The storage adapter then reports the row as corrupt.
    #[test]
    fn parse_rejects_unknown_names() {
        assert_eq!(OrgRole::parse("Superuser"), None);
        assert_eq!(OrgRole::parse("owner"), None);
    }

    /// Each role prints as its stored name, such as `Owner`, and that text
    /// reads back as the same role. So an audit line always names a real role.
    #[test]
    fn a_role_displays_as_the_name_it_parses_back_from() {
        for role in OrgRole::ALL {
            assert_eq!(role.to_string(), role.as_str());
            assert_eq!(OrgRole::parse(&role.to_string()), Some(role));
        }
        assert_eq!(OrgRole::Owner.to_string(), "Owner");
    }
}
