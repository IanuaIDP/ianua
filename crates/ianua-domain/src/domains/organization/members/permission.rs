//! Org-plane permissions, which say what an organization credential may do.
//!
//! The tenant plane has [`SystemPermission`](crate::domains::authorization::permission::SystemPermission),
//! written `idp:<domain>:<action>`. This is the same idea one level up,
//! written `org:<domain>:<action>`. The two never overlap. A scope names
//! exactly one realm, so an org key cannot reach a tenant permission and a
//! tenant key cannot reach an org one.
//!
//! Org users get their authority from their [`OrgRole`](crate::domains::organization::members::membership::OrgRole),
//! not from a permission list. These permissions let a *credential* carry
//! less than the role of whoever issued it. Both limits apply. The role says
//! what its holder may do. The scopes say how much of that one key carries.

use std::fmt;

use crate::types::Scope;

/// Actions on the organization itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrganizationAction {
    /// Full control. Implies every other organization action.
    Manage,
    /// Read the organization profile.
    View,
    /// Change the profile and its linked identities.
    Update,
    /// Suspend or reactivate the organization.
    Suspend,
    /// Close the organization.
    Close,
    /// Read or replace the organization's sign-in settings.
    ///
    /// Kept apart from [`Self::Update`] because these settings decide who can
    /// reach the management plane at all. Sam may edit the contact email.
    /// That alone must not let him change who can sign in.
    AuthConfig,
}

/// Actions on the organization's tenants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TenantAction {
    /// Full control. Implies every other tenant action.
    Manage,
    /// List and read tenants.
    View,
    /// Provision a new tenant.
    Create,
    /// Move a tenant through its lifecycle.
    Update,
    /// Delete a tenant.
    Delete,
}

/// Actions on the organization's members and invitations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MemberAction {
    /// Full control. Implies every other member action.
    Manage,
    /// List and read members.
    View,
    /// Invite a member, and resend or revoke that invitation.
    Invite,
    /// Create a member directly.
    Create,
    /// Change a member's status, role, or password.
    Update,
    /// Remove a member.
    Remove,
}

/// Actions on which tenants a member may enter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TenantAccessAction {
    /// Full control. Implies every other tenant-access action.
    Manage,
    /// Read a member's tenant grants.
    View,
}

/// Actions on the organization's own API keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgApiKeyAction {
    /// Full control. Implies every other API key action.
    Manage,
    /// List keys.
    View,
    /// Mint a key.
    Create,
    /// Revoke a key.
    Revoke,
}

/// Actions on the organization's audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgAuditAction {
    /// Read the audit log and the activity feed.
    View,
    /// Export the audit log in bulk.
    Export,
}

/// Actions on the organization's notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgNotificationAction {
    /// Full control. Implies every other notification action.
    Manage,
    /// Read notifications and their unread count.
    View,
    /// Mark notifications read.
    Update,
}

/// Actions on the organization's active sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgSessionAction {
    /// List who is currently signed in.
    View,
}

/// Actions on the organization's metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgMetricsAction {
    /// Read the organization's metrics overview.
    View,
}

/// Actions on what the organization pays for: its subscription, its payment
/// method and its plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgBillingAction {
    /// Full control. Implies every other billing action.
    Manage,
    /// Read the subscription, its trial and its payment standing.
    View,
    /// Choose a plan or change how it is paid for.
    Update,
}

/// Actions on how the organization's own pages and mail look.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgBrandingAction {
    /// Full control. Implies every other branding action.
    Manage,
    /// Read the organization's branding.
    View,
    /// Change the logo, the colors or the sender name.
    Update,
}

/// A permission on the organization plane.
///
/// Renders as `org:<domain>:<action>` and parses back from the same string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OrgPermission {
    /// The organization profile and its lifecycle.
    Organization(OrganizationAction),
    /// The organization's tenants.
    Tenants(TenantAction),
    /// The organization's members and invitations.
    Members(MemberAction),
    /// Which tenants a member may enter.
    TenantAccess(TenantAccessAction),
    /// The organization's own API keys.
    ApiKeys(OrgApiKeyAction),
    /// The organization's audit trail.
    AuditLog(OrgAuditAction),
    /// The organization's notifications.
    Notifications(OrgNotificationAction),
    /// The organization's active sessions.
    Sessions(OrgSessionAction),
    /// The organization's metrics.
    Metrics(OrgMetricsAction),
    /// The organization's subscription and payment.
    Billing(OrgBillingAction),
    /// The organization's own look.
    Branding(OrgBrandingAction),
}

/// The realm segment every org scope must name.
const REALM: &str = "org:";

impl OrgPermission {
    /// Every permission on this plane, finest grain included.
    pub const ALL_VARIANTS: &'static [OrgPermission] = &[
        Self::Organization(OrganizationAction::Manage),
        Self::Organization(OrganizationAction::View),
        Self::Organization(OrganizationAction::Update),
        Self::Organization(OrganizationAction::Suspend),
        Self::Organization(OrganizationAction::Close),
        Self::Organization(OrganizationAction::AuthConfig),
        Self::Tenants(TenantAction::Manage),
        Self::Tenants(TenantAction::View),
        Self::Tenants(TenantAction::Create),
        Self::Tenants(TenantAction::Update),
        Self::Tenants(TenantAction::Delete),
        Self::Members(MemberAction::Manage),
        Self::Members(MemberAction::View),
        Self::Members(MemberAction::Invite),
        Self::Members(MemberAction::Create),
        Self::Members(MemberAction::Update),
        Self::Members(MemberAction::Remove),
        Self::TenantAccess(TenantAccessAction::Manage),
        Self::TenantAccess(TenantAccessAction::View),
        Self::ApiKeys(OrgApiKeyAction::Manage),
        Self::ApiKeys(OrgApiKeyAction::View),
        Self::ApiKeys(OrgApiKeyAction::Create),
        Self::ApiKeys(OrgApiKeyAction::Revoke),
        Self::AuditLog(OrgAuditAction::View),
        Self::AuditLog(OrgAuditAction::Export),
        Self::Notifications(OrgNotificationAction::Manage),
        Self::Notifications(OrgNotificationAction::View),
        Self::Notifications(OrgNotificationAction::Update),
        Self::Sessions(OrgSessionAction::View),
        Self::Metrics(OrgMetricsAction::View),
        Self::Billing(OrgBillingAction::Manage),
        Self::Billing(OrgBillingAction::View),
        Self::Billing(OrgBillingAction::Update),
        Self::Branding(OrgBrandingAction::Manage),
        Self::Branding(OrgBrandingAction::View),
        Self::Branding(OrgBrandingAction::Update),
    ];

    /// Whether `self` implies `other`.
    ///
    /// `Manage` implies every action in the same domain. One rule crosses
    /// domains. Any authority over members carries the right to read their
    /// tenant access, because the member listing includes it. Changing grants
    /// still needs `TenantAccess` itself.
    #[must_use]
    pub fn implies(&self, other: &Self) -> bool {
        self == other
            || matches!(
                (self, other),
                (
                    Self::Members(_),
                    Self::TenantAccess(TenantAccessAction::View)
                ) | (
                    Self::Organization(OrganizationAction::Manage),
                    Self::Organization(_)
                ) | (Self::Tenants(TenantAction::Manage), Self::Tenants(_))
                    | (Self::Members(MemberAction::Manage), Self::Members(_))
                    | (
                        Self::TenantAccess(TenantAccessAction::Manage),
                        Self::TenantAccess(_)
                    )
                    | (Self::ApiKeys(OrgApiKeyAction::Manage), Self::ApiKeys(_))
                    | (
                        Self::Notifications(OrgNotificationAction::Manage),
                        Self::Notifications(_)
                    )
                    | (Self::Billing(OrgBillingAction::Manage), Self::Billing(_))
                    | (Self::Branding(OrgBrandingAction::Manage), Self::Branding(_))
            )
    }

    /// Parses a permission from its `org:<domain>:<action>` rendering.
    ///
    /// The inverse of [`Display`](std::fmt::Display). Unlike the tenant
    /// plane's parser, this accepts only the full form with the realm.
    /// Without it, `api_keys:view` could mean either plane.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        Self::ALL_VARIANTS
            .iter()
            .copied()
            .find(|perm| perm.to_string() == trimmed)
    }

    /// Whether `scopes` admit this permission.
    ///
    /// Deny by default. An empty list admits nothing.
    #[must_use]
    pub fn granted_by(&self, scopes: &[Scope]) -> bool {
        scopes.iter().any(|scope| self.is_named_by(scope))
    }

    /// Whether `scope` names this permission, directly or by implication.
    ///
    /// The realm segment is matched exactly, so `*:*:*` names nothing here
    /// and no single scope spans both planes. Past the realm, `*` stands for
    /// one segment. A scope that parses as an implying permission also
    /// counts, so `org:tenants:manage` reaches every tenant action.
    #[must_use]
    pub fn is_named_by(&self, scope: &Scope) -> bool {
        if !scope.as_str().starts_with(REALM) {
            return false;
        }

        scope.permits(&self.to_string())
            || Self::parse(scope.as_str()).is_some_and(|granted| granted.implies(self))
    }

    /// Whether `scope` reaches at least one permission on this plane.
    #[must_use]
    pub fn is_recognized_scope(scope: &Scope) -> bool {
        Self::ALL_VARIANTS.iter().any(|p| p.is_named_by(scope))
    }

    /// Whether someone holding `held` may hand out `scope`. They must hold
    /// every permission it reaches, so a key they mint never does more than
    /// they could themselves.
    #[must_use]
    pub fn may_grant_scope(held: &[Self], scope: &Scope) -> bool {
        Self::ALL_VARIANTS
            .iter()
            .filter(|permission| permission.is_named_by(scope))
            .all(|permission| held.iter().any(|holding| holding.implies(permission)))
    }

    /// The domain this permission belongs to, for UI grouping.
    #[must_use]
    pub fn domain(&self) -> &'static str {
        match self {
            Self::Organization(_) => "organization",
            Self::Tenants(_) => "tenants",
            Self::Members(_) => "members",
            Self::TenantAccess(_) => "tenant_access",
            Self::ApiKeys(_) => "api_keys",
            Self::AuditLog(_) => "audit_log",
            Self::Notifications(_) => "notifications",
            Self::Sessions(_) => "sessions",
            Self::Metrics(_) => "metrics",
            Self::Billing(_) => "billing",
            Self::Branding(_) => "branding",
        }
    }
}

impl fmt::Display for OrgPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self {
            Self::Organization(a) => action_str_organization(*a),
            Self::Tenants(a) => action_str_tenant(*a),
            Self::Members(a) => action_str_member(*a),
            Self::TenantAccess(a) => action_str_tenant_access(*a),
            Self::ApiKeys(a) => action_str_api_key(*a),
            Self::AuditLog(a) => action_str_audit(*a),
            Self::Notifications(a) => action_str_notification(*a),
            Self::Sessions(OrgSessionAction::View) | Self::Metrics(OrgMetricsAction::View) => {
                "view"
            }
            Self::Billing(a) => action_str_billing(*a),
            Self::Branding(a) => action_str_branding(*a),
        };
        write!(f, "org:{}:{action}", self.domain())
    }
}

fn action_str_organization(a: OrganizationAction) -> &'static str {
    match a {
        OrganizationAction::Manage => "manage",
        OrganizationAction::View => "view",
        OrganizationAction::Update => "update",
        OrganizationAction::Suspend => "suspend",
        OrganizationAction::Close => "close",
        OrganizationAction::AuthConfig => "auth_config",
    }
}

fn action_str_tenant(a: TenantAction) -> &'static str {
    match a {
        TenantAction::Manage => "manage",
        TenantAction::View => "view",
        TenantAction::Create => "create",
        TenantAction::Update => "update",
        TenantAction::Delete => "delete",
    }
}

fn action_str_member(a: MemberAction) -> &'static str {
    match a {
        MemberAction::Manage => "manage",
        MemberAction::View => "view",
        MemberAction::Invite => "invite",
        MemberAction::Create => "create",
        MemberAction::Update => "update",
        MemberAction::Remove => "remove",
    }
}

fn action_str_tenant_access(a: TenantAccessAction) -> &'static str {
    match a {
        TenantAccessAction::Manage => "manage",
        TenantAccessAction::View => "view",
    }
}

fn action_str_api_key(a: OrgApiKeyAction) -> &'static str {
    match a {
        OrgApiKeyAction::Manage => "manage",
        OrgApiKeyAction::View => "view",
        OrgApiKeyAction::Create => "create",
        OrgApiKeyAction::Revoke => "revoke",
    }
}

fn action_str_audit(a: OrgAuditAction) -> &'static str {
    match a {
        OrgAuditAction::View => "view",
        OrgAuditAction::Export => "export",
    }
}

fn action_str_notification(a: OrgNotificationAction) -> &'static str {
    match a {
        OrgNotificationAction::Manage => "manage",
        OrgNotificationAction::View => "view",
        OrgNotificationAction::Update => "update",
    }
}

/// The action segment of a billing permission.
fn action_str_billing(a: OrgBillingAction) -> &'static str {
    match a {
        OrgBillingAction::Manage => "manage",
        OrgBillingAction::View => "view",
        OrgBillingAction::Update => "update",
    }
}

/// The action segment of a branding permission.
fn action_str_branding(a: OrgBrandingAction) -> &'static str {
    match a {
        OrgBrandingAction::Manage => "manage",
        OrgBrandingAction::View => "view",
        OrgBrandingAction::Update => "update",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(s: &str) -> Scope {
        Scope::new(s).unwrap()
    }

    /// Every org permission is printed as `org:<domain>:<action>` and parsed
    /// back. It comes back as the same permission.
    #[test]
    fn display_and_parse_round_trip_every_variant() {
        for perm in OrgPermission::ALL_VARIANTS {
            assert_eq!(OrgPermission::parse(&perm.to_string()), Some(*perm));
        }
    }

    /// `org:tenants:explode` names no action, and `idp:users:view` is a
    /// tenant permission. Neither parses as an org permission.
    #[test]
    fn parse_rejects_unknown() {
        assert!(OrgPermission::parse("org:tenants:explode").is_none());
        assert!(OrgPermission::parse("idp:users:view").is_none());
    }

    /// `tenants:view` and `api_keys:view` leave out the `org:` realm. Neither
    /// parses, since without it the scope could mean either plane.
    #[test]
    fn parse_rejects_the_bare_form() {
        assert!(OrgPermission::parse("tenants:view").is_none());
        assert!(OrgPermission::parse("api_keys:view").is_none());
    }

    /// A key with no scopes asks to view tenants. It is not allowed, since an
    /// empty list grants nothing.
    #[test]
    fn no_scope_grants_nothing() {
        assert!(!OrgPermission::Tenants(TenantAction::View).granted_by(&[]));
    }

    /// A key holds `org:tenants:create`. It may create tenants but not
    /// delete them.
    #[test]
    fn an_exact_scope_grants_only_that_permission() {
        let granted = [scope("org:tenants:create")];

        assert!(OrgPermission::Tenants(TenantAction::Create).granted_by(&granted));
        assert!(!OrgPermission::Tenants(TenantAction::Delete).granted_by(&granted));
    }

    /// A key holds `org:tenants:manage`. It may delete tenants, but may not
    /// remove members, which is another domain.
    #[test]
    fn a_manage_scope_grants_every_action_in_its_domain() {
        let granted = [scope("org:tenants:manage")];

        assert!(OrgPermission::Tenants(TenantAction::Delete).granted_by(&granted));
        assert!(!OrgPermission::Members(MemberAction::Remove).granted_by(&granted));
    }

    /// Keys holding `org:tenants:*`, `org:*:view` and `org:*:*` each reach
    /// the permissions their `*` covers, one segment at a time.
    #[test]
    fn a_star_stands_for_one_segment_past_the_realm() {
        assert!(OrgPermission::Tenants(TenantAction::Delete).granted_by(&[scope("org:tenants:*")]));
        assert!(OrgPermission::Members(MemberAction::View).granted_by(&[scope("org:*:view")]));
        assert!(OrgPermission::Tenants(TenantAction::Create).granted_by(&[scope("org:*:*")]));
    }

    /// Scopes with a wildcard realm cannot grant organization tenant
    /// creation, even when their remaining segments match.
    #[test]
    fn the_realm_is_never_a_wildcard() {
        assert!(!OrgPermission::Tenants(TenantAction::Create).granted_by(&[scope("*:*:*")]));
        assert!(
            !OrgPermission::Tenants(TenantAction::Create).granted_by(&[scope("*:tenants:create")])
        );
    }

    /// Exact and wildcard tenant-plane scopes cannot grant organization
    /// API-key viewing.
    #[test]
    fn a_tenant_plane_scope_grants_nothing_here() {
        assert!(
            !OrgPermission::ApiKeys(OrgApiKeyAction::View)
                .granted_by(&[scope("idp:api_keys:view")])
        );
        assert!(!OrgPermission::ApiKeys(OrgApiKeyAction::View).granted_by(&[scope("idp:*:*")]));
    }

    /// A key holds `org:tenants` with no action. It does not reach deleting
    /// tenants, since a scope is not matched as a prefix.
    #[test]
    fn a_shorter_scope_is_not_a_prefix() {
        assert!(!OrgPermission::Tenants(TenantAction::Delete).granted_by(&[scope("org:tenants")]));
    }

    /// A key holds `org:members:view`. It may read tenant access, which the
    /// member listing shows, but may not change it.
    #[test]
    fn member_authority_carries_reading_tenant_access() {
        let granted = [scope("org:members:view")];

        assert!(OrgPermission::TenantAccess(TenantAccessAction::View).granted_by(&granted));
        assert!(!OrgPermission::TenantAccess(TenantAccessAction::Manage).granted_by(&granted));
    }

    /// A key holds `org:billing:manage`. It may choose a plan, but may not
    /// change the organization's branding, which is another domain.
    #[test]
    fn billing_manage_stays_inside_billing() {
        let granted = [scope("org:billing:manage")];

        assert!(OrgPermission::Billing(OrgBillingAction::Update).granted_by(&granted));
        assert!(!OrgPermission::Branding(OrgBrandingAction::Update).granted_by(&granted));
    }

    /// `org:billing:view` and `org:branding:update` print and parse as
    /// themselves, as every other org permission does.
    #[test]
    fn billing_and_branding_render_under_their_own_domains() {
        assert_eq!(
            OrgPermission::Billing(OrgBillingAction::View).to_string(),
            "org:billing:view"
        );
        assert_eq!(
            OrgPermission::parse("org:branding:update"),
            Some(OrgPermission::Branding(OrgBrandingAction::Update))
        );
    }

    /// `org:tenants:view` and `org:tenants:*` are known scopes. A scope with
    /// no realm, an unknown domain, or a bare `*` is not.
    #[test]
    fn recognized_scopes_are_realm_qualified() {
        assert!(OrgPermission::is_recognized_scope(&scope(
            "org:tenants:view"
        )));
        assert!(OrgPermission::is_recognized_scope(&scope("org:tenants:*")));
        assert!(!OrgPermission::is_recognized_scope(&scope("tenants:view")));
        assert!(!OrgPermission::is_recognized_scope(&scope(
            "org:projects:read"
        )));
        assert!(!OrgPermission::is_recognized_scope(&scope("*")));
    }
}
