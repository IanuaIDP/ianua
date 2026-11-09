//! Permissions the platform defines and enforces.

use std::fmt;

use crate::domains::authorization::permission::{
    AgentAction, ApiKeyAction, AuditLogAction, AuthConfigAction, BrandingAction,
    ClassificationAction, ComplianceAction, ConsumersAction, CryptoAction, DataAccessAction,
    DomainAction, FederationAction, MANAGE, MessagingAction, MetricsAction, MtlsAction,
    PipelineAction, PolicySetAction, REALM, RoleAction, RoutingAction, ScimAction, SignalsAction,
    TenantSettingsAction, UserAction, VIEW, WebhooksAction, WorkflowAction,
};
use crate::types::{PermissionName, Scope};

/// Permissions built into the `IdP` for running a tenant.
///
/// They are grouped by area. Each area has a `Manage` action that covers all
/// its other actions, and single actions for finer roles.
///
/// Tenant admins put these on roles, and users get them through their roles.
/// The UI shows each area as a "Manage all" toggle with a checkbox per action
/// below it.
///
/// # Delegation rule
///
/// A user can only grant permissions they hold themselves. Someone with an
/// area's `Manage` can grant any action in that area. Someone with single
/// actions can grant only those actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SystemPermission {
    /// User management permissions.
    Users(UserAction),
    /// Role and assignment management.
    Roles(RoleAction),
    /// Authentication configuration.
    AuthConfig(AuthConfigAction),
    /// Federation (SAML/OIDC) management.
    Federation(FederationAction),
    /// Audit log access.
    AuditLog(AuditLogAction),
    /// Branding configuration.
    Branding(BrandingAction),
    /// API key and OAuth client management.
    ApiKeys(ApiKeyAction),
    /// Compliance posture management.
    Compliance(ComplianceAction),
    /// The tenant's mTLS trust anchor.
    Mtls(MtlsAction),
    /// SCIM provisioning configuration.
    Scim(ScimAction),
    /// Signing key and algorithm migration management.
    Crypto(CryptoAction),
    /// Data classification rule management.
    Classification(ClassificationAction),
    /// How sensitive a data class someone may see.
    Data(DataAccessAction),
    /// The tenant's authorization policy, its rules and their rollout.
    PolicySet(PolicySetAction),
    /// Route management.
    Routing(RoutingAction),
    /// Proxy pipeline management.
    Pipeline(PipelineAction),
    /// Signal stream management.
    Signals(SignalsAction),
    /// Webhook subscription management.
    Webhooks(WebhooksAction),
    /// Consumer management. Consumers are the non-human callers a tenant lets
    /// through.
    Consumers(ConsumersAction),
    /// Tenant messaging: topics, subscriptions and publishing.
    Messaging(MessagingAction),
    /// Agent identity and delegation management.
    Agents(AgentAction),
    /// The tenant's custom domains.
    Domains(DomainAction),
    /// The tenant's own settings.
    ///
    /// Stored roles may carry the tag `{"Settings": "View"}`. The
    /// `serde(alias)` reads that tag as this one. Writes always use
    /// `TenantSettings`.
    #[cfg_attr(feature = "serde", serde(alias = "Settings"))]
    TenantSettings(TenantSettingsAction),
    /// The tenant's metrics overview.
    Metrics(MetricsAction),
    /// Workflows, their executions and the integration accounts they use.
    Workflows(WorkflowAction),
}

/// Short names for common permissions, mostly each area's `Manage`.
///
/// `SystemPermission::ManageUsers` reads better than
/// `SystemPermission::Users(UserAction::Manage)`, and both are the same value.
#[allow(non_upper_case_globals)]
impl SystemPermission {
    /// Full user management. Covers View, Create, Update, Deactivate, Delete.
    pub const ManageUsers: Self = Self::Users(UserAction::Manage);
    /// Full role management. Covers View, Create, Update, Delete, Assign,
    /// Escalate.
    pub const ManageRoles: Self = Self::Roles(RoleAction::Manage);
    /// Full auth config management. Covers View, Update.
    pub const ManageAuthConfig: Self = Self::AuthConfig(AuthConfigAction::Manage);
    /// Full federation management. Covers View, Create, Update, Delete.
    pub const ManageFederation: Self = Self::Federation(FederationAction::Manage);
    /// View the audit log. The audit log has no `Manage` action.
    pub const ViewAuditLog: Self = Self::AuditLog(AuditLogAction::View);
    /// Export the audit log in bulk. Viewing it does not cover this.
    pub const ExportAuditLog: Self = Self::AuditLog(AuditLogAction::Export);
    /// Full branding management. Covers View, Update.
    pub const ManageBranding: Self = Self::Branding(BrandingAction::Manage);
    /// Full API key management. Covers View, Create, Update, Revoke.
    pub const ManageApiKeys: Self = Self::ApiKeys(ApiKeyAction::Manage);
    /// Full compliance management. Covers View, Update.
    pub const ManageCompliance: Self = Self::Compliance(ComplianceAction::Manage);
    /// Full mTLS management. Covers View, Update.
    pub const ManageMtls: Self = Self::Mtls(MtlsAction::Manage);
    /// Full SCIM management. Covers View, Configure.
    pub const ManageScim: Self = Self::Scim(ScimAction::Manage);
    /// Full crypto management. Covers View, Update.
    pub const ManageCrypto: Self = Self::Crypto(CryptoAction::Manage);
    /// Full classification management. Covers View, Update.
    pub const ManageClassification: Self = Self::Classification(ClassificationAction::Manage);
    /// Full policy management. Covers View, Update, Activate.
    pub const ManagePolicy: Self = Self::PolicySet(PolicySetAction::Manage);
    /// Full routing management. Covers View, Create, Update, Delete.
    pub const ManageRouting: Self = Self::Routing(RoutingAction::Manage);
    /// Full pipeline management. Covers View, Update.
    pub const ManagePipeline: Self = Self::Pipeline(PipelineAction::Manage);
    /// Full signals management. Covers View, Update.
    pub const ManageSignals: Self = Self::Signals(SignalsAction::Manage);
    /// Full webhooks management. Covers View, Update.
    pub const ManageWebhooks: Self = Self::Webhooks(WebhooksAction::Manage);
    /// Full consumer management. Covers View, Create, Update, Delete.
    pub const ManageConsumers: Self = Self::Consumers(ConsumersAction::Manage);
    /// Full agent management. Covers View, Create, Update, Delete, Delegate,
    /// Approve.
    pub const ManageAgents: Self = Self::Agents(AgentAction::Manage);
    /// Full domain management. Covers View, Create, Update, Delete.
    pub const ManageDomains: Self = Self::Domains(DomainAction::Manage);
    /// Full settings management. Covers View, Update.
    pub const ManageTenantSettings: Self = Self::TenantSettings(TenantSettingsAction::Manage);
    /// Full metrics access. Covers View.
    pub const ManageMetrics: Self = Self::Metrics(MetricsAction::Manage);
    /// Read the tenant's metrics overview.
    pub const ViewMetrics: Self = Self::Metrics(MetricsAction::View);
    /// Full workflow management. Covers every workflow action.
    pub const ManageWorkflows: Self = Self::Workflows(WorkflowAction::Manage);

    /// The widest permission of every area, as the first admin role holds,
    /// with exporting the audit log, which its widest, viewing, does not
    /// cover.
    #[must_use]
    pub fn all() -> &'static [SystemPermission] {
        &[
            Self::ManageUsers,
            Self::ManageRoles,
            Self::ManageAuthConfig,
            Self::ManageFederation,
            Self::ViewAuditLog,
            Self::ExportAuditLog,
            Self::ManageBranding,
            Self::ManageApiKeys,
            Self::ManageCompliance,
            Self::ManageMtls,
            Self::ManageScim,
            Self::ManageCrypto,
            Self::ManageClassification,
            Self::Data(DataAccessAction::Restricted),
            Self::ManagePolicy,
            Self::ManageRouting,
            Self::ManagePipeline,
            Self::ManageSignals,
            Self::ManageWebhooks,
            Self::ManageConsumers,
            Self::Messaging(MessagingAction::Manage),
            Self::ManageAgents,
            Self::ManageDomains,
            Self::ManageTenantSettings,
            Self::ManageMetrics,
            Self::ManageWorkflows,
        ]
    }

    /// Every system permission, both each area's `Manage` and its single
    /// actions.
    pub const ALL_VARIANTS: &'static [SystemPermission] = &[
        Self::Users(UserAction::Manage),
        Self::Users(UserAction::View),
        Self::Users(UserAction::Create),
        Self::Users(UserAction::Update),
        Self::Users(UserAction::Deactivate),
        Self::Users(UserAction::Delete),
        Self::Roles(RoleAction::Manage),
        Self::Roles(RoleAction::View),
        Self::Roles(RoleAction::Create),
        Self::Roles(RoleAction::Update),
        Self::Roles(RoleAction::Delete),
        Self::Roles(RoleAction::Assign),
        Self::Roles(RoleAction::Escalate),
        Self::AuthConfig(AuthConfigAction::Manage),
        Self::AuthConfig(AuthConfigAction::View),
        Self::AuthConfig(AuthConfigAction::Update),
        Self::Federation(FederationAction::Manage),
        Self::Federation(FederationAction::View),
        Self::Federation(FederationAction::Create),
        Self::Federation(FederationAction::Update),
        Self::Federation(FederationAction::Delete),
        Self::AuditLog(AuditLogAction::View),
        Self::AuditLog(AuditLogAction::Export),
        Self::Branding(BrandingAction::Manage),
        Self::Branding(BrandingAction::View),
        Self::Branding(BrandingAction::Update),
        Self::ApiKeys(ApiKeyAction::Manage),
        Self::ApiKeys(ApiKeyAction::View),
        Self::ApiKeys(ApiKeyAction::Create),
        Self::ApiKeys(ApiKeyAction::Update),
        Self::ApiKeys(ApiKeyAction::Revoke),
        Self::Compliance(ComplianceAction::Manage),
        Self::Compliance(ComplianceAction::View),
        Self::Compliance(ComplianceAction::Update),
        Self::Mtls(MtlsAction::Manage),
        Self::Mtls(MtlsAction::View),
        Self::Mtls(MtlsAction::Update),
        Self::Scim(ScimAction::Manage),
        Self::Scim(ScimAction::View),
        Self::Scim(ScimAction::Configure),
        Self::Crypto(CryptoAction::Manage),
        Self::Crypto(CryptoAction::View),
        Self::Crypto(CryptoAction::Update),
        Self::Classification(ClassificationAction::Manage),
        Self::Classification(ClassificationAction::View),
        Self::Classification(ClassificationAction::Update),
        Self::Data(DataAccessAction::Restricted),
        Self::Data(DataAccessAction::Confidential),
        Self::PolicySet(PolicySetAction::Manage),
        Self::PolicySet(PolicySetAction::View),
        Self::PolicySet(PolicySetAction::Update),
        Self::PolicySet(PolicySetAction::Activate),
        Self::Routing(RoutingAction::Manage),
        Self::Routing(RoutingAction::View),
        Self::Routing(RoutingAction::Create),
        Self::Routing(RoutingAction::Update),
        Self::Routing(RoutingAction::Delete),
        Self::Pipeline(PipelineAction::Manage),
        Self::Pipeline(PipelineAction::View),
        Self::Pipeline(PipelineAction::Update),
        Self::Signals(SignalsAction::Manage),
        Self::Signals(SignalsAction::View),
        Self::Signals(SignalsAction::Update),
        Self::Webhooks(WebhooksAction::Manage),
        Self::Webhooks(WebhooksAction::View),
        Self::Webhooks(WebhooksAction::Update),
        Self::Consumers(ConsumersAction::Manage),
        Self::Consumers(ConsumersAction::View),
        Self::Consumers(ConsumersAction::Create),
        Self::Consumers(ConsumersAction::Update),
        Self::Consumers(ConsumersAction::Delete),
        Self::Messaging(MessagingAction::Manage),
        Self::Messaging(MessagingAction::View),
        Self::Messaging(MessagingAction::Create),
        Self::Messaging(MessagingAction::Publish),
        Self::Messaging(MessagingAction::Consume),
        Self::Messaging(MessagingAction::Delete),
        Self::Agents(AgentAction::Manage),
        Self::Agents(AgentAction::View),
        Self::Agents(AgentAction::Create),
        Self::Agents(AgentAction::Update),
        Self::Agents(AgentAction::Delete),
        Self::Agents(AgentAction::Delegate),
        Self::Agents(AgentAction::Approve),
        Self::Domains(DomainAction::Manage),
        Self::Domains(DomainAction::View),
        Self::Domains(DomainAction::Create),
        Self::Domains(DomainAction::Update),
        Self::Domains(DomainAction::Delete),
        Self::TenantSettings(TenantSettingsAction::Manage),
        Self::TenantSettings(TenantSettingsAction::View),
        Self::TenantSettings(TenantSettingsAction::Update),
        Self::Metrics(MetricsAction::Manage),
        Self::Metrics(MetricsAction::View),
        Self::Workflows(WorkflowAction::Manage),
        Self::Workflows(WorkflowAction::View),
        Self::Workflows(WorkflowAction::Create),
        Self::Workflows(WorkflowAction::Update),
        Self::Workflows(WorkflowAction::Delete),
        Self::Workflows(WorkflowAction::Run),
        Self::Workflows(WorkflowAction::Approve),
        Self::Workflows(WorkflowAction::ConnectAccounts),
    ];

    /// Whether `self` implies `other`.
    ///
    /// `Manage` implies every action in the same area. Any other action
    /// implies only itself, with one exception: any user permission also
    /// implies reading roles.
    ///
    /// A user is shown with their roles. The user list includes them, and
    /// the create form offers a role to assign. Without this, Ann may manage
    /// users but sees a list she cannot read and a picker she cannot fill.
    /// It only grants reading roles. Changing them still needs a `Roles`
    /// permission.
    #[must_use]
    pub fn implies(&self, other: &Self) -> bool {
        if self == other {
            return true;
        }
        if matches!(
            (self, other),
            (Self::Users(_), Self::Roles(RoleAction::View))
                | (
                    Self::Data(DataAccessAction::Restricted),
                    Self::Data(DataAccessAction::Confidential)
                )
        ) {
            return true;
        }
        self.is_manage() && std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    /// Whether this is its area's `Manage` action, which covers every action
    /// in the same area.
    fn is_manage(&self) -> bool {
        self.parts().1 == MANAGE
    }

    /// Whether any of `held` grants this permission, as it is or through
    /// [`Self::implies`].
    ///
    /// `held` is permissions written out, as a token or the gateway carries
    /// them. Only the full `idp:` form counts. A tenant's own permission can
    /// be named `users:view`, and must never pass for this one.
    #[must_use]
    pub fn held_in(&self, held: &[PermissionName]) -> bool {
        held.iter()
            .map(PermissionName::as_str)
            .filter(|held| held.starts_with(REALM))
            .filter_map(Self::parse)
            .any(|held| held.implies(self))
    }

    /// Whether someone holding `granter` may give out all of `to_grant`.
    ///
    /// A user can only grant permissions they hold, directly or through
    /// [`Self::implies`]. So an area's `Manage` lets them grant any action in
    /// that area.
    #[must_use]
    pub fn can_delegate(granter: &[Self], to_grant: &[Self]) -> bool {
        to_grant
            .iter()
            .all(|needed| granter.iter().any(|held| held.implies(needed)))
    }

    /// `perms` without the ones a wider permission in the list implies.
    ///
    /// With an area's `Manage` in the list, that area's single actions are
    /// dropped. Repeats are dropped too.
    #[must_use]
    pub fn normalize(perms: &[Self]) -> Vec<Self> {
        let mut result: Vec<Self> = Vec::with_capacity(perms.len());
        for perm in perms {
            let dominated = result.iter().any(|existing| existing.implies(perm));
            if dominated {
                continue;
            }
            result.retain(|existing| !perm.implies(existing));
            result.push(*perm);
        }
        result
    }

    /// Parses a permission written as `idp:area:action` or `area:action`.
    ///
    /// The reverse of [`Display`](std::fmt::Display), which writes the
    /// `idp:` form. `None` for anything that names no system permission.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let normalized = match s.trim().split(':').collect::<Vec<_>>().as_slice() {
            ["idp", domain, action] | [domain, action] => format!("idp:{domain}:{action}"),
            _ => return None,
        };
        Self::ALL_VARIANTS
            .iter()
            .copied()
            .find(|perm| perm.to_string() == normalized)
    }

    /// Whether `scopes` admit this permission.
    ///
    /// A role says what its holder may do. A scope list says how much of that
    /// one credential carries. Both must allow the call, so a scope can only
    /// take away.
    ///
    /// An empty list admits nothing. A key with no scopes was granted
    /// nothing, not everything.
    #[must_use]
    pub fn granted_by(&self, scopes: &[Scope]) -> bool {
        scopes.iter().any(|scope| self.is_named_by(scope))
    }

    /// Whether `scope` names this permission, directly or by implication.
    ///
    /// The `idp:` realm must be written out. So `*:*:*` names nothing, and no
    /// one scope spans both this plane and
    /// [`OrgPermission`](crate::domains::organization::members::permission::OrgPermission).
    /// The bare `area:action` form is refused for the same reason.
    /// `api_keys:view` could mean either plane.
    ///
    /// After the realm, a scope names this permission in one of two ways:
    /// - Its segments match this permission's text, where `*` stands for one
    ///   segment.
    /// - It parses as a permission that implies this one. So
    ///   `idp:users:manage` reaches every user action, as it does in a role.
    #[must_use]
    pub fn is_named_by(&self, scope: &Scope) -> bool {
        if !scope.as_str().starts_with(REALM) {
            return false;
        }

        scope.permits(&self.to_string())
            || Self::parse(scope.as_str()).is_some_and(|granted| granted.implies(self))
    }

    /// Whether `scope` reaches at least one permission this system checks.
    ///
    /// A scope that names nothing would refuse every request. Callers use
    /// this to refuse such a scope when it is written.
    #[must_use]
    pub fn is_recognized_scope(scope: &Scope) -> bool {
        Self::ALL_VARIANTS.iter().any(|p| p.is_named_by(scope))
    }

    /// Whether someone holding `held` may hand out `scope`.
    ///
    /// They must hold every permission the scope reaches. So a key or token
    /// they grant never does more than they could themselves.
    #[must_use]
    pub fn may_grant_scope(held: &[Self], scope: &Scope) -> bool {
        let reached: Vec<Self> = Self::ALL_VARIANTS
            .iter()
            .filter(|permission| permission.is_named_by(scope))
            .copied()
            .collect();
        Self::can_delegate(held, &reached)
    }

    /// The area this permission belongs to. The UI groups permissions by it.
    #[must_use]
    pub fn domain(&self) -> &'static str {
        match self {
            Self::Users(_) => "users",
            Self::Roles(_) => "roles",
            Self::AuthConfig(_) => "auth_config",
            Self::Federation(_) => "federation",
            Self::AuditLog(_) => "audit_log",
            Self::Branding(_) => "branding",
            Self::ApiKeys(_) => "api_keys",
            Self::Compliance(_) => "compliance",
            Self::Mtls(_) => "mtls",
            Self::Scim(_) => "scim",
            Self::Crypto(_) => "crypto",
            Self::Classification(_) => "classification",
            Self::Data(_) => "data",
            Self::PolicySet(_) => "policy",
            Self::Routing(_) => "routing",
            Self::Pipeline(_) => "pipeline",
            Self::Signals(_) => "signals",
            Self::Webhooks(_) => "webhooks",
            Self::Consumers(_) => "consumers",
            Self::Messaging(_) => "messaging",
            Self::Agents(_) => "agents",
            Self::Domains(_) => "domains",
            Self::TenantSettings(_) => "tenant_settings",
            Self::Metrics(_) => "metrics",
            Self::Workflows(_) => "workflows",
        }
    }

    /// Whether this permission lets its holder view its area. That is the
    /// area's `View`, or its `Manage`. Notifications filter on it.
    #[must_use]
    pub fn is_view(&self) -> bool {
        matches!(self.parts().1, VIEW | MANAGE)
    }

    /// Whether holding this permission gives power over other people,
    /// their data or the tenant's settings. Every built-in permission does
    /// but the metrics overview, which shows counts and never a person, a
    /// record or a setting. Every member holds it, so it alone never makes
    /// an account one that a directory or a provider must leave alone.
    #[must_use]
    pub fn gives_power(&self) -> bool {
        !matches!(self, Self::Metrics(_))
    }
}

impl fmt::Display for SystemPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (domain, action) = self.parts();
        write!(f, "idp:{domain}:{action}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The short names "manage users", "manage roles" and "view audit log"
    /// equal the area and action they stand for, so code may use either.
    #[test]
    fn legacy_aliases_match_grouped_variants() {
        assert_eq!(
            SystemPermission::ManageUsers,
            SystemPermission::Users(UserAction::Manage)
        );
        assert_eq!(
            SystemPermission::ManageRoles,
            SystemPermission::Roles(RoleAction::Manage)
        );
        assert_eq!(
            SystemPermission::ViewAuditLog,
            SystemPermission::AuditLog(AuditLogAction::View)
        );
    }

    /// The first admin role gets [`SystemPermission::all`]. It lists one
    /// widest permission for each of the 25 areas, and exporting the audit
    /// log, which viewing it does not cover.
    #[test]
    fn all_returns_one_coarse_permission_per_domain() {
        assert_eq!(SystemPermission::all().len(), 26);
    }

    /// [`SystemPermission::ALL_VARIANTS`] lists all 102 permissions. A new
    /// action left out of it could never be parsed or matched by a scope.
    #[test]
    fn all_variants_returns_all_fine_grained() {
        assert_eq!(SystemPermission::ALL_VARIANTS.len(), 102);
    }

    fn scope(s: &str) -> Scope {
        Scope::new(s).unwrap()
    }

    /// An empty credential scope list does not grant permission to view metrics.
    #[test]
    fn no_scope_grants_nothing() {
        assert!(!SystemPermission::ViewMetrics.granted_by(&[]));
    }

    /// A key carries the scope `idp:domains:create`. It may create domains
    /// but not delete them.
    #[test]
    fn an_exact_scope_grants_only_that_permission() {
        let granted = [scope("idp:domains:create")];

        assert!(SystemPermission::Domains(DomainAction::Create).granted_by(&granted));
        assert!(!SystemPermission::Domains(DomainAction::Delete).granted_by(&granted));
    }

    /// A key carries the scope `domains:create` without the `idp:` realm. It
    /// grants nothing, since a bare `api_keys:view` could mean this plane or
    /// the org plane.
    #[test]
    fn the_bare_form_grants_nothing() {
        assert!(
            !SystemPermission::Domains(DomainAction::Create).granted_by(&[scope("domains:create")])
        );
    }

    /// A key carries `idp:domains:manage`. It may delete domains, as a role
    /// with that permission may, but not delete agents.
    #[test]
    fn a_manage_scope_grants_every_action_in_its_domain() {
        let granted = [scope("idp:domains:manage")];

        assert!(SystemPermission::Domains(DomainAction::Delete).granted_by(&granted));
        assert!(!SystemPermission::Agents(AgentAction::Delete).granted_by(&granted));
    }

    /// `idp:domains:*` reaches deleting domains, `idp:*:view` reaches viewing
    /// agents, and `idp:*:*` reaches managing users. Each `*` fills one
    /// segment.
    #[test]
    fn a_star_stands_for_one_segment() {
        assert!(
            SystemPermission::Domains(DomainAction::Delete).granted_by(&[scope("idp:domains:*")])
        );
        assert!(SystemPermission::Agents(AgentAction::View).granted_by(&[scope("idp:*:view")]));
        assert!(SystemPermission::ManageUsers.granted_by(&[scope("idp:*:*")]));
    }

    /// Scopes with a wildcard realm do not grant tenant user-management rights.
    #[test]
    fn the_realm_is_never_a_wildcard() {
        assert!(!SystemPermission::ManageUsers.granted_by(&[scope("*:*:*")]));
        assert!(!SystemPermission::ManageUsers.granted_by(&[scope("*:users:manage")]));
    }

    /// An organization API-key scope does not grant tenant API-key management.
    #[test]
    fn an_org_plane_scope_grants_nothing_here() {
        assert!(!SystemPermission::ManageApiKeys.granted_by(&[scope("org:api_keys:manage")]));
    }

    /// A key carries `idp:domains` with no action. It does not reach deleting
    /// domains, since a scope is matched segment by segment and not as a
    /// prefix.
    #[test]
    fn a_shorter_scope_is_not_a_prefix() {
        assert!(
            !SystemPermission::Domains(DomainAction::Delete).granted_by(&[scope("idp:domains")])
        );
    }

    /// A key carries `idp:agents:view` and `idp:domains:create`. The second
    /// one alone lets it create domains. Neither lets it delete them.
    #[test]
    fn any_scope_in_the_list_is_enough() {
        let granted = [scope("idp:agents:view"), scope("idp:domains:create")];

        assert!(SystemPermission::Domains(DomainAction::Create).granted_by(&granted));
        assert!(!SystemPermission::Domains(DomainAction::Delete).granted_by(&granted));
    }

    /// An admin writes the scope `projects:read` or `idp:domains`. Neither
    /// reaches a built-in permission, so both can be refused when written.
    #[test]
    fn a_scope_naming_no_permission_is_not_recognized() {
        assert!(!SystemPermission::is_recognized_scope(&scope(
            "projects:read"
        )));
        assert!(!SystemPermission::is_recognized_scope(&scope(
            "idp:domains"
        )));
    }

    /// `idp:domains:*` is recognized. `domains:create` without the realm is
    /// not, even though it names a real action.
    #[test]
    fn recognized_scopes_are_realm_qualified() {
        assert!(SystemPermission::is_recognized_scope(&scope(
            "idp:domains:*"
        )));
        assert!(!SystemPermission::is_recognized_scope(&scope(
            "domains:create"
        )));
    }

    /// The scope `*` is not recognized, since one segment names no
    /// permission. The scope that reaches everything here, `idp:*:*`, is.
    #[test]
    fn a_lone_star_is_not_recognized() {
        assert!(!SystemPermission::is_recognized_scope(&scope("*")));
        assert!(SystemPermission::is_recognized_scope(&scope("idp:*:*")));
    }

    /// "Manage users" prints as `idp:users:manage`, and the same holds for
    /// roles and the audit log. Stored roles and tokens rely on these
    /// strings.
    #[test]
    fn coarse_display_unchanged() {
        assert_eq!(
            SystemPermission::ManageUsers.to_string(),
            "idp:users:manage"
        );
        assert_eq!(
            SystemPermission::ManageRoles.to_string(),
            "idp:roles:manage"
        );
        assert_eq!(
            SystemPermission::ViewAuditLog.to_string(),
            "idp:audit_log:view"
        );
    }

    /// Single actions print as `idp:area:action`, such as
    /// `idp:users:deactivate` and `idp:roles:assign`.
    #[test]
    fn fine_grained_display() {
        assert_eq!(
            SystemPermission::Users(UserAction::View).to_string(),
            "idp:users:view"
        );
        assert_eq!(
            SystemPermission::Users(UserAction::Deactivate).to_string(),
            "idp:users:deactivate"
        );
        assert_eq!(
            SystemPermission::Roles(RoleAction::Assign).to_string(),
            "idp:roles:assign"
        );
    }

    /// Ann may manage users. That covers viewing, creating, updating and
    /// deactivating users, and managing them.
    #[test]
    fn manage_implies_all_actions_in_domain() {
        assert!(SystemPermission::ManageUsers.implies(&SystemPermission::Users(UserAction::View)));
        assert!(
            SystemPermission::ManageUsers.implies(&SystemPermission::Users(UserAction::Create))
        );
        assert!(
            SystemPermission::ManageUsers.implies(&SystemPermission::Users(UserAction::Update))
        );
        assert!(
            SystemPermission::ManageUsers.implies(&SystemPermission::Users(UserAction::Deactivate))
        );
        assert!(SystemPermission::ManageUsers.implies(&SystemPermission::ManageUsers));
    }

    /// User-viewing permission covers viewing but neither creating nor managing users.
    #[test]
    fn fine_grained_implies_only_itself() {
        let view = SystemPermission::Users(UserAction::View);
        assert!(view.implies(&view));
        assert!(!view.implies(&SystemPermission::Users(UserAction::Create)));
        assert!(!view.implies(&SystemPermission::ManageUsers));
    }

    /// Every user action, from viewing to deleting, also covers reading
    /// roles. The user list shows each user's roles, and the create form
    /// offers a role to pick.
    #[test]
    fn any_authority_over_users_can_read_roles() {
        let read_roles = SystemPermission::Roles(RoleAction::View);

        for action in [
            UserAction::Manage,
            UserAction::View,
            UserAction::Create,
            UserAction::Update,
            UserAction::Deactivate,
            UserAction::Delete,
        ] {
            assert!(
                SystemPermission::Users(action).implies(&read_roles),
                "Users({action:?}) must carry Roles(View)"
            );
        }
    }

    /// Managing users does not authorize managing, creating, updating, deleting,
    /// assigning or escalating roles.
    #[test]
    fn authority_over_users_does_not_extend_to_changing_roles() {
        let manage_users = SystemPermission::ManageUsers;

        for action in [
            RoleAction::Manage,
            RoleAction::Create,
            RoleAction::Update,
            RoleAction::Delete,
            RoleAction::Assign,
            RoleAction::Escalate,
        ] {
            assert!(
                !manage_users.implies(&SystemPermission::Roles(action)),
                "Users(Manage) must not carry Roles({action:?})"
            );
        }
    }

    /// Managing users covers neither managing roles nor managing branding.
    /// Managing roles does not cover viewing users.
    #[test]
    fn manage_does_not_imply_other_domain() {
        assert!(!SystemPermission::ManageUsers.implies(&SystemPermission::ManageRoles));
        assert!(!SystemPermission::ManageUsers.implies(&SystemPermission::ManageBranding));
        assert!(!SystemPermission::ManageRoles.implies(&SystemPermission::Users(UserAction::View)));
    }

    /// An admin holds every area's widest permission. They may hand out
    /// viewing users, assigning roles and managing branding.
    #[test]
    fn admin_can_delegate_everything() {
        let admin = SystemPermission::all().to_vec();
        let to_grant = vec![
            SystemPermission::Users(UserAction::View),
            SystemPermission::Roles(RoleAction::Assign),
            SystemPermission::ManageBranding,
        ];
        assert!(SystemPermission::can_delegate(&admin, &to_grant));
    }

    /// A user manager cannot delegate compliance-management rights she does not hold.
    #[test]
    fn user_cannot_delegate_what_they_lack() {
        let alice = vec![SystemPermission::ManageUsers];
        let to_grant = vec![SystemPermission::ManageCompliance];
        assert!(!SystemPermission::can_delegate(&alice, &to_grant));
    }

    /// Alice may manage users. She may hand out viewing users, which that
    /// covers.
    #[test]
    fn manage_holder_can_delegate_fine_grained() {
        let alice = vec![SystemPermission::ManageUsers];
        let to_grant = vec![SystemPermission::Users(UserAction::View)];
        assert!(SystemPermission::can_delegate(&alice, &to_grant));
    }

    /// User-viewing rights cannot authorize delegating user-management rights.
    #[test]
    fn fine_grained_holder_cannot_delegate_manage() {
        let alice = vec![SystemPermission::Users(UserAction::View)];
        let to_grant = vec![SystemPermission::ManageUsers];
        assert!(!SystemPermission::can_delegate(&alice, &to_grant));
    }

    /// Someone holding nothing hands out nothing. That is allowed.
    #[test]
    fn empty_grant_always_succeeds() {
        assert!(SystemPermission::can_delegate(&[], &[]));
    }

    /// Someone holding nothing hands out viewing users. It is refused.
    #[test]
    fn empty_granter_fails_for_any_permission() {
        let to_grant = vec![SystemPermission::Users(UserAction::View)];
        assert!(!SystemPermission::can_delegate(&[], &to_grant));
    }

    /// "Manage users" and "view users" both belong to the `users` area, so
    /// the UI shows them together. Roles and the audit log have their own.
    #[test]
    fn domain_returns_group_name() {
        assert_eq!(SystemPermission::ManageUsers.domain(), "users");
        assert_eq!(SystemPermission::Users(UserAction::View).domain(), "users");
        assert_eq!(SystemPermission::ManageRoles.domain(), "roles");
        assert_eq!(SystemPermission::ViewAuditLog.domain(), "audit_log");
    }

    /// "Manage users" and "manage roles" count as viewing their area, so a
    /// manager gets the notifications a viewer gets.
    #[test]
    fn manage_counts_as_view() {
        assert!(SystemPermission::ManageUsers.is_view());
        assert!(SystemPermission::ManageRoles.is_view());
    }

    /// "View users" and "view audit log" count as viewing their area.
    #[test]
    fn explicit_view_counts() {
        assert!(SystemPermission::Users(UserAction::View).is_view());
        assert!(SystemPermission::ViewAuditLog.is_view());
    }

    /// Across every area, each permission ending in `:view` or `:manage`
    /// counts as viewing, and no other one does.
    #[test]
    fn every_areas_view_and_manage_count_as_view() {
        for permission in SystemPermission::ALL_VARIANTS {
            let action = permission.to_string();
            let reads = action.ends_with(":view") || action.ends_with(":manage");
            assert_eq!(permission.is_view(), reads, "{action}");
        }
        assert!(SystemPermission::ViewMetrics.is_view());
    }

    /// Creating users, deactivating users and deleting roles do not count as
    /// viewing. Someone holding only those gets no viewer notifications.
    #[test]
    fn write_only_is_not_view() {
        assert!(!SystemPermission::Users(UserAction::Create).is_view());
        assert!(!SystemPermission::Users(UserAction::Deactivate).is_view());
        assert!(!SystemPermission::Roles(RoleAction::Delete).is_view());
    }

    /// "Manage users" is written to JSON and read back. It comes back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn system_permission_roundtrips_through_json() {
        let original = SystemPermission::ManageUsers;
        let json = serde_json::to_string(&original).unwrap();
        let restored: SystemPermission = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    /// "View users" is written to JSON and read back. It comes back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn fine_grained_roundtrips_through_json() {
        let original = SystemPermission::Users(UserAction::View);
        let json = serde_json::to_string(&original).unwrap();
        let restored: SystemPermission = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    /// A stored role carries the tag `{"Settings": "View"}`. It reads as
    /// viewing tenant settings. Otherwise the role's whole permission list
    /// fails to read and the role denies everything.
    #[cfg(feature = "serde")]
    #[test]
    fn the_old_settings_tag_still_deserializes() {
        let restored: SystemPermission = serde_json::from_str(r#"{"Settings":"View"}"#).unwrap();
        assert_eq!(
            restored,
            SystemPermission::TenantSettings(TenantSettingsAction::View)
        );
    }

    /// Viewing tenant settings is written as `{"TenantSettings":"View"}`,
    /// never as the `Settings` tag.
    #[cfg(feature = "serde")]
    #[test]
    fn tenant_settings_serializes_under_the_new_tag() {
        let json = serde_json::to_string(&SystemPermission::TenantSettings(
            TenantSettingsAction::View,
        ))
        .unwrap();
        assert_eq!(json, r#"{"TenantSettings":"View"}"#);
    }

    /// "Manage agents" covers creating agents and delegating to them.
    /// Viewing agents does not cover managing them.
    #[test]
    fn manage_agents_implies_fine_grained_agent_actions() {
        let manage = SystemPermission::ManageAgents;
        assert!(manage.implies(&SystemPermission::Agents(AgentAction::Create)));
        assert!(manage.implies(&SystemPermission::Agents(AgentAction::Delegate)));
        assert!(!SystemPermission::Agents(AgentAction::View).implies(&manage));
    }

    /// Delegating to agents prints as `idp:agents:delegate` and belongs to
    /// the `agents` area.
    #[test]
    fn agent_permission_renders_and_groups() {
        let perm = SystemPermission::Agents(AgentAction::Delegate);
        assert_eq!(perm.to_string(), "idp:agents:delegate");
        assert_eq!(perm.domain(), "agents");
    }

    /// Both `routing:view` and `idp:agents:delegate` parse. Every permission
    /// parses back from the text it prints as.
    #[test]
    fn parse_accepts_both_forms_and_roundtrips() {
        assert_eq!(
            SystemPermission::parse("routing:view"),
            Some(SystemPermission::Routing(RoutingAction::View))
        );
        assert_eq!(
            SystemPermission::parse("idp:agents:delegate"),
            Some(SystemPermission::Agents(AgentAction::Delegate))
        );
        for perm in SystemPermission::ALL_VARIANTS {
            assert_eq!(SystemPermission::parse(&perm.to_string()), Some(*perm));
        }
    }

    /// `routing:teleport` names no action, `nope` has one segment, and
    /// `a:b:c:d` has four. None of them parse.
    #[test]
    fn parse_rejects_unknown() {
        assert!(SystemPermission::parse("routing:teleport").is_none());
        assert!(SystemPermission::parse("nope").is_none());
        assert!(SystemPermission::parse("a:b:c:d").is_none());
    }
}
