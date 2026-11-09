//! How a permission is written: the area and the action, as `idp:area:action`
//! spells them.

use crate::domains::authorization::permission::{
    AgentAction, ApiKeyAction, AuditLogAction, AuthConfigAction, BrandingAction,
    ClassificationAction, ComplianceAction, ConsumersAction, CryptoAction, DataAccessAction,
    DomainAction, FederationAction, MANAGE, MessagingAction, MetricsAction, MtlsAction,
    PipelineAction, PolicySetAction, RoleAction, RoutingAction, ScimAction, SignalsAction,
    SystemPermission, TenantSettingsAction, UserAction, VIEW, WebhooksAction, WorkflowAction,
};

impl SystemPermission {
    /// The area and the action within it, as written in `idp:area:action`.
    pub(super) fn parts(&self) -> (&'static str, &'static str) {
        match self {
            Self::Users(a) => ("users", action_str_user(*a)),
            Self::Roles(a) => ("roles", action_str_role(*a)),
            Self::AuthConfig(a) => ("auth_config", action_str_auth(*a)),
            Self::Federation(a) => ("federation", action_str_fed(*a)),
            Self::AuditLog(a) => ("audit_log", action_str_audit(*a)),
            Self::Branding(a) => ("branding", action_str_branding(*a)),
            Self::ApiKeys(a) => ("api_keys", action_str_apikey(*a)),
            Self::Compliance(a) => ("compliance", action_str_compliance(*a)),
            Self::Mtls(a) => ("mtls", action_str_crud(*a)),
            Self::Scim(a) => ("scim", action_str_scim(*a)),
            Self::Crypto(a) => ("crypto", action_str_crud(*a)),
            Self::Classification(a) => ("classification", action_str_crud(*a)),
            Self::Data(a) => ("data", action_str_data(*a)),
            Self::PolicySet(a) => ("policy", action_str_policy_set(*a)),
            Self::Routing(a) => ("routing", action_str_routing(*a)),
            Self::Pipeline(a) => ("pipeline", action_str_crud(*a)),
            Self::Signals(a) => ("signals", action_str_crud(*a)),
            Self::Webhooks(a) => ("webhooks", action_str_crud(*a)),
            Self::Consumers(a) => ("consumers", action_str_consumers(*a)),
            Self::Messaging(a) => ("messaging", action_str_messaging(*a)),
            Self::Agents(a) => ("agents", action_str_agents(*a)),
            Self::Workflows(a) => ("workflows", action_str_workflows(*a)),
            Self::Domains(a) => ("domains", action_str_domain(*a)),
            Self::TenantSettings(a) => ("tenant_settings", action_str_tenant_settings(*a)),
            Self::Metrics(a) => ("metrics", action_str_metrics(*a)),
        }
    }
}

fn action_str_user(a: UserAction) -> &'static str {
    match a {
        UserAction::Manage => MANAGE,
        UserAction::View => VIEW,
        UserAction::Create => "create",
        UserAction::Update => "update",
        UserAction::Deactivate => "deactivate",
        UserAction::Delete => "delete",
    }
}

fn action_str_role(a: RoleAction) -> &'static str {
    match a {
        RoleAction::Manage => MANAGE,
        RoleAction::View => VIEW,
        RoleAction::Create => "create",
        RoleAction::Update => "update",
        RoleAction::Delete => "delete",
        RoleAction::Assign => "assign",
        RoleAction::Escalate => "escalate",
    }
}

fn action_str_auth(a: AuthConfigAction) -> &'static str {
    match a {
        AuthConfigAction::Manage => MANAGE,
        AuthConfigAction::View => VIEW,
        AuthConfigAction::Update => "update",
    }
}

fn action_str_fed(a: FederationAction) -> &'static str {
    match a {
        FederationAction::Manage => MANAGE,
        FederationAction::View => VIEW,
        FederationAction::Create => "create",
        FederationAction::Update => "update",
        FederationAction::Delete => "delete",
    }
}

fn action_str_audit(a: AuditLogAction) -> &'static str {
    match a {
        AuditLogAction::View => VIEW,
        AuditLogAction::Export => "export",
    }
}

fn action_str_branding(a: BrandingAction) -> &'static str {
    match a {
        BrandingAction::Manage => MANAGE,
        BrandingAction::View => VIEW,
        BrandingAction::Update => "update",
    }
}

fn action_str_apikey(a: ApiKeyAction) -> &'static str {
    match a {
        ApiKeyAction::Manage => MANAGE,
        ApiKeyAction::View => VIEW,
        ApiKeyAction::Create => "create",
        ApiKeyAction::Update => "update",
        ApiKeyAction::Revoke => "revoke",
    }
}

fn action_str_compliance(a: ComplianceAction) -> &'static str {
    match a {
        ComplianceAction::Manage => MANAGE,
        ComplianceAction::View => VIEW,
        ComplianceAction::Update => "update",
    }
}

fn action_str_scim(a: ScimAction) -> &'static str {
    match a {
        ScimAction::Manage => MANAGE,
        ScimAction::View => VIEW,
        ScimAction::Configure => "configure",
    }
}

fn action_str_crud<T: CrudLike>(a: T) -> &'static str {
    a.as_str()
}

fn action_str_policy_set(a: PolicySetAction) -> &'static str {
    match a {
        PolicySetAction::Manage => MANAGE,
        PolicySetAction::View => VIEW,
        PolicySetAction::Update => "update",
        PolicySetAction::Activate => "activate",
    }
}

trait CrudLike: Copy {
    fn as_str(self) -> &'static str;
}

impl CrudLike for CryptoAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manage => MANAGE,
            Self::View => VIEW,
            Self::Update => "update",
        }
    }
}

impl CrudLike for ClassificationAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manage => MANAGE,
            Self::View => VIEW,
            Self::Update => "update",
        }
    }
}

impl CrudLike for PipelineAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manage => MANAGE,
            Self::View => VIEW,
            Self::Update => "update",
        }
    }
}

impl CrudLike for SignalsAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manage => MANAGE,
            Self::View => VIEW,
            Self::Update => "update",
        }
    }
}

impl CrudLike for WebhooksAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manage => MANAGE,
            Self::View => VIEW,
            Self::Update => "update",
        }
    }
}

impl CrudLike for MtlsAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manage => MANAGE,
            Self::View => VIEW,
            Self::Update => "update",
        }
    }
}

fn action_str_consumers(a: ConsumersAction) -> &'static str {
    match a {
        ConsumersAction::Manage => MANAGE,
        ConsumersAction::View => VIEW,
        ConsumersAction::Create => "create",
        ConsumersAction::Update => "update",
        ConsumersAction::Delete => "delete",
    }
}

fn action_str_messaging(a: MessagingAction) -> &'static str {
    match a {
        MessagingAction::Manage => MANAGE,
        MessagingAction::View => VIEW,
        MessagingAction::Create => "create",
        MessagingAction::Publish => "publish",
        MessagingAction::Consume => "consume",
        MessagingAction::Delete => "delete",
    }
}

fn action_str_agents(a: AgentAction) -> &'static str {
    match a {
        AgentAction::Manage => MANAGE,
        AgentAction::View => VIEW,
        AgentAction::Create => "create",
        AgentAction::Update => "update",
        AgentAction::Delete => "delete",
        AgentAction::Delegate => "delegate",
        AgentAction::Approve => "approve",
    }
}

fn action_str_workflows(a: WorkflowAction) -> &'static str {
    match a {
        WorkflowAction::Manage => MANAGE,
        WorkflowAction::View => VIEW,
        WorkflowAction::Create => "create",
        WorkflowAction::Update => "update",
        WorkflowAction::Delete => "delete",
        WorkflowAction::Run => "run",
        WorkflowAction::Approve => "approve",
        WorkflowAction::ConnectAccounts => "connect_accounts",
    }
}

fn action_str_data(a: DataAccessAction) -> &'static str {
    match a {
        DataAccessAction::Confidential => "confidential",
        DataAccessAction::Restricted => "restricted",
    }
}

fn action_str_domain(a: DomainAction) -> &'static str {
    match a {
        DomainAction::Manage => MANAGE,
        DomainAction::View => VIEW,
        DomainAction::Create => "create",
        DomainAction::Update => "update",
        DomainAction::Delete => "delete",
    }
}

fn action_str_metrics(a: MetricsAction) -> &'static str {
    match a {
        MetricsAction::Manage => MANAGE,
        MetricsAction::View => VIEW,
    }
}

fn action_str_tenant_settings(a: TenantSettingsAction) -> &'static str {
    match a {
        TenantSettingsAction::Manage => MANAGE,
        TenantSettingsAction::View => VIEW,
        TenantSettingsAction::Update => "update",
    }
}

fn action_str_routing(a: RoutingAction) -> &'static str {
    match a {
        RoutingAction::Manage => MANAGE,
        RoutingAction::View => VIEW,
        RoutingAction::Create => "create",
        RoutingAction::Update => "update",
        RoutingAction::Delete => "delete",
    }
}
