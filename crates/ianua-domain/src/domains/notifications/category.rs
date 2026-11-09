//! Notification categories, which group events so users can turn each
//! group on or off.

use std::fmt;

use crate::domains::authorization::permission::{
    AgentAction, ApiKeyAction, AuditLogAction, AuthConfigAction, BrandingAction,
    ClassificationAction, ConsumersAction, CryptoAction, DomainAction, FederationAction,
    MessagingAction, MtlsAction, PipelineAction, PolicySetAction, RoleAction, RoutingAction,
    ScimAction, SignalsAction, SystemPermission, TenantSettingsAction, UserAction, WebhooksAction,
    WorkflowAction,
};
use crate::types::event_type::{
    AuthorizationEvent, BrandingEvent, FederationEvent, MessagingEvent, NotificationsEvent,
    ProxyEvent, TenantEvent,
};
use crate::types::{EventType, EventVisibility};

/// A group of events a user can turn notifications on or off for.
///
/// Each category needs one permission to see. An event whose subject has a
/// permission of its own gets its own category. Custom domains, the mTLS
/// trust anchor, SCIM and the policy are examples. So seeing the
/// notification never takes less than seeing the thing itself.
///
/// Categories are used for:
/// - user preferences, one channel per category,
/// - fan-out, which picks the category of each event,
/// - visibility, through the [`SystemPermission`] each category needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NotificationCategory {
    /// User lifecycle: registration, deactivation, email changes. Also the
    /// notification events themselves.
    Identity,
    /// Signing keys: rotation, revocation, algorithm migration.
    Crypto,
    /// OAuth clients and API keys.
    OAuth,
    /// Roles, groups and assignments.
    Authorization,
    /// Federation connections.
    Federation,
    /// Proxy routes.
    Routing,
    /// Proxy pipeline and stages.
    Pipeline,
    /// CAEP/SSE signal streams.
    Signals,
    /// Webhook subscriptions and delivery.
    Webhooks,
    /// Branding and templates.
    Branding,
    /// Login, MFA, break glass, sessions, passkeys.
    Authentication,
    /// Organization lifecycle and operator changes.
    Organization,
    /// Tenant lifecycle and settings.
    Tenant,
    /// Agents, their delegations, runs and approvals.
    Agents,
    /// Consumers and their credentials.
    Consumers,
    /// Messaging topics, subscriptions and channels.
    Messaging,
    /// The tenant's custom domains and their certificates.
    Domains,
    /// The tenant's mTLS trust anchor.
    Mtls,
    /// SCIM provisioning.
    Scim,
    /// Data classification rules.
    Classification,
    /// The tenant's authorization policy and its rollout.
    Policy,
    /// The integrity of the tenant's audit log. It is kept apart from every
    /// other category, so muting routine changes never mutes a broken chain.
    Audit,
    /// Workflows, their executions and integration accounts.
    Workflows,
}

impl NotificationCategory {
    /// All categories in definition order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Identity,
            Self::Crypto,
            Self::OAuth,
            Self::Authorization,
            Self::Federation,
            Self::Routing,
            Self::Pipeline,
            Self::Signals,
            Self::Webhooks,
            Self::Branding,
            Self::Authentication,
            Self::Organization,
            Self::Tenant,
            Self::Agents,
            Self::Consumers,
            Self::Messaging,
            Self::Domains,
            Self::Mtls,
            Self::Scim,
            Self::Classification,
            Self::Policy,
            Self::Audit,
            Self::Workflows,
        ]
    }

    /// The category an event type belongs to.
    #[must_use]
    pub fn from_event_type(event_type: &EventType) -> Self {
        match event_type {
            EventType::Identity(_) => Self::Identity,
            EventType::Notifications(event) => Self::of_notifications(*event),
            EventType::Crypto(_) => Self::Crypto,
            EventType::OAuth(_) => Self::OAuth,
            EventType::Authorization(event) => Self::of_authorization(*event),
            EventType::Agents(_) => Self::Agents,
            EventType::Federation(event) => Self::of_federation(*event),
            EventType::Routing(_) => Self::Routing,
            EventType::Proxy(event) => Self::of_proxy(*event),
            EventType::Signals(_) => Self::Signals,
            EventType::Webhooks(_) => Self::Webhooks,
            EventType::Branding(event) => Self::of_branding(*event),
            EventType::Authentication(_) => Self::Authentication,
            EventType::Organization(_) | EventType::Operator(_) => Self::Organization,
            EventType::Tenant(event) => Self::of_tenant(*event),
            EventType::Messaging(event) => Self::of_messaging(*event),
            EventType::Consumers(_) => Self::Consumers,
            EventType::Workflows(_) => Self::Workflows,
        }
    }

    /// A mail given up on belongs to whoever runs the tenant's mail, so it
    /// shows to those who may see branding. The other notification events
    /// are about the notifications themselves.
    fn of_notifications(event: NotificationsEvent) -> Self {
        match event {
            NotificationsEvent::MailUndelivered => Self::Branding,
            NotificationsEvent::NotificationRead
            | NotificationsEvent::AllNotificationsRead
            | NotificationsEvent::PreferencesUpdated
            | NotificationsEvent::DestinationAdded
            | NotificationsEvent::DestinationChanged
            | NotificationsEvent::DestinationPaused
            | NotificationsEvent::DestinationResumed
            | NotificationsEvent::DestinationRemoved
            | NotificationsEvent::MemberPreferencesUpdated
            | NotificationsEvent::OperatorPreferencesUpdated
            | NotificationsEvent::NoticeSent
            | NotificationsEvent::AccessOffered => Self::Identity,
        }
    }

    /// Channels between agents belong to agents, though their events carry
    /// messaging names. Seeing one takes the permission to see agents.
    fn of_messaging(event: MessagingEvent) -> Self {
        match event {
            MessagingEvent::ChannelOpened | MessagingEvent::ChannelClosed => Self::Agents,
            MessagingEvent::TopicCreated
            | MessagingEvent::TopicPaused
            | MessagingEvent::TopicResumed
            | MessagingEvent::TopicArchived
            | MessagingEvent::TopicSchemaChanged
            | MessagingEvent::TopicRetentionChanged
            | MessagingEvent::TopicDataClassRaised
            | MessagingEvent::TopicDeleted
            | MessagingEvent::SubscriptionCreated
            | MessagingEvent::SubscriptionPaused
            | MessagingEvent::SubscriptionResumed
            | MessagingEvent::SubscriptionDeleted
            | MessagingEvent::SubscriptionSecretRotated
            | MessagingEvent::DeadLetterReplayed
            | MessagingEvent::MessagePublished
            | MessagingEvent::SchemaRegistered
            | MessagingEvent::SchemaEvolved
            | MessagingEvent::SchemaDeleted => Self::Messaging,
        }
    }

    // One arm per event, with no catch-all: a new authorization event must
    // be given a category here before it builds, so it is never filed by a
    // default. Splitting it would bring that default back.
    #[allow(clippy::too_many_lines)]
    fn of_authorization(event: AuthorizationEvent) -> Self {
        match event {
            AuthorizationEvent::PolicyRuleAdded
            | AuthorizationEvent::PolicyRuleRemoved
            | AuthorizationEvent::PolicyRuleSwitched
            | AuthorizationEvent::PolicyDefaultActionChanged
            | AuthorizationEvent::PolicyDraftStarted
            | AuthorizationEvent::BreakGlassPolicyChanged
            | AuthorizationEvent::AccessRequestPolicyChanged
            | AuthorizationEvent::PolicySubmittedForReview
            | AuthorizationEvent::PolicyActivated
            | AuthorizationEvent::PolicyRejected
            | AuthorizationEvent::PolicyArchived
            | AuthorizationEvent::PolicySimulated
            | AuthorizationEvent::PolicyRuleChanged
            | AuthorizationEvent::PolicyRulesReordered => Self::Policy,
            AuthorizationEvent::RoleCreated
            | AuthorizationEvent::RoleAssigned
            | AuthorizationEvent::RoleRevoked
            | AuthorizationEvent::RoleDeleted
            | AuthorizationEvent::RoleReassigned
            | AuthorizationEvent::RoleRenamed
            | AuthorizationEvent::RoleDefaultAssignmentChanged
            | AuthorizationEvent::PermissionGranted
            | AuthorizationEvent::PermissionRevoked
            | AuthorizationEvent::GroupCreated
            | AuthorizationEvent::GroupDeleted
            | AuthorizationEvent::GroupRenamed
            | AuthorizationEvent::GroupRoleAssigned
            | AuthorizationEvent::GroupRoleUnassigned
            | AuthorizationEvent::GroupMemberAdded
            | AuthorizationEvent::GroupMemberRemoved
            | AuthorizationEvent::GroupMoved
            | AuthorizationEvent::ResourceTypeDeclared
            | AuthorizationEvent::ResourceTypeUpdated
            | AuthorizationEvent::ResourceTypeDeleted
            | AuthorizationEvent::RoleAssignmentExpired
            | AuthorizationEvent::GroupMembershipExpired
            | AuthorizationEvent::AccessRequested
            | AuthorizationEvent::AccessRequestApproved
            | AuthorizationEvent::AccessRequestDenied
            | AuthorizationEvent::AccessRequestCancelled
            | AuthorizationEvent::AccessRequestExpired
            | AuthorizationEvent::RelationshipAdded
            | AuthorizationEvent::RelationshipRemoved
            | AuthorizationEvent::AccessReviewStarted
            | AuthorizationEvent::AccessReviewDecided
            | AuthorizationEvent::AccessReviewSuggested
            | AuthorizationEvent::AccessReviewCompleted
            | AuthorizationEvent::AccessReviewCancelled
            | AuthorizationEvent::SeparationRuleAdded
            | AuthorizationEvent::SeparationRuleRemoved
            | AuthorizationEvent::ClearanceRuleAdded
            | AuthorizationEvent::ClearanceRuleChanged
            | AuthorizationEvent::ClearanceRuleRemoved => Self::Authorization,
        }
    }

    fn of_federation(event: FederationEvent) -> Self {
        match event {
            FederationEvent::ScimEnabled
            | FederationEvent::ScimDisabled
            | FederationEvent::ScimTokenRotated
            | FederationEvent::ScimSettingsUpdated => Self::Scim,
            FederationEvent::ConnectionCreated
            | FederationEvent::ConnectionActivated
            | FederationEvent::ConnectionDisabled
            | FederationEvent::ConnectionUpdated
            | FederationEvent::ConnectionDeleted
            | FederationEvent::JitUserProvisioned
            | FederationEvent::AccountLinked
            | FederationEvent::AccountUnlinked
            | FederationEvent::LinkReconfirmed
            | FederationEvent::ServiceProviderCreated
            | FederationEvent::ServiceProviderUpdated
            | FederationEvent::ServiceProviderDeleted
            | FederationEvent::SamlAssertionIssued
            | FederationEvent::LogoutRequestSent
            | FederationEvent::LogoutResponseTaken => Self::Federation,
        }
    }

    fn of_proxy(event: ProxyEvent) -> Self {
        match event {
            ProxyEvent::ClassificationRuleAdded
            | ProxyEvent::ClassificationRuleRemoved
            | ProxyEvent::ClassificationRuleChanged => Self::Classification,
            ProxyEvent::PipelineCreated
            | ProxyEvent::PipelineRenamed
            | ProxyEvent::PipelineDeleted
            | ProxyEvent::PipelineActivated
            | ProxyEvent::PipelineDisabled
            | ProxyEvent::StageAdded
            | ProxyEvent::StageRemoved
            | ProxyEvent::StageEnabled
            | ProxyEvent::StageDisabled
            | ProxyEvent::PipelineReordered
            | ProxyEvent::HoneypotHit
            | ProxyEvent::PersonTurnedAway
            | ProxyEvent::AutomatedThreatDetected
            | ProxyEvent::CanaryTokenTriggered
            | ProxyEvent::CanaryTokenLeaked
            | ProxyEvent::CanaryTokenGenerated
            | ProxyEvent::WasmModuleUploaded
            | ProxyEvent::StageReconfigured => Self::Pipeline,
            ProxyEvent::LogTargetCreated
            | ProxyEvent::LogTargetChanged
            | ProxyEvent::LogTargetPaused
            | ProxyEvent::LogTargetResumed
            | ProxyEvent::LogTargetDeleted => Self::Routing,
        }
    }

    fn of_branding(event: BrandingEvent) -> Self {
        match event {
            BrandingEvent::Updated
            | BrandingEvent::MailProviderChanged
            | BrandingEvent::MailProviderTested => Self::Branding,
        }
    }

    // One arm per event, with no catch-all, for the same reason as
    // `of_authorization`.
    #[allow(clippy::too_many_lines)]
    fn of_tenant(event: TenantEvent) -> Self {
        match event {
            TenantEvent::MtlsConfigUpdated => Self::Mtls,
            TenantEvent::AuthConfigUpdated => Self::Authentication,
            TenantEvent::AuditChainBroken
            | TenantEvent::AuditRecordsPurged
            | TenantEvent::AuditStreamCreated
            | TenantEvent::AuditStreamChanged
            | TenantEvent::AuditStreamPaused
            | TenantEvent::AuditStreamResumed
            | TenantEvent::AuditStreamRemoved
            | TenantEvent::AuditLogExportRequested
            | TenantEvent::AuditLogExportDownloaded => Self::Audit,
            TenantEvent::DomainRegistered
            | TenantEvent::DomainRemoved
            | TenantEvent::DomainVerified
            | TenantEvent::DomainVerificationLost
            | TenantEvent::PrimaryDomainChanged
            | TenantEvent::DomainTlsProvisioned
            | TenantEvent::DomainHandoverOffered
            | TenantEvent::DomainTransferred
            | TenantEvent::DomainTlsRequested
            | TenantEvent::DomainCertificateUploaded
            | TenantEvent::DomainCertificateReplaced
            | TenantEvent::DomainCertificateRemoved
            | TenantEvent::DomainCertificateExpiring
            | TenantEvent::DnsRecordSetChanged
            | TenantEvent::DnsRecordSetRemoved => Self::Domains,
            TenantEvent::Provisioned
            | TenantEvent::ReadableAddressChanged
            | TenantEvent::StatusChanged
            | TenantEvent::Renamed
            | TenantEvent::ContactEmailChanged
            | TenantEvent::TimezoneChanged
            | TenantEvent::LocaleChanged
            | TenantEvent::InfraFailed
            | TenantEvent::ComplianceChanged
            | TenantEvent::Deleted
            | TenantEvent::DeletedEarly
            | TenantEvent::TornDown
            | TenantEvent::TeardownFailed
            | TenantEvent::EnvironmentChanged
            | TenantEvent::CloneStarted
            | TenantEvent::CloneCompleted
            | TenantEvent::CloneFailed => Self::Tenant,
        }
    }

    /// The permission needed to see this category's notifications in a
    /// tenant.
    ///
    /// Every category has one. A notification that needed no permission
    /// would reach every end user of the tenant, even one who signed up a
    /// minute ago. Tenant events need the tenant's settings. Organization
    /// and operator events record what someone outside the tenant did to
    /// it, so they need its audit log.
    #[must_use]
    pub fn required_permission(&self) -> SystemPermission {
        match self {
            Self::Identity => SystemPermission::Users(UserAction::View),
            Self::Crypto => SystemPermission::Crypto(CryptoAction::View),
            Self::OAuth => SystemPermission::ApiKeys(ApiKeyAction::View),
            Self::Authorization => SystemPermission::Roles(RoleAction::View),
            Self::Federation => SystemPermission::Federation(FederationAction::View),
            Self::Routing => SystemPermission::Routing(RoutingAction::View),
            Self::Pipeline => SystemPermission::Pipeline(PipelineAction::View),
            Self::Signals => SystemPermission::Signals(SignalsAction::View),
            Self::Webhooks => SystemPermission::Webhooks(WebhooksAction::View),
            Self::Branding => SystemPermission::Branding(BrandingAction::View),
            Self::Authentication => SystemPermission::AuthConfig(AuthConfigAction::View),
            Self::Organization => SystemPermission::AuditLog(AuditLogAction::View),
            Self::Tenant => SystemPermission::TenantSettings(TenantSettingsAction::View),
            Self::Agents => SystemPermission::Agents(AgentAction::View),
            Self::Consumers => SystemPermission::Consumers(ConsumersAction::View),
            Self::Messaging => SystemPermission::Messaging(MessagingAction::View),
            Self::Domains => SystemPermission::Domains(DomainAction::View),
            Self::Mtls => SystemPermission::Mtls(MtlsAction::View),
            Self::Scim => SystemPermission::Scim(ScimAction::View),
            Self::Classification => SystemPermission::Classification(ClassificationAction::View),
            Self::Policy => SystemPermission::PolicySet(PolicySetAction::View),
            Self::Audit => SystemPermission::AuditLog(AuditLogAction::View),
            Self::Workflows => SystemPermission::Workflows(WorkflowAction::View),
        }
    }

    /// The string key used for persistence and preference matching.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Crypto => "crypto",
            Self::OAuth => "oauth",
            Self::Authorization => "authorization",
            Self::Federation => "federation",
            Self::Routing => "routing",
            Self::Pipeline => "pipeline",
            Self::Signals => "signals",
            Self::Webhooks => "webhooks",
            Self::Branding => "branding",
            Self::Authentication => "authentication",
            Self::Organization => "organization",
            Self::Tenant => "tenant",
            Self::Agents => "agents",
            Self::Consumers => "consumers",
            Self::Messaging => "messaging",
            Self::Domains => "domains",
            Self::Mtls => "mtls",
            Self::Scim => "scim",
            Self::Classification => "classification",
            Self::Policy => "policy",
            Self::Audit => "audit",
            Self::Workflows => "workflows",
        }
    }

    /// Reads a category from its string key.
    ///
    /// Gives `None` for an unknown key.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "identity" => Some(Self::Identity),
            "crypto" => Some(Self::Crypto),
            "oauth" => Some(Self::OAuth),
            "authorization" => Some(Self::Authorization),
            "federation" => Some(Self::Federation),
            "routing" => Some(Self::Routing),
            "pipeline" => Some(Self::Pipeline),
            "signals" => Some(Self::Signals),
            "webhooks" => Some(Self::Webhooks),
            "branding" => Some(Self::Branding),
            "authentication" => Some(Self::Authentication),
            "organization" => Some(Self::Organization),
            "tenant" => Some(Self::Tenant),
            "agents" => Some(Self::Agents),
            "consumers" => Some(Self::Consumers),
            "messaging" => Some(Self::Messaging),
            "domains" => Some(Self::Domains),
            "mtls" => Some(Self::Mtls),
            "scim" => Some(Self::Scim),
            "classification" => Some(Self::Classification),
            "policy" => Some(Self::Policy),
            "audit" => Some(Self::Audit),
            "workflows" => Some(Self::Workflows),
            _ => None,
        }
    }
}

/// The events someone holding these permissions may see.
///
/// An event is visible when a held permission implies the one its category
/// needs. The same rule decides whose feed an event reaches and what a
/// webhook they create may receive.
#[derive(Debug, Clone, Copy)]
pub struct VisibleTo<'a>(pub &'a [SystemPermission]);

impl EventVisibility for VisibleTo<'_> {
    fn may_see(&self, event_type: &EventType) -> bool {
        let needed = NotificationCategory::from_event_type(event_type).required_permission();
        self.0.iter().any(|held| held.implies(&needed))
    }
}

impl fmt::Display for NotificationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::event_type::*;

    /// Holding only user-view permission exposes user registration events
    /// while keeping crypto events hidden.
    #[test]
    fn an_event_is_visible_only_with_its_categorys_permission() {
        let held = [SystemPermission::Users(UserAction::View)];
        let viewer = VisibleTo(&held);

        assert!(viewer.may_see(&IdentityEvent::UserRegistered.into()));
        assert!(!viewer.may_see(&CryptoEvent::ALL[0].0.into()));
    }

    /// The list of categories holds all 23. One left out would get no
    /// default preference.
    #[test]
    fn all_returns_every_category() {
        assert_eq!(NotificationCategory::all().len(), 23);
    }

    /// Each category's stored key parses back to the same category, so a
    /// saved preference reads back unchanged.
    #[test]
    fn as_str_roundtrips_via_from_str() {
        for cat in NotificationCategory::all() {
            assert_eq!(NotificationCategory::parse(cat.as_str()), Some(*cat));
        }
    }

    /// The key `nonexistent` is not a category, so it parses to nothing.
    #[test]
    fn from_str_unknown_returns_none() {
        assert_eq!(NotificationCategory::parse("nonexistent"), None);
    }

    /// Each category prints as its stored key, so what is shown matches
    /// what is saved.
    #[test]
    fn display_matches_as_str() {
        for cat in NotificationCategory::all() {
            assert_eq!(cat.to_string(), cat.as_str());
        }
    }

    /// A user registering files under identity.
    #[test]
    fn from_event_type_identity() {
        let et = EventType::Identity(IdentityEvent::UserRegistered);
        assert_eq!(
            NotificationCategory::from_event_type(&et),
            NotificationCategory::Identity
        );
    }

    /// A key rotation files under crypto.
    #[test]
    fn from_event_type_crypto() {
        let et = EventType::Crypto(CryptoEvent::KeyRotated);
        assert_eq!(
            NotificationCategory::from_event_type(&et),
            NotificationCategory::Crypto
        );
    }

    /// A successful login files under authentication.
    #[test]
    fn from_event_type_authentication() {
        let et = EventType::Authentication(AuthenticationEvent::LoginSucceeded);
        assert_eq!(
            NotificationCategory::from_event_type(&et),
            NotificationCategory::Authentication
        );
    }

    /// A new proxy pipeline files under pipeline, not under some general
    /// proxy group.
    #[test]
    fn from_event_type_proxy_maps_to_pipeline() {
        let et = EventType::Proxy(ProxyEvent::PipelineCreated);
        assert_eq!(
            NotificationCategory::from_event_type(&et),
            NotificationCategory::Pipeline
        );
    }

    /// Identity notifications need `idp:users:view` to be seen.
    #[test]
    fn required_permission_for_identity() {
        assert_eq!(
            NotificationCategory::Identity
                .required_permission()
                .to_string(),
            "idp:users:view"
        );
    }

    /// Tenant notifications need `idp:tenant_settings:view` and organization
    /// ones need `idp:audit_log:view`. An end user who signed up a minute
    /// ago holds neither, so sees neither.
    #[test]
    fn tenant_and_organization_notifications_need_an_admin_permission() {
        assert_eq!(
            NotificationCategory::Tenant
                .required_permission()
                .to_string(),
            "idp:tenant_settings:view"
        );
        assert_eq!(
            NotificationCategory::Organization
                .required_permission()
                .to_string(),
            "idp:audit_log:view"
        );
    }

    /// One event from each of fourteen contexts, from identity to operator,
    /// is filed. Each lands in a category from the full list.
    #[test]
    fn every_event_type_variant_maps_to_a_category() {
        let samples: Vec<EventType> = vec![
            EventType::Identity(IdentityEvent::UserRegistered),
            EventType::Crypto(CryptoEvent::KeyRotated),
            EventType::OAuth(OAuthEvent::ClientCreated),
            EventType::Authorization(AuthorizationEvent::RoleCreated),
            EventType::Federation(FederationEvent::ConnectionCreated),
            EventType::Routing(RoutingEvent::RouteCreated),
            EventType::Proxy(ProxyEvent::PipelineCreated),
            EventType::Signals(SignalsEvent::StreamRegistered),
            EventType::Webhooks(WebhooksEvent::SubscriptionCreated),
            EventType::Branding(BrandingEvent::Updated),
            EventType::Authentication(AuthenticationEvent::LoginSucceeded),
            EventType::Organization(OrganizationEvent::Created),
            EventType::Tenant(TenantEvent::Provisioned),
            EventType::Operator(OperatorEvent::OperatorCreated),
        ];

        for et in &samples {
            let cat = NotificationCategory::from_event_type(et);
            assert!(
                NotificationCategory::all().contains(&cat),
                "unmapped event type: {et:?}"
            );
        }
    }

    /// Each category's permission prints as a name that parses back to the
    /// same permission. A name the authorizer did not know would hide the
    /// notifications from everyone.
    #[test]
    fn every_category_permission_is_a_real_one() {
        for category in NotificationCategory::all() {
            let named = category.required_permission();

            assert_eq!(SystemPermission::parse(&named.to_string()), Some(named));
        }
    }

    /// Subject-specific events and the permissions needed to see them.
    const SUBJECT_PERMISSIONS: &[(EventType, &str)] = &[
        (
            EventType::Agents(AgentsEvent::AgentCreated),
            "idp:agents:view",
        ),
        (
            EventType::Consumers(ConsumersEvent::ConsumerCreated),
            "idp:consumers:view",
        ),
        (
            EventType::Tenant(TenantEvent::DomainRegistered),
            "idp:domains:view",
        ),
        (
            EventType::Tenant(TenantEvent::MtlsConfigUpdated),
            "idp:mtls:view",
        ),
        (
            EventType::Federation(FederationEvent::ScimEnabled),
            "idp:scim:view",
        ),
        (
            EventType::Proxy(ProxyEvent::ClassificationRuleAdded),
            "idp:classification:view",
        ),
        (
            EventType::Authorization(AuthorizationEvent::PolicyActivated),
            "idp:policy:view",
        ),
        (
            EventType::Tenant(TenantEvent::DnsRecordSetChanged),
            "idp:domains:view",
        ),
        (
            EventType::Tenant(TenantEvent::AuthConfigUpdated),
            "idp:auth_config:view",
        ),
        (
            EventType::Tenant(TenantEvent::AuditChainBroken),
            "idp:audit_log:view",
        ),
    ];

    /// A new custom domain needs `idp:domains:view` and an activated policy
    /// needs `idp:policy:view`. Each listed event needs the permission of
    /// its own subject, so the notification never asks for less.
    #[test]
    fn events_with_their_own_permission_need_that_permission() {
        for (event, permission) in SUBJECT_PERMISSIONS {
            let category = NotificationCategory::from_event_type(event);

            assert_eq!(
                category.required_permission().to_string(),
                *permission,
                "{event:?}"
            );
        }
    }
}
