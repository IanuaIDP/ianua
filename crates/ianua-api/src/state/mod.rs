//! What every handler can reach: the use cases of its context, built once
//! by the assembly from the server's adapters, and the HTTP layer's own
//! settings.
//!
//! `ApiState` holds one group per app context, and each handler takes only
//! its own (`State<NotificationState>`). Each group and its builder live in
//! `ianua_assembly::<context>`.

pub mod http;
pub(crate) mod streams;

use std::sync::Arc;

use http::HttpSettings;
use ianua_app::ports::organization::OrganizationStore;
use ianua_app::ports::runtime::UnitOfWork;
use ianua_app::ports::shared::EventDispatcher;
use ianua_app::ports::tenant::TenantStore;
use ianua_assembly::activity::ActivityState;
use ianua_assembly::agents::AgentState;
use ianua_assembly::audit::AuditState;
use ianua_assembly::authentication::AuthenticationState;
use ianua_assembly::authorization::AuthorizationState;
use ianua_assembly::branding::BrandingState;
use ianua_assembly::consumers::ConsumerState;
use ianua_assembly::crypto::CryptoState;
use ianua_assembly::data_classification::DataClassificationState;
use ianua_assembly::deps::{Adapters, Settings};
use ianua_assembly::directory::DirectoryState;
use ianua_assembly::domain::DomainState;
use ianua_assembly::federation::FederationState;
use ianua_assembly::files::FilesState;
use ianua_assembly::gateway::GatewayState;
use ianua_assembly::identity::IdentityState;
use ianua_assembly::messaging::MessagingState;
use ianua_assembly::notifications::NotificationState;
use ianua_assembly::oauth::OAuthState;
use ianua_assembly::onboarding::OnboardingState;
use ianua_assembly::operator::OperatorState;
use ianua_assembly::organization::OrganizationState;
use ianua_assembly::proxy::ProxyState;
use ianua_assembly::realtime::RealtimeState;
use ianua_assembly::routing::RoutingState;
use ianua_assembly::runtime::RuntimeState;
use ianua_assembly::scim::ScimState;
use ianua_assembly::signals::SignalState;
use ianua_assembly::tenant::TenantState;
use ianua_assembly::webhooks::WebhookState;
use ianua_assembly::workflows::WorkflowState;
use ianua_assembly::{
    activity, agents, audit, authentication, authorization, branding, consumers, crypto,
    data_classification, directory, domain, federation, files, gateway, identity, messaging,
    notifications, oauth, onboarding, operator, organization, proxy, realtime, routing, runtime,
    scim, signals, tenant, webhooks, workflows,
};

use crate::middleware::client_ip::TrustedProxies;
use crate::ws::StreamTiming;
use crate::ws_limits::StreamLimiter;

/// Everything the API is built from: the adapters and settings its use
/// cases are built with, and the HTTP layer's own settings.
#[derive(Clone)]
pub struct Deps {
    /// The adapter behind each port.
    pub adapters: Adapters,
    /// The settings the use cases are built with.
    pub settings: Settings,
    /// How the HTTP layer itself behaves.
    pub http: HttpSettings,
    /// Proxies whose `X-Forwarded-For` is believed.
    pub trusted_proxies: TrustedProxies,
}

/// What bounds the live streams on this node: how many each caller holds,
/// how often each asks again, and how long each lasts at most.
#[derive(Clone)]
pub(crate) struct StreamGates {
    /// Counts each caller's live streams.
    pub(crate) streams: Arc<StreamLimiter>,
    /// How often a stream asks again, and how long it lasts at most.
    pub(crate) timing: StreamTiming,
}

/// Everything the handlers, extractors and middleware share.
#[derive(Clone)]
pub struct ApiState {
    /// Lengths and counts the domain checks values against.
    pub domain_limits: ianua_domain::shared::config::DomainLimits,
    /// How the HTTP layer itself behaves.
    pub http: HttpSettings,
    /// Proxies whose `X-Forwarded-For` is believed.
    pub trusted_proxies: Arc<TrustedProxies>,
    /// Where each request's auditor sends its events.
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    /// Runs each state-changing request as one unit.
    pub unit_of_work: Arc<dyn UnitOfWork>,
    /// Finds the organization a path names.
    pub org_store: Arc<dyn OrganizationStore>,
    /// Finds the tenant a path names.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Turns a second bearer, such as a linked session, into its caller.
    pub token_resolver: Arc<dyn ianua_app::ports::shared::TokenResolver>,
    /// The notification use cases.
    pub notifications: NotificationState,
    /// The directory use cases: LDAP client certificates and service
    /// accounts.
    pub directory: DirectoryState,
    /// The tenant use cases: lifecycle and settings.
    pub tenant: TenantState,
    /// The custom domain use cases.
    pub domain: DomainState,
    /// The branding use cases.
    pub branding: BrandingState,
    /// The authorization use cases: roles, groups, policy, resource types
    /// and the governance around them.
    pub authorization: AuthorizationState,
    /// The audit trail use cases.
    pub audit: AuditState,
    /// The activity calendar use cases.
    pub activity: ActivityState,
    /// The agent use cases.
    pub agents: AgentState,
    /// The live streams: the subscriber and the admissions.
    pub realtime: RealtimeState,
    /// What bounds the live streams on this node.
    pub(crate) stream_gates: StreamGates,
    /// The workflow use cases.
    pub workflows: WorkflowState,
    /// The webhook use cases.
    pub webhooks: WebhookState,
    /// The signal stream use cases.
    pub signals: SignalState,
    /// The messaging use cases and the live topic stream's subscriber.
    pub messaging: MessagingState,
    /// The consumer use cases.
    pub consumers: ConsumerState,
    /// The SCIM provisioning use cases.
    pub scim: ScimState,
    /// The federation use cases: connections, links, SCIM settings and identity provider metadata.
    pub federation: FederationState,
    /// The files handed out by address: export downloads and logos.
    pub files: FilesState,
    /// The OAuth use cases: clients, API keys and flows.
    pub oauth: OAuthState,
    /// The signing key use cases.
    pub crypto: CryptoState,
    /// The onboarding use cases: sign-up.
    pub onboarding: OnboardingState,
    /// The operator use cases: accounts, keys and impersonation grants.
    pub operator: OperatorState,
    /// The organization use cases: the organization, its members and their sign-in.
    pub organization: OrganizationState,
    /// The authentication use cases: sign-in, factors, passkeys, sessions, single sign-on and app sign-in.
    pub authentication: AuthenticationState,
    /// The identity use cases: users, invitations, email, attributes and privacy.
    pub identity: IdentityState,
    /// The data classification use cases.
    pub data_classification: DataClassificationState,
    /// The gateway configuration use cases: export and import.
    pub gateway: GatewayState,
    /// The proxy use cases: pipelines and their stages.
    pub proxy: ProxyState,
    /// The routing use cases: routes, services, stream routes and egress policies.
    pub routing: RoutingState,
    /// The use cases for running the service: readiness and the metrics
    /// scrape.
    pub runtime: RuntimeState,
}

/// Builds the API's state from what the server plugged in.
// Every context is wired once in this exhaustive literal; splitting it would hide the field mapping.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn build(deps: &Deps) -> ApiState {
    let (adapters, settings) = (&deps.adapters, &deps.settings);
    let identity = identity::build(adapters, settings);
    ApiState {
        authentication: authentication::build(adapters, settings, &identity),
        domain_limits: settings.domain_limits.clone(),
        http: deps.http.clone(),
        trusted_proxies: Arc::new(deps.trusted_proxies.clone()),
        stream_gates: stream_gates(&deps.http),
        event_dispatcher: adapters.event_dispatcher.clone(),
        unit_of_work: adapters.unit_of_work.clone(),
        org_store: adapters.organization_store.clone(),
        tenant_store: adapters.tenant_store.clone(),
        token_resolver: adapters.token_resolver.clone(),
        notifications: notifications::build(adapters),
        directory: directory::build(adapters, settings),
        tenant: tenant::build(adapters, settings),
        domain: domain::build(adapters, settings),
        branding: branding::build(adapters),
        authorization: authorization::build(adapters),
        audit: audit::build(adapters, settings.tunables.audit_export_limits),
        activity: activity::build(adapters),
        agents: agents::build(adapters, settings),
        realtime: realtime::build(adapters),
        workflows: workflows::build(adapters, settings),
        webhooks: webhooks::build(adapters),
        signals: signals::build(adapters, settings),
        messaging: messaging::build(adapters),
        consumers: consumers::build(adapters, settings),
        scim: scim::build(adapters, settings),
        federation: federation::build(adapters, settings),
        files: files::build(adapters),
        oauth: oauth::build(adapters, settings),
        crypto: crypto::build(adapters, settings),
        onboarding: onboarding::build(adapters, settings),
        operator: operator::build(adapters, settings),
        organization: organization::build(adapters, settings),
        identity,
        data_classification: data_classification::build(adapters),
        gateway: gateway::build(adapters, settings),
        proxy: proxy::build(adapters),
        routing: routing::build(adapters, settings),
        runtime: runtime::build(adapters),
    }
}

/// Builds stream admission gates from the HTTP listener's configured limits.
fn stream_gates(http: &HttpSettings) -> StreamGates {
    StreamGates {
        streams: http.streams.clone(),
        timing: StreamTiming {
            recheck: http.stream_recheck,
            lifetime: http.stream_lifetime,
        },
    }
}

/// Lets a handler take one context's state, `State<NotificationState>`,
/// rather than the whole of `ApiState`.
macro_rules! sub_states {
    ($($field:ident : $ty:ty),* $(,)?) => {
        $(
            impl axum::extract::FromRef<ApiState> for $ty {
                fn from_ref(state: &ApiState) -> Self {
                    state.$field.clone()
                }
            }
        )*
    };
}

sub_states! {
    domain_limits: ianua_domain::shared::config::DomainLimits,
    notifications: NotificationState,
    routing: RoutingState,
    runtime: RuntimeState,
    proxy: ProxyState,
    gateway: GatewayState,
    data_classification: DataClassificationState,
    identity: IdentityState,
    authentication: AuthenticationState,
    organization: OrganizationState,
    operator: OperatorState,
    onboarding: OnboardingState,
    crypto: CryptoState,
    oauth: OAuthState,
    federation: FederationState,
    files: FilesState,
    scim: ScimState,
    consumers: ConsumerState,
    messaging: MessagingState,
    signals: SignalState,
    webhooks: WebhookState,
    workflows: WorkflowState,
    realtime: RealtimeState,
    stream_gates: StreamGates,
    agents: AgentState,
    activity: ActivityState,
    audit: AuditState,
    authorization: AuthorizationState,
    branding: BrandingState,
    domain: DomainState,
    tenant: TenantState,
    directory: DirectoryState,
}
