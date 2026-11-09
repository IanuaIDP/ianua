//! Event types, one enum per bounded context, composed into [`EventType`].
//!
//! Each context lists its events once, in `event_types!`. Each event has the
//! dotted string it is published and audited under, such as
//! `agents.agent_created`. That one list makes the enum, its
//! [`ALL`](AgentsEvent::ALL) table, `as_str` and `parse`. So a string cannot
//! be added to one of them and forgotten in another.

/// Declares a context's event enum from one list of `Variant => "string"`.
///
/// It writes the enum with the derives every event type carries. It also
/// writes an `ALL` table of every variant and its string, `as_str`, `parse`
/// and `description`, which reads each variant's doc comment, so the words
/// a catalog shows are the ones the declaration gives.
macro_rules! event_types {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[doc = $doc:literal])* $variant:ident => $text:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub enum $name {
            $( $(#[doc = $doc])* $variant, )+
        }

        impl $name {
            /// What the event means, as its declaration says it.
            #[must_use]
            pub fn description(&self) -> &'static str {
                match self {
                    $( Self::$variant => concat!($($doc),*).trim(), )+
                }
            }

            /// Every event of this context, with the string it is published
            /// and audited under.
            pub const ALL: &'static [(Self, &'static str)] = &[ $( (Self::$variant, $text), )+ ];

            /// The dotted string the event is published under.
            #[must_use]
            pub fn as_str(&self) -> &'static str {
                match self {
                    $( Self::$variant => $text, )+
                }
            }

            /// The event with this dotted string, if there is one.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $( $text => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

/// Agent events.
pub mod agents;
/// Authentication events.
pub mod authentication;
/// Authorization events.
pub mod authorization;
/// Branding events.
pub mod branding;
/// Consumer events.
pub mod consumers;
/// Signing key and algorithm migration events.
pub mod crypto;
/// Federation events.
pub mod federation;
/// Identity events.
pub mod identity;
/// Messaging events.
pub mod messaging;
/// Notification events.
pub mod notifications;
/// OAuth and API key events.
pub mod oauth;
/// Operator events.
pub mod operator;
/// Organization events.
pub mod organization;
/// Proxy pipeline events.
pub mod proxy;
/// Routing events.
pub mod routing;
/// Security signal stream events.
pub mod signals;
/// Tenant events.
pub mod tenant;
mod visibility;
/// Webhook events.
pub mod webhooks;
/// Workflow events.
pub mod workflows;

pub use agents::AgentsEvent;
pub use authentication::AuthenticationEvent;
pub use authorization::AuthorizationEvent;
pub use branding::BrandingEvent;
pub use consumers::ConsumersEvent;
pub use crypto::CryptoEvent;
pub use federation::FederationEvent;
pub use identity::IdentityEvent;
pub use messaging::MessagingEvent;
pub use notifications::NotificationsEvent;
pub use oauth::OAuthEvent;
pub use operator::OperatorEvent;
pub use organization::OrganizationEvent;
pub use proxy::ProxyEvent;
pub use routing::RoutingEvent;
pub use signals::SignalsEvent;
pub use tenant::TenantEvent;
pub use visibility::EventVisibility;
pub use webhooks::WebhooksEvent;
pub use workflows::WorkflowsEvent;

/// Any event of any context, in one type.
///
/// Each context owns its own event enum. This type wraps them all, for the
/// code that handles every event: the audit log, event bus routing and
/// webhook filters. No context depends on another. Each knows only its own
/// enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EventType {
    /// Agent events, such as agent identities and delegations.
    Agents(AgentsEvent),
    /// Authentication events, such as sign-ins, sessions and tokens.
    Authentication(AuthenticationEvent),
    /// Authorization events, such as roles, groups and policies.
    Authorization(AuthorizationEvent),
    /// Branding events, such as a change to a tenant's look.
    Branding(BrandingEvent),
    /// Crypto events, such as key rotation and algorithm migrations.
    Crypto(CryptoEvent),
    /// Federation events, such as connections, just-in-time users and SCIM.
    Federation(FederationEvent),
    /// Identity events, such as users, email and status.
    Identity(IdentityEvent),
    /// OAuth events, such as clients and API keys.
    OAuth(OAuthEvent),
    /// Operator events, such as accounts, API keys and impersonation.
    Operator(OperatorEvent),
    /// Organization events, such as its life, members and tenants.
    Organization(OrganizationEvent),
    /// Proxy pipeline events, such as stages and their setup.
    Proxy(ProxyEvent),
    /// Routing events, such as routes, services, stream routes and egress
    /// policies.
    Routing(RoutingEvent),
    /// Signals events, such as CAEP and SSE stream changes.
    Signals(SignalsEvent),
    /// Tenant events, such as its life, settings, domains and DNS.
    Tenant(TenantEvent),
    /// Notification events, such as read receipts and preferences.
    Notifications(NotificationsEvent),
    /// Messaging events, such as topics, subscriptions and publishes.
    Messaging(MessagingEvent),
    /// Consumer events, such as creating, disabling and rotating
    /// credentials.
    Consumers(ConsumersEvent),
    /// Webhook events, such as subscriptions and deliveries.
    Webhooks(WebhooksEvent),
    /// Workflow events, such as versions, executions, steps and integration
    /// accounts.
    Workflows(WorkflowsEvent),
}

impl EventType {
    /// Every event type of every context.
    pub fn all() -> impl Iterator<Item = Self> {
        every(AgentsEvent::ALL)
            .chain(every(AuthenticationEvent::ALL))
            .chain(every(AuthorizationEvent::ALL))
            .chain(every(BrandingEvent::ALL))
            .chain(every(CryptoEvent::ALL))
            .chain(every(FederationEvent::ALL))
            .chain(every(IdentityEvent::ALL))
            .chain(every(OAuthEvent::ALL))
            .chain(every(OperatorEvent::ALL))
            .chain(every(OrganizationEvent::ALL))
            .chain(every(ProxyEvent::ALL))
            .chain(every(RoutingEvent::ALL))
            .chain(every(SignalsEvent::ALL))
            .chain(every(TenantEvent::ALL))
            .chain(every(NotificationsEvent::ALL))
            .chain(every(MessagingEvent::ALL))
            .chain(every(ConsumersEvent::ALL))
            .chain(every(WebhooksEvent::ALL))
            .chain(every(WorkflowsEvent::ALL))
    }

    /// The dotted string the event is published under.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agents(e) => e.as_str(),
            Self::Authentication(e) => e.as_str(),
            Self::Authorization(e) => e.as_str(),
            Self::Branding(e) => e.as_str(),
            Self::Crypto(e) => e.as_str(),
            Self::Federation(e) => e.as_str(),
            Self::Identity(e) => e.as_str(),
            Self::OAuth(e) => e.as_str(),
            Self::Operator(e) => e.as_str(),
            Self::Organization(e) => e.as_str(),
            Self::Proxy(e) => e.as_str(),
            Self::Routing(e) => e.as_str(),
            Self::Signals(e) => e.as_str(),
            Self::Tenant(e) => e.as_str(),
            Self::Notifications(e) => e.as_str(),
            Self::Messaging(e) => e.as_str(),
            Self::Consumers(e) => e.as_str(),
            Self::Webhooks(e) => e.as_str(),
            Self::Workflows(e) => e.as_str(),
        }
    }

    /// What the event means, in the words of its declaration, such as "A
    /// webhook subscription was created." for
    /// `webhooks.subscription_created`.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Agents(e) => e.description(),
            Self::Authentication(e) => e.description(),
            Self::Authorization(e) => e.description(),
            Self::Branding(e) => e.description(),
            Self::Crypto(e) => e.description(),
            Self::Federation(e) => e.description(),
            Self::Identity(e) => e.description(),
            Self::OAuth(e) => e.description(),
            Self::Operator(e) => e.description(),
            Self::Organization(e) => e.description(),
            Self::Proxy(e) => e.description(),
            Self::Routing(e) => e.description(),
            Self::Signals(e) => e.description(),
            Self::Tenant(e) => e.description(),
            Self::Notifications(e) => e.description(),
            Self::Messaging(e) => e.description(),
            Self::Consumers(e) => e.description(),
            Self::Webhooks(e) => e.description(),
            Self::Workflows(e) => e.description(),
        }
    }

    /// Whether an occurrence of this event belongs in the audit trail.
    ///
    /// Almost every event does, since the audit log records what was done to
    /// an organization and by whom. The exceptions are notification read
    /// receipts, which hold only screen state. They are published for live
    /// listeners but never written down.
    #[must_use]
    pub fn is_auditable(&self) -> bool {
        match self {
            Self::Notifications(e) => e.is_auditable(),
            Self::Agents(_)
            | Self::Authentication(_)
            | Self::Authorization(_)
            | Self::Branding(_)
            | Self::Crypto(_)
            | Self::Federation(_)
            | Self::Identity(_)
            | Self::OAuth(_)
            | Self::Operator(_)
            | Self::Organization(_)
            | Self::Proxy(_)
            | Self::Routing(_)
            | Self::Signals(_)
            | Self::Tenant(_)
            | Self::Messaging(_)
            | Self::Consumers(_)
            | Self::Webhooks(_)
            | Self::Workflows(_) => true,
        }
    }

    /// Whether an occurrence of this event is worth a notification.
    ///
    /// Notification events never are, so sending notifications cannot loop.
    /// Nor is a user's own activity, such as sign-in steps and mails sent.
    /// Nor is an event a caller can repeat on every request, such as a
    /// honeypot hit or a refused egress. Only the audit trail needs those.
    /// The few of them someone must still hear of are security alerts, a
    /// separate answer with its own limit, the notifications context's
    /// `SecurityAlert`.
    #[must_use]
    pub fn is_notifiable(&self) -> bool {
        match self {
            Self::Notifications(_) => false,
            Self::Organization(e) => e.is_notifiable(),
            Self::Identity(e) => e.is_notifiable(),
            Self::Authentication(e) => e.is_notifiable(),
            Self::Agents(e) => e.is_notifiable(),
            Self::Messaging(e) => e.is_notifiable(),
            Self::Webhooks(e) => e.is_notifiable(),
            Self::OAuth(e) => e.is_notifiable(),
            Self::Workflows(e) => e.is_notifiable(),
            Self::Authorization(e) => e.is_notifiable(),
            Self::Proxy(e) => e.is_notifiable(),
            Self::Signals(e) => e.is_notifiable(),
            Self::Federation(e) => e.is_notifiable(),
            Self::Branding(e) => e.is_notifiable(),
            Self::Tenant(e) => e.is_notifiable(),
            Self::Operator(e) => e.is_notifiable(),
            Self::Routing(e) => e.is_notifiable(),
            Self::Crypto(e) => e.is_notifiable(),
            Self::Consumers(_) => true,
        }
    }

    /// The event with this dotted string, such as
    /// `"authentication.login_succeeded"`, if there is one.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (prefix, _) = s.split_once('.')?;
        match prefix {
            "agents" => AgentsEvent::parse(s).map(Self::Agents),
            "authentication" => AuthenticationEvent::parse(s).map(Self::Authentication),
            "authorization" => AuthorizationEvent::parse(s).map(Self::Authorization),
            "branding" => BrandingEvent::parse(s).map(Self::Branding),
            "crypto" => CryptoEvent::parse(s).map(Self::Crypto),
            "federation" => FederationEvent::parse(s).map(Self::Federation),
            "identity" => IdentityEvent::parse(s).map(Self::Identity),
            "oauth" => OAuthEvent::parse(s).map(Self::OAuth),
            "operator" => OperatorEvent::parse(s).map(Self::Operator),
            "organization" => OrganizationEvent::parse(s).map(Self::Organization),
            "proxy" => ProxyEvent::parse(s).map(Self::Proxy),
            "routing" => RoutingEvent::parse(s).map(Self::Routing),
            "signals" => SignalsEvent::parse(s).map(Self::Signals),
            "tenant" => TenantEvent::parse(s).map(Self::Tenant),
            "notifications" => NotificationsEvent::parse(s).map(Self::Notifications),
            "messaging" => MessagingEvent::parse(s).map(Self::Messaging),
            "consumers" => ConsumersEvent::parse(s).map(Self::Consumers),
            "webhooks" => WebhooksEvent::parse(s).map(Self::Webhooks),
            "workflows" => WorkflowsEvent::parse(s).map(Self::Workflows),
            _ => None,
        }
    }
}

/// The event types of one context's `ALL` table.
fn every<E: Copy + Into<EventType>>(
    all: &'static [(E, &'static str)],
) -> impl Iterator<Item = EventType> {
    all.iter().map(|(event, _)| (*event).into())
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<AgentsEvent> for EventType {
    fn from(e: AgentsEvent) -> Self {
        Self::Agents(e)
    }
}

impl From<AuthenticationEvent> for EventType {
    fn from(e: AuthenticationEvent) -> Self {
        Self::Authentication(e)
    }
}

impl From<AuthorizationEvent> for EventType {
    fn from(e: AuthorizationEvent) -> Self {
        Self::Authorization(e)
    }
}

impl From<BrandingEvent> for EventType {
    fn from(e: BrandingEvent) -> Self {
        Self::Branding(e)
    }
}

impl From<CryptoEvent> for EventType {
    fn from(e: CryptoEvent) -> Self {
        Self::Crypto(e)
    }
}

impl From<FederationEvent> for EventType {
    fn from(e: FederationEvent) -> Self {
        Self::Federation(e)
    }
}

impl From<IdentityEvent> for EventType {
    fn from(e: IdentityEvent) -> Self {
        Self::Identity(e)
    }
}

impl From<OAuthEvent> for EventType {
    fn from(e: OAuthEvent) -> Self {
        Self::OAuth(e)
    }
}

impl From<OperatorEvent> for EventType {
    fn from(e: OperatorEvent) -> Self {
        Self::Operator(e)
    }
}

impl From<OrganizationEvent> for EventType {
    fn from(e: OrganizationEvent) -> Self {
        Self::Organization(e)
    }
}

impl From<ProxyEvent> for EventType {
    fn from(e: ProxyEvent) -> Self {
        Self::Proxy(e)
    }
}

impl From<RoutingEvent> for EventType {
    fn from(e: RoutingEvent) -> Self {
        Self::Routing(e)
    }
}

impl From<SignalsEvent> for EventType {
    fn from(e: SignalsEvent) -> Self {
        Self::Signals(e)
    }
}

impl From<TenantEvent> for EventType {
    fn from(e: TenantEvent) -> Self {
        Self::Tenant(e)
    }
}

impl From<NotificationsEvent> for EventType {
    fn from(e: NotificationsEvent) -> Self {
        Self::Notifications(e)
    }
}

impl From<MessagingEvent> for EventType {
    fn from(e: MessagingEvent) -> Self {
        Self::Messaging(e)
    }
}

impl From<ConsumersEvent> for EventType {
    fn from(e: ConsumersEvent) -> Self {
        Self::Consumers(e)
    }
}

impl From<WebhooksEvent> for EventType {
    fn from(e: WebhooksEvent) -> Self {
        Self::Webhooks(e)
    }
}

impl From<WorkflowsEvent> for EventType {
    fn from(e: WorkflowsEvent) -> Self {
        Self::Workflows(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A successful login is published as `authentication.login_succeeded`
    /// and a new user as `identity.user_registered`.
    #[test]
    fn bc_enum_produces_correct_string() {
        assert_eq!(
            AuthenticationEvent::LoginSucceeded.as_str(),
            "authentication.login_succeeded"
        );
        assert_eq!(
            IdentityEvent::UserRegistered.as_str(),
            "identity.user_registered"
        );
    }

    /// A failed login wrapped in [`EventType`] keeps the string its context
    /// gave it, `authentication.login_failed`.
    #[test]
    fn composed_delegates_to_bc() {
        let et = EventType::from(AuthenticationEvent::LoginFailed);
        assert_eq!(et.as_str(), "authentication.login_failed");
    }

    /// Ann, an organization member, signs in. The audit trail records it,
    /// but her colleagues get no notification.
    #[test]
    fn a_members_own_sign_in_is_audited_but_not_notified() {
        let et = EventType::from(OrganizationEvent::OrgLoginSucceeded);

        assert!(et.is_auditable());
        assert!(!et.is_notifiable());
    }

    /// Bob, a tenant user, signs in. The audit trail records it, but no
    /// administrator is notified.
    #[test]
    fn a_tenant_users_own_sign_in_is_audited_but_not_notified() {
        let et = EventType::from(AuthenticationEvent::LoginSucceeded);

        assert!(et.is_auditable());
        assert!(!et.is_notifiable());
    }

    /// Bob's account is locked after too many failed sign-ins. Unlike a
    /// plain sign-in, this does reach administrators as a notification.
    #[test]
    fn a_lockout_is_still_notified() {
        let et = EventType::from(AuthenticationEvent::AccountLockedOut);

        assert!(et.is_notifiable());
    }

    /// A new member is added to the organization. Colleagues are notified.
    #[test]
    fn a_change_to_the_organization_is_notified() {
        let et = EventType::from(OrganizationEvent::OrgUserCreated);

        assert!(et.is_notifiable());
    }

    /// Password-reset requests, consent changes and personal preference
    /// updates remain excluded from notifications through the composed event type.
    #[test]
    fn one_persons_own_activity_is_not_notified() {
        for event in [
            EventType::from(AuthenticationEvent::PasswordResetRequested),
            EventType::from(IdentityEvent::ConsentGranted),
            EventType::from(IdentityEvent::ConsentRevoked),
            EventType::from(IdentityEvent::UserPreferencesUpdated),
        ] {
            assert!(!event.is_notifiable(), "{event:?}");
        }
    }

    /// Repeatable threat, egress and simulation events remain auditable through
    /// the composed event type without becoming feed notifications.
    #[test]
    fn events_anyone_can_repeat_per_request_are_not_notified() {
        for event in [
            EventType::from(ProxyEvent::HoneypotHit),
            EventType::from(ProxyEvent::AutomatedThreatDetected),
            EventType::from(ProxyEvent::CanaryTokenTriggered),
            EventType::from(AgentsEvent::EgressDenied),
            EventType::from(AuthorizationEvent::PolicySimulated),
        ] {
            assert!(event.is_auditable(), "{event:?}");
            assert!(!event.is_notifiable(), "{event:?}");
        }
    }

    /// [`EventType::all`] lists no event twice, and it reaches the last
    /// context, workflows, so no context's table was left out.
    #[test]
    fn every_event_type_is_listed_once() {
        let all: Vec<EventType> = EventType::all().collect();
        let distinct: std::collections::HashSet<EventType> = all.iter().copied().collect();

        assert_eq!(all.len(), distinct.len());
        assert!(all.contains(&EventType::from(WorkflowsEvent::ALL[0].0)));
    }

    /// Ann reads the list of events a webhook may receive. Every event
    /// carries the words of its declaration, trimmed, so none shows up
    /// blank, and a creation reads as "A webhook subscription was created."
    #[test]
    fn every_event_type_describes_itself() {
        for event in EventType::all() {
            let description = event.description();
            assert!(!description.is_empty(), "{event}");
            assert_eq!(description, description.trim(), "{event}");
        }
        assert_eq!(
            EventType::from(WebhooksEvent::SubscriptionCreated).description(),
            "A webhook subscription was created."
        );
    }

    /// A user changes their notification preferences. That event sends no
    /// notification, so notifications cannot trigger each other in a loop.
    #[test]
    fn notifications_are_never_notified() {
        let et = EventType::from(NotificationsEvent::PreferencesUpdated);

        assert!(!et.is_notifiable());
    }

    /// A provisioned tenant prints as `tenant.provisioned`, the same string
    /// it is published under.
    #[test]
    fn display_matches_as_str() {
        let et = EventType::Tenant(TenantEvent::Provisioned);
        assert_eq!(et.to_string(), "tenant.provisioned");
    }

    #[cfg(feature = "serde")]
    /// Every event's stored text and its JSON name, one line each. Webhook
    /// filters save the JSON name.
    fn names_as_stored() -> String {
        let mut lines: Vec<String> = every_event()
            .into_iter()
            .map(|(event, text)| format!("{text} {}\n", serde_json::to_string(&event).unwrap()))
            .collect();
        lines.sort();
        lines.concat()
    }

    /// Every event's dotted string and JSON name match the checked-in
    /// snapshot. Audit records, the event bus and saved webhook filters
    /// store these names, so renaming one is caught here.
    /// `IANUA_WRITE_SNAPSHOTS=1` rewrites the snapshot after a deliberate
    /// change.
    #[cfg(feature = "serde")]
    #[test]
    fn every_event_keeps_the_names_it_is_stored_under() {
        if std::env::var_os("IANUA_WRITE_SNAPSHOTS").is_some() {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/types/event_type/names.snapshot"
            );
            std::fs::write(path, names_as_stored()).unwrap();
            return;
        }
        assert_eq!(names_as_stored(), include_str!("names.snapshot"));
    }

    /// A sample of events, including all three notification events, parses
    /// back from its own string to the same event.
    #[test]
    fn parse_roundtrips_all_known_types() {
        let samples = vec![
            EventType::Authentication(AuthenticationEvent::LoginSucceeded),
            EventType::Identity(IdentityEvent::UserRegistered),
            EventType::Tenant(TenantEvent::Provisioned),
            EventType::Notifications(NotificationsEvent::NotificationRead),
            EventType::Notifications(NotificationsEvent::AllNotificationsRead),
            EventType::Notifications(NotificationsEvent::PreferencesUpdated),
        ];
        for et in &samples {
            let parsed = EventType::parse(et.as_str());
            assert_eq!(parsed, Some(*et), "failed to roundtrip {}", et.as_str());
        }
    }

    /// An unknown context, an unknown event in a known context, and a
    /// string with no dot all parse to nothing.
    #[test]
    fn parse_returns_none_for_unknown_string() {
        assert_eq!(EventType::parse("unknown.event"), None);
        assert_eq!(EventType::parse("authentication.nonexistent"), None);
        assert_eq!(EventType::parse("nodot"), None);
    }

    /// One event from every context, so [`EventType`] is tested with each.
    /// A prefix it fails to match makes every event of that context
    /// unparseable. A wrong string publishes the event on a subject nobody
    /// listens to.
    const ONE_PER_CONTEXT: &[EventType] = &[
        EventType::Agents(AgentsEvent::AgentCreated),
        EventType::Authentication(AuthenticationEvent::LoginSucceeded),
        EventType::Authorization(AuthorizationEvent::RoleAssigned),
        EventType::Branding(BrandingEvent::Updated),
        EventType::Crypto(CryptoEvent::KeyRotated),
        EventType::Federation(FederationEvent::ConnectionCreated),
        EventType::Identity(IdentityEvent::UserRegistered),
        EventType::OAuth(OAuthEvent::ClientCreated),
        EventType::Operator(OperatorEvent::ImpersonationGranted),
        EventType::Organization(OrganizationEvent::Created),
        EventType::Proxy(ProxyEvent::PipelineCreated),
        EventType::Routing(RoutingEvent::RouteCreated),
        EventType::Signals(SignalsEvent::StreamRegistered),
        EventType::Tenant(TenantEvent::Provisioned),
        EventType::Notifications(NotificationsEvent::PreferencesUpdated),
        EventType::Messaging(MessagingEvent::TopicCreated),
        EventType::Consumers(ConsumersEvent::ConsumerCreated),
        EventType::Webhooks(WebhooksEvent::SubscriptionCreated),
        EventType::Workflows(WorkflowsEvent::ExecutionStarted),
    ];

    /// One event from each context prints as its string and parses back
    /// through [`EventType::parse`]. A prefix the parser missed would make
    /// that whole context unparseable.
    #[test]
    fn every_context_renders_and_parses_through_the_composed_type() {
        for event in ONE_PER_CONTEXT {
            let text = event.as_str();
            assert_eq!(EventType::parse(text), Some(*event), "{text}");
            assert_eq!(event.to_string(), text);
        }
    }

    /// One event from each context is audited. Marking one or all
    /// notifications read is not, since a read receipt is only screen state.
    #[test]
    fn everything_but_a_read_receipt_belongs_in_the_audit_trail() {
        for event in ONE_PER_CONTEXT {
            assert!(event.is_auditable(), "{event}");
        }

        assert!(
            !EventType::Notifications(NotificationsEvent::NotificationRead).is_auditable(),
            "a read receipt says nothing about who did what"
        );
        assert!(!EventType::Notifications(NotificationsEvent::AllNotificationsRead).is_auditable());
    }

    /// Every event of every context, as the composed type, with its string.
    fn every_event() -> Vec<(EventType, &'static str)> {
        fn composed<E: Copy + Into<EventType>>(
            table: &'static [(E, &'static str)],
        ) -> impl Iterator<Item = (EventType, &'static str)> {
            table.iter().map(|(event, text)| ((*event).into(), *text))
        }

        composed(AgentsEvent::ALL)
            .chain(composed(AuthenticationEvent::ALL))
            .chain(composed(AuthorizationEvent::ALL))
            .chain(composed(BrandingEvent::ALL))
            .chain(composed(CryptoEvent::ALL))
            .chain(composed(FederationEvent::ALL))
            .chain(composed(IdentityEvent::ALL))
            .chain(composed(OAuthEvent::ALL))
            .chain(composed(OperatorEvent::ALL))
            .chain(composed(OrganizationEvent::ALL))
            .chain(composed(ProxyEvent::ALL))
            .chain(composed(RoutingEvent::ALL))
            .chain(composed(SignalsEvent::ALL))
            .chain(composed(TenantEvent::ALL))
            .chain(composed(NotificationsEvent::ALL))
            .chain(composed(MessagingEvent::ALL))
            .chain(composed(ConsumersEvent::ALL))
            .chain(composed(WebhooksEvent::ALL))
            .chain(composed(WorkflowsEvent::ALL))
            .collect()
    }

    /// Every event of every context parses back from its string to itself.
    /// A consumer subscribed to a string that parsed into another event
    /// would stop matching with no error.
    #[test]
    fn every_event_renders_the_string_it_parses_back_from() {
        for (event, text) in every_event() {
            assert_eq!(event.as_str(), text);
            assert_eq!(EventType::parse(text), Some(event), "{text}");
        }
    }

    /// No two events in any context are published under the same string,
    /// so a subscriber never gets an event it did not ask for.
    #[test]
    fn no_two_events_share_a_string() {
        let mut texts: Vec<&str> = every_event().into_iter().map(|(_, text)| text).collect();
        texts.sort_unstable();
        let total = texts.len();
        texts.dedup();

        assert_eq!(texts.len(), total);
    }

    /// `nosuchcontext.created`, `.created` and the empty string all parse
    /// to nothing.
    #[test]
    fn a_prefix_no_context_owns_parses_to_nothing() {
        assert_eq!(EventType::parse("nosuchcontext.created"), None);
        assert_eq!(EventType::parse(".created"), None);
        assert_eq!(EventType::parse(""), None);
    }
}
