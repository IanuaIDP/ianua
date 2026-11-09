//! Real-time notification delivery port.
//!
//! Abstracts the pub/sub mechanism for pushing notifications to
//! connected WebSocket clients: the message bus every node reaches, or one
//! in the process for a single node and for tests.

use async_trait::async_trait;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::notification::{AboutResource, Notification, ReadState};
use ianua_domain::domains::notifications::reach::NotificationReach;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::domains::proxy::observation::{ObservedPrincipal, RequestObservation};
use ianua_domain::domains::workflows::events::RunMoment;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CorrelationId, EventType, Fact, Label, NotificationId, OperatorId, OrgUserId, OrganizationId,
    TenantId, Text, UntrustedText, UserId, WorkflowExecutionId, WorkflowId,
};
use time::Duration;

use crate::ports::provisioning::SetupProgress;

/// One live update, pushed to whoever is subscribed to its subject.
///
/// Each variant carries exactly what reaches a subscriber, so the update can
/// cross a process boundary and arrive whole. How it is written on a wire is
/// the adapter's business.
#[derive(Debug, Clone)]
pub enum RealtimeMessage {
    /// A notification someone was just sent.
    Notification(NotificationUpdate),
    /// A step of a tenant's setup ended.
    SetupProgress(SetupProgress),
    /// A message published on the agent message plane.
    BrokerMessage(BrokerDelivery),
    /// A request the proxy decided.
    ProxyAudit(ProxyAuditEntry),
    /// Something happened in a workflow run.
    RunMoment(RunMoment),
    /// Someone changed a workflow's draft.
    DraftChanged(DraftChange),
}

impl RealtimeMessage {
    /// The tenant a setup update is about, for filtering a stream to what a
    /// subscriber may see. `None` for every other kind of update.
    #[must_use]
    pub fn setup_tenant(&self) -> Option<&TenantId> {
        match self {
            Self::SetupProgress(progress) => Some(&progress.tenant_id),
            Self::Notification(_)
            | Self::BrokerMessage(_)
            | Self::ProxyAudit(_)
            | Self::RunMoment(_)
            | Self::DraftChanged(_) => None,
        }
    }
}

/// A workflow's draft someone changed, for whoever has it open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftChange {
    /// The owner of the workflow whose draft changed.
    pub tenant_id: TenantId,
    /// The workflow whose draft changed.
    pub workflow_id: WorkflowId,
    /// The event that changed it, so the builder can say how.
    pub event_type: EventType,
}

/// The subject one workflow run's live moments are published on.
///
/// The tenant comes from the subscriber's own session, not from the URL,
/// so a caller naming another tenant's run listens where nothing is ever
/// published. The publisher and the WebSocket handler both derive it here.
#[must_use]
pub fn run_subject(tenant_id: &TenantId, execution_id: &WorkflowExecutionId) -> String {
    format!(
        "workflow.run.{}.{}",
        tenant_id.as_uuid().as_simple(),
        execution_id.as_uuid().as_simple()
    )
}

/// The subject changes to one workflow's draft are published on, derived
/// the same way as [`run_subject`].
#[must_use]
pub fn draft_subject(tenant_id: &TenantId, workflow_id: &WorkflowId) -> String {
    format!(
        "workflow.draft.{}.{}",
        tenant_id.as_uuid().as_simple(),
        workflow_id.as_uuid().as_simple()
    )
}

/// What a subscriber sees of a notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationUpdate {
    /// The notification's id.
    pub id: NotificationId,
    /// The event it reports.
    pub event_type: EventType,
    /// The subject area used to group this notice.
    pub category: NotificationCategory,
    /// How urgent it is.
    pub severity: NotificationSeverity,
    /// The heading displayed in the recipient's inbox.
    pub title: Label,
    /// Its rendered body, if it has one.
    pub body: Option<Text>,
    /// The resource it is about, if any.
    pub resource_id: AboutResource,
    /// How it reaches its reader: by their rights, or on their own account,
    /// whatever they hold.
    pub reach: NotificationReach,
    /// Whether it has been read.
    pub read: ReadState,
}

impl From<&Notification> for NotificationUpdate {
    fn from(notification: &Notification) -> Self {
        Self {
            id: notification.id(),
            event_type: *notification.event_type(),
            category: notification.category(),
            severity: notification.severity(),
            title: notification.title().clone(),
            body: notification.body().cloned(),
            resource_id: notification.resource_id(),
            reach: notification.reach(),
            read: ReadState::from(notification.is_read()),
        }
    }
}

/// A message on the agent message plane, as published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerDelivery {
    /// The tenant-relative topic it was published to.
    pub topic: TopicName,
    /// The message body.
    pub payload: Vec<u8>,
}

/// Whether the proxy let a request through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyDecision {
    /// Forwarded upstream.
    Allowed,
    /// Refused.
    Denied,
}

/// What the live security dashboard shows of one proxied request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAuditEntry {
    /// Ties the request to its logs, traces and audit rows.
    pub correlation_id: CorrelationId,
    /// The method as it arrived.
    pub method: UntrustedText,
    /// The path as it arrived.
    pub path: UntrustedText,
    /// The tenant the request resolved to, if it did.
    pub tenant_id: Fact<TenantId>,
    /// Who the proxy decided was asking.
    pub principal: ObservedPrincipal,
    /// Whether it was let through.
    pub decision: ProxyDecision,
    /// The status returned to the client.
    pub status: u16,
    /// How long the proxy took.
    pub latency: Duration,
}

impl From<&RequestObservation> for ProxyAuditEntry {
    fn from(observation: &RequestObservation) -> Self {
        Self {
            correlation_id: observation.correlation_id,
            method: observation.method.clone(),
            path: observation.path.as_text().clone(),
            tenant_id: observation.tenant_id,
            principal: observation.principal,
            decision: match observation.is_allowed() {
                true => ProxyDecision::Allowed,
                false => ProxyDecision::Denied,
            },
            status: observation.status(),
            latency: observation.latency,
        }
    }
}

/// Dyn-safe port for publishing notifications to real-time subscribers.
///
/// The fan-out worker calls it after persisting the notification. The
/// listening side is [`NotificationSubscriber`], kept apart because the app
/// only ever publishes.
#[async_trait]
pub trait NotificationPublisher: Send + Sync {
    /// Publishes a notification to a specific operator.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the message could not be published.
    async fn publish_to_operator(
        &self,
        operator_id: &OperatorId,
        message: &RealtimeMessage,
    ) -> Result<(), DomainError>;

    /// Publishes a notification to a specific org user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the message could not be published.
    async fn publish_to_org_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        message: &RealtimeMessage,
    ) -> Result<(), DomainError>;

    /// Publishes a notification to a specific tenant user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the message could not be published.
    async fn publish_to_tenant_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        message: &RealtimeMessage,
    ) -> Result<(), DomainError>;

    /// Publishes a notification to a named dashboard subject.
    ///
    /// Used by the fan-out to relay notifications to monitoring UIs.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the message could not be published.
    async fn publish_dashboard(
        &self,
        subject: &str,
        message: &RealtimeMessage,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for listening to real-time notifications.
///
/// The WebSocket handler calls it when a client connects; the messages it
/// yields are the ones a [`NotificationPublisher`] sent.
#[async_trait]
pub trait NotificationSubscriber: Send + Sync {
    /// Subscribes to notifications for an operator.
    /// Returns a receiver that yields messages as they arrive.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the subscription could not be opened.
    async fn subscribe_operator(
        &self,
        operator_id: &OperatorId,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError>;

    /// Subscribes to notifications for an org user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the subscription could not be opened.
    async fn subscribe_org_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError>;

    /// Subscribes to notifications for a tenant user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the subscription could not be opened.
    async fn subscribe_tenant_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError>;

    /// Subscribes to a named dashboard subject.
    ///
    /// Dashboard subjects aggregate notifications for monitoring UIs
    /// (e.g. `"ianua.dashboard.platform"`, `"ianua.dashboard.org.{uuid}"`).
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the subscription could not be opened.
    async fn subscribe_dashboard(
        &self,
        subject: &str,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError>;
}

/// The dashboard subject carrying live progress of one tenant's setup.
///
/// The organization comes first because a subscriber derives it from their
/// own session rather than from the URL: a caller naming a tenant of
/// someone else lands on a subject no publisher ever writes to, so the
/// stream stays silent even if an authorization check above it is ever
/// weakened.
///
/// The publisher and the WebSocket handler both derive the subject here, so
/// the two cannot drift into streams that never meet. Its words stay those
/// the dashboard subscribes to.
#[must_use]
pub fn setup_subject(organization_id: &OrganizationId, tenant_id: &TenantId) -> String {
    format!("{}.{tenant_id}", org_setup_subject(organization_id))
}

/// The dashboard subject carrying the setup progress of *every* tenant in
/// one organization.
///
/// A list of tenants would otherwise need one socket per row. Each update is
/// published here as well as on its own subject, and names its tenant, so a
/// single connection can drive the whole list.
#[must_use]
pub fn org_setup_subject(organization_id: &OrganizationId) -> String {
    format!("workflow.{}", organization_id.as_uuid())
}

/// The subject carrying an organization's live security dashboard.
///
/// Derived here by both the fan-out and the WebSocket handler. The two used
/// to format the same UUID differently, one hyphenated and one `as_simple()`,
/// which fails closed and silently: the socket subscribes to a subject nobody
/// publishes to, so the dashboard connects, stays empty, and looks merely
/// quiet rather than broken.
#[must_use]
pub(crate) fn org_dashboard_subject(organization_id: &OrganizationId) -> String {
    format!(
        "ianua.dashboard.org.{}",
        organization_id.as_uuid().as_simple()
    )
}

/// The subject the platform dashboard's live feed is published on.
pub const PLATFORM_DASHBOARD_SUBJECT: &str = "ianua.dashboard.platform";

/// A receiver of real-time notification messages.
///
/// Yields messages one at a time. Returns `None` when the
/// subscription is closed (publisher dropped or unsubscribed).
#[async_trait]
pub trait NotificationReceiver: Send {
    /// Waits for the next message. Returns `None` when the stream ends.
    async fn recv(&mut self) -> Option<RealtimeMessage>;
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::observation::{
        DecidingRule, DecidingStage, GatewayCheck, RequestOutcome,
    };
    use ianua_domain::domains::tenant::setup::SetupStep;
    use ianua_domain::shared::model::steps::RunOutcome;

    use super::*;
    use crate::ports::provisioning::StepOutcome;

    fn org() -> OrganizationId {
        OrganizationId::from_uuid(uuid::uuid!("019f0000-0000-7000-8000-0000000000a6"))
    }

    /// The publisher and the socket both call these, so a subject that changed
    /// shape would still agree with itself. The expected strings are what
    /// pin the wire format a deployed peer relies on.
    #[test]
    fn a_setup_subject_nests_the_tenant_under_its_organization() {
        let tenant = TenantId::from_uuid(uuid::uuid!("019f0000-0000-7000-8000-0000000000b1"));

        assert_eq!(
            org_setup_subject(&org()),
            "workflow.019f0000-0000-7000-8000-0000000000a6"
        );
        assert_eq!(
            setup_subject(&org(), &tenant),
            "workflow.019f0000-0000-7000-8000-0000000000a6.019f0000-0000-7000-8000-0000000000b1"
        );
    }

    fn progress(tenant_id: TenantId) -> SetupProgress {
        SetupProgress {
            tenant_id,
            organization_id: org(),
            step: SetupStep::SigningKey,
            step_outcome: StepOutcome::Done,
            done_steps: 1,
            total_steps: 3,
            setup: RunOutcome::Running,
            failure_reason: None,
        }
    }

    /// A progress update for setting up tenant 42 says it is about tenant 42.
    #[test]
    fn a_setup_update_names_its_tenant() {
        let tenant = TenantId::new();
        let message = RealtimeMessage::SetupProgress(progress(tenant));

        assert_eq!(message.setup_tenant(), Some(&tenant));
    }

    /// A message from a broker topic is about no tenant's setup.
    #[test]
    fn no_other_update_names_a_tenant_set_up() {
        let message = RealtimeMessage::BrokerMessage(BrokerDelivery {
            topic: TopicName::new("orders").unwrap(),
            payload: Vec::new(),
        });

        assert_eq!(message.setup_tenant(), None);
    }

    fn observation(outcome: RequestOutcome) -> RequestObservation {
        crate::test_support::request_observation(outcome)
    }

    /// A request the proxy let through shows on the live feed as allowed,
    /// with the status the upstream answered.
    #[test]
    fn an_audit_entry_of_a_forwarded_request_is_allowed_with_the_upstream_status() {
        let entry = ProxyAuditEntry::from(&observation(RequestOutcome::Allowed {
            upstream_status: 201,
        }));

        assert_eq!(entry.decision, ProxyDecision::Allowed);
        assert_eq!(entry.status, 201);
    }

    /// A request the policy refused shows on the live feed as denied, with
    /// the status it was refused with.
    #[test]
    fn an_audit_entry_of_a_refused_request_is_denied() {
        let entry = ProxyAuditEntry::from(&observation(RequestOutcome::Denied {
            status: 403,
            reason: "policy".to_owned(),
            decided_by: DecidingStage::Gateway(GatewayCheck::Route),
            rule: DecidingRule::Unnamed,
        }));

        assert_eq!(entry.decision, ProxyDecision::Denied);
        assert_eq!(entry.status, 403);
    }

    /// A request with no decision becomes a denied entry in the live audit feed.
    #[test]
    fn an_undecided_request_is_never_shown_as_allowed() {
        let entry = ProxyAuditEntry::from(&observation(RequestOutcome::Undecided));

        assert_eq!(entry.decision, ProxyDecision::Denied);
    }

    /// Acme's dashboard feed is published under its id written without
    /// hyphens, the form the subscribers expect.
    #[test]
    fn the_dashboard_subject_uses_the_simple_uuid_form() {
        assert_eq!(
            org_dashboard_subject(&org()),
            "ianua.dashboard.org.019f00000000700080000000000000a6"
        );
    }
}
