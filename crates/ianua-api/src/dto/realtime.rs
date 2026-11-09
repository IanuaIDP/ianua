//! The JSON frames a WebSocket subscriber receives.
//!
//! Every frame is `{"msg_type": "...", "notification": {...}}`: the dashboard
//! picks the kind from `msg_type` and reads the update from `notification`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_app::listing::{Limit, PageRequest, SortOrder};
use ianua_app::ports::provisioning::{SetupProgress, StepOutcome};
use ianua_app::ports::realtime::{
    BrokerDelivery, DraftChange, NotificationUpdate, ProxyAuditEntry, ProxyDecision,
    RealtimeMessage,
};
use ianua_app::use_cases::tenant::lifecycle::ListTenantsRequest;
use ianua_domain::domains::notifications::notification::AboutResource;
use ianua_domain::domains::proxy::observation::ObservedPrincipal;
use ianua_domain::domains::workflows::events::{RunHappening, RunMoment};
use ianua_domain::shared::model::steps::{PlanStep as _, RunOutcome};
use ianua_domain::types::{Text, UntrustedText};
use serde::Serialize;
use uuid::Uuid;

/// The most tenants an organization-wide provisioning stream follows: one
/// full page of the tenants the member sees.
const MAX_FOLLOWED_TENANTS: u32 = 100;

/// The tenants an organization-wide provisioning stream follows: every one
/// the member sees, in the listing's own order, up to one full page.
#[must_use]
pub(crate) fn followed_tenants() -> ListTenantsRequest {
    ListTenantsRequest {
        status: None,
        sort: SortOrder::default(),
        page: PageRequest::first(Limit::internal(MAX_FOLLOWED_TENANTS)),
    }
}

/// One live update, as sent to the browser.
#[derive(Serialize)]
#[serde(tag = "msg_type", content = "notification", rename_all = "snake_case")]
pub(crate) enum RealtimeFrame<'a> {
    /// A notification the subscriber was just sent.
    Notification(NotificationFrame<'a>),
    /// A step of a tenant's setup ended. The dashboard knows it by its
    /// older name.
    #[serde(rename = "workflow_progress")]
    SetupProgress(SetupProgressFrame<'a>),
    /// A message published on a topic the subscriber watches.
    #[serde(rename = "message")]
    BrokerMessage(BrokerMessageFrame<'a>),
    /// A request the proxy decided.
    ProxyAudit(ProxyAuditFrame<'a>),
    /// Something happened in a workflow run the subscriber watches.
    RunMoment(RunMomentFrame),
    /// Someone changed a workflow's draft the subscriber has open.
    DraftChanged(DraftChangedFrame),
}

/// What just happened in a workflow run, so the builder lights the step
/// up. It names steps and ends, never data: the run itself is read again
/// for what the caller may see.
#[derive(Serialize)]
pub(crate) struct RunMomentFrame {
    /// The run.
    pub execution_id: Uuid,
    /// `started`, `step_started`, `step_succeeded`, `step_failed`,
    /// `step_stood_in`, `step_skipped`, `step_approved` or `ended`.
    pub happened: &'static str,
    /// The step, for a step's moment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// How it ended, for `ended`: `succeeded`, `failed`, `cancelled`,
    /// `timed_out` or `loop_ended`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<&'static str>,
}

/// A workflow's draft that someone changed, so whoever has it open reads
/// it again instead of working on a stale copy.
#[derive(Serialize)]
pub(crate) struct DraftChangedFrame {
    /// The draft to reload when the notification arrives.
    pub workflow_id: Uuid,
    /// How it changed, such as `workflows.draft_steps_replaced`.
    pub event_type: &'static str,
}

impl From<&RunMoment> for RunMomentFrame {
    fn from(moment: &RunMoment) -> Self {
        let (happened, step, end) = match &moment.happened {
            RunHappening::Started => ("started", None, None),
            RunHappening::StepStarted(key) => ("step_started", Some(key), None),
            RunHappening::StepSucceeded(key) => ("step_succeeded", Some(key), None),
            RunHappening::StepFailed(key) => ("step_failed", Some(key), None),
            RunHappening::StepStoodIn(key) => ("step_stood_in", Some(key), None),
            RunHappening::StepSkipped(key) => ("step_skipped", Some(key), None),
            RunHappening::StepApproved(key) => ("step_approved", Some(key), None),
            RunHappening::Ended(end) => ("ended", None, Some(end.as_str())),
        };
        Self {
            execution_id: *moment.execution_id.as_uuid(),
            happened,
            step: step.map(|key| key.as_str().to_owned()),
            end,
        }
    }
}

impl From<&DraftChange> for DraftChangedFrame {
    fn from(change: &DraftChange) -> Self {
        Self {
            workflow_id: *change.workflow_id.as_uuid(),
            event_type: change.event_type.as_str(),
        }
    }
}

/// A notification, as the bell and toast show it.
#[derive(Serialize)]
pub(crate) struct NotificationFrame<'a> {
    /// Notification id.
    pub id: Uuid,
    /// The event it reports.
    pub event_type: &'static str,
    /// The domain used to group the reported event in notification views.
    pub category: &'static str,
    /// How urgent it is.
    pub severity: &'static str,
    /// The short text shown before the optional detailed notification body.
    pub title: &'a str,
    /// Its rendered body, `null` when it has none.
    pub body: Option<&'a str>,
    /// The resource it is about, `null` when none.
    pub resource_id: Option<Uuid>,
    /// Whether it has been read.
    pub read: bool,
}

/// A step of a tenant's setup that ended, as the progress view shows it,
/// in the keys the dashboard reads.
#[derive(Serialize)]
pub(crate) struct SetupProgressFrame<'a> {
    /// The setup's id: its tenant's.
    pub workflow_id: String,
    /// The organization the tenant belongs to.
    pub organization_id: Option<Uuid>,
    /// Always `tenant_provisioning`.
    pub workflow_type: &'static str,
    /// The tenant set up.
    pub reference_id: String,
    /// The step that ended.
    pub step_name: &'static str,
    /// How it ended: `completed` or `failed`.
    pub step_status: &'static str,
    /// Steps done so far.
    pub completed_steps: u32,
    /// Steps in all.
    pub total_steps: u32,
    /// Whether the setup finished.
    pub workflow_completed: bool,
    /// Whether the setup failed.
    pub workflow_failed: bool,
    /// Why it failed; left out while it has not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<&'a str>,
}

/// A message published on a topic.
#[derive(Serialize)]
pub(crate) struct BrokerMessageFrame<'a> {
    /// The tenant-relative topic.
    pub topic: &'a str,
    /// The message body, base64-encoded.
    pub payload: String,
    /// The body's size in bytes.
    pub size: usize,
}

/// A proxied request, as the live security dashboard lists it.
#[derive(Serialize)]
pub(crate) struct ProxyAuditFrame<'a> {
    /// Ties the request to its logs, traces and audit rows.
    pub correlation_id: Uuid,
    /// The method as it arrived.
    pub method: &'a str,
    /// The path as it arrived.
    pub path: &'a str,
    /// The tenant the request resolved to.
    pub tenant_id: Option<Uuid>,
    /// The tenant user behind the request.
    pub user_id: Option<String>,
    /// The agent that made it.
    pub agent_id: Option<String>,
    /// The delegation the agent acted under.
    pub delegation_id: Option<String>,
    /// Who the agent acted for, as `<kind>:<uuid>`.
    pub on_behalf_of: Option<String>,
    /// The tenant's machine identity that made it.
    pub consumer_id: Option<Uuid>,
    /// `"allowed"` or `"denied"`.
    pub decision: &'static str,
    /// The status returned to the client.
    pub status: u16,
    /// How long the proxy took, in milliseconds.
    pub latency_ms: i128,
}

impl<'a> From<&'a RealtimeMessage> for RealtimeFrame<'a> {
    fn from(message: &'a RealtimeMessage) -> Self {
        match message {
            RealtimeMessage::Notification(n) => Self::Notification(n.into()),
            RealtimeMessage::SetupProgress(p) => Self::SetupProgress(p.into()),
            RealtimeMessage::BrokerMessage(m) => Self::BrokerMessage(m.into()),
            RealtimeMessage::ProxyAudit(a) => Self::ProxyAudit(a.into()),
            RealtimeMessage::RunMoment(moment) => Self::RunMoment(moment.into()),
            RealtimeMessage::DraftChanged(change) => Self::DraftChanged(change.into()),
        }
    }
}

impl<'a> From<&'a NotificationUpdate> for NotificationFrame<'a> {
    fn from(n: &'a NotificationUpdate) -> Self {
        Self {
            id: *n.id.as_uuid(),
            event_type: n.event_type.as_str(),
            category: n.category.as_str(),
            severity: n.severity.as_str(),
            title: n.title.as_str(),
            body: n.body.as_ref().map(Text::as_str),
            resource_id: match n.resource_id {
                AboutResource::Resource(id) => Some(id),
                AboutResource::Nothing => None,
            },
            read: n.read.into(),
        }
    }
}

impl<'a> From<&'a SetupProgress> for SetupProgressFrame<'a> {
    fn from(p: &'a SetupProgress) -> Self {
        Self {
            workflow_id: p.tenant_id.to_string(),
            organization_id: Some(*p.organization_id.as_uuid()),
            workflow_type: "tenant_provisioning",
            reference_id: p.tenant_id.to_string(),
            step_name: p.step.as_str(),
            step_status: match p.step_outcome {
                StepOutcome::Done => "completed",
                StepOutcome::Failed => "failed",
            },
            completed_steps: p.done_steps,
            total_steps: p.total_steps,
            workflow_completed: p.setup == RunOutcome::Done,
            workflow_failed: p.setup == RunOutcome::Failed,
            failure_reason: p.failure_reason.as_ref().map(UntrustedText::as_str),
        }
    }
}

impl<'a> From<&'a BrokerDelivery> for BrokerMessageFrame<'a> {
    fn from(m: &'a BrokerDelivery) -> Self {
        Self {
            topic: m.topic.as_str(),
            payload: STANDARD.encode(&m.payload),
            size: m.payload.len(),
        }
    }
}

impl<'a> From<&'a ProxyAuditEntry> for ProxyAuditFrame<'a> {
    fn from(a: &'a ProxyAuditEntry) -> Self {
        let who = PrincipalColumns::of(&a.principal);
        Self {
            correlation_id: *a.correlation_id.as_uuid(),
            method: a.method.as_str(),
            path: a.path.as_str(),
            tenant_id: a.tenant_id.known().map(|t| *t.as_uuid()),
            user_id: who.user_id,
            agent_id: who.agent_id,
            delegation_id: who.delegation_id,
            on_behalf_of: who.on_behalf_of,
            consumer_id: who.consumer_id,
            decision: match a.decision {
                ProxyDecision::Allowed => "allowed",
                ProxyDecision::Denied => "denied",
            },
            status: a.status,
            latency_ms: a.latency.whole_milliseconds(),
        }
    }
}

/// Who made a proxied request, spread over the frame's columns.
#[derive(Default)]
struct PrincipalColumns {
    user_id: Option<String>,
    agent_id: Option<String>,
    delegation_id: Option<String>,
    on_behalf_of: Option<String>,
    consumer_id: Option<Uuid>,
}

impl PrincipalColumns {
    /// The columns for a principal: the user, the agent and its delegation
    /// with whom it acts for, or the consumer. All empty when anonymous.
    fn of(principal: &ObservedPrincipal) -> Self {
        match principal {
            ObservedPrincipal::Anonymous => Self::default(),
            ObservedPrincipal::User(id) => Self {
                user_id: Some(id.to_string()),
                ..Self::default()
            },
            ObservedPrincipal::Agent {
                agent_id,
                delegation_id,
                on_behalf_of,
            } => Self {
                user_id: on_behalf_of.as_user().map(|id| id.to_string()),
                agent_id: Some(agent_id.to_string()),
                delegation_id: Some(delegation_id.to_string()),
                on_behalf_of: Some(on_behalf_of.label()),
                consumer_id: None,
            },
            ObservedPrincipal::Consumer { consumer_id, .. } => Self {
                consumer_id: Some(*consumer_id.as_uuid()),
                ..Self::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::messaging::topic_name::TopicName;
    use ianua_domain::domains::tenant::setup::SetupStep;
    use ianua_domain::types::{CorrelationId, Fact, OrganizationId, TenantId};
    use time::Duration;

    use super::*;

    /// The JSON frame a message is sent as.
    fn json_of(message: &RealtimeMessage) -> serde_json::Value {
        serde_json::to_value(RealtimeFrame::from(message)).unwrap()
    }

    /// A message on `orders` reaches the dashboard with its topic, its bytes
    /// in base64 and its size.
    #[test]
    fn a_broker_message_frame_carries_its_topic_base64_payload_and_size() {
        let message = RealtimeMessage::BrokerMessage(BrokerDelivery {
            topic: TopicName::new("orders").unwrap(),
            payload: b"hi".to_vec(),
        });

        let json = json_of(&message);

        assert_eq!(json["msg_type"], "message");
        assert_eq!(json["notification"]["topic"], "orders");
        assert_eq!(json["notification"]["payload"], "aGk=");
        assert_eq!(json["notification"]["size"], 2);
    }

    /// A denied anonymous request shows as `denied` with its latency in
    /// milliseconds, and no tenant or user.
    #[test]
    fn a_proxy_audit_frame_names_its_decision_and_latency_in_milliseconds() {
        let message = RealtimeMessage::ProxyAudit(ProxyAuditEntry {
            correlation_id: CorrelationId::new(),
            method: UntrustedText::record("POST"),
            path: UntrustedText::record("/orders"),
            tenant_id: Fact::Unknown,
            principal: ObservedPrincipal::Anonymous,
            decision: ProxyDecision::Denied,
            status: 403,
            latency: Duration::milliseconds(7),
        });

        let json = json_of(&message);

        assert_eq!(json["msg_type"], "proxy_audit");
        assert_eq!(json["notification"]["decision"], "denied");
        assert_eq!(json["notification"]["latency_ms"], 7);
        assert!(json["notification"]["tenant_id"].is_null());
        assert!(json["notification"]["user_id"].is_null());
    }

    /// A setup still running sends its progress in the dashboard's keys,
    /// with no failure reason field at all.
    #[test]
    fn a_setup_frame_leaves_out_the_reason_until_it_fails() {
        let tenant = TenantId::new();
        let progress = SetupProgress {
            tenant_id: tenant,
            organization_id: OrganizationId::new(),
            step: SetupStep::SigningKey,
            step_outcome: StepOutcome::Done,
            done_steps: 1,
            total_steps: 3,
            setup: RunOutcome::Running,
            failure_reason: None,
        };

        let json = json_of(&RealtimeMessage::SetupProgress(progress));

        assert_eq!(json["msg_type"], "workflow_progress");
        assert_eq!(json["notification"]["reference_id"], tenant.to_string());
        assert_eq!(json["notification"]["step_name"], "signing_key");
        assert_eq!(json["notification"]["step_status"], "completed");
        assert_eq!(json["notification"]["workflow_completed"], false);
        assert!(json["notification"].get("failure_reason").is_none());
    }
}
