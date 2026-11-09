//! A live update as it travels between nodes: plain JSON fields, read back
//! through each value's own rules, so a malformed update is dropped, never
//! handed on half read.

use ianua_app::ports::provisioning::{SetupProgress, StepOutcome};
use ianua_app::ports::realtime::{
    BrokerDelivery, DraftChange, NotificationUpdate, ProxyAuditEntry, ProxyDecision,
    RealtimeMessage,
};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::notification::{AboutResource, ReadState, title_label};
use ianua_domain::domains::notifications::reach::NotificationReach;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::domains::proxy::observation::ObservedPrincipal;
use ianua_domain::domains::proxy::request::context::ConsumerCredential;
use ianua_domain::domains::tenant::setup::SetupStep;
use ianua_domain::domains::workflows::design::node::NodeKey;
use ianua_domain::domains::workflows::events::{RunEnd, RunHappening, RunMoment};
use ianua_domain::shared::model::steps::{PlanStep as _, RunOutcome};
use ianua_domain::types::{
    AgentId, ConsumerId, CorrelationId, DelegationId, EventType, Fact, NotificationId,
    OrganizationId, PrincipalRef, TenantId, Text, UntrustedText, UserId, WorkflowExecutionId,
    WorkflowId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One live update, as it is written.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Wire {
    Notification(Notification),
    SetupProgress(Progress),
    BrokerMessage {
        topic: String,
        payload: Vec<u8>,
    },
    ProxyAudit(ProxyRequest),
    RunMoment(Moment),
    DraftChanged {
        tenant_id: Uuid,
        workflow_id: Uuid,
        event_type: String,
    },
}

/// A workflow transition carried beside the wire message's kind tag.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Moment {
    tenant_id: Uuid,
    execution_id: Uuid,
    happened: String,
    step: Option<String>,
    end: Option<String>,
}

impl From<&RunMoment> for Moment {
    /// Writes transition names and optional step or ending in the existing wire fields.
    fn from(moment: &RunMoment) -> Self {
        let (happened, step, end) = happening_parts(&moment.happened);
        Self {
            tenant_id: *moment.tenant_id.as_uuid(),
            execution_id: *moment.execution_id.as_uuid(),
            happened: happened.to_owned(),
            step,
            end,
        }
    }
}

impl Moment {
    /// Restores a workflow transition only when its step and ending are recognized.
    fn read(self) -> Option<RunMoment> {
        Some(RunMoment {
            tenant_id: TenantId::from_uuid(self.tenant_id),
            execution_id: WorkflowExecutionId::from_uuid(self.execution_id),
            happened: happening_named(&self.happened, self.step.as_deref(), self.end.as_deref())?,
        })
    }
}

/// Notification fields carried beside the wire message's kind tag.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Notification {
    id: Uuid,
    event_type: String,
    category: String,
    severity: String,
    title: String,
    body: Option<String>,
    resource_id: Option<Uuid>,
    reach: String,
    read: bool,
}

impl From<&NotificationUpdate> for Notification {
    /// Writes validated notification values using their established protocol names.
    fn from(update: &NotificationUpdate) -> Self {
        Self {
            id: *update.id.as_uuid(),
            event_type: update.event_type.as_str().to_owned(),
            category: update.category.as_str().to_owned(),
            severity: update.severity.as_str().to_owned(),
            title: update.title.as_str().to_owned(),
            body: update.body.as_ref().map(|body| body.as_str().to_owned()),
            resource_id: update.resource_id.into(),
            reach: update.reach.as_str().to_owned(),
            read: update.read == ReadState::Read,
        }
    }
}

impl Notification {
    /// Validates every named notification value before delivering the update.
    fn read(self) -> Option<NotificationUpdate> {
        Some(NotificationUpdate {
            id: NotificationId::from_uuid(self.id),
            event_type: EventType::parse(&self.event_type)?,
            category: NotificationCategory::parse(&self.category)?,
            severity: NotificationSeverity::parse(&self.severity)?,
            title: title_label(self.title).ok()?,
            body: self
                .body
                .map(|body| Text::new("body", body))
                .transpose()
                .ok()?,
            resource_id: AboutResource::from_stored(self.resource_id),
            reach: NotificationReach::parse(&self.reach)?,
            read: ReadState::from(self.read),
        })
    }
}

/// Setup progress fields carried beside the wire message's kind tag.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Progress {
    tenant_id: Uuid,
    organization_id: Uuid,
    step: String,
    step_failed: bool,
    done_steps: u32,
    total_steps: u32,
    setup: String,
    failure_reason: Option<String>,
}

impl From<&SetupProgress> for Progress {
    /// Preserves the tenant, organization, step counts and reported failure text.
    fn from(progress: &SetupProgress) -> Self {
        Self {
            tenant_id: *progress.tenant_id.as_uuid(),
            organization_id: *progress.organization_id.as_uuid(),
            step: progress.step.as_str().to_owned(),
            step_failed: progress.step_outcome == StepOutcome::Failed,
            done_steps: progress.done_steps,
            total_steps: progress.total_steps,
            setup: outcome_word(progress.setup).to_owned(),
            failure_reason: progress
                .failure_reason
                .as_ref()
                .map(|why| why.as_str().to_owned()),
        }
    }
}

impl Progress {
    /// Restores recognized setup steps and outcomes while retaining the reported counts.
    fn read(self) -> Option<SetupProgress> {
        Some(SetupProgress {
            tenant_id: TenantId::from_uuid(self.tenant_id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            step: SetupStep::named(&self.step)?,
            step_outcome: match self.step_failed {
                true => StepOutcome::Failed,
                false => StepOutcome::Done,
            },
            done_steps: self.done_steps,
            total_steps: self.total_steps,
            setup: outcome_named(&self.setup)?,
            failure_reason: self.failure_reason.as_deref().map(UntrustedText::record),
        })
    }
}

/// A decided proxy request carried beside the wire message's kind tag.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ProxyRequest {
    correlation_id: Uuid,
    method: String,
    path: String,
    tenant_id: Option<Uuid>,
    principal: Principal,
    allowed: bool,
    status: u16,
    latency_micros: i64,
}

impl From<&ProxyAuditEntry> for ProxyRequest {
    /// Writes the decided request while saturating latency at the wire's integer bound.
    fn from(entry: &ProxyAuditEntry) -> Self {
        Self {
            correlation_id: *entry.correlation_id.as_uuid(),
            method: entry.method.as_str().to_owned(),
            path: entry.path.as_str().to_owned(),
            tenant_id: entry.tenant_id.known().map(|id| *id.as_uuid()),
            principal: Principal::from(&entry.principal),
            allowed: entry.decision == ProxyDecision::Allowed,
            status: entry.status,
            latency_micros: i64::try_from(entry.latency.whole_microseconds()).unwrap_or(i64::MAX),
        }
    }
}

impl ProxyRequest {
    /// Restores the caller and decision, refusing an unrecognized principal.
    fn read(self) -> Option<ProxyAuditEntry> {
        Some(ProxyAuditEntry {
            correlation_id: CorrelationId::from_uuid(self.correlation_id),
            method: UntrustedText::record(&self.method),
            path: UntrustedText::record(&self.path),
            tenant_id: Fact::from_option(self.tenant_id.map(TenantId::from_uuid)),
            principal: self.principal.read()?,
            decision: match self.allowed {
                true => ProxyDecision::Allowed,
                false => ProxyDecision::Denied,
            },
            status: self.status,
            latency: time::Duration::microseconds(self.latency_micros),
        })
    }
}

/// What happened in a run, as its word, its step and its end are written.
fn happening_parts(happened: &RunHappening) -> (&'static str, Option<String>, Option<String>) {
    let step = |key: &NodeKey| Some(key.as_str().to_owned());
    match happened {
        RunHappening::Started => ("started", None, None),
        RunHappening::StepStarted(key) => ("step_started", step(key), None),
        RunHappening::StepSucceeded(key) => ("step_succeeded", step(key), None),
        RunHappening::StepFailed(key) => ("step_failed", step(key), None),
        RunHappening::StepStoodIn(key) => ("step_stood_in", step(key), None),
        RunHappening::StepSkipped(key) => ("step_skipped", step(key), None),
        RunHappening::StepApproved(key) => ("step_approved", step(key), None),
        RunHappening::Ended(end) => ("ended", None, Some(end.as_str().to_owned())),
    }
}

/// What happened in a run, read back from its word, its step and its end;
/// `None` for a word, step or end it cannot be.
fn happening_named(happened: &str, step: Option<&str>, end: Option<&str>) -> Option<RunHappening> {
    let key = || NodeKey::new(step?).ok();
    Some(match happened {
        "started" => RunHappening::Started,
        "step_started" => RunHappening::StepStarted(key()?),
        "step_succeeded" => RunHappening::StepSucceeded(key()?),
        "step_failed" => RunHappening::StepFailed(key()?),
        "step_stood_in" => RunHappening::StepStoodIn(key()?),
        "step_skipped" => RunHappening::StepSkipped(key()?),
        "step_approved" => RunHappening::StepApproved(key()?),
        "ended" => RunHappening::Ended(RunEnd::named(end?)?),
        _ => return None,
    })
}

/// Who a decided request came from, as it is written.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Principal {
    Anonymous,
    User {
        id: Uuid,
    },
    Agent {
        agent: Uuid,
        delegation: Uuid,
        on_behalf_of: String,
    },
    Consumer {
        id: Uuid,
        credential: String,
    },
}

fn credential_word(credential: ConsumerCredential) -> &'static str {
    match credential {
        ConsumerCredential::ApiKey => "api_key",
        ConsumerCredential::Certificate => "certificate",
        ConsumerCredential::Token => "token",
    }
}

impl From<&ObservedPrincipal> for Principal {
    fn from(principal: &ObservedPrincipal) -> Self {
        match principal {
            ObservedPrincipal::Anonymous => Self::Anonymous,
            ObservedPrincipal::User(id) => Self::User { id: *id.as_uuid() },
            ObservedPrincipal::Agent {
                agent_id,
                delegation_id,
                on_behalf_of,
            } => Self::Agent {
                agent: *agent_id.as_uuid(),
                delegation: *delegation_id.as_uuid(),
                on_behalf_of: on_behalf_of.label(),
            },
            ObservedPrincipal::Consumer {
                consumer_id,
                credential,
            } => Self::Consumer {
                id: *consumer_id.as_uuid(),
                credential: credential_word(*credential).to_owned(),
            },
        }
    }
}

impl Principal {
    fn read(self) -> Option<ObservedPrincipal> {
        Some(match self {
            Self::Anonymous => ObservedPrincipal::Anonymous,
            Self::User { id } => ObservedPrincipal::User(UserId::from_uuid(id)),
            Self::Agent {
                agent,
                delegation,
                on_behalf_of,
            } => ObservedPrincipal::Agent {
                agent_id: AgentId::from_uuid(agent),
                delegation_id: DelegationId::from_uuid(delegation),
                on_behalf_of: PrincipalRef::from_label(&on_behalf_of).ok()?,
            },
            Self::Consumer { id, credential } => ObservedPrincipal::Consumer {
                consumer_id: ConsumerId::from_uuid(id),
                credential: credential_named(&credential)?,
            },
        })
    }
}

fn credential_named(word: &str) -> Option<ConsumerCredential> {
    match word {
        "api_key" => Some(ConsumerCredential::ApiKey),
        "certificate" => Some(ConsumerCredential::Certificate),
        "token" => Some(ConsumerCredential::Token),
        _ => None,
    }
}

fn outcome_word(outcome: RunOutcome) -> &'static str {
    match outcome {
        RunOutcome::Running => "running",
        RunOutcome::Done => "done",
        RunOutcome::Failed => "failed",
    }
}

fn outcome_named(word: &str) -> Option<RunOutcome> {
    [RunOutcome::Running, RunOutcome::Done, RunOutcome::Failed]
        .into_iter()
        .find(|outcome| outcome_word(*outcome) == word)
}

impl From<&RealtimeMessage> for Wire {
    fn from(message: &RealtimeMessage) -> Self {
        match message {
            RealtimeMessage::Notification(update) => Self::Notification(Notification::from(update)),
            RealtimeMessage::SetupProgress(progress) => {
                Self::SetupProgress(Progress::from(progress))
            }
            RealtimeMessage::BrokerMessage(delivery) => Self::BrokerMessage {
                topic: delivery.topic.as_str().to_owned(),
                payload: delivery.payload.clone(),
            },
            RealtimeMessage::ProxyAudit(entry) => Self::ProxyAudit(ProxyRequest::from(entry)),
            RealtimeMessage::RunMoment(moment) => Self::RunMoment(Moment::from(moment)),
            RealtimeMessage::DraftChanged(change) => Self::DraftChanged {
                tenant_id: *change.tenant_id.as_uuid(),
                workflow_id: *change.workflow_id.as_uuid(),
                event_type: change.event_type.as_str().to_owned(),
            },
        }
    }
}

impl Wire {
    /// The update the wire form writes, or `None` when a value no longer
    /// passes its rules.
    pub(super) fn read(self) -> Option<RealtimeMessage> {
        match self {
            Self::Notification(update) => update.read().map(RealtimeMessage::Notification),
            Self::SetupProgress(progress) => progress.read().map(RealtimeMessage::SetupProgress),
            Self::BrokerMessage { topic, payload } => {
                Some(RealtimeMessage::BrokerMessage(BrokerDelivery {
                    topic: TopicName::new(topic).ok()?,
                    payload,
                }))
            }
            Self::ProxyAudit(entry) => entry.read().map(RealtimeMessage::ProxyAudit),
            Self::RunMoment(moment) => moment.read().map(RealtimeMessage::RunMoment),
            Self::DraftChanged {
                tenant_id,
                workflow_id,
                event_type,
            } => Some(RealtimeMessage::DraftChanged(DraftChange {
                tenant_id: TenantId::from_uuid(tenant_id),
                workflow_id: WorkflowId::from_uuid(workflow_id),
                event_type: EventType::parse(&event_type)?,
            })),
        }
    }
}
