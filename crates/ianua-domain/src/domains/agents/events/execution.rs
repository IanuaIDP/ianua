//! Events from an agent at work: runs, tools and model providers.

use time::OffsetDateTime;

use crate::domains::agents::execution::model_provider::{
    ModelProviderKind, ModelProviderStatus, ModelProviderTestStatus,
};
use crate::domains::agents::execution::run::RunStatus;
use crate::domains::agents::execution::tool::{ToolName, ToolStatus};
use crate::domains::data_classification::level::DataClassLevel;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{DomainEvent, tenant_event};
use crate::shared::events::raised::scoped;
use crate::types::event_type::AgentsEvent;
use crate::types::{
    ActionClass, AgentId, AgentRunId, AgentToolId, CanonicalPath, DelegationId, EventLabel,
    ModelProviderId, TenantId, UntrustedText,
};

/// A tenant connected its own model provider for agent runs to reason with.
#[derive(Debug)]
pub(crate) struct AgentModelProviderConnected {
    /// The new provider.
    pub(crate) provider_id: ModelProviderId,
    /// The provider's name when the event fired.
    pub(crate) provider_label: EventLabel,
    /// The kind of backend it is.
    pub(crate) kind: ModelProviderKind,
    /// When it was connected.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentModelProviderConnected => AgentsEvent::ModelProviderConnected,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "provider",
                Reference::new(
                    RefKind::PROVIDER,
                    self.provider_id.to_string(),
                    self.provider_label.as_str(),
                ),
            )
            .field("kind", self.kind.as_str().to_owned())
    }
}

/// A tool was registered for agents to call.
#[derive(Debug)]
pub(crate) struct AgentToolRegistered {
    /// The new tool.
    pub(crate) tool_id: AgentToolId,
    /// The tool's name, shown as the label of the tool reference.
    pub(crate) name: ToolName,
    /// The kind of action the tool performs.
    pub(crate) action_class: ActionClass,
    /// The tool's data class.
    ///
    /// It decides which runs may call the tool, and how sensitive the data is
    /// that a run reads from it.
    pub(crate) classification: DataClassLevel,
    /// When it was registered.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentToolRegistered => AgentsEvent::ToolRegistered,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "tool",
                Reference::new(RefKind::TOOL, self.tool_id.to_string(), self.name.as_str()),
            )
            .field("action_class", self.action_class.as_str().to_owned())
            .field("classification", self.classification.as_str().to_owned())
    }
}

/// A person turned a tool on or off.
#[derive(Debug)]
pub(crate) struct AgentToolStatusChanged {
    /// The callable operation whose availability changed.
    pub(crate) tool_id: AgentToolId,
    /// The tool's name when the event fired.
    pub(crate) name: ToolName,
    /// The new status.
    pub(crate) status: ToolStatus,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentToolStatusChanged => AgentsEvent::ToolStatusChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "tool",
                Reference::new(RefKind::TOOL, self.tool_id.to_string(), self.name.as_str()),
            )
            .field("status", self.status.as_str().to_owned())
    }
}

/// A tool was permanently deleted.
#[derive(Debug)]
pub(crate) struct AgentToolDeleted {
    /// The deleted tool.
    pub(crate) tool_id: AgentToolId,
    /// The tool's name when it was deleted.
    pub(crate) name: ToolName,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentToolDeleted => AgentsEvent::ToolDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "tool",
            Reference::new(RefKind::TOOL, self.tool_id.to_string(), self.name.as_str()),
        )
    }
}

/// A person turned a model provider on or off.
#[derive(Debug)]
pub(crate) struct AgentModelProviderStatusChanged {
    /// The model connection whose availability changed.
    pub(crate) provider_id: ModelProviderId,
    /// The provider's name when the event fired.
    pub(crate) provider_label: EventLabel,
    /// The new status.
    pub(crate) status: ModelProviderStatus,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentModelProviderStatusChanged => AgentsEvent::ModelProviderStatusChanged,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "provider",
                Reference::new(
                    RefKind::PROVIDER,
                    self.provider_id.to_string(),
                    self.provider_label.as_str(),
                ),
            )
            .field("status", self.status.as_str().to_owned())
    }
}

/// A model provider was permanently deleted.
#[derive(Debug)]
pub(crate) struct AgentModelProviderDeleted {
    /// The deleted provider.
    pub(crate) provider_id: ModelProviderId,
    /// The provider's name when it was deleted.
    pub(crate) provider_label: EventLabel,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentModelProviderDeleted => AgentsEvent::ModelProviderDeleted,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "provider",
            Reference::new(
                RefKind::PROVIDER,
                self.provider_id.to_string(),
                self.provider_label.as_str(),
            ),
        )
    }
}

/// A model provider was sent a test request.
///
/// It records the outcome, never the model's answer. The answer is untrusted
/// text from outside the platform.
#[derive(Debug)]
pub(crate) struct AgentModelProviderTested {
    /// The tested provider.
    pub(crate) provider_id: ModelProviderId,
    /// The provider's name.
    pub(crate) provider_label: EventLabel,
    /// Whether the provider answered.
    pub(crate) result: ModelProviderTestStatus,
    /// When the test ran.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentModelProviderTested => AgentsEvent::ModelProviderTested,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "provider",
                Reference::new(
                    RefKind::PROVIDER,
                    self.provider_id.to_string(),
                    self.provider_label.as_str(),
                ),
            )
            .field("result", self.result.as_str())
    }
}

/// The reference every run event names its run by: the run's id, with the
/// id as its label too.
///
/// A run has no name, and its goal is never the label. A workflow step's
/// goal carries what earlier steps read, and a goal a person writes may quote
/// confidential text. The label goes into the audit record and every
/// notification the event fans out to, with no data class on it. Ann's run
/// is told to "check Bob's salary of 140,000". Labelled by its goal, every
/// colleague notified of the run would read the salary.
pub(super) fn run_reference(run_id: &AgentRunId) -> Reference {
    let id = run_id.to_string();
    Reference::new(RefKind::RUN, id.clone(), id)
}

/// An agent run was accepted and started.
///
/// The worker reads it and starts running the run's steps.
#[derive(Debug)]
pub(crate) struct AgentRunStarted {
    /// The run to drive.
    pub(crate) run_id: AgentRunId,
    /// The acting agent.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The model provider to reason with.
    pub(crate) provider_id: ModelProviderId,
    /// The provider's name when the event fired.
    pub(crate) provider_label: EventLabel,
    /// When it started.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentRunStarted => AgentsEvent::RunStarted,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("run", run_reference(&self.run_id))
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .reference(
                "provider",
                Reference::new(
                    RefKind::PROVIDER,
                    self.provider_id.to_string(),
                    self.provider_label.as_str(),
                ),
            )
    }
}

/// An agent run paused until a person approves one of its tool calls.
#[derive(Debug)]
pub(crate) struct AgentRunAwaitingApproval {
    /// The paused run.
    pub(crate) run_id: AgentRunId,
    /// The acting agent.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// The tool whose call waits for approval.
    pub(crate) tool: UntrustedText,
    /// When it paused.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentRunAwaitingApproval => AgentsEvent::RunAwaitingApproval,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("run", run_reference(&self.run_id))
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .field("tool", self.tool.as_str())
    }
}

/// Records the outcome and usage totals when execution reaches a terminal state.
#[derive(Debug)]
pub(crate) struct AgentRunFinished {
    /// The execution whose final outcome is recorded.
    pub(crate) run_id: AgentRunId,
    /// The acting agent.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// How the run ended.
    pub(crate) status: RunStatus,
    /// How many steps the run took.
    pub(crate) steps: u32,
    /// When it finished.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentRunFinished => AgentsEvent::RunFinished,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("run", run_reference(&self.run_id))
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .field("status", self.status.as_str().to_owned())
            .field("steps", self.steps.to_string())
    }
}

/// A person asked a running agent run to stop.
///
/// It is recorded when the person asks, not when the run stops. The run checks
/// for the request between steps, so it may take a few more steps to stop. The
/// record answers who asked for the stop and when.
#[derive(Debug)]
pub(crate) struct AgentRunCancelRequested {
    /// The execution asked to stop between steps.
    pub(crate) run_id: AgentRunId,
    /// The acting agent.
    pub(crate) agent_id: AgentId,
    /// The agent's name when the event fired.
    pub(crate) agent_label: EventLabel,
    /// When the stop was requested.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentRunCancelRequested => AgentsEvent::RunCancelRequested,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference("run", run_reference(&self.run_id))
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
    }
}

/// Two or more agents used the same path within the convergence window, and at
/// least one of them wrote to it.
///
/// Data could have passed between them outside any channel. Agent A writes a
/// file and agent B reads it a minute later. This always raises an alert. If
/// the acting agent's delegation enforces its intent, that agent is also
/// suspended.
///
/// The agent whose request completed the meeting is the event's actor, so
/// the payload does not name it.
#[derive(Debug)]
pub struct AgentsConverged {
    /// The delegation the acting agent acted under.
    pub(crate) delegation_id: DelegationId,
    /// The agents it met there.
    pub(crate) met: Vec<AgentId>,
    /// The path they met at.
    pub(crate) path: UntrustedText,
    /// When the meeting was completed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentsConverged => AgentsEvent::Converged,
    fn payload(&self) -> EventData {
        let met: Vec<String> = self.met.iter().map(ToString::to_string).collect();
        EventData::new()
            .field("delegation_id", self.delegation_id.to_string())
            .field("met_agent_ids", met.join(","))
            .field("path", self.path.as_str())
    }
}

impl AgentsConverged {
    /// The record that an agent acting under `delegation_id` in `tenant_id`
    /// met the agents in `met` at `path`, with the request it made at `at`.
    ///
    /// The convergence detector reads the meeting off the ledger of recent
    /// touches. Nothing the domain keeps changes, so no aggregate raises
    /// it, and the tenant is the one whose traffic the ledger holds. The
    /// time is the request's, not the moment the detector read it.
    #[must_use]
    pub fn observed(
        tenant_id: TenantId,
        delegation_id: DelegationId,
        met: Vec<AgentId>,
        path: &CanonicalPath,
        at: OffsetDateTime,
    ) -> DomainEvent {
        scoped(
            tenant_id,
            Self {
                delegation_id,
                met,
                path: UntrustedText::record(path.as_str()),
                occurred_at: at,
            },
        )
    }
}

/// A person lowered a stopped agent's data mark.
#[derive(Debug)]
pub(crate) struct AgentExposureReset {
    /// The identity whose accumulated data exposure was lowered.
    pub(crate) agent_id: AgentId,
    /// The agent's name when it happened.
    pub(crate) agent_label: EventLabel,
    /// The mark before the reset.
    pub(crate) from: DataClassLevel,
    /// The mark after the reset.
    pub(crate) to: DataClassLevel,
    /// Why, in the person's words.
    pub(crate) reason: UntrustedText,
    /// When it was reset.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    AgentExposureReset => AgentsEvent::ExposureReset,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "agent",
                Reference::new(
                    RefKind::AGENT,
                    self.agent_id.to_string(),
                    self.agent_label.as_str(),
                ),
            )
            .field("from", self.from.as_str())
            .field("to", self.to.as_str())
            .field("reason", self.reason.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// The entity a payload field points at: its id and the name it carried
    /// when the event fired. Both are what an audit screen renders and what a
    /// consumer keys on.
    fn entity(payload: &EventData, key: &str) -> (String, String) {
        match payload.value(key) {
            Some(FieldValue::Reference(reference)) => {
                (reference.id().to_owned(), reference.label().to_owned())
            }
            other => panic!("{key} is not an entity reference: {other:?}"),
        }
    }

    /// A plain scalar field of a payload.
    fn text(payload: &EventData, key: &str) -> String {
        match payload.value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// The provider "prod-deepseek" is connected, turned off and deleted. Each
    /// record names it by id and by name, and also says its kind or its new
    /// status.
    #[test]
    fn the_model_provider_events_name_the_provider_and_what_changed() {
        let provider = ModelProviderId::new();

        let connected = AgentModelProviderConnected {
            provider_id: provider,
            provider_label: EventLabel::of("prod-deepseek"),
            kind: ModelProviderKind::SelfHosted,
            occurred_at: now(),
        };
        let changed = AgentModelProviderStatusChanged {
            provider_id: provider,
            provider_label: EventLabel::of("prod-deepseek"),
            status: ModelProviderStatus::Disabled,
            occurred_at: now(),
        };
        let deleted = AgentModelProviderDeleted {
            provider_id: provider,
            provider_label: EventLabel::of("prod-deepseek"),
            occurred_at: now(),
        };

        let expected = (provider.to_string(), "prod-deepseek".to_owned());
        assert_eq!(entity(&connected.payload(), "provider"), expected);
        assert_eq!(text(&connected.payload(), "kind"), "self_hosted");
        assert_eq!(entity(&changed.payload(), "provider"), expected);
        assert_eq!(text(&changed.payload(), "status"), "disabled");
        assert_eq!(entity(&deleted.payload(), "provider"), expected);
    }

    /// The tool `get_order` is registered, turned off and deleted. Each record
    /// names the tool. The registration also carries its action class and data
    /// class, because those decide which runs may call it.
    #[test]
    fn the_tool_events_name_the_tool_and_what_changed() {
        let tool = AgentToolId::new();

        let registered = AgentToolRegistered {
            tool_id: tool,
            name: ToolName::new("get_order").unwrap(),
            action_class: ActionClass::Read,
            classification: DataClassLevel::Confidential,
            occurred_at: now(),
        };
        let changed = AgentToolStatusChanged {
            tool_id: tool,
            name: ToolName::new("get_order").unwrap(),
            status: ToolStatus::Disabled,
            occurred_at: now(),
        };
        let deleted = AgentToolDeleted {
            tool_id: tool,
            name: ToolName::new("get_order").unwrap(),
            occurred_at: now(),
        };

        let expected = (tool.to_string(), "get_order".to_owned());
        assert_eq!(entity(&registered.payload(), "tool"), expected);
        assert_eq!(text(&registered.payload(), "action_class"), "read");
        assert_eq!(
            text(&registered.payload(), "classification"),
            "confidential"
        );
        assert_eq!(entity(&changed.payload(), "tool"), expected);
        assert_eq!(text(&changed.payload(), "status"), "disabled");
        assert_eq!(entity(&deleted.payload(), "tool"), expected);
    }

    /// The agent "nightly-report" starts, pauses, finishes and is asked to stop
    /// a run. Every record names the agent, and the run by its id alone, so
    /// no goal text reaches the audit record. The start also names the
    /// provider, the pause the tool, and the finish how it ended and its step
    /// count.
    #[test]
    fn the_run_events_name_the_run_the_agent_and_what_happened() {
        let run = AgentRunId::new();
        let agent = AgentId::new();

        started_and_paused(run, agent);
        finished_and_cancelled(run, agent);
    }

    /// Every run event identifies its run without goal text and labels its agent.
    fn run_subjects(event: &impl DomainEventCore, run: AgentRunId, agent: AgentId) {
        let kind = event.event_type();
        let payload = event.payload();
        assert_eq!(
            entity(&payload, "run"),
            (run.to_string(), run.to_string()),
            "{kind}"
        );
        assert_eq!(
            entity(&payload, "agent"),
            (agent.to_string(), "nightly-report".to_owned()),
            "{kind}"
        );
    }

    /// Starting names the provider, while pausing names the tool awaiting approval.
    fn started_and_paused(run: AgentRunId, agent: AgentId) {
        let provider = ModelProviderId::new();
        let agent_label = "nightly-report";

        let started = AgentRunStarted {
            run_id: run,
            agent_id: agent,
            agent_label: EventLabel::of(agent_label),
            provider_id: provider,
            provider_label: EventLabel::of("prod-deepseek"),
            occurred_at: now(),
        };
        let paused = AgentRunAwaitingApproval {
            run_id: run,
            agent_id: agent,
            agent_label: EventLabel::of(agent_label),
            tool: UntrustedText::record("delete_order"),
            occurred_at: now(),
        };

        run_subjects(&started, run, agent);
        run_subjects(&paused, run, agent);
        assert_eq!(
            entity(&started.payload(), "provider"),
            (provider.to_string(), "prod-deepseek".to_owned())
        );
        assert_eq!(text(&paused.payload(), "tool"), "delete_order");
    }

    /// Finishing records its outcome and step count; cancellation still names the run.
    fn finished_and_cancelled(run: AgentRunId, agent: AgentId) {
        let agent_label = "nightly-report";
        let finished = AgentRunFinished {
            run_id: run,
            agent_id: agent,
            agent_label: EventLabel::of(agent_label),
            status: RunStatus::Completed,
            steps: 3,
            occurred_at: now(),
        };
        let cancelled = AgentRunCancelRequested {
            run_id: run,
            agent_id: agent,
            agent_label: EventLabel::of(agent_label),
            occurred_at: now(),
        };

        run_subjects(&finished, run, agent);
        run_subjects(&cancelled, run, agent);
        assert_eq!(text(&finished.payload(), "status"), "completed");
        assert_eq!(text(&finished.payload(), "steps"), "3");
    }

    /// An agent reads `/files/report` a minute after two others wrote it.
    /// The meeting names Acme, the delegation, both agents met and the
    /// path, at the time of the request that completed it.
    #[test]
    fn a_meeting_names_who_was_met_and_where() {
        let acme = TenantId::new();
        let delegation = DelegationId::new();
        let met = vec![AgentId::new(), AgentId::new()];
        let path = CanonicalPath::new("/files/report").unwrap();

        let event = AgentsConverged::observed(acme, delegation, met.clone(), &path, now());

        let payload = event.payload();
        assert_eq!(event.tenant_id(), Some(&acme));
        assert_eq!(event.occurred_at(), now());
        assert_eq!(text(&payload, "delegation_id"), delegation.to_string());
        assert_eq!(
            text(&payload, "met_agent_ids"),
            format!("{},{}", met[0], met[1])
        );
        assert_eq!(text(&payload, "path"), "/files/report");
    }
}
