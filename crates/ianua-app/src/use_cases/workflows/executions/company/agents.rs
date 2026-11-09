//! The company steps about agents: pausing one, ending one of its runs,
//! reading its recent runs, taking back its tasks and taking one thing out
//! of them. Each only narrows what the agent may do.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::{ResourceCapability, ResourceRef};
use ianua_domain::domains::agents::authority::delegation::Delegation;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::company::{
    AGENT_INPUT, RUN_INPUT, SHARED_INPUT, SINCE_INPUT,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::types::{AgentId, AgentRunId};

use crate::listing::{Limit, PageRequest};
use crate::ports::agents::RunSummary;
use crate::ports::workflows::CompanyCall;
use crate::use_case::{Command as _, Query as _};
use crate::use_cases::agents::delegation::{
    ListDelegationsUseCase, RevokeRequest, RevokeResourceRequest, RevokeResourceUseCase,
    RevokeUseCase,
};
use crate::use_cases::agents::lifecycle::SuspendAgentUseCase;
use crate::use_cases::agents::runs::{CancelRequest, CancelUseCase, ListRequest, ListUseCase};
use crate::use_cases::workflows::executions::answers::{data, failed, moment_text};
use crate::use_cases::workflows::executions::company::inputs::{id, since, text};
use crate::use_cases::workflows::executions::company::people::count;
use crate::use_cases::workflows::executions::company::{succeeded, unmade};

/// The most runs one step reads, newest first.
const RUNS_READ: u32 = 100;

/// The dashboard's actions on agents.
pub struct AgentActions {
    /// Pauses an agent.
    pub suspend: Arc<SuspendAgentUseCase>,
    /// Ends one of an agent's runs.
    pub cancel: Arc<CancelUseCase>,
    /// Lists an agent's runs.
    pub runs: Arc<ListUseCase>,
    /// Lists the tasks an agent holds.
    pub delegations: Arc<ListDelegationsUseCase>,
    /// Takes back one task and every one passed on from it.
    pub revoke: Arc<RevokeUseCase>,
    /// Takes one relation out of one task.
    pub revoke_resource: Arc<RevokeResourceUseCase>,
}

impl AgentActions {
    /// Pauses the agent the step names.
    pub(super) async fn pause(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let agent_id = id(step.call, AGENT_INPUT, AgentId::from_uuid)?;
        self.suspend
            .execute(step.caller, step.auditor, agent_id)
            .await
            .map_err(unmade)?;
        let output = data(vec![("agent_id", FlowData::text(agent_id.to_string()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Takes back every task the agent the step names still holds.
    pub(super) async fn revoke_tasks(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let agent_id = id(step.call, AGENT_INPUT, AgentId::from_uuid)?;
        let held = self.live_tasks(step, agent_id).await?;
        for delegation in &held {
            let request = RevokeRequest {
                agent_id,
                delegation_id: *delegation.id(),
            };
            self.revoke
                .execute(step.caller, step.auditor, request)
                .await
                .map_err(unmade)?;
        }
        let output = data(vec![("tasks_revoked", count(held.len()))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Takes every relation on what the step names out of each task the
    /// agent it names still holds.
    pub(super) async fn narrow(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let agent_id = id(step.call, AGENT_INPUT, AgentId::from_uuid)?;
        let shared = ResourceRef::new(text(step.call, SHARED_INPUT)?)
            .map_err(|_| failed("the step's shared is not something an agent is given"))?;
        let mut taken = 0;
        for delegation in self.live_tasks(step, agent_id).await? {
            for capability in held_on(&delegation, &shared) {
                let request = RevokeResourceRequest {
                    agent_id,
                    delegation_id: *delegation.id(),
                    relation: capability.relation().clone(),
                    resource_ref: capability.resource_ref().clone(),
                };
                self.revoke_resource
                    .execute(step.caller, step.auditor, request)
                    .await
                    .map_err(unmade)?;
                taken += 1;
            }
        }
        let output = data(vec![("relations_taken", count(taken))])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// The tasks `agent_id` still holds, read as the run's person may.
    async fn live_tasks(
        &self,
        step: &CompanyCall<'_>,
        agent_id: AgentId,
    ) -> Result<Vec<Delegation<ResolvedTenant>>, ActionOutcome> {
        let now = clock::now();
        let described = self
            .delegations
            .execute(step.caller, agent_id)
            .await
            .map_err(unmade)?;
        Ok(described
            .into_iter()
            .map(|described| described.delegation)
            .filter(|delegation| delegation.is_valid(now))
            .collect())
    }

    /// Ends the run of the agent the step names.
    pub(super) async fn end_run(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let request = CancelRequest {
            agent_id: id(step.call, AGENT_INPUT, AgentId::from_uuid)?,
            run_id: id(step.call, RUN_INPUT, AgentRunId::from_uuid)?,
        };
        let run = self
            .cancel
            .execute(step.caller, step.auditor, request)
            .await
            .map_err(unmade)?;
        let output = data(vec![(
            "status",
            FlowData::text(run.state().status().as_str()),
        )])?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }

    /// Reads the runs of the agent the step names, started since when it
    /// says, with what they spent.
    pub(super) async fn recent(
        &self,
        step: &CompanyCall<'_>,
    ) -> Result<ActionOutcome, ActionOutcome> {
        let from = clock::now() - since(step.call, SINCE_INPUT)?.span();
        let request = ListRequest {
            agent_id: id(step.call, AGENT_INPUT, AgentId::from_uuid)?,
            status: None,
            page: PageRequest::first(Limit::internal(RUNS_READ)),
        };
        let page = self
            .runs
            .execute(step.caller, request)
            .await
            .map_err(unmade)?;
        let recent: Vec<_> = page
            .items
            .iter()
            .filter(|run| run.created_at >= from)
            .collect();
        let output = runs_output(&recent)?;
        Ok(succeeded(step, output, DataClassLevel::Internal))
    }
}

/// The runs read, their count and what they spent together, as workflow
/// data.
fn runs_output(recent: &[&RunSummary]) -> Result<FlowData, ActionOutcome> {
    let spent: u64 = recent.iter().map(|run| run.spent.micros()).sum();
    let runs = recent
        .iter()
        .map(|run| run_data(run))
        .collect::<Result<Vec<_>, _>>()?;
    let total = runs.len();
    let list = FlowData::list(runs).map_err(|_| failed("the runs do not fit workflow data"))?;
    data(vec![
        ("runs", Ok(list)),
        ("count", count(total)),
        ("spent", amount(spent)),
    ])
}

/// One run as workflow data: its id, status, spend and start.
fn run_data(run: &RunSummary) -> Result<FlowData, ActionOutcome> {
    data(vec![
        ("run_id", FlowData::text(run.id.to_string())),
        ("status", FlowData::text(run.state.status().as_str())),
        ("spent", amount(run.spent.micros())),
        ("started_at", moment_text(run.created_at)),
    ])
}

/// An amount of `micros` millionths of the currency as exact text, such as
/// `12.500000`, which no number in workflow data rounds.
fn amount(micros: u64) -> Result<FlowData, ianua_domain::shared::errors::DomainError> {
    FlowData::text(format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000))
}

/// The relations `delegation` holds on `shared`.
fn held_on<'a>(
    delegation: &'a Delegation<ResolvedTenant>,
    shared: &'a ResourceRef,
) -> impl Iterator<Item = &'a ResourceCapability> {
    delegation
        .granted()
        .resources()
        .iter()
        .filter(move |capability| capability.resource_ref() == shared)
}
