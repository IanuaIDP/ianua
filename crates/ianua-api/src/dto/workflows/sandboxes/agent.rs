//! A version's held agent on the wire: the rules it works under, sent when
//! a version is saved and shown with it. The version's code is then the
//! check every answer of the agent must pass.

use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::{CheckTries, GoalTemplate};
use ianua_domain::domains::agents::execution::usage::Spend;
use ianua_domain::domains::workflows::sandbox::agent::{HeldAgent, HeldAgentParams};
use ianua_domain::types::{AgentId, ModelProviderId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dto::agents::runs::{amount, micros_of};
use crate::dto::workflows::graph::{class_names, classes, tool_names};
use crate::error::ApiError;

/// The agent a version holds, and the rules it works under.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct HeldAgentBody {
    /// The agent that does the step's work.
    pub agent_id: Uuid,
    /// The tenant's model provider it reasons with.
    pub provider_id: Uuid,
    /// What it works toward; the fields the step maps are added to it.
    pub goal: String,
    /// The action classes its tool calls may take, such as `read`.
    #[serde(default)]
    pub purpose: Vec<String>,
    /// The tools and integration steps it may call, by name. None when
    /// empty: it only writes.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Action classes whose calls wait for a person's approval. High-risk
    /// classes wait whether named or not.
    #[serde(default)]
    pub approval_classes: Vec<String>,
    /// The most steps it may take across every try, from 1 to 50.
    pub max_steps: u32,
    /// The most it may spend on its model across every try, in millionths
    /// of the tenant's billing currency. Required: once spent, the run
    /// stops and the step fails as over budget.
    pub spend_cap_micros: u64,
    /// What it may spend before it pauses for a person to let it go on, in
    /// the same millionths, below the cap. Left out for no pause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_past_micros: Option<u64>,
    /// How many answers it may give, from 1 to 3. An answer the check
    /// turns back goes to the agent with what the check said; one turned
    /// back on the last try fails the step.
    pub tries: u8,
}

impl HeldAgentBody {
    /// The rules this body sets.
    ///
    /// # Errors
    ///
    /// - `422` for a goal, class or tool name that is not valid, a step cap
    ///   or try count out of range, a tool or class named twice, a spend cap
    ///   of nothing, or an amount to ask at that is not below the cap.
    pub(crate) fn rules(self) -> Result<HeldAgent, ApiError> {
        HeldAgent::new(HeldAgentParams {
            agent_id: AgentId::from_uuid(self.agent_id),
            provider_id: ModelProviderId::from_uuid(self.provider_id),
            goal: GoalTemplate::new(self.goal).map_err(ApiError::validation)?,
            purpose: IntentEnvelope::new(classes(&self.purpose)?),
            tools: tool_names(self.tools)?,
            approval_classes: classes(&self.approval_classes)?,
            max_steps: self.max_steps,
            spend_cap: Spend::from_micros(self.spend_cap_micros),
            ask_past: amount(self.ask_past_micros),
            tries: CheckTries::new(self.tries).map_err(ApiError::validation)?,
        })
        .map_err(ApiError::validation)
    }
}

impl From<&HeldAgent> for HeldAgentBody {
    fn from(held: &HeldAgent) -> Self {
        let run = held.run();
        Self {
            agent_id: *run.agent_id().as_uuid(),
            provider_id: *run.provider_id().as_uuid(),
            goal: run.goal().as_str().to_owned(),
            purpose: class_names(run.purpose().allowed()),
            tools: run
                .tools()
                .iter()
                .map(|tool| tool.as_str().to_owned())
                .collect(),
            approval_classes: class_names(run.approval_classes()),
            max_steps: run.max_steps(),
            spend_cap_micros: micros_of(run.spend_cap()).unwrap_or_default(),
            ask_past_micros: micros_of(run.ask_past()),
            tries: held.tries().get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A held agent's body as Ann sends it, allowing `tries` answers.
    fn body(tries: u8) -> HeldAgentBody {
        let sent = json!({
            "agent_id": Uuid::from_u128(1),
            "provider_id": Uuid::from_u128(2),
            "goal": "Draft a reply to the customer",
            "purpose": ["read"],
            "approval_classes": ["communicate"],
            "max_steps": 10,
            "spend_cap_micros": 2_000_000,
            "ask_past_micros": 1_000_000,
            "tries": tries,
        });
        let Ok(body) = serde_json::from_value(sent) else {
            panic!("the body reads");
        };
        body
    }

    /// A drafter's rules go in and come back out as they were sent.
    #[test]
    fn the_rules_come_back_as_they_were_sent() {
        let Ok(rules) = body(3).rules() else {
            panic!("the rules are valid");
        };

        let back = serde_json::to_value(HeldAgentBody::from(&rules)).ok();

        assert_eq!(
            back.as_ref().and_then(|value| value.get("tries")),
            Some(&json!(3))
        );
        assert_eq!(
            back.as_ref()
                .and_then(|value| value.get("spend_cap_micros")),
            Some(&json!(2_000_000))
        );
    }

    /// Four tries, past the most a check allows, are refused.
    #[test]
    fn more_tries_than_a_check_allows_are_refused() {
        assert!(body(4).rules().is_err());
    }
}
