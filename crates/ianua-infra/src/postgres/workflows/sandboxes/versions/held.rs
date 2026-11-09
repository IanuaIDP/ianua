//! What a version holds, as its `held_agent` column keeps it: empty when
//! the version's code is the step's work, or the agent it holds with the
//! rules it works under, its code then being the check each answer passes.

use ianua_domain::domains::workflows::sandbox::agent::{HeldAgent, VersionHolds};
use ianua_domain::shared::errors::DomainError;
use serde_json::Value;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;

const VERSION: Stored = Stored("sandbox version");

const HELD_AGENT: Kept = Kept {
    entity: VERSION.0,
    column: "held_agent",
    shape: 1,
};

/// What a row's version holds: the agent its `held_agent` column names
/// with its rules, or code when the column is empty.
pub(super) fn holds_from(stored: Option<Value>) -> Result<VersionHolds, DomainError> {
    let Some(stored) = stored else {
        return Ok(VersionHolds::Code);
    };
    HELD_AGENT
        .open::<HeldAgent>(stored)
        .map(|held| VersionHolds::Agent(Box::new(held)))
}

/// The `held_agent` column `holds` is written to: empty for code.
pub(super) fn held_agent_of(holds: &VersionHolds) -> Result<Option<Value>, DomainError> {
    match holds {
        VersionHolds::Code => Ok(None),
        VersionHolds::Agent(held) => HELD_AGENT.seal(held).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
    use ianua_domain::domains::agents::execution::run::{CheckTries, GoalTemplate};
    use ianua_domain::domains::agents::execution::usage::Spend;
    use ianua_domain::domains::workflows::sandbox::agent::HeldAgentParams;
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::types::{ActionClass, AgentId, ModelProviderId};
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    /// The agent Ann's version holds: it drafts replies, may take ten
    /// steps, spend two of the tenant's currency and answer twice.
    fn drafter() -> HeldAgent {
        HeldAgent::new(HeldAgentParams {
            agent_id: AgentId::from_uuid(Uuid::from_u128(1)),
            provider_id: ModelProviderId::from_uuid(Uuid::from_u128(2)),
            goal: GoalTemplate::new("Draft a reply to the customer").unwrap(),
            purpose: IntentEnvelope::new([ActionClass::Read]),
            tools: Vec::new(),
            approval_classes: Vec::new(),
            max_steps: 10,
            spend_cap: Spend::from_micros(2_000_000),
            ask_past: Restriction::Unrestricted,
            tries: CheckTries::new(2).unwrap(),
        })
        .unwrap()
    }

    /// A held agent is written with its run's rules and its tries, and
    /// read back; code holds nothing.
    #[test]
    fn a_held_agent_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "run": {
                "agent_id": "00000000-0000-0000-0000-000000000001",
                "provider_id": "00000000-0000-0000-0000-000000000002",
                "goal": "Draft a reply to the customer",
                "inputs": {"fields": []},
                "purpose": {"allowed": ["Read"]},
                "tools": [],
                "approval_classes": [],
                "max_steps": 10,
                "spend_cap": {"to": 2_000_000},
                "ask_past": "unrestricted",
                "checks": "nothing"
            },
            "tries": 2
        }});

        let written = held_agent_of(&VersionHolds::Agent(Box::new(drafter()))).unwrap();

        assert_eq!(written, Some(stored.clone()));
        assert_eq!(HELD_AGENT.seal(&drafter()).unwrap(), stored);
        assert!(matches!(
            holds_from(Some(stored)).unwrap(),
            VersionHolds::Agent(_)
        ));
        assert_eq!(held_agent_of(&VersionHolds::Code).unwrap(), None);
    }
}
