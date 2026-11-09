//! What the tests of versions holding an agent share: the rules of an
//! agent summarising orders, and a built version holding it.

use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::agents::execution::run::{CheckTries, GoalTemplate, MAX_CHECK_TRIES};
use ianua_domain::domains::agents::execution::usage::Spend;
use ianua_domain::domains::workflows::sandbox::agent::{HeldAgent, HeldAgentParams, VersionHolds};
use ianua_domain::domains::workflows::sandbox::version::{SandboxVersion, SandboxVersionRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{ActionClass, AgentId};

use crate::test_support::workflows::code_fixtures::ready_version;
use crate::test_support::workflows::graphs::test_provider;

/// The rules of `agent` summarising orders with [`test_provider`], calling
/// no tool, in at most ten steps, two of the tenant's currency and every
/// try a check allows.
///
/// # Panics
///
/// Never: the rules are within every bound.
#[must_use]
pub fn summarising_rules(agent: AgentId) -> HeldAgent {
    HeldAgent::new(HeldAgentParams {
        agent_id: agent,
        provider_id: test_provider(),
        goal: GoalTemplate::new("summarise the orders").expect("a goal"),
        purpose: IntentEnvelope::new([ActionClass::Read]),
        tools: Vec::new(),
        approval_classes: Vec::new(),
        max_steps: 10,
        spend_cap: Spend::from_micros(2_000_000),
        ask_past: Restriction::Unrestricted,
        tries: CheckTries::new(MAX_CHECK_TRIES).expect("tries within the cap"),
    })
    .expect("bounded rules")
}

/// A built version holding `agent` under [`summarising_rules`], its code
/// the check of every summary.
///
/// # Panics
///
/// Never: the version read back is the one kept, holding valid rules.
#[must_use]
pub fn held_version_of(agent: AgentId) -> SandboxVersion<ResolvedTenant> {
    let code = ready_version();
    SandboxVersion::reconstitute(SandboxVersionRow {
        id: *code.id(),
        sandbox_id: *code.sandbox_id(),
        number: code.number(),
        recipe: code.recipe().clone(),
        source: code.source().clone(),
        build: code.build().clone(),
        holds: VersionHolds::Agent(Box::new(summarising_rules(agent))),
        saved_by: code.saved_by().clone(),
        created_at: Aggregate::created_at(&code),
        updated_at: Aggregate::updated_at(&code),
    })
    .expect("a built version reads back holding an agent")
}
