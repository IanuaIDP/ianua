//! Sandbox versions holding an agent, and the code steps naming them.

use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::agents::execution::run::{CheckTries, GoalTemplate};
use crate::domains::agents::execution::usage::Spend;
use crate::domains::workflows::design::node::{CodeStep, Join, Mapping, Node, NodeKind, Source};
use crate::domains::workflows::execution::tests::fixtures::{
    ann, field, managing, node, path, provider,
};
use crate::domains::workflows::sandbox::agent::{HeldAgent, HeldAgentParams};
use crate::domains::workflows::sandbox::network::NetworkAccess;
use crate::domains::workflows::sandbox::package::Packages;
use crate::domains::workflows::sandbox::recipe::{
    CodeParams, CodeProgram, Program, RunBudget, SandboxCode,
};
use crate::domains::workflows::sandbox::runtime::{Language, Runtime, RuntimeImage};
use crate::domains::workflows::sandbox::source::CodeSource;
use crate::domains::workflows::sandbox::version::SandboxVersion;
use crate::domains::workflows::sandbox::{CreateSandboxParams, Sandbox, SandboxKind, VersionDraft};
use crate::isolation::scope::ResolvedTenant;
use crate::shared::model::restriction::Restriction;
use crate::types::{ActionClass, AgentId, Label, SandboxVersionId};

/// Ann's version of a Python sandbox holding `agent`, which drafts replies
/// with [`provider`], may take ten steps, spend two of the tenant's
/// currency and give two answers; its code checks each one.
pub(crate) fn held_version(agent: AgentId) -> SandboxVersion<ResolvedTenant> {
    let by = ann();
    let mut sandbox = Sandbox::create(
        CreateSandboxParams {
            name: Label::new("name", "Reply drafter").unwrap(),
            kind: SandboxKind::Code(Language::Python),
        },
        &managing(&by),
    )
    .unwrap();
    sandbox
        .save_agent_version(&managing(&by), check_draft(), drafter(agent))
        .unwrap()
}

/// A code step called `name` naming `version`, handed the trigger's `ok`.
pub(crate) fn held_code(name: &str, version: SandboxVersionId) -> Node {
    let inputs = Mapping::new(vec![(field("ok"), Source::Input(path("trigger.ok")))]).unwrap();
    node(
        name,
        NodeKind::Code(CodeStep::new(version, inputs)),
        Join::All,
    )
}

/// The rules of `agent` drafting replies to customers.
fn drafter(agent: AgentId) -> HeldAgent {
    HeldAgent::new(HeldAgentParams {
        agent_id: agent,
        provider_id: provider(),
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

/// Python code checking that a reply promises no refund.
fn check_draft() -> VersionDraft {
    let code = CodeProgram::new(CodeParams {
        runtime: Runtime::Python313,
        image: RuntimeImage::new(format!("python:3.13-slim@sha256:{}", "cd".repeat(32))).unwrap(),
        code: SandboxCode::new(
            "def main(item):\n\treturn {'pass': 'refund' not in item['answer']}\n",
        )
        .unwrap(),
        packages: Packages::new(Vec::new()).unwrap(),
    })
    .unwrap();
    VersionDraft {
        program: Program::Code(code),
        budget: RunBudget::new(30, 256).unwrap(),
        network: NetworkAccess::closed(),
        source: CodeSource::Written,
    }
}
