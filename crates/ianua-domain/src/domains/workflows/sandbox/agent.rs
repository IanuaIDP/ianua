//! Versions that hold an agent: the agent does a step's work under rules
//! saved with the version, and the version's code is the check its answer
//! must pass.
//!
//! The rules live in the version, pinned with it like the image of its
//! runtime: a workflow step names a version, so what the agent may do is
//! exactly what was reviewed when the workflow was published, and changing
//! a rule makes the next version. They say which agent works and with which
//! model, toward what goal, which tools it may call and inside which
//! purpose, which actions wait for a person, how many steps it may take
//! and how much it may spend across every try, and how many tries it gets.
//!
//! The agent runs as any agent run does, so every tool call goes through
//! the same call check and proxy decision, deny by default. The check is
//! code the company writes, run in the same locked-down container as any
//! version's code: it is handed the answer and which try it is, and gives
//! back `{"pass": true}`, or `{"pass": false, "broken": [...]}` naming what
//! is wrong. Anything else, or a check that does not run, lets nothing
//! through.

use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::agents::execution::run::{CheckTries, CheckVerdict, DueCheck, GoalTemplate};
use crate::domains::agents::execution::tool::ToolName;
use crate::domains::agents::execution::usage::Spend;
use crate::domains::workflows::data::{FieldName, FlowData, FlowValue};
use crate::domains::workflows::design::node::{AgentRunParams, AgentRunStep, Checks, Mapping};
use crate::domains::workflows::execution::step::{CodeFailure, CodeOutcome};
use crate::shared::errors::DomainError;
use crate::shared::model::restriction::Restriction;
use crate::types::{ActionClass, AgentId, ModelProviderId, UntrustedText};

/// The field the check reads the answer from.
pub(crate) const CHECKED_ANSWER_FIELD: &str = "answer";

/// The field the check reads which try it is from, counted from one.
pub(crate) const CHECKED_TRY_FIELD: &str = "try";

/// The field of a check's verdict that says whether the answer passed.
pub const PASS_FIELD: &str = "pass";

/// The field of a check's verdict listing what the answer broke.
pub const BROKEN_FIELD: &str = "broken";

/// What a version holds: code that does a step's work, or an agent that
/// does it while the version's code checks its answer.
#[derive(Debug, Clone, PartialEq)]
pub enum VersionHolds {
    /// Its code is the step's work, run once on the step's input.
    Code,
    /// An agent does the step's work under these rules; its code is the
    /// check each answer must pass.
    Agent(Box<HeldAgent>),
}

/// The rules an agent held by a version works under, before they are
/// checked.
pub struct HeldAgentParams {
    /// The agent that works.
    pub agent_id: AgentId,
    /// The tenant's model provider it reasons with.
    pub provider_id: ModelProviderId,
    /// What it works toward; the step's mapped input is composed into it.
    pub goal: GoalTemplate,
    /// The action classes its tool calls may take.
    pub purpose: IntentEnvelope,
    /// The tools and integration steps it may call. None means it only
    /// writes.
    pub tools: Vec<ToolName>,
    /// The action classes whose calls wait for a person's approval.
    pub approval_classes: Vec<ActionClass>,
    /// The most steps it may take across every try.
    pub max_steps: u32,
    /// The most it may spend on its model across every try.
    pub spend_cap: Spend,
    /// What it may spend before it pauses for a person to let it go on.
    pub ask_past: Restriction<Spend>,
    /// How many answers it may give before the step fails.
    pub tries: CheckTries,
}

/// The rules an agent held by a version works under. Always capped in
/// spend, since a check that keeps failing would otherwise spend without
/// end until its tries ran out.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "HeldAgentWire"))]
pub struct HeldAgent {
    run: AgentRunStep,
    tries: CheckTries,
}

/// A [`HeldAgent`] as stored, checked again as it is read.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct HeldAgentWire {
    run: AgentRunStep,
    tries: CheckTries,
}

#[cfg(feature = "serde")]
impl TryFrom<HeldAgentWire> for HeldAgent {
    type Error = DomainError;

    fn try_from(wire: HeldAgentWire) -> Result<Self, Self::Error> {
        let mapped = !wire.run.inputs().fields().is_empty();
        let unchecked = *wire.run.checks() != Checks::Nothing;
        if mapped || unchecked || wire.run.spend_cap() == Restriction::Unrestricted {
            return Err(DomainError::corrupt_row(
                "sandbox version",
                "an agent whose rules map input, check a step, or spend without a cap",
            ));
        }
        Ok(Self {
            run: wire.run,
            tries: wire.tries,
        })
    }
}

impl HeldAgent {
    /// The rules `params` set.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for a step cap outside what a
    ///   workflow's agent run may take, a tool or approval class named
    ///   twice, a spend cap of nothing, or an amount to ask a person at
    ///   that is nothing or not below the cap.
    pub fn new(params: HeldAgentParams) -> Result<Self, DomainError> {
        let run = AgentRunStep::new(AgentRunParams {
            agent_id: params.agent_id,
            provider_id: params.provider_id,
            goal: params.goal,
            inputs: Mapping::new(Vec::new())?,
            purpose: params.purpose,
            tools: params.tools,
            approval_classes: params.approval_classes,
            max_steps: params.max_steps,
            spend_cap: Restriction::To(params.spend_cap),
            ask_past: params.ask_past,
            checks: Checks::Nothing,
        })?;
        Ok(Self {
            run,
            tries: params.tries,
        })
    }

    /// The run the agent makes: its agent, model provider, goal, purpose,
    /// tools, approvals, step cap and spending. It maps no input of its
    /// own; the step naming the version does.
    #[must_use]
    pub fn run(&self) -> &AgentRunStep {
        &self.run
    }

    /// How many answers it may give before the step fails.
    #[must_use]
    pub fn tries(&self) -> CheckTries {
        self.tries
    }

    /// The agent run a step makes of these rules, given the fields
    /// `inputs` maps from the step's input.
    #[must_use]
    pub(crate) fn step_for(&self, inputs: &Mapping) -> AgentRunStep {
        self.run.clone().given(inputs.clone())
    }
}

/// What the check is handed for the answer `due`: the answer, and which
/// try it is.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the answer is larger than workflow
///   data may hold.
pub fn check_input(due: &DueCheck<'_>) -> Result<FlowData, DomainError> {
    FlowData::map(vec![
        (
            FieldName::new(CHECKED_ANSWER_FIELD)?,
            FlowData::text(due.answer)?,
        ),
        (
            FieldName::new(CHECKED_TRY_FIELD)?,
            FlowData::number(f64::from(due.attempt))?,
        ),
    ])
}

/// What the check said, read from how its run went.
///
/// Only a verdict whose `pass` is `true` passes. One whose `pass` is
/// `false` broke a rule, named by its `broken` texts. Anything else, and a
/// check that raised, timed out or did not run, is a check that did not
/// run: it lets nothing through.
#[must_use]
pub fn verdict_of(outcome: CodeOutcome) -> CheckVerdict {
    match outcome {
        CodeOutcome::Succeeded(verdict) => read_verdict(&verdict),
        CodeOutcome::Failed(failure) => CheckVerdict::NotRun(why_not_run(failure)),
    }
}

/// The verdict a check gave back, read as [`verdict_of`] says.
fn read_verdict(verdict: &FlowData) -> CheckVerdict {
    let pass = FieldName::new(PASS_FIELD)
        .ok()
        .and_then(|field| verdict.field(&field).map(FlowData::value));
    match pass {
        Some(FlowValue::Bool(true)) => CheckVerdict::Passed,
        Some(FlowValue::Bool(false)) => CheckVerdict::Broken(broken_of(verdict)),
        Some(_) | None => CheckVerdict::NotRun(UntrustedText::record(
            "the check gave back no verdict: a map whose pass is true or false",
        )),
    }
}

/// What a verdict says the answer broke: its `broken` texts, one after
/// another, or a plain note when it names nothing.
fn broken_of(verdict: &FlowData) -> UntrustedText {
    let listed = FieldName::new(BROKEN_FIELD)
        .ok()
        .and_then(|field| verdict.field(&field).map(FlowData::value));
    let said = match listed {
        Some(FlowValue::Text(text)) => text.to_owned(),
        Some(FlowValue::List(items)) => items
            .iter()
            .filter_map(|item| match item.value() {
                FlowValue::Text(text) => Some(text),
                FlowValue::Null
                | FlowValue::Bool(_)
                | FlowValue::Number(_)
                | FlowValue::List(_)
                | FlowValue::Map(_) => None,
            })
            .collect::<Vec<_>>()
            .join("; "),
        Some(_) | None => String::new(),
    };
    if said.is_empty() {
        return UntrustedText::record("the check found a broken rule and named none");
    }
    UntrustedText::record(&said)
}

/// Why a check that failed gave no verdict.
fn why_not_run(failure: CodeFailure) -> UntrustedText {
    match failure {
        CodeFailure::Raised(said) => {
            UntrustedText::record(&format!("the check raised: {}", said.as_str()))
        }
        CodeFailure::TimedOut => UntrustedText::record("the check ran past its time limit"),
        CodeFailure::OutOfMemory => UntrustedText::record("the check used more memory than it may"),
        CodeFailure::Unreadable => UntrustedText::record("the check gave back no JSON"),
        CodeFailure::NotRun(why) => {
            UntrustedText::record(&format!("the check did not run: {}", why.as_str()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::execution::run::MAX_CHECK_TRIES;

    fn verdict(entries: Vec<(&str, FlowData)>) -> CodeOutcome {
        let fields = entries
            .into_iter()
            .map(|(name, value)| (FieldName::new(name).unwrap(), value))
            .collect();
        CodeOutcome::Succeeded(FlowData::map(fields).unwrap())
    }

    fn texts(items: &[&str]) -> FlowData {
        FlowData::list(
            items
                .iter()
                .map(|item| FlowData::text(*item).unwrap())
                .collect(),
        )
        .unwrap()
    }

    /// The check says the reply passes. The verdict is a pass.
    #[test]
    fn a_verdict_whose_pass_is_true_passes() {
        let outcome = verdict(vec![(PASS_FIELD, FlowData::bool(true))]);

        assert_eq!(verdict_of(outcome), CheckVerdict::Passed);
    }

    /// The check finds an internal name and a promised refund. Both go back
    /// to the model, one after the other.
    #[test]
    fn a_failed_verdict_names_every_broken_rule() {
        let outcome = verdict(vec![
            (PASS_FIELD, FlowData::bool(false)),
            (
                BROKEN_FIELD,
                texts(&["no internal names", "no promises of refunds"]),
            ),
        ]);

        assert_eq!(
            verdict_of(outcome),
            CheckVerdict::Broken(UntrustedText::record(
                "no internal names; no promises of refunds"
            ))
        );
    }

    /// A check that answers `"yes"`, a pass written as text, or nothing at
    /// all gives no verdict, so the answer is not let through.
    #[test]
    fn anything_but_a_true_or_false_pass_lets_nothing_through() {
        let unreadable = [
            CodeOutcome::Succeeded(FlowData::text("yes").unwrap()),
            verdict(vec![(PASS_FIELD, FlowData::text("true").unwrap())]),
            verdict(Vec::new()),
            CodeOutcome::Failed(CodeFailure::TimedOut),
        ];

        for outcome in unreadable {
            assert!(matches!(verdict_of(outcome), CheckVerdict::NotRun(_)));
        }
    }

    /// The check is handed the drafted reply and that it is the second try.
    #[test]
    fn the_check_is_handed_the_answer_and_its_try() {
        let due = DueCheck {
            version: crate::types::SandboxVersionId::new(),
            answer: "Dear Pat",
            attempt: 2,
        };

        let input = check_input(&due).unwrap();

        let field = |name: &str| input.field(&FieldName::new(name).unwrap()).cloned();
        assert_eq!(
            field(CHECKED_ANSWER_FIELD),
            Some(FlowData::text("Dear Pat").unwrap())
        );
        assert_eq!(
            field(CHECKED_TRY_FIELD),
            Some(FlowData::number(2.0).unwrap())
        );
    }

    fn params(spend_cap: u64, ask_past: Restriction<Spend>) -> HeldAgentParams {
        HeldAgentParams {
            agent_id: AgentId::new(),
            provider_id: ModelProviderId::new(),
            goal: GoalTemplate::new("Draft a reply to the customer").unwrap(),
            purpose: IntentEnvelope::default(),
            tools: Vec::new(),
            approval_classes: Vec::new(),
            max_steps: 10,
            spend_cap: Spend::from_micros(spend_cap),
            ask_past,
            tries: CheckTries::new(MAX_CHECK_TRIES).unwrap(),
        }
    }

    /// Ann saves a version holding a reply drafter. The version holds the
    /// drafter's rules, and the record of the save names the agent.
    #[test]
    fn a_version_holding_an_agent_names_it_in_the_record_of_its_save() {
        let agent = AgentId::new();
        let mut version =
            crate::domains::workflows::execution::tests::fixtures::held_version(agent);

        let saved = crate::test_support::events::raised(&mut version);

        let held = version.held_agent().map(|held| *held.run().agent_id());
        assert_eq!(held, Some(agent));
        let named = agent.to_string();
        assert_eq!(saved[0].payload().get("agent"), Some(named.as_str()));
    }

    /// An agent capped at two dollars, asking a person past one, is held.
    /// A cap of nothing, or asking at the cap itself, is refused.
    #[test]
    fn a_held_agent_is_always_capped_in_spend() {
        let ask = |micros| Restriction::To(Spend::from_micros(micros));

        assert!(HeldAgent::new(params(2_000_000, ask(1_000_000))).is_ok());
        assert!(HeldAgent::new(params(0, Restriction::Unrestricted)).is_err());
        assert!(HeldAgent::new(params(2_000_000, ask(2_000_000))).is_err());
    }
}
