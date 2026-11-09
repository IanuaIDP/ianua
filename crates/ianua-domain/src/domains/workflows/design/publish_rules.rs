//! The rules a workflow's graph keeps before it is put in service.
//!
//! A version is checked when it is published, and again whenever a stored
//! version or execution is rebuilt.

use crate::domains::workflows::data::FieldName;
use crate::domains::workflows::design::graph::WorkflowGraph;
use crate::domains::workflows::design::node::{
    Checks, Covering, HandsOn, NodeKey, NodeKind, TRIGGER_FIELD,
};
use crate::domains::workflows::design::workflow::{CodeReach, RunnableCode};
use crate::domains::workflows::integration::company::{COMPANY_INTEGRATION, CompanyOperation};
use crate::domains::workflows::integration::events::ServiceEventSpec;
use crate::domains::workflows::triggers::Trigger;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{DeclaredAction, SandboxVersionId};

/// Refuses a graph whose code step names a sandbox version not among
/// `runnable`. Ann's step names a version whose packages failed to build,
/// or one of a sandbox she archived; every run would fail at that step, so
/// the draft is not published.
///
/// # Errors
///
/// - [`DomainError::Validation`] naming the first such step.
pub(in crate::domains::workflows) fn ensure_code_runnable(
    graph: &WorkflowGraph,
    runnable: &[RunnableCode],
) -> Result<(), DomainError> {
    let Some((node, _)) = graph
        .code_steps()
        .find(|(_, step)| !runnable.iter().any(|code| code.version == step.version()))
    else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "workflows-the-step-s-sandbox-version-may-not-run",
        format!(
            "{} names a sandbox version that may not run: it is gone, archived, or its packages are not built",
            node.key()
        )
    )))
}

/// Refuses a graph where a step reads a path that starts anywhere but at
/// the trigger's data or at an earlier step that leads to it.
///
/// A typo, a step on another branch or a removed step would otherwise read
/// as nothing, and an action would be called with that. A loop's own steps
/// keep the rule among themselves, the trigger's data being what each pass
/// starts with.
///
/// # Errors
///
/// - [`DomainError::Validation`] naming the first step and path that does.
pub(in crate::domains::workflows) fn ensure_paths_name_earlier_steps(
    graph: &WorkflowGraph,
) -> Result<(), DomainError> {
    bodies(graph).try_for_each(ensure_paths_name_earlier_steps)?;
    for node in graph.nodes() {
        let earlier = graph.ancestors(node.key());
        let reaches = |root: &FieldName| {
            root.as_str() == TRIGGER_FIELD
                || earlier.iter().any(|step| step.key().as_field() == root)
        };
        let stray = node
            .kind()
            .input_paths()
            .into_iter()
            .find(|path| !path.root().is_some_and(reaches));
        if let Some(stray) = stray {
            return Err(DomainError::invalid(message!(
                "workflows-reads-which-is-neither-the-trigger",
                format!(
                    "{} reads {stray}, which is neither the trigger nor a step before it",
                    node.key()
                )
            )));
        }
    }
    Ok(())
}

/// Refuses a graph where an agent step checks work that is not an earlier
/// agent step's, or is its own agent's.
///
/// "Have another agent check it" means another agent: the Triage bot
/// checking its own fix would only agree with itself. And the work checked
/// must come before the check, or the check reads nothing.
///
/// # Errors
///
/// - [`DomainError::Validation`] naming the first step that does.
pub(in crate::domains::workflows) fn ensure_checks_are_of_other_agents(
    graph: &WorkflowGraph,
) -> Result<(), DomainError> {
    bodies(graph).try_for_each(ensure_checks_are_of_other_agents)?;
    for node in graph.nodes() {
        let NodeKind::AgentRun(step) = node.kind() else {
            continue;
        };
        let Checks::Step(checked) = step.checks() else {
            continue;
        };
        let earlier = graph.ancestors(node.key());
        let other_agent = earlier.iter().any(|before| {
            before.key() == checked
                && matches!(before.kind(), NodeKind::AgentRun(work) if work.agent_id() != step.agent_id())
        });
        if !other_agent {
            return Err(DomainError::invalid(message!(
                "workflows-checks-which-is-not-an-earlier",
                format!(
                    "{} checks {checked}, which is not an earlier agent step of another agent",
                    node.key()
                )
            )));
        }
    }
    Ok(())
}

/// Refuses a graph with a guardrail that points at no text: its path
/// starts at a condition, an approval or a wait, which hand nothing on, so
/// every run would find nothing to check and stop. That the path starts at
/// the trigger or an earlier step at all is
/// [`ensure_paths_name_earlier_steps`]'s rule.
///
/// # Errors
///
/// - [`DomainError::Validation`] naming the first such guardrail and the
///   step it reads.
pub(in crate::domains::workflows) fn ensure_guardrails_read_text(
    graph: &WorkflowGraph,
) -> Result<(), DomainError> {
    bodies(graph).try_for_each(ensure_guardrails_read_text)?;
    let blind = graph.nodes().iter().find_map(|node| {
        let NodeKind::Guardrail(step) = node.kind() else {
            return None;
        };
        let root = step.text().root()?;
        let read = graph
            .nodes()
            .iter()
            .find(|before| before.key().as_field() == root)?;
        (HandsOn::of(read.kind()) == HandsOn::Nothing).then_some((node, read))
    });
    let Some((guard, read)) = blind else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "workflows-a-guardrail-points-at-no-text",
        format!(
            "{} checks {}, a step that hands on no text to check",
            guard.key(),
            read.key()
        )
    )))
}

/// Refuses a trigger on a service event its integration no longer offers,
/// or no longer as the trigger names it.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the event is not among `events`, or
///   the trigger's filters no longer fit it.
pub(in crate::domains::workflows) fn ensure_trigger_event_offered(
    trigger: &Trigger,
    events: &[ServiceEventSpec],
) -> Result<(), DomainError> {
    let Trigger::Service(on) = trigger else {
        return Ok(());
    };
    let spec = events
        .iter()
        .find(|spec| spec.integration() == on.integration() && spec.event() == on.event());
    let Some(spec) = spec else {
        return Err(DomainError::invalid(message!(
            "workflows-the-event-is-not-offered-any-more",
            format!(
                "the event {}.{} is not offered any more",
                on.integration(),
                on.event()
            )
        )));
    };
    on.ensure_fits(spec)
}

/// Refuses a graph with a high-risk action that is not approved right
/// before it.
///
/// High-risk means moving money, deleting, administering, configuring, or
/// not saying what it does. Every edge into such an action must come from
/// an approval step covering its class. It may also come from a condition
/// or transform that is itself reached only that way. Nothing that waits,
/// runs an agent or calls another integration sits between the approval and
/// the action. So what people approved is what runs, while it is still
/// current. Inside a loop, the approval sits among the loop's own steps,
/// so each pass asks for it about its own item, or one approval listing
/// every item is asked before the passes start.
///
/// # Errors
///
/// - [`DomainError::Validation`] naming the first action not approved so.
pub(in crate::domains::workflows) fn ensure_high_risk_actions_approved(
    graph: &WorkflowGraph,
) -> Result<(), DomainError> {
    bodies(graph).try_for_each(ensure_high_risk_actions_approved)?;
    let unguarded = graph.nodes().iter().find(|node| {
        let NodeKind::Action(step) = node.kind() else {
            return false;
        };
        step.effect().may_be_high_risk()
            && !approved_right_before(graph, step.effect()).contains(&node.key())
    });
    let Some(unguarded) = unguarded else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "workflows-is-a-high-risk-action-without",
        format!(
            "{} is a high-risk action without an approval right before it",
            unguarded.key()
        )
    )))
}

/// Refuses an approval asked once for every item that sits outside a loop,
/// where there are no items to list.
///
/// # Errors
///
/// - [`DomainError::Validation`] naming the first such step.
pub(in crate::domains::workflows) fn ensure_item_approvals_in_loops(
    graph: &WorkflowGraph,
) -> Result<(), DomainError> {
    let Some(stray) = graph.nodes().iter().find(|node| {
        matches!(node.kind(), NodeKind::Approval(step) if step.covers_items() == Covering::WholeLoop)
    }) else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "workflows-an-approval-for-every-item-sits-in-a-loop",
        format!(
            "{} asks one approval for every item, which only a loop's first step may do",
            stray.key()
        )
    )))
}

/// Refuses a "before" workflow that could end without deciding, or wait on
/// something that cannot answer while the change waits: every step with no
/// step after it is Allow or Refuse, and none waits for people, time, an
/// agent or code.
///
/// # Errors
///
/// - [`DomainError::Validation`] naming the first step that breaks it.
pub(in crate::domains::workflows) fn ensure_before_decides(
    trigger: &Trigger,
    graph: &WorkflowGraph,
) -> Result<(), DomainError> {
    let Trigger::Before(_) = trigger else {
        return Ok(());
    };
    if let Some(slow) = graph.nodes().iter().find(|node| is_slow(node.kind())) {
        return Err(DomainError::invalid(message!(
            "workflows-a-before-rule-cannot-wait",
            format!(
                "{} waits for people, time, an agent or code, which a change cannot wait for",
                slow.key()
            )
        )));
    }
    let undecided = graph.nodes().iter().find(|node| {
        let ends = graph.edges().iter().all(|edge| edge.from() != node.key());
        ends && !decides(node.kind())
    });
    let Some(undecided) = undecided else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "workflows-a-before-rule-ends-undecided",
        format!("{} ends the rule without Allow or Refuse", undecided.key())
    )))
}

/// Whether a step of `kind` waits on something a change cannot wait for.
fn is_slow(kind: &NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Approval(_) | NodeKind::Wait(_) | NodeKind::AgentRun(_) | NodeKind::Code(_)
    )
}

/// Whether a step of `kind` is the company's Allow or Refuse.
fn decides(kind: &NodeKind) -> bool {
    let NodeKind::Action(step) = kind else {
        return false;
    };
    step.integration().as_str() == COMPANY_INTEGRATION
        && matches!(
            CompanyOperation::named(step.operation()),
            Some(CompanyOperation::Allow | CompanyOperation::Refuse)
        )
}

/// Refuses a graph with a code step whose version reaches the network and
/// is not approved right before it, as an action that does not say what it
/// does is: the code may call outside services, and may call them twice
/// when a worker runs it again. Inside a loop, the approval sits among the
/// loop's own steps.
///
/// # Errors
///
/// - [`DomainError::Validation`] naming the first such step.
pub(in crate::domains::workflows) fn ensure_networked_code_approved(
    graph: &WorkflowGraph,
    runnable: &[RunnableCode],
) -> Result<(), DomainError> {
    bodies(graph).try_for_each(|body| ensure_networked_code_approved(body, runnable))?;
    let networked = |version: SandboxVersionId| {
        runnable
            .iter()
            .any(|code| code.version == version && code.reach == CodeReach::Networked)
    };
    let approved = approved_right_before(graph, DeclaredAction::Undeclared);
    let unguarded = graph.nodes().iter().find(|node| {
        let NodeKind::Code(step) = node.kind() else {
            return false;
        };
        networked(step.version()) && !approved.contains(&node.key())
    });
    let Some(unguarded) = unguarded else {
        return Ok(());
    };
    Err(DomainError::invalid(message!(
        "workflows-runs-code-that-reaches-the-network",
        format!(
            "{} runs code that reaches the network without an approval right before it",
            unguarded.key()
        )
    )))
}

/// The steps whose every incoming edge comes from an approval covering
/// `effect`, or from a condition or transform that is itself one of these
/// steps.
fn approved_right_before(graph: &WorkflowGraph, effect: DeclaredAction) -> Vec<&NodeKey> {
    let mut approved: Vec<&NodeKey> = Vec::new();
    for key in graph.in_order() {
        let mut incoming = graph.incoming(key).peekable();
        let reached = incoming.peek().is_some();
        let guarded = incoming.all(|edge| {
            graph
                .node(edge.from())
                .is_some_and(|from| match from.kind() {
                    NodeKind::Approval(approval) => approval.covers(effect),
                    NodeKind::Condition(_) | NodeKind::Transform(_) => {
                        approved.contains(&from.key())
                    }
                    NodeKind::AgentRun(_)
                    | NodeKind::Action(_)
                    | NodeKind::Wait(_)
                    | NodeKind::Loop(_)
                    | NodeKind::Code(_)
                    | NodeKind::Guardrail(_) => false,
                })
        });
        if reached && guarded {
            approved.push(key);
        }
    }
    approved
}

/// The steps each loop of `graph` runs for every item.
fn bodies(graph: &WorkflowGraph) -> impl Iterator<Item = &WorkflowGraph> {
    graph.nodes().iter().filter_map(|node| node.kind().body())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::oversight::approval::ApprovalAction;
    use crate::domains::data_classification::level::DataClassLevel;
    use crate::domains::workflows::data::{DataPath, FlowData};
    use crate::domains::workflows::design::graph::Edge;
    use crate::domains::workflows::design::node::{
        GuardrailParams, GuardrailStep, Join, Mapping, Node, Port, Source, WaitStep,
        WorkflowApprovalStep,
    };
    use crate::domains::workflows::guardrail::finding::GuardrailCheck;
    use crate::domains::workflows::triggers::before::GuardedChange;
    use crate::types::{Label, Lifetime};

    fn tidy(name: &str) -> Node {
        let mapping = Mapping::new(vec![(
            FieldName::new("seen").unwrap(),
            Source::Literal(FlowData::bool(true)),
        )])
        .unwrap();
        Node::new(
            NodeKey::new(name).unwrap(),
            Label::new("name", name).unwrap(),
            NodeKind::Transform(mapping),
            Join::All,
        )
    }

    /// Ann's workflow asks one approval "for every item" as a plain step,
    /// outside any loop. There is no list to show, so publishing refuses it;
    /// the same approval asked the usual way publishes.
    #[test]
    fn an_approval_for_every_item_outside_a_loop_is_refused() {
        let asking = |covers: Covering| {
            let step = WorkflowApprovalStep::new(
                ApprovalAction::new("pay").unwrap(),
                DeclaredAction::Undeclared,
                Lifetime::seconds(3600).unwrap(),
            )
            .unwrap()
            .covering(covers);
            let node = Node::new(
                NodeKey::new("approve").unwrap(),
                Label::new("name", "approve").unwrap(),
                NodeKind::Approval(step),
                Join::All,
            );
            WorkflowGraph::new(vec![node], Vec::new()).unwrap()
        };

        let stray = ensure_item_approvals_in_loops(&asking(Covering::WholeLoop));
        let plain = ensure_item_approvals_in_loops(&asking(Covering::EachPass));

        assert!(matches!(stray, Err(DomainError::Validation(_))));
        assert!(plain.is_ok());
    }

    /// Ann's "before admin given" rule only tidies the data and stops: it
    /// never says Allow or Refuse, so publishing refuses it. The same graph
    /// on a schedule is no rule and publishes.
    #[test]
    fn a_before_rule_that_ends_undecided_is_refused() {
        let graph = WorkflowGraph::new(vec![tidy("tidy")], Vec::new()).unwrap();

        let before = ensure_before_decides(&Trigger::Before(GuardedChange::AdminGiven), &graph);
        let manual = ensure_before_decides(&Trigger::Manual, &graph);

        assert!(matches!(before, Err(DomainError::Validation(_))));
        assert!(manual.is_ok());
    }

    /// A guardrail checking `<step>.answer` right after `step`.
    fn guarding(step: Node) -> WorkflowGraph {
        let guard = GuardrailStep::new(GuardrailParams {
            text: DataPath::parse(&format!("{}.answer", step.key())).unwrap(),
            checks: vec![GuardrailCheck::ModelTricks],
            personal_from: DataClassLevel::Confidential,
            banned: Default::default(),
            on_finding: Default::default(),
        })
        .unwrap();
        let edge = Edge::new(
            step.key().clone(),
            Port::Next,
            NodeKey::new("guard").unwrap(),
        );
        let guard = Node::new(
            NodeKey::new("guard").unwrap(),
            Label::new("name", "guard").unwrap(),
            NodeKind::Guardrail(guard),
            Join::All,
        );
        WorkflowGraph::new(vec![step, guard], vec![edge]).unwrap()
    }

    /// Pat's guardrail checks what a wait step hands on, which is nothing:
    /// every run would stop on no text, so publishing refuses it. Checking
    /// what a transform builds publishes.
    #[test]
    fn a_guardrail_pointing_at_no_text_is_refused() {
        let wait = Node::new(
            NodeKey::new("pause").unwrap(),
            Label::new("name", "pause").unwrap(),
            NodeKind::Wait(WaitStep::new(Lifetime::seconds(60).unwrap()).unwrap()),
            Join::All,
        );

        let blind = ensure_guardrails_read_text(&guarding(wait));
        let reading = ensure_guardrails_read_text(&guarding(tidy("tidy")));

        assert!(matches!(blind, Err(DomainError::Validation(_))));
        assert!(reading.is_ok());
    }
}
