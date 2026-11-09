//! Reading the model's answer: the proposal it holds, kept to the shape a
//! draft takes and to what the catalog offers now. Whatever does not fit is
//! left out with a note, never invented.

use ianua_domain::domains::workflows::data::DataPath;
use ianua_domain::domains::workflows::design::node::{NodeKey, Port};
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationSpec};
use ianua_domain::types::{ActionClass, DeclaredAction, Label, Text};
use serde_json::Value;

use crate::use_cases::workflows::definitions::drafting::{
    DraftPlace, MAX_PROPOSED_STEPS, Proposal, ProposedEdge, ProposedKind, ProposedStep,
    ProposedTrigger, ProposedValue,
};

/// The proposal in `answer`, held to what is `offered`. Whatever does not
/// fit is left out with a note.
pub(super) fn proposal_from(
    answer: &str,
    offered: &[OperationSpec],
    place: &DraftPlace,
) -> Proposal {
    let Some(object) = json_object_in(answer) else {
        return only_note("The model did not answer with a draft. Try other words.");
    };
    let mut notes = Vec::new();
    let steps: Vec<ProposedStep> = object
        .get("steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROPOSED_STEPS)
        .filter_map(|step| step_from(step, offered, &mut notes))
        .collect();
    let edges = edges_from(&object, &steps);
    let trigger = match place {
        DraftPlace::NewWorkflow => Some(trigger_from(object.get("trigger"))),
        DraftPlace::After { .. } => None,
    };
    notes.extend(notes_in(&object));
    Proposal {
        trigger,
        steps,
        edges,
        notes,
    }
}

/// A proposal of no steps, saying only `note`.
pub(super) fn only_note(note: &str) -> Proposal {
    Proposal {
        trigger: None,
        steps: Vec::new(),
        edges: Vec::new(),
        notes: vec![note.to_owned()],
    }
}

/// What the model noted for the person, at most five notes of 300
/// characters each.
fn notes_in(object: &Value) -> impl Iterator<Item = String> + '_ {
    object
        .get("notes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(5)
        .map(|note| note.chars().take(300).collect())
}

/// The first JSON object in `answer`, which may be wrapped in prose.
fn json_object_in(answer: &str) -> Option<Value> {
    let start = answer.find('{')?;
    let end = answer.rfind('}')?;
    let value: Value = serde_json::from_str(answer.get(start..=end)?).ok()?;
    value.is_object().then_some(value)
}

/// The step `value` describes, when it fits; a note says why one that does
/// not is left out.
fn step_from(
    value: &Value,
    offered: &[OperationSpec],
    notes: &mut Vec<String>,
) -> Option<ProposedStep> {
    let key = NodeKey::new(value.get("key")?.as_str()?).ok()?;
    let title = Label::new("title", value.get("title")?.as_str()?).ok()?;
    let kind = match value.get("kind")?.as_str()? {
        "action" => action_from(value, offered, notes)?,
        "agent_run" => ProposedKind::AgentRun {
            goal: Text::new("goal", value.get("goal")?.as_str()?).ok()?,
        },
        "condition" => ProposedKind::Condition {
            path: DataPath::parse(value.get("path")?.as_str()?).ok()?,
            equals: value
                .get("equals")
                .and_then(Value::as_str)
                .map(str::to_owned),
        },
        "approval" => ProposedKind::Approval {
            summary: Text::new("summary", value.get("summary")?.as_str()?).ok()?,
            class: class_from(value.get("class").and_then(Value::as_str)),
        },
        "wait" => ProposedKind::Wait {
            seconds: u32::try_from(value.get("seconds")?.as_u64()?).ok()?,
        },
        _ => return None,
    };
    Some(ProposedStep { key, title, kind })
}

/// The action `value` describes, when the catalog offers its operation.
fn action_from(
    value: &Value,
    offered: &[OperationSpec],
    notes: &mut Vec<String>,
) -> Option<ProposedKind> {
    let integration = value.get("integration")?.as_str()?;
    let operation = value.get("operation")?.as_str()?;
    let Some(spec) = offered.iter().find(|spec| {
        spec.integration().as_str() == integration && spec.operation().as_str() == operation
    }) else {
        notes.push(format!(
            "{integration} offers no step \"{operation}\", so it was left out."
        ));
        return None;
    };
    let inputs = value
        .get("inputs")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, source)| {
            let field = spec
                .inputs()
                .iter()
                .find(|input| input.name().as_str() == name)?;
            Some((field.name().clone(), value_from(source)?))
        })
        .collect();
    Some(ProposedKind::Action {
        integration: spec.integration().clone(),
        operation: spec.operation().clone(),
        inputs,
    })
}

/// An input's value as the model gave it.
fn value_from(source: &Value) -> Option<ProposedValue> {
    if let Some(path) = source.get("path").and_then(Value::as_str) {
        return DataPath::parse(path).ok().map(ProposedValue::Path);
    }
    let text = source.get("text")?.as_str()?;
    Some(ProposedValue::Text(text.chars().take(2_000).collect()))
}

/// The class an approval guards, read from the model's word; anything else
/// is undeclared, the most careful.
fn class_from(word: Option<&str>) -> DeclaredAction {
    let classes = [
        ActionClass::Read,
        ActionClass::Write,
        ActionClass::Communicate,
        ActionClass::Delete,
        ActionClass::Configure,
        ActionClass::Financial,
        ActionClass::Admin,
    ];
    classes
        .into_iter()
        .find(|class| Some(class.as_str()) == word)
        .map_or(DeclaredAction::Undeclared, DeclaredAction::Declared)
}

/// The edges between the kept `steps`; one naming a step left out is
/// dropped with it.
fn edges_from(object: &Value, steps: &[ProposedStep]) -> Vec<ProposedEdge> {
    let kept = |key: &str| {
        steps
            .iter()
            .find(|step| step.key.to_string() == key)
            .map(|step| step.key.clone())
    };
    object
        .get("edges")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|edge| {
            let to = kept(edge.get("to")?.as_str()?)?;
            let from = match edge.get("from") {
                Some(Value::String(key)) => Some(kept(key)?),
                _ => None,
            };
            let port = match edge.get("port").and_then(Value::as_str) {
                Some("when_true") => Port::WhenTrue,
                Some("when_false") => Port::WhenFalse,
                _ => Port::Next,
            };
            Some(ProposedEdge { from, port, to })
        })
        .collect()
}

/// The trigger the model proposed, or a start by hand when it named none
/// the platform has.
fn trigger_from(value: Option<&Value>) -> ProposedTrigger {
    let kind = value
        .and_then(|value| value.get("kind"))
        .and_then(Value::as_str);
    let text = |field: &str| {
        value
            .and_then(|value| value.get(field))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    match kind {
        Some("webhook") => ProposedTrigger::Webhook,
        Some("schedule") => text("cron").map_or(ProposedTrigger::Manual, ProposedTrigger::Schedule),
        Some("service_event") => {
            let integration = text("integration").and_then(|key| IntegrationKey::new(key).ok());
            match (integration, text("event")) {
                (Some(integration), Some(event)) => {
                    ProposedTrigger::ServiceEvent { integration, event }
                }
                (Some(_) | None, _) => ProposedTrigger::Manual,
            }
        }
        Some(_) | None => ProposedTrigger::Manual,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::data::FieldName;
    use ianua_domain::domains::workflows::integration::{
        AccountNeed, InputNeed, InputSpec, OperationKey, OperationSpecParams,
    };

    use super::*;

    fn slack_post() -> OperationSpec {
        OperationSpec::new(OperationSpecParams {
            integration: IntegrationKey::new("slack").unwrap(),
            operation: OperationKey::new("post-message").unwrap(),
            inputs: ["channel", "text"]
                .into_iter()
                .map(|name| InputSpec::new(FieldName::new(name).unwrap(), InputNeed::Required))
                .collect(),
            effect: DeclaredAction::Declared(ActionClass::Communicate),
            account: AccountNeed::Account,
            ceiling: DataClassLevel::Internal,
        })
        .unwrap()
    }

    /// The model proposes posting in Slack after a check, wrapped in a
    /// sentence. Both steps are kept, with the arrow between them, and the
    /// Slack step's inputs come through as a value and a path.
    #[test]
    fn a_proposal_that_fits_the_catalog_is_kept() {
        let answer = r##"Here you go: {"trigger": {"kind": "webhook"},
          "steps": [
            {"key": "passed", "title": "Did the tests pass?", "kind": "condition", "path": "trigger.status", "equals": "passed"},
            {"key": "tell", "title": "Tell the team", "kind": "action", "integration": "slack", "operation": "post-message",
             "inputs": {"channel": {"text": "#team"}, "text": {"path": "trigger.summary"}}}],
          "edges": [{"from": "passed", "port": "when_true", "to": "tell"}]}"##;

        let proposal = proposal_from(answer, &[slack_post()], &DraftPlace::NewWorkflow);

        assert_eq!(proposal.trigger, Some(ProposedTrigger::Webhook));
        assert_eq!(proposal.steps.len(), 2);
        assert_eq!(proposal.edges[0].port, Port::WhenTrue);
        let ProposedKind::Action { inputs, .. } = &proposal.steps[1].kind else {
            panic!("the second step posts in Slack");
        };
        assert_eq!(inputs.len(), 2);
    }

    /// An unavailable GitHub operation and its edge are omitted from the model's
    /// proposal, leaving the offered Slack step and a note naming the omission.
    #[test]
    fn an_operation_that_is_not_offered_is_left_out_with_a_note() {
        let answer = r#"{"steps": [
            {"key": "commit", "title": "Commit the change", "kind": "action", "integration": "github", "operation": "commit"},
            {"key": "tell", "title": "Tell the team", "kind": "action", "integration": "slack", "operation": "post-message", "inputs": {}}],
          "edges": [{"from": "commit", "port": "next", "to": "tell"}]}"#;

        let proposal = proposal_from(answer, &[slack_post()], &DraftPlace::NewWorkflow);

        assert_eq!(proposal.steps.len(), 1);
        assert!(proposal.edges.is_empty());
        assert!(proposal.notes.iter().any(|note| note.contains("commit")));
    }

    /// A model answer without JSON yields no proposed steps and one explanatory note.
    #[test]
    fn an_answer_with_no_draft_gives_a_note() {
        let proposal = proposal_from("I cannot help with that.", &[], &DraftPlace::NewWorkflow);

        assert!(proposal.steps.is_empty());
        assert_eq!(proposal.notes.len(), 1);
    }
}
