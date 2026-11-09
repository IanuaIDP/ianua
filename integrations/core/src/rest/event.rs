//! The events a service sends that a workflow may start on, each described
//! once, as data, from which its spec and its guide are made, beside what
//! registers workflows for them and reads what the service sends.

use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowData};
use ianua_domain::domains::workflows::integration::events::{
    ServiceEventGuide, ServiceEventGuideParams, ServiceEventKey, ServiceEventSpec,
};
use ianua_domain::domains::workflows::integration::guide::OutputNote;
use ianua_domain::domains::workflows::integration::{InputNeed, InputSpec, IntegrationKey};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, Text};
use serde_json::{Map, Value};

use crate::answer::flow_of;
use crate::describe::InputText;
use crate::events::Events;
use crate::form::{FormText, Suggested};

/// One filter an event takes: its name, whether a trigger must set it, and
/// what it means.
#[derive(Debug, Clone, Copy)]
pub struct FilterText {
    /// Its name, such as `repository`.
    pub name: &'static str,
    /// Whether a trigger must set it.
    pub need: InputNeed,
    /// What it means.
    pub meaning: &'static str,
}

/// One event a service sends, described once.
#[derive(Debug, Clone, Copy)]
pub struct EventText {
    /// Its key, such as `issue-opened`.
    pub key: &'static str,
    /// Its name for people, such as `An issue is opened`.
    pub title: &'static str,
    /// When it happens.
    pub description: &'static str,
    /// The filters a trigger may set.
    pub filters: &'static [FilterText],
    /// Each value it gives the workflow: its path in the trigger's output
    /// and what it is.
    pub outputs: &'static [(&'static str, &'static str)],
}

/// The events a service offers and what starts workflows on them.
pub struct ServiceEvents {
    /// Every event, described.
    pub described: Vec<&'static EventText>,
    /// What registers workflows for them and reads what the service sends.
    pub watcher: Box<dyn Events>,
}

/// The specs and guides of a service's events, made from their texts.
pub(crate) struct DescribedEvents {
    /// What the domain checks a trigger against.
    pub(crate) specs: Vec<ServiceEventSpec>,
    /// What the builder reads.
    pub(crate) guides: Vec<ServiceEventGuide>,
}

/// The specs and guides `events` describe, as `key`'s.
///
/// # Errors
///
/// Returns `DomainError::Validation` when a name or text breaks its rules,
/// or an event names one filter twice.
pub(crate) fn described_events(
    events: &[&'static EventText],
    key: &IntegrationKey,
) -> Result<DescribedEvents, DomainError> {
    let mut specs = Vec::new();
    let mut guides = Vec::new();
    for text in events {
        let event = ServiceEventKey::new(text.key)?;
        let filters = text
            .filters
            .iter()
            .map(|filter| Ok(InputSpec::new(FieldName::new(filter.name)?, filter.need)))
            .collect::<Result<Vec<_>, DomainError>>()?;
        specs.push(ServiceEventSpec::new(key.clone(), event.clone(), filters)?);
        guides.push(guide_of(text, event)?);
    }
    Ok(DescribedEvents { specs, guides })
}

/// The values `text` says its event gives, picked from `payload` at their
/// paths, a value the payload lacks as null. Nothing else the service sent
/// reaches the workflow.
///
/// # Errors
///
/// Returns `DomainError::Validation` when a picked value is larger than
/// workflow data may be.
pub fn picked(text: &EventText, payload: &Value) -> Result<FlowData, DomainError> {
    let mut kept = Map::new();
    for (path, _) in text.outputs {
        let parts: Vec<&str> = path.split('.').collect();
        let found = parts
            .iter()
            .try_fold(payload, |value, part| value.get(part))
            .cloned()
            .unwrap_or(Value::Null);
        place(&mut kept, &parts, found);
    }
    flow_of(&Value::Object(kept))
}

/// `value` put into `into` at `parts`, making the maps on the way.
fn place(into: &mut Map<String, Value>, parts: &[&str], value: Value) {
    match parts {
        [] => {}
        [last] => {
            into.insert((*last).to_owned(), value);
        }
        [first, rest @ ..] => {
            let inner = into
                .entry((*first).to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(map) = inner {
                place(map, rest, value);
            }
        }
    }
}

/// The guide `text` writes for `event`.
fn guide_of(text: &EventText, event: ServiceEventKey) -> Result<ServiceEventGuide, DomainError> {
    let filters = text
        .filters
        .iter()
        .map(|filter| {
            InputText {
                name: filter.name,
                meaning: filter.meaning,
                suggested: Suggested::Text,
                form: FormText::plain(),
            }
            .note()
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    let outputs = text
        .outputs
        .iter()
        .map(|(path, meaning)| {
            Ok(OutputNote::new(
                DataPath::parse(path)?,
                Text::new("description", *meaning)?,
            ))
        })
        .collect::<Result<Vec<_>, DomainError>>()?;
    Ok(ServiceEventGuide::new(ServiceEventGuideParams {
        event,
        title: Label::new("title", text.title)?,
        description: Text::new("description", text.description)?,
        filters,
        outputs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENED: EventText = EventText {
        key: "issue-opened",
        title: "An issue is opened",
        description: "Someone opens an issue in the repository.",
        filters: &[FilterText {
            name: "repository",
            need: InputNeed::Required,
            meaning: "The repository, as owner/name.",
        }],
        outputs: &[("issue.number", "The issue's number.")],
    };

    /// An event described as text becomes its spec and a guide explaining
    /// exactly its filters.
    #[test]
    fn an_event_text_makes_its_spec_and_guide() {
        let key = IntegrationKey::new("github").unwrap();

        let described = described_events(&[&OPENED], &key).unwrap();

        assert_eq!(described.specs[0].event().as_str(), "issue-opened");
        assert!(
            described.guides[0]
                .ensure_explains(&described.specs[0])
                .is_ok()
        );
    }

    /// Only the values the event describes reach the workflow, at their
    /// paths; the rest of what the service sent stays behind.
    #[test]
    fn only_the_described_values_are_picked() {
        let payload = serde_json::json!({
            "issue": { "number": 7, "body": "secret notes" },
            "sender": { "login": "mallory" }
        });

        let input = picked(&OPENED, &payload).unwrap();

        assert_eq!(
            input
                .at(&DataPath::parse("issue.number").unwrap())
                .map(FlowData::value),
            Some(ianua_domain::domains::workflows::data::FlowValue::Number(
                7.0
            ))
        );
        assert!(input.at(&DataPath::parse("issue.body").unwrap()).is_none());
        assert!(input.at(&DataPath::parse("sender").unwrap()).is_none());
    }

    /// A described value the service left out reads as null.
    #[test]
    fn a_missing_value_is_null() {
        let input = picked(&OPENED, &serde_json::json!({})).unwrap();

        assert!(
            input
                .at(&DataPath::parse("issue.number").unwrap())
                .is_some_and(FlowData::is_null)
        );
    }
}
