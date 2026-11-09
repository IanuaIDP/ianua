//! Each domain creator's and change's facts: the proofs it takes, the
//! rights it checks, the events it raises, and the use cases that call it.

use super::known::Known;
use super::{CallerRef, ChangeFacts, EventFact, UseCaseFacts};
use crate::model::Model;

/// The facts of every public creator and change of the domain's
/// aggregates, with the callers found among `use_cases`.
pub(super) fn read_all(known: &Known<'_>, use_cases: &[UseCaseFacts]) -> Vec<ChangeFacts> {
    known
        .model
        .domain
        .behaviours
        .iter()
        .map(|behaviour| ChangeFacts {
            owner: behaviour.owner.clone(),
            name: behaviour.name.clone(),
            kind: behaviour.kind.as_str(),
            context: context_of(known.model, &behaviour.owner),
            place: behaviour.place.clone(),
            takes: known.proofs_taken(&behaviour.owner, &behaviour.name),
            rights: known
                .raising()
                .rights_of(Some(&behaviour.owner), &behaviour.name)
                .to_vec(),
            events: events_of(known, Some(&behaviour.owner), &behaviour.name),
            callers: callers(use_cases, &behaviour.owner, &behaviour.name),
        })
        .collect()
}

/// The events the domain function `name` of `owner` raises.
pub(super) fn events_of(known: &Known<'_>, owner: Option<&str>, name: &str) -> Vec<EventFact> {
    known
        .raising()
        .raised_by(owner, name)
        .into_iter()
        .map(|event| event_fact(known.model, event))
        .collect()
}

/// The event `name`, with the dotted type it is recorded under.
fn event_fact(model: &Model, name: &str) -> EventFact {
    let event_type = model
        .domain
        .events
        .iter()
        .find(|event| event.name == name)
        .and_then(|event| event.event_type.as_ref())
        .and_then(|(enum_name, variant)| {
            model
                .domain
                .event_types
                .iter()
                .find(|listed| listed.enum_name == *enum_name && listed.variant == *variant)
        })
        .map(|listed| listed.text.clone());
    EventFact {
        name: name.to_owned(),
        event_type,
    }
}

fn context_of(model: &Model, owner: &str) -> String {
    model
        .domain
        .aggregates
        .iter()
        .find(|aggregate| aggregate.name == owner)
        .map_or_else(
            || "kernel".to_owned(),
            |aggregate| aggregate.context.clone(),
        )
}

fn callers(use_cases: &[UseCaseFacts], owner: &str, name: &str) -> Vec<CallerRef> {
    use_cases
        .iter()
        .flat_map(|use_case| {
            use_case
                .changes
                .iter()
                .filter(|change| change.owner == owner && change.name == name)
                .map(|change| CallerRef {
                    use_case: use_case.name.clone(),
                    context: use_case.context.clone(),
                    place: change.place.clone(),
                    via: change.via.clone(),
                })
        })
        .collect()
}
