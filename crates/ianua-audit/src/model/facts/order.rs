//! What a use case's flow says of the order of its steps, for its card:
//! each plan limit against each create, and saves against dispatches.

use std::collections::BTreeSet;

use super::flow::{
    Answer, Flow, Step, StepPicks, creates, holds, inside_one_unit, is_store_write, kept_unchecked,
    owed, reaches_without, succeeds_without,
};
use super::{OrderFact, UseCaseFacts};
use crate::source::Place;

/// The order lines for `facts`, read from `flow`, whose body ends at `end`.
pub(super) fn lines(facts: &UseCaseFacts, flow: &Flow, end: &Place) -> Vec<OrderFact> {
    let mut found = limit_lines(facts, flow, end);
    found.extend(record_lines(facts, flow, end));
    found
}

fn limit_lines(facts: &UseCaseFacts, flow: &Flow, end: &Place) -> Vec<OrderFact> {
    let kinds: BTreeSet<&str> = facts
        .limits
        .iter()
        .map(|limit| limit.kind.as_str())
        .collect();
    let creations: BTreeSet<(&str, &str)> = facts
        .changes
        .iter()
        .filter(|change| change.kind == "create")
        .map(|change| (change.owner.as_str(), change.name.as_str()))
        .collect();
    let mut found = Vec::new();
    for kind in &kinds {
        for (owner, name) in &creations {
            found.push(limit_line(flow, end, Created { kind, owner, name }));
        }
    }
    found
}

/// A creation a plan limit may guard: the limit's kind, and the owner and
/// name of what creates.
#[derive(Clone, Copy)]
struct Created<'c> {
    kind: &'c str,
    owner: &'c str,
    name: &'c str,
}

/// Whether `flow`, ending at `end`, checks the limit before `created`
/// makes and keeps its value.
fn limit_line(flow: &Flow, end: &Place, created: Created<'_>) -> OrderFact {
    let Created { kind, owner, name } = created;
    let checked = |step: &Step| matches!(step, Step::Limit { kind: checked } if checked == kind);
    let made = |step: &Step| creates(step, owner, name);
    let before = reaches_without(flow, checked, made, end);
    let picks = StepPicks {
        checked,
        made,
        kept: is_store_write,
    };
    limit_order(created, before, kept_unchecked(flow, picks, end))
}

/// What `before`, whether the limit is checked before `created` makes its
/// value, and `kept`, whether it is kept unchecked, say together.
fn limit_order(created: Created<'_>, before: Answer, kept: Answer) -> OrderFact {
    let Created { kind, owner, name } = created;
    let (what, place) = match (before, kept) {
        (Answer::No, _) => (
            format!("{kind} limit checked before {owner}::{name} on every path"),
            None,
        ),
        (_, Answer::No) => (
            format!(
                "{kind} limit checked on every path before what {owner}::{name} makes is stored"
            ),
            None,
        ),
        (_, Answer::Yes(places)) => (
            format!(
                "a path calls {owner}::{name} and stores it or succeeds without the {kind} limit check"
            ),
            places.into_iter().next(),
        ),
        (_, Answer::Unknown(unread)) => (
            format!(
                "whether the {kind} limit is checked before what {owner}::{name} makes is stored is not known: a path passes a point the flow does not follow, {}",
                unread.what
            ),
            Some(unread.place),
        ),
    };
    OrderFact { what, place }
}

/// What `unanswered`, whether a path saves what a change raised and
/// succeeds without dispatching it, says.
fn dispatch_line(unanswered: Answer) -> OrderFact {
    match unanswered {
        Answer::Yes(places) => OrderFact {
            what: "a path saves what a change raised and hands back Ok without dispatching"
                .to_owned(),
            place: places.into_iter().next(),
        },
        Answer::No => OrderFact {
            what: "every path that saves what a change raised and succeeds dispatches".to_owned(),
            place: None,
        },
        Answer::Unknown(unread) => OrderFact {
            what: format!(
                "whether every path that saves what a change raised dispatches is not known: a path passes a point the flow does not follow, {}",
                unread.what
            ),
            place: Some(unread.place),
        },
    }
}

fn record_lines(facts: &UseCaseFacts, flow: &Flow, end: &Place) -> Vec<OrderFact> {
    let dispatches = |step: &Step| matches!(step, Step::Dispatch);
    if !holds(flow, &is_store_write) {
        return Vec::new();
    }
    let mut found = vec![dispatch_line(succeeds_without(flow, owed(facts), end))];
    if !holds(flow, &dispatches) {
        return found;
    }
    if reaches_without(flow, is_store_write, dispatches, end) == Answer::No {
        found.push(OrderFact {
            what: "save before dispatch on every path".to_owned(),
            place: None,
        });
    }
    if let Some((name, place, Answer::Yes(_))) = inside_one_unit(flow, &is_store_write, &dispatches)
    {
        found.push(OrderFact {
            what: format!("save and dispatch inside one unit ({name})"),
            place: Some(place),
        });
    }
    found
}
