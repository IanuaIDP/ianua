//! `explain`: short cards that say what a use case, a context's use cases,
//! a domain type or one of its changes does, each fact read from the code.
//! A fact the reader could not read is printed as not read.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::Serialize;

use crate::model::facts::{ChangeCall, ChangeFacts, EventFact, Facts, UseCaseFacts};
use crate::model::raising::RightFound;
use crate::report::{Paint, Style};
use crate::source::Place;

/// What every card leaves out, said under the cards.
const LIMITS_NOTE: &str = "Read from the code: what is called and checked; only the order line follows paths and branches.";

/// How many close names an unknown name's message offers.
const SUGGESTIONS: usize = 8;

/// What a name given to `explain` stands for.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum Explained<'f> {
    /// One use case, or every use case of a context.
    UseCases {
        /// The use cases.
        use_cases: Vec<&'f UseCaseFacts>,
    },
    /// A domain type's creators and changes, or one of them.
    Changes {
        /// The type.
        owner: String,
        /// The creators and changes.
        changes: Vec<&'f ChangeFacts>,
        /// Whether the name was the type, rather than one change of it.
        #[serde(skip)]
        whole_type: bool,
    },
}

/// What `name` stands for: a use case (`CreateUseCase`,
/// `webhooks::CreateUseCase`, or a path to its file), a context folder, a
/// domain type, or one of its creators or changes (`Type::name`).
///
/// # Errors
///
/// A message saying why, when `name` names nothing or more than one use
/// case.
pub(crate) fn find<'f>(facts: &'f Facts, name: &str) -> Result<Explained<'f>, String> {
    if let Some((head, tail)) = name.split_once("::") {
        return qualified(facts, name, head, tail);
    }
    if name.contains('/') {
        return by_path(facts, name);
    }
    named_use_cases(facts, name)
        .or_else(|| context_use_cases(facts, name))
        .or_else(|| type_changes(facts, name))
        .unwrap_or_else(|| Err(unknown(facts, name)))
}

fn qualified<'f>(
    facts: &'f Facts,
    name: &str,
    head: &str,
    tail: &str,
) -> Result<Explained<'f>, String> {
    let use_cases: Vec<&UseCaseFacts> = facts
        .use_cases
        .iter()
        .filter(|found| found.context == head && found.name == tail)
        .collect();
    if !use_cases.is_empty() {
        return one_of(name, use_cases);
    }
    let changes: Vec<&ChangeFacts> = facts
        .changes
        .iter()
        .filter(|found| found.owner == head && found.name == tail)
        .collect();
    if changes.is_empty() {
        return Err(unknown(facts, name));
    }
    Ok(Explained::Changes {
        owner: head.to_owned(),
        changes,
        whole_type: false,
    })
}

fn by_path<'f>(facts: &'f Facts, name: &str) -> Result<Explained<'f>, String> {
    let use_cases: Vec<&UseCaseFacts> = facts
        .use_cases
        .iter()
        .filter(|found| found.place.file.ends_with(name))
        .collect();
    if use_cases.is_empty() {
        return Err(unknown(facts, name));
    }
    Ok(Explained::UseCases { use_cases })
}

fn named_use_cases<'f>(facts: &'f Facts, name: &str) -> Option<Result<Explained<'f>, String>> {
    let use_cases: Vec<&UseCaseFacts> = facts
        .use_cases
        .iter()
        .filter(|found| found.name == name)
        .collect();
    (!use_cases.is_empty()).then(|| one_of(name, use_cases))
}

/// The one use case of `use_cases`, or why `name` is ambiguous.
fn one_of<'f>(name: &str, use_cases: Vec<&'f UseCaseFacts>) -> Result<Explained<'f>, String> {
    if use_cases.len() == 1 {
        return Ok(Explained::UseCases { use_cases });
    }
    Err(ambiguous(name, &use_cases))
}

/// Why `name`, which names each of `use_cases`, is not enough, with what
/// to say instead.
pub(crate) fn ambiguous(name: &str, use_cases: &[&UseCaseFacts]) -> String {
    let choices: Vec<String> = use_cases
        .iter()
        .map(|found| {
            format!(
                "  {}::{}  {}",
                found.context,
                found.name,
                location(&found.place)
            )
        })
        .collect();
    format!(
        "`{name}` names {} use cases; say which with `context::Name`, or a path ending in its file when two share a context:\n{}",
        use_cases.len(),
        choices.join("\n")
    )
}

fn context_use_cases<'f>(facts: &'f Facts, name: &str) -> Option<Result<Explained<'f>, String>> {
    let use_cases: Vec<&UseCaseFacts> = facts
        .use_cases
        .iter()
        .filter(|found| found.context == name)
        .collect();
    (!use_cases.is_empty()).then_some(Ok(Explained::UseCases { use_cases }))
}

fn type_changes<'f>(facts: &'f Facts, name: &str) -> Option<Result<Explained<'f>, String>> {
    let changes: Vec<&ChangeFacts> = facts
        .changes
        .iter()
        .filter(|found| found.owner == name)
        .collect();
    (!changes.is_empty()).then(|| {
        Ok(Explained::Changes {
            owner: name.to_owned(),
            changes,
            whole_type: true,
        })
    })
}

/// Why `name` names nothing, with the known names that contain it.
fn unknown(facts: &Facts, name: &str) -> String {
    let wanted = name.to_lowercase();
    let known: BTreeSet<String> = facts
        .use_cases
        .iter()
        .flat_map(|found| [found.name.clone(), found.context.clone()])
        .chain(
            facts
                .changes
                .iter()
                .flat_map(|found| [found.owner.clone(), found.subject()]),
        )
        .filter(|candidate| candidate.to_lowercase().contains(&wanted))
        .collect();
    let close: Vec<String> = known.into_iter().take(SUGGESTIONS).collect();
    match close.as_slice() {
        [] => format!("no use case, context, domain type or change named `{name}`"),
        _ => format!(
            "no use case, context, domain type or change named `{name}`; close names: {}",
            close.join(", ")
        ),
    }
}

/// One card: a heading and labelled rows.
struct Card {
    title: String,
    about: String,
    place: Place,
    rows: Vec<Row>,
}

/// One labelled row of a card.
struct Row {
    label: &'static str,
    items: Vec<Item>,
}

/// One entry of a row.
struct Item {
    text: String,
    detail: Option<String>,
    place: Option<Place>,
    missing: bool,
}

impl Item {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            detail: None,
            place: None,
            missing: false,
        }
    }

    fn at(text: impl Into<String>, place: &Place) -> Self {
        Self {
            place: Some(place.clone()),
            ..Self::plain(text)
        }
    }

    fn missing(text: impl Into<String>, place: Option<&Place>) -> Self {
        Self {
            missing: true,
            place: place.cloned(),
            ..Self::plain(text)
        }
    }

    fn written(text: Option<&str>) -> Self {
        match text {
            Some(text) => Self::plain(text),
            None => Self::missing("not read", None),
        }
    }
}

fn row(label: &'static str, items: Vec<Item>) -> Row {
    Row { label, items }
}

/// `items`, or one plain item saying `none` when there are none.
fn or_none(items: Vec<Item>, none: &str) -> Vec<Item> {
    match items.is_empty() {
        true => vec![Item::plain(none)],
        false => items,
    }
}

fn cards(explained: &Explained<'_>) -> Vec<Card> {
    match explained {
        Explained::UseCases { use_cases } => {
            use_cases.iter().map(|found| use_case_card(found)).collect()
        }
        Explained::Changes { changes, .. } => {
            changes.iter().map(|found| change_card(found)).collect()
        }
    }
}

/// Whether calls the reader did not follow leave a card open: then no row
/// may say there is nothing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// Every call in the followed bodies was read.
    Whole,
    /// Some were not, listed under "not read".
    Open,
}

/// `items`, or one item saying `none`; when the card is open, saying that
/// it is only as far as read.
fn or_none_read(items: Vec<Item>, none: &str, reading: Reading) -> Vec<Item> {
    if !items.is_empty() {
        return items;
    }
    match reading {
        Reading::Whole => vec![Item::plain(none)],
        Reading::Open => vec![Item::missing(format!("{none} read, see not read"), None)],
    }
}

fn use_case_card(facts: &UseCaseFacts) -> Card {
    let unread = unread_items(facts);
    let reading = match unread.is_empty() {
        true => Reading::Whole,
        false => Reading::Open,
    };
    let changes = or_none_read(change_items(&facts.changes), "no domain change", reading);
    let rights_none = "none outside the changes it calls";
    let rights = or_none_read(right_items(&facts.rights), rights_none, reading);
    let records = or_none_read(dispatch_items(facts), "nothing dispatched", reading);
    Card {
        title: facts.name.clone(),
        about: format!("{} in {}", facts.kind, facts.context),
        place: facts.place.clone(),
        rows: vec![
            row("caller", vec![Item::written(facts.caller.as_deref())]),
            row("input", vec![Item::written(facts.input.as_deref())]),
            row("output", vec![Item::written(facts.output.as_deref())]),
            row("ports", or_none(port_items(facts, reading), "none read")),
            row("changes", changes),
            row("rights", rights),
            row("limits", or_none_read(limit_items(facts), "none", reading)),
            row("records", records),
            row("errors", vec![Item::plain(errors_text(facts))]),
            row("order", order_items(facts)),
            row("not read", or_none(unread, "nothing")),
        ]
        .into_iter()
        .filter(|row| !row.items.is_empty())
        .collect(),
    }
}

/// What the flow says of the order of the use case's steps; none when it
/// says nothing worth a line.
fn order_items(facts: &UseCaseFacts) -> Vec<Item> {
    facts
        .order
        .iter()
        .map(|fact| match &fact.place {
            Some(place) => Item::at(fact.what.clone(), place),
            None => Item::plain(fact.what.clone()),
        })
        .collect()
}

fn port_items(facts: &UseCaseFacts, reading: Reading) -> Vec<Item> {
    facts
        .ports
        .iter()
        .map(|port| {
            let field = port.field.as_deref().unwrap_or("a field not read");
            let port_trait = port
                .trait_name
                .as_deref()
                .or(port.written.as_deref())
                .unwrap_or("a type not read");
            let mut calls: Vec<String> = port
                .calls
                .iter()
                .map(|call| with_via(&call.name, call.via.as_deref()))
                .collect();
            calls.dedup();
            let called = match (calls.is_empty(), reading) {
                (true, Reading::Whole) => "no call read".to_owned(),
                (true, Reading::Open) => "no call read, see not read".to_owned(),
                (false, _) => calls.join(", "),
            };
            let text = format!("{field} ({port_trait}): {called}");
            match port.calls.first() {
                Some(first) => Item::at(text, &first.place),
                None => Item::plain(text),
            }
        })
        .collect()
}

fn change_items(changes: &[ChangeCall]) -> Vec<Item> {
    changes
        .iter()
        .map(|change| Item {
            detail: Some(domain_detail(&change.rights, &change.takes, &change.events)),
            ..Item::at(
                with_via(
                    &format!("{} ({})", change.subject(), change.kind),
                    change.via.as_deref(),
                ),
                &change.place,
            )
        })
        .collect()
}

/// What the domain says a change checks and raises, on one line: the
/// caller proofs it takes, which hold a right by their type, then the
/// rights it checks by a call.
fn domain_detail(rights: &[RightFound], takes: &[String], events: &[EventFact]) -> String {
    let mut texts: Vec<String> = takes
        .iter()
        .map(|proof| format!("proof: {proof}"))
        .collect();
    let mut checked: Vec<String> = rights.iter().map(right_text).collect();
    checked.sort();
    checked.dedup();
    texts.extend(checked);
    let rights = match texts.is_empty() {
        true => "checks no right read".to_owned(),
        false => texts.join(", "),
    };
    let events = match events.is_empty() {
        true => "raises nothing".to_owned(),
        false => format!(
            "raises {}",
            events.iter().map(event_text).collect::<Vec<_>>().join(", ")
        ),
    };
    format!("{rights}; {events}")
}

fn right_items(rights: &[RightFound]) -> Vec<Item> {
    rights
        .iter()
        .map(|right| {
            let text = format!("{} ({})", right_text(right), right.check.call);
            Item::at(with_via(&text, right.via.as_deref()), &right.place)
        })
        .collect()
}

fn right_text(right: &RightFound) -> String {
    format!(
        "{} {}",
        right.check.kind.as_str(),
        right.check.right.as_deref().unwrap_or("a right not read")
    )
}

fn event_text(event: &EventFact) -> String {
    match &event.event_type {
        Some(dotted) => format!("{} ({dotted})", event.name),
        None => event.name.clone(),
    }
}

fn limit_items(facts: &UseCaseFacts) -> Vec<Item> {
    facts
        .limits
        .iter()
        .map(|limit| {
            let text = format!("{}, checked by {}", limit.kind, limit.call);
            Item::at(with_via(&text, limit.via.as_deref()), &limit.place)
        })
        .collect()
}

fn dispatch_items(facts: &UseCaseFacts) -> Vec<Item> {
    facts
        .dispatches
        .iter()
        .map(|dispatch| {
            let by = with_via(&format!("by {}", dispatch.method), dispatch.via.as_deref());
            match dispatch.events.is_empty() {
                true => Item::missing(format!("events not read, {by}"), Some(&dispatch.place)),
                false => Item::at(
                    format!(
                        "{} {by}",
                        dispatch
                            .events
                            .iter()
                            .map(event_text)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    &dispatch.place,
                ),
            }
        })
        .collect()
}

fn errors_text(facts: &UseCaseFacts) -> String {
    let documented: BTreeSet<&str> = facts
        .documented_errors
        .iter()
        .map(|error| error.variant.as_str())
        .collect();
    let listed = |names: Vec<&str>| match names.is_empty() {
        true => "none".to_owned(),
        false => names.join(", "),
    };
    let written: Vec<&str> = facts.written_errors.iter().map(String::as_str).collect();
    format!(
        "documented {}; written {}",
        listed(documented.into_iter().collect()),
        listed(written)
    )
}

fn unread_items(facts: &UseCaseFacts) -> Vec<Item> {
    let dispatched = facts.dispatches.iter().flat_map(|dispatch| {
        dispatch
            .not_read
            .iter()
            .map(|what| Item::missing(what.clone(), Some(&dispatch.place)))
    });
    facts
        .not_read
        .iter()
        .map(|unread| Item::missing(unread.what.clone(), Some(&unread.place)))
        .chain(dispatched)
        .collect()
}

/// The rights a change checks by a call, and those its caller proofs hold
/// by their type.
fn change_rights(facts: &ChangeFacts) -> Vec<Item> {
    let proofs = facts
        .takes
        .iter()
        .map(|proof| Item::plain(format!("proof: {proof}")));
    let items: Vec<Item> = proofs.chain(right_items(&facts.rights)).collect();
    or_none(items, "none read")
}

fn change_card(facts: &ChangeFacts) -> Card {
    Card {
        title: facts.subject(),
        about: format!("{} in {}", facts.kind, facts.context),
        place: facts.place.clone(),
        rows: vec![
            row(
                "takes",
                or_none(
                    facts.takes.iter().map(Item::plain).collect(),
                    "no caller proof",
                ),
            ),
            row("rights", change_rights(facts)),
            row("raises", or_none(event_items(facts), "nothing")),
            row(
                "called by",
                or_none(caller_items(facts), "no use case read"),
            ),
        ],
    }
}

/// The events the change `facts` raises.
fn event_items(facts: &ChangeFacts) -> Vec<Item> {
    (facts.events.iter())
        .map(|event| Item::plain(event_text(event)))
        .collect()
}

/// The use cases that call the change `facts`, and through what.
fn caller_items(facts: &ChangeFacts) -> Vec<Item> {
    (facts.callers.iter())
        .map(|caller| {
            let text = format!("{} ({})", caller.use_case, caller.context);
            Item::at(with_via(&text, caller.via.as_deref()), &caller.place)
        })
        .collect()
}

fn with_via(text: &str, via: Option<&str>) -> String {
    match via {
        Some(via) => format!("{text} via {via}"),
        None => text.to_owned(),
    }
}

fn location(place: &Place) -> String {
    format!("{}:{}", place.file, place.line)
}

/// A heading line for a domain type's cards.
fn type_heading(explained: &Explained<'_>) -> Option<String> {
    let Explained::Changes {
        owner,
        changes,
        whole_type: true,
    } = explained
    else {
        return None;
    };
    Some(format!("{owner}: {} creators and changes", changes.len()))
}

/// The cards as text for a terminal.
pub(crate) fn render_text(explained: &Explained<'_>, style: Style) -> String {
    let mut out = String::new();
    if let Some(heading) = type_heading(explained) {
        let _ = writeln!(out, "{}\n", style.paint(&heading, Paint::Heading));
    }
    for card in cards(explained) {
        out.push_str(&card_text(&card, style));
        out.push('\n');
    }
    let _ = writeln!(out, "{}", style.paint(LIMITS_NOTE, Paint::Dim));
    out
}

fn card_text(card: &Card, style: Style) -> String {
    let mut out = format!(
        "{}  {}  {}\n",
        style.paint(&card.title, Paint::Heading),
        card.about,
        style.paint(&location(&card.place), Paint::Dim)
    );
    for row in &card.rows {
        for (index, item) in row.items.iter().enumerate() {
            let label = match index {
                0 => row.label,
                _ => "",
            };
            let text = match item.missing {
                true => style.paint(&item.text, Paint::Missing),
                false => item.text.clone(),
            };
            let _ = writeln!(
                out,
                "  {} {text}",
                style.paint(&format!("{label:<10}"), Paint::Dim)
            );
            if let Some(detail) = &item.detail {
                let _ = writeln!(out, "  {:<10}   {detail}", "");
            }
        }
    }
    out
}

/// The cards as Markdown, each fact with its `file:line`.
pub(crate) fn render_markdown(explained: &Explained<'_>) -> String {
    let mut out = String::new();
    if let Some(heading) = type_heading(explained) {
        let _ = writeln!(out, "## {heading}\n");
    }
    for card in cards(explained) {
        out.push_str(&card_markdown(&card));
        out.push('\n');
    }
    let _ = writeln!(out, "_{LIMITS_NOTE}_");
    out
}

fn card_markdown(card: &Card) -> String {
    let mut out = format!(
        "### `{}`\n\n{}, `{}`\n\n",
        card.title,
        card.about,
        location(&card.place)
    );
    for row in &card.rows {
        match row.items.as_slice() {
            [only] if only.detail.is_none() => {
                let _ = writeln!(out, "- **{}**: {}", row.label, item_markdown(only));
            }
            items => {
                let _ = writeln!(out, "- **{}**:", row.label);
                for item in items {
                    let _ = writeln!(out, "  - {}", item_markdown(item));
                    if let Some(detail) = &item.detail {
                        let _ = writeln!(out, "    - {detail}");
                    }
                }
            }
        }
    }
    out
}

fn item_markdown(item: &Item) -> String {
    let text = match item.missing {
        true => format!("_{}_", item.text),
        false => item.text.clone(),
    };
    match &item.place {
        Some(place) => format!("{text} (`{}`)", location(place)),
        None => text,
    }
}

/// The facts as pretty JSON.
///
/// # Errors
///
/// Fails only if serialising fails, which these plain types do not.
pub(crate) fn render_json(explained: &Explained<'_>) -> serde_json::Result<String> {
    serde_json::to_string_pretty(explained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::facts::planted::{model, planted};

    fn facts() -> Facts {
        let ws = planted();
        Facts::build(&ws, &model(&ws))
    }

    fn text(name: &str) -> String {
        let found = facts();
        render_text(&find(&found, name).unwrap(), Style::new(false))
    }

    #[test]
    fn a_use_case_card_says_what_it_calls_checks_and_records() {
        let card = text("CreateUseCase");

        assert!(card.starts_with("CreateUseCase  command in webhooks  crates/ianua-app/src/use_cases/webhooks/subscriptions/create.rs:"));
        assert!(card.contains("  caller     CallerContext\n"));
        assert!(card.contains("  ports      webhook_store (WebhookStore): save\n"));
        assert!(card.contains("WebhookSubscription::create (create) via new_subscription"));
        assert!(card.contains("proof: WebhookControl, requires WebhooksAction::Update; raises WebhookSubscriptionCreated (webhooks.subscription_created)"));
        assert!(card.contains("  limits     Webhooks, checked by ensure_room_in_tenant"));
        assert!(card.contains(
            "  records    WebhookSubscriptionCreated (webhooks.subscription_created) by dispatch_by"
        ));
        assert!(card.contains("  errors     documented Forbidden, Internal; written Conflict\n"));
    }

    /// The webhook create checks its limit, then creates, saves and
    /// dispatches, all on one path.
    #[test]
    fn a_use_case_card_says_the_order_of_its_steps() {
        let card = text("CreateUseCase");

        assert!(card.contains(
            "  order      Webhooks limit checked before WebhookSubscription::create on every path\n"
        ));
        assert!(card.contains("             save before dispatch on every path\n"));
    }

    #[test]
    fn a_card_whose_flow_says_nothing_of_order_has_no_order_line() {
        let card = text("ListUseCase");

        assert!(!card.contains("  order "));
    }

    #[test]
    fn what_was_not_read_is_on_the_card() {
        let card = text("ListUseCase");

        assert!(card.contains(
            "  not read   `self.store.all(..)`: the type of that field of `self` was not read\n"
        ));
        assert!(card.contains("its ports: it holds no `*Ports` struct the audit found\n"));
    }

    #[test]
    fn a_context_gives_one_card_per_use_case() {
        let found = facts();

        let Explained::UseCases { use_cases } = find(&found, "webhooks").unwrap() else {
            panic!("use cases");
        };

        assert_eq!(use_cases.len(), 3);
    }

    #[test]
    fn a_change_card_says_its_proof_rights_events_and_callers() {
        let card = text("WebhookSubscription::pause");

        assert!(card.starts_with("WebhookSubscription::pause  change in webhooks"));
        assert!(card.contains("  takes      WebhookControl\n"));
        assert!(card.contains(
            "  rights     proof: WebhookControl\n             requires WebhooksAction::Update (ensure_may)"
        ));
        assert!(
            card.contains(
                "  raises     WebhookSubscriptionPaused (webhooks.subscription_paused)\n"
            )
        );
        assert!(card.contains("  called by  PauseUseCase (webhooks)"));
    }

    /// `RotateUseCase` hands its auditor to calls the reader does not
    /// follow. Its card lists them and says nothing is empty for sure.
    #[test]
    fn a_card_with_calls_not_read_claims_no_nothing() {
        let ws = crate::model::facts::planted::operator();
        let found = Facts::build(&ws, &model(&ws));

        let card = render_text(&find(&found, "RotateUseCase").unwrap(), Style::new(false));

        assert!(card.contains("  records    nothing dispatched read, see not read\n"));
        assert!(card.contains("token_lookup (TokenLookup): no call read, see not read\n"));
        assert!(!card.contains("not read   nothing"));
    }

    /// `RevokeAllOperatorUseCase` dispatches through a method of its
    /// `*Ports` struct, and its creator holds the right by a proof.
    #[test]
    fn the_revoke_all_card_records_through_its_ports_method() {
        let ws = crate::model::facts::planted::operator();
        let found = Facts::build(&ws, &model(&ws));

        let card = render_text(
            &find(&found, "RevokeAllOperatorUseCase").unwrap(),
            Style::new(false),
        );

        assert!(card.contains(
            "  records    OperatorApiKeysRevoked (operator.keys_revoked) by dispatch_by via settle_revocation\n"
        ));
        assert!(card.contains("proof: OperatorAuthority; raises OperatorApiKeysRevoked"));
        assert!(card.contains("  not read   nothing\n"));
    }

    #[test]
    fn a_type_gives_a_heading_and_a_card_per_change() {
        let card = text("WebhookSubscription");

        assert!(card.starts_with("WebhookSubscription: 2 creators and changes\n"));
        assert!(card.contains("WebhookSubscription::create  create in webhooks"));
    }

    #[test]
    fn a_name_two_contexts_share_is_ambiguous_and_lists_both() {
        let mut found = facts();
        let mut other = found.use_cases[0].clone();
        other.context = "messaging".to_owned();
        found.use_cases.push(other);

        let message = find(&found, "CreateUseCase").unwrap_err();

        assert!(message.starts_with("`CreateUseCase` names 2 use cases"));
        assert!(message.contains("  messaging::CreateUseCase  "));
        assert!(find(&found, "messaging::CreateUseCase").is_ok());
    }

    #[test]
    fn an_unknown_name_offers_close_ones() {
        let found = facts();

        let message = find(&found, "Pause").unwrap_err();

        assert_eq!(
            message,
            "no use case, context, domain type or change named `Pause`; close names: PauseUseCase, WebhookSubscription::pause"
        );
    }

    #[test]
    fn markdown_gives_each_fact_its_place() {
        let found = facts();

        let markdown = render_markdown(&find(&found, "PauseUseCase").unwrap());

        assert!(markdown.starts_with("### `PauseUseCase`\n\ncommand in webhooks, `crates/ianua-app/src/use_cases/webhooks/subscriptions/pause.rs:"));
        assert!(markdown.contains("- **ports**: webhook_store (WebhookStore): find_by_id via existing_subscription, save (`crates/ianua-app/src/use_cases/webhooks/lookup.rs:"));
    }

    #[test]
    fn json_carries_the_facts() {
        let found = facts();

        let json = render_json(&find(&found, "PauseUseCase").unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["use_cases"][0]["name"], "PauseUseCase");
        assert_eq!(value["use_cases"][0]["changes"][0]["name"], "pause");
    }
}
