//! The domain's rules as text for a terminal, as a Starlight page for the
//! docs, or as JSON.
//!
//! The page is `docs/src/content/docs/reference/rules.mdx`, written by
//! `rules --markdown`. It leaves out any rule that speaks of plans, which
//! the public docs do not cover.

use std::fmt::Write as _;

use crate::model::rules::Rules;
use crate::model::rules::decisions::{Decision, Reading, Row};
use crate::model::rules::moves::MachineCard;
use crate::model::rules::refusals::Refusals;
use crate::report::{Paint, Style};
use crate::source::Place;

/// What every page starts with.
const FRONT: &str = "---
title: Domain rules
description: The decisions the domain makes, its status machines and what each change refuses, read from the code.
sidebar:
  order: 2
---

This page is written by `ianua-audit rules --markdown` from the domain's code, and a test fails when it falls behind. Do not edit it by hand.

Each table says what the code says, with the file and line it says it in. A row marked **not read** rests on code the reader could not work out; read the code there.

- **Decisions** are the domain's functions whose answer is chosen by a `match` over enums. One whose inputs are all enums is worked out for every combination, and **any** means the answer is the same whatever that input is. One that decides on values it works out itself is shown arm by arm, as written.
- **Status machines** list the states, the moves the machine allows, the states no move leaves, and the changes that move a value into each state, with the use cases that call them and the right each takes.
- **Refusals** list, for each change, what leads it to refuse and with which error.
";

/// The rules as text.
pub(crate) fn render_text(rules: &Rules, style: Style) -> String {
    let mut out = String::new();
    for decision in &rules.decisions {
        out.push_str(&decision_text(decision, style));
    }
    for card in &rules.machines {
        out.push_str(&machine_text(card, style));
    }
    for found in &rules.refusals {
        out.push_str(&refusals_text(found, style));
    }
    if out.is_empty() {
        out.push_str("no rules read\n");
    }
    out
}

fn decision_text(decision: &Decision, style: Style) -> String {
    let how = match decision.reading {
        Reading::WorkedOut => "worked out",
        Reading::Arms => "arm by arm",
    };
    let mut out = format!(
        "\n{}  {}  {}  ({how})\n",
        style.paint("decision", Paint::Heading),
        decision.subject,
        style.paint(&location(&decision.place), Paint::Dim)
    );
    if let Some(summary) = &decision.summary {
        let _ = writeln!(out, "  {summary}");
    }
    for input in &decision.inputs {
        if let Some(defined) = &input.defined {
            let _ = writeln!(out, "  where {} = {defined}", input.name);
        }
    }
    out.push_str(&decision_table(decision));
    out
}

/// The rows of `decision` as a table: one column for each input, then
/// the answer and where it is given.
fn decision_table(decision: &Decision) -> String {
    let mut header: Vec<String> = (decision.inputs.iter())
        .map(|input| input.name.clone())
        .collect();
    header.push(format!("-> {}", decision.outcome));
    let rows: Vec<Vec<String>> = (decision.rows.iter())
        .map(|row| {
            let mut cells: Vec<String> = row.when.iter().map(cell_value).collect();
            cells.push(outcome_text(row));
            cells.push(row.place.as_ref().map(location).unwrap_or_default());
            cells
        })
        .collect();
    columns(&header, &rows)
}

fn cell_value(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "any".to_owned())
}

fn outcome_text(row: &Row) -> String {
    let outcome = row.outcome.clone().unwrap_or_else(|| "not read".to_owned());
    match &row.guard {
        Some(guard) => format!("{outcome} (if {guard})"),
        None => outcome,
    }
}

/// `rows` under `header`, each column as wide as its widest cell.
fn columns(header: &[String], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(String::len).collect();
    for row in rows {
        for (at, cell) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(at) {
                *width = (*width).max(cell.len());
            }
        }
    }
    let line = |cells: &[String]| {
        let padded: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(at, cell)| {
                format!(
                    "{cell:<width$}",
                    width = widths.get(at).copied().unwrap_or(0)
                )
            })
            .collect();
        format!("  {}\n", padded.join("  ").trim_end())
    };
    let mut out = line(header);
    for row in rows {
        out.push_str(&line(row));
    }
    out
}

/// A machine's `moves`, as `from -> to` joined, or why they were not read.
fn moves_listed(moves: Option<&[(String, String)]>) -> String {
    let Some(moves) = moves else {
        return "not read: its try_transition is in a shape the reader does not work out"
            .to_owned();
    };
    let shown: Vec<String> = (moves.iter())
        .map(|(from, to)| format!("{from} -> {to}"))
        .collect();
    shown.join(", ")
}

fn machine_text(card: &MachineCard, style: Style) -> String {
    let mut out = format!(
        "\n{}  {}  {}\n",
        style.paint("machine", Paint::Heading),
        card.machine,
        style.paint(&location(&card.place), Paint::Dim)
    );
    let _ = writeln!(out, "  states  {}", card.states.join(", "));
    let _ = writeln!(out, "  moves   {}", moves_listed(card.moves.as_deref()));
    let _ = writeln!(out, "  final   {}", or_none(&card.finals));
    for mover in &card.movers {
        let _ = writeln!(
            out,
            "  into {}  {}{}, called by {}  {}",
            mover.to,
            mover.change,
            mover_rights(&mover.proofs, &mover.rights),
            or_none(&mover.callers),
            style.paint(&location(&mover.place), Paint::Dim)
        );
    }
    out
}

fn mover_rights(proofs: &[String], rights: &[String]) -> String {
    let mut parts = Vec::new();
    if !proofs.is_empty() {
        parts.push(format!("proof {}", proofs.join(", ")));
    }
    if !rights.is_empty() {
        parts.push(format!("right {}", rights.join(", ")));
    }
    match parts.is_empty() {
        true => String::new(),
        false => format!(" ({})", parts.join("; ")),
    }
}

fn refusals_text(found: &Refusals, style: Style) -> String {
    let mut out = format!(
        "\n{}  {}  {}\n",
        style.paint("refusals", Paint::Heading),
        found.change,
        style.paint(&location(&found.place), Paint::Dim)
    );
    for refusal in &found.refusals {
        let via = refusal
            .via
            .as_ref()
            .map_or_else(String::new, |via| format!(" (via {via})"));
        let _ = writeln!(
            out,
            "  when {}: {}{via}  {}",
            when_text(&refusal.when),
            refusal.error,
            style.paint(&location(&refusal.place), Paint::Dim)
        );
    }
    out
}

fn when_text(when: &[String]) -> String {
    match when.is_empty() {
        true => "always".to_owned(),
        false => when.join(" and "),
    }
}

fn or_none(items: &[String]) -> String {
    match items.is_empty() {
        true => "none".to_owned(),
        false => items.join(", "),
    }
}

fn location(place: &Place) -> String {
    format!("{}:{}", place.file, place.line)
}

/// The rules as JSON.
///
/// # Errors
///
/// Fails only if serialising fails, which these plain types do not.
pub(crate) fn render_json(rules: &Rules) -> serde_json::Result<String> {
    serde_json::to_string_pretty(rules)
}

/// The rules as the docs page, those that speak of plans left out.
pub(crate) fn render_page(rules: &Rules) -> String {
    let mut out = FRONT.to_owned();
    for context in rules.contexts() {
        let section = context_section(rules, context);
        if section.is_empty() {
            continue;
        }
        let _ = write!(out, "\n## {}\n{section}", title_of(context));
    }
    out
}

fn context_section(rules: &Rules, context: &str) -> String {
    let decisions = pages(
        &rules.decisions,
        |found| found.context == context,
        decision_page,
    );
    let machines = pages(
        &rules.machines,
        |card| card.context == context,
        machine_page,
    );
    let refusals = pages(
        &rules.refusals,
        |found| found.context == context,
        refusals_page,
    );
    let mut out = String::new();
    for (title, parts) in [
        ("Decisions", decisions),
        ("Status machines", machines),
        ("Refusals", refusals),
    ] {
        if parts.is_empty() {
            continue;
        }
        let _ = write!(out, "\n### {title}\n{}", parts.concat());
    }
    out
}

fn decision_page(decision: &Decision) -> String {
    let mut out = format!(
        "\n#### `{}`\n\n{}",
        decision.subject,
        decision
            .summary
            .as_ref()
            .map_or_else(String::new, |summary| format!("{}\n\n", text(summary)))
    );
    let how = match decision.reading {
        Reading::WorkedOut => "Worked out for every combination of its inputs",
        Reading::Arms => "Its last `match`, arm by arm, as written",
    };
    let _ = writeln!(out, "{how}, at {}.\n", short(&decision.place));
    for input in &decision.inputs {
        if let Some(defined) = &input.defined {
            let _ = writeln!(out, "- `{}` is `{}`", input.name, defined);
        }
    }
    if decision.inputs.iter().any(|input| input.defined.is_some()) {
        out.push('\n');
    }
    out.push_str(&decision_page_table(decision));
    out
}

/// The rows of `decision` as a page's table: its inputs, then the answer
/// and where it is given.
fn decision_page_table(decision: &Decision) -> String {
    let mut header: Vec<String> = (decision.inputs.iter())
        .map(|input| format!("`{}`", input.name))
        .collect();
    header.push(format!("Answer (`{}`)", decision.outcome));
    header.push("Where".to_owned());
    let shown = |value: &Option<String>| {
        (value.as_ref()).map_or_else(|| "any".to_owned(), |value| format!("`{value}`"))
    };
    let rows: Vec<Vec<String>> = (decision.rows.iter())
        .map(|row| {
            let mut cells: Vec<String> = row.when.iter().map(shown).collect();
            cells.push(page_outcome(row));
            cells.push(row.place.as_ref().map(short).unwrap_or_default());
            cells
        })
        .collect();
    table(&header, &rows)
}

/// The pages of the `items` `in_context` keeps, each written by `page`,
/// leaving out any that mentions plans.
fn pages<T>(
    items: &[T],
    in_context: impl Fn(&T) -> bool,
    page: impl Fn(&T) -> String,
) -> Vec<String> {
    (items.iter())
        .filter(|item| in_context(item))
        .map(page)
        .filter(|text| !mentions_plans(text))
        .collect()
}

fn page_outcome(row: &Row) -> String {
    let outcome = row.outcome.as_ref().map_or_else(
        || "**not read**".to_owned(),
        |outcome| format!("`{outcome}`"),
    );
    match &row.guard {
        Some(guard) => format!("{outcome} when `{guard}`"),
        None => outcome,
    }
}

fn machine_page(card: &MachineCard) -> String {
    let mut out = format!("\n#### `{}`\n\n", card.machine);
    let _ = writeln!(
        out,
        "Its moves are read from `try_transition`, at {}.\n",
        short(&card.place)
    );
    let _ = writeln!(out, "- States: {}", code_list(&card.states));
    let _ = writeln!(
        out,
        "- Final, which no move leaves: {}",
        code_list(&card.finals)
    );
    let Some(moves) = &card.moves else {
        out.push_str("- Moves: **not read**, its `try_transition` is in a shape the reader does not work out\n");
        return out;
    };
    out.push('\n');
    let header = ["Move", "Made by", "Called by", "Proof or right"].map(str::to_owned);
    let rows: Vec<Vec<String>> = (moves.iter())
        .map(|(from, to)| move_row(card, from, to))
        .collect();
    out.push_str(&table(&header, &rows));
    out
}

/// The table row of the move from `from` to `to` of `card`: the changes
/// that make it, the use cases that call them, and the proofs or rights.
fn move_row(card: &MachineCard, from: &str, to: &str) -> Vec<String> {
    let into: Vec<_> = card.movers.iter().filter(|mover| mover.to == to).collect();
    let made: Vec<String> = (into.iter())
        .map(|mover| format!("`{}`", mover.change))
        .collect();
    let callers: Vec<String> = (into.iter())
        .flat_map(|mover| mover.callers.clone())
        .collect();
    let rights: Vec<String> = (into.iter())
        .flat_map(|mover| mover.proofs.iter().chain(&mover.rights))
        .map(|right| format!("`{right}`"))
        .collect();
    vec![
        format!("`{from}` to `{to}`"),
        listed(&made),
        listed(&unique(callers)),
        listed(&unique(rights)),
    ]
}

fn refusals_page(found: &Refusals) -> String {
    let mut out = format!("\n#### `{}`\n\n", found.change);
    let header = ["When", "Refused with", "Where"].map(str::to_owned);
    let rows: Vec<Vec<String>> = found
        .refusals
        .iter()
        .map(|refusal| {
            let via = refusal
                .via
                .as_ref()
                .map_or_else(String::new, |via| format!(", through `{via}`"));
            vec![
                when_text(&refusal.when),
                refusal.error.clone(),
                format!("{}{via}", short(&refusal.place)),
            ]
        })
        .collect();
    out.push_str(&table(&header, &rows));
    out
}

fn listed(items: &[String]) -> String {
    match items.is_empty() {
        true => "none read".to_owned(),
        false => items.join(", "),
    }
}

fn unique(items: Vec<String>) -> Vec<String> {
    let mut seen = Vec::new();
    for item in items {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

fn code_list(items: &[String]) -> String {
    match items.is_empty() {
        true => "none".to_owned(),
        false => items
            .iter()
            .map(|item| format!("`{item}`"))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// A Markdown table, each cell made safe for MDX.
fn table(header: &[String], rows: &[Vec<String>]) -> String {
    let line = |cells: &[String]| {
        let safe: Vec<String> = cells.iter().map(|cell| text(cell)).collect();
        format!("| {} |\n", safe.join(" | "))
    };
    let mut out = line(header);
    out.push_str(&format!("|{}\n", " --- |".repeat(header.len())));
    for row in rows {
        out.push_str(&line(row));
    }
    out
}

/// `raw` made safe for MDX: a `|` escaped everywhere, and outside code
/// spans the characters MDX reads as code (`{`, `}`, `<`, `>`) written as
/// entities.
fn text(raw: &str) -> String {
    let mut out = String::new();
    for (at, part) in raw.split('`').enumerate() {
        if at > 0 {
            out.push('`');
        }
        let in_code = at % 2 == 1;
        for character in part.chars() {
            match (character, in_code) {
                ('|', _) => out.push_str("\\|"),
                ('{', false) => out.push_str("&#123;"),
                ('}', false) => out.push_str("&#125;"),
                ('<', false) => out.push_str("&lt;"),
                ('>', false) => out.push_str("&gt;"),
                (other, _) => out.push(other),
            }
        }
    }
    out
}

/// A place in the domain as the page shows it: the path below the domain's
/// `src/`.
fn short(place: &Place) -> String {
    let path = place
        .file
        .strip_prefix("crates/ianua-domain/src/")
        .unwrap_or(&place.file);
    format!("`{path}:{}`", place.line)
}

/// A context's folder name as a heading: `access_control` as `Access
/// control`.
fn title_of(context: &str) -> String {
    let spaced = context.replace('_', " ");
    let mut characters = spaced.chars();
    characters.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(characters).collect()
    })
}

/// Whether `text` speaks of plans, which the public docs leave out.
fn mentions_plans(text: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric() && c != '\'')
        .any(|word| {
            let lower = word.to_lowercase();
            matches!(lower.as_str(), "plan" | "plans" | "plan's")
                || lower.ends_with("plan")
                || matches!(word, "Free" | "Starter" | "Business")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::rules::decisions::Input;

    fn place(line: usize) -> Place {
        Place {
            file: "crates/ianua-domain/src/domains/authentication/mfa/owed.rs".to_owned(),
            line,
        }
    }

    /// A row owing a mailed confirmation where mail is available, and one
    /// whose answer was not worked out.
    fn owed_rows() -> Vec<Row> {
        vec![
            Row {
                when: vec![Some("Available".to_owned())],
                outcome: Some("ConfirmByEmail".to_owned()),
                guard: None,
                place: Some(place(200)),
            },
            Row {
                when: vec![None],
                outcome: None,
                guard: None,
                place: None,
            },
        ]
    }

    fn rules() -> Rules {
        Rules {
            decisions: vec![Decision {
                subject: "SecondFactor::under".to_owned(),
                context: "authentication".to_owned(),
                place: place(173),
                summary: Some("What a sign-in owes.".to_owned()),
                inputs: vec![Input {
                    name: "mail".to_owned(),
                    ty: "MailReach".to_owned(),
                    values: vec!["Available".to_owned(), "NotSetUp".to_owned()],
                    defined: None,
                }],
                outcome: "SecondFactor".to_owned(),
                outcome_values: vec!["Verify".to_owned(), "ConfirmByEmail".to_owned()],
                reading: Reading::WorkedOut,
                rows: owed_rows(),
            }],
            machines: Vec::new(),
            refusals: Vec::new(),
        }
    }

    #[test]
    fn the_page_shows_a_rule_as_a_table_with_any_and_not_read() {
        let page = render_page(&rules());

        assert!(page.starts_with("---\ntitle: Domain rules\n"));
        assert!(page.contains("\n## Authentication\n"));
        assert!(page.contains("| `mail` | Answer (`SecondFactor`) | Where |\n"));
        assert!(page.contains(
            "| `Available` | `ConfirmByEmail` | `domains/authentication/mfa/owed.rs:200` |\n"
        ));
        assert!(page.contains("| any | **not read** |  |\n"));
    }

    #[test]
    fn text_is_made_safe_for_mdx_outside_code() {
        assert_eq!(
            text("`a | b` when {x} < y"),
            "`a \\| b` when &#123;x&#125; &lt; y"
        );
    }

    #[test]
    fn a_rule_speaking_of_plans_is_left_off_the_page() {
        let mut rules = rules();
        rules.decisions[0].summary = Some("Whether the plan has room.".to_owned());

        let page = render_page(&rules);

        assert!(!page.contains("SecondFactor::under"));
    }

    #[test]
    fn the_text_lists_a_rule_with_its_columns() {
        let text = render_text(&rules(), Style::new(false));

        assert!(text.contains("decision  SecondFactor::under"));
        assert!(text.contains("  mail       -> SecondFactor\n"));
        assert!(text.contains("  any        not read"));
    }
}
