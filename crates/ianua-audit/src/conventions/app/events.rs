//! Events are raised by the domain, never built by the app. An aggregate
//! records what happened when it changes, and a use case saves it and
//! dispatches what it raised. Three ways of building an event fail the
//! build:
//!
//! - **An event written out**: a struct literal of a type the domain
//!   declares as an event, such as `TopicPaused { .. }`.
//! - **An event builder**: a function named `*_event` or `*_events` that
//!   returns a `DomainEvent`.
//! - **A wrapped literal**: `DomainEvent::tenant(Box::new(..))` and its
//!   organization and platform siblings around a struct literal.
//!
//! The check covers every file the app builds, with no exceptions.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprStruct, Item, ItemFn, ReturnType};

use crate::conventions::app::source::{Findings, SourceFile, built_files, line_of};

/// The macros the domain declares its events with.
const EVENT_MACROS: [&str; 3] = [
    "tenant_event! {",
    "organization_event! {",
    "platform_event! {",
];

/// The constructors that wrap an event body into a `DomainEvent`.
const WRAPPERS: [&str; 3] = ["tenant", "organization", "platform"];

/// Every event the domain declares, by its type name.
fn domain_events() -> BTreeSet<String> {
    let root = crate::conventions::crate_dir("ianua-app").join("../ianua-domain/src");
    let mut events = BTreeSet::new();
    collect_events(&root, &mut events);
    events
}

fn collect_events(dir: &Path, events: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for path in entries.flatten().map(|entry| entry.path()) {
        if path.is_dir() {
            collect_events(&path, events);
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        events.extend(declared_events(&text));
    }
}

/// The events `text` declares: the name after each event macro opener.
fn declared_events(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    lines
        .windows(2)
        .filter(|pair| EVENT_MACROS.contains(&pair[0]))
        .filter_map(|pair| pair[1].split_once(" =>"))
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// The last name of a path, such as `TopicPaused` for `events::TopicPaused`.
fn last_name(path: &syn::Path) -> Option<String> {
    path.segments
        .last()
        .map(|segment| segment.ident.to_string())
}

/// The struct literals of domain events in one file.
struct Literals<'a> {
    events: &'a BTreeSet<String>,
    found: Vec<(usize, String)>,
}

impl<'ast> Visit<'ast> for Literals<'_> {
    fn visit_expr_struct(&mut self, literal: &'ast ExprStruct) {
        if let Some(name) = last_name(&literal.path).filter(|name| self.events.contains(name)) {
            self.found.push((line_of(literal), name));
        }
        visit::visit_expr_struct(self, literal);
    }
}

/// The structs `file` declares itself. A use case's own answer may share an
/// event's name, as the start of a factor's setup does, and building it is
/// no event.
fn own_structs(file: &SourceFile) -> BTreeSet<String> {
    file.items()
        .iter()
        .filter_map(|item| match item {
            Item::Struct(declared) => Some(declared.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// Events written out as struct literals.
fn event_literals(files: &[SourceFile], events: &BTreeSet<String>) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let own = own_structs(file);
        let mut literals = Literals {
            events,
            found: Vec::new(),
        };
        file.items()
            .iter()
            .for_each(|item| literals.visit_item(item));
        for (line, name) in literals
            .found
            .into_iter()
            .filter(|(_, name)| !own.contains(name))
        {
            findings.flag_line(
                file,
                line,
                format!("builds `{name}`; let the aggregate raise it"),
            );
        }
    }
    findings
}

/// Functions named for the event they build that return a `DomainEvent`.
struct Builders {
    found: Vec<(usize, String)>,
}

impl<'ast> Visit<'ast> for Builders {
    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        let name = function.sig.ident.to_string();
        let named_for_an_event = name.ends_with("_event") || name.ends_with("_events");
        if named_for_an_event && returns_a_domain_event(&function.sig.output) {
            self.found.push((line_of(&function.sig), name));
        }
        visit::visit_item_fn(self, function);
    }
}

fn returns_a_domain_event(output: &ReturnType) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let mut names = NamesDomainEvent(false);
    names.visit_type(ty);
    names.0
}

/// Whether a type names `DomainEvent` anywhere in it, as `Vec<DomainEvent>`
/// does.
struct NamesDomainEvent(bool);

impl<'ast> Visit<'ast> for NamesDomainEvent {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.0 |= ident == "DomainEvent";
    }
}

/// Functions that build an event for the app to dispatch.
fn event_builders(files: &[SourceFile], _: &BTreeSet<String>) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let mut builders = Builders { found: Vec::new() };
        file.items()
            .iter()
            .for_each(|item| builders.visit_item(item));
        for (line, name) in builders.found {
            findings.flag_line(
                file,
                line,
                format!("`{name}` builds an event; take what the aggregate raised"),
            );
        }
    }
    findings
}

/// `DomainEvent::tenant(Box::new(<literal>))` and its siblings.
struct Wrapped {
    found: Vec<usize>,
}

impl<'ast> Visit<'ast> for Wrapped {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if wraps_a_literal(call) {
            self.found.push(line_of(call));
        }
        visit::visit_expr_call(self, call);
    }
}

fn wraps_a_literal(call: &ExprCall) -> bool {
    let Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    let names: Vec<String> = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let wraps = matches!(names.as_slice(), [.., owner, wrapper]
        if owner == "DomainEvent" && WRAPPERS.contains(&wrapper.as_str()));
    wraps && call.args.first().is_some_and(boxes_a_literal)
}

fn boxes_a_literal(arg: &Expr) -> bool {
    let Expr::Call(boxed) = arg else {
        return false;
    };
    matches!(boxed.args.first(), Some(Expr::Struct(_)))
}

/// Event literals wrapped into a `DomainEvent` by hand.
fn wrapped_literals(files: &[SourceFile], _: &BTreeSet<String>) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let mut wrapped = Wrapped { found: Vec::new() };
        file.items()
            .iter()
            .for_each(|item| wrapped.visit_item(item));
        for line in wrapped.found {
            findings.flag_line(
                file,
                line,
                "wraps an event it built; take what the aggregate raised",
            );
        }
    }
    findings
}

/// A check over files, given the domain's events.
type EventCheck = fn(&[SourceFile], &BTreeSet<String>) -> Findings;

const CHECKS: [(&str, EventCheck); 3] = [
    ("event literal", event_literals),
    ("event builder", event_builders),
    ("wrapped literal", wrapped_literals),
];

#[cfg_attr(test, test)]
pub(crate) fn the_app_builds_no_event_of_its_own() {
    let events = domain_events();
    let files = built_files();
    for (rule, check) in CHECKS {
        check(&files, &events).assert_none(rule);
    }
}

/// The domain's events are read through every macro that declares one, so
/// a check that compares against them is not comparing against nothing.
#[cfg_attr(test, test)]
pub(crate) fn every_event_macro_is_read() {
    let events = domain_events();

    for known in [
        "WebhookSubscriptionCreated",
        "TopicPaused",
        "CloudConnectionStarted",
        "OperatorCreated",
    ] {
        assert!(events.contains(known), "{known} was not read");
    }
}

/// Each check, run over a file that builds an event each way, finds it.
#[cfg_attr(test, test)]
pub(crate) fn every_event_check_finds_its_planted_break() {
    let files = [SourceFile::planted("use_cases/planted.rs", PLANTED)];
    let events = BTreeSet::from(["PlantedHappened".to_owned()]);

    let missed: Vec<&str> = CHECKS
        .iter()
        .filter(|(_, check)| check(&files, &events).is_empty())
        .map(|(name, _)| *name)
        .collect();

    assert!(
        missed.is_empty(),
        "event checks that missed their planted break: {missed:?}"
    );
}

/// A file building an event every way the checks look for.
const PLANTED: &str = r"
fn planted_event(topic: &Topic) -> DomainEvent {
    DomainEvent::tenant(Box::new(PlantedHappened { topic_id: *topic.id() }))
}
";
