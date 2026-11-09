//! A use case's facts: its `execute` and the helpers it calls, read and
//! joined with what the domain says of the changes it calls.

use std::collections::{BTreeMap, BTreeSet};

use syn::{Attribute, ImplItem, Item, ItemImpl};

use super::body::{self, HelperCall, HelperSelf, Local, PortRef, Seen, SeenAt, Source};
use super::change::events_of;
use super::flow::{self, BodyFlow, Flow, FnKey, HelperAt};
use super::known::Known;
use super::scope::{FnRef, functions_of};
use super::{
    Call, ChangeCall, Dispatch, DocumentedError, EventFact, FOLLOW_DEPTH, LimitCheck, NotRead,
    PortUse, ServiceFacts, UseCaseFacts, order,
};
use crate::model::app::{PortLookup, UseCase};
use crate::model::domain::BehaviourKind;
use crate::model::paths::AppItem;
use crate::model::raising::{RightFound, chained};
use crate::source::syntax::{
    doc_lines, impl_fns, implemented_trait, items_of, names_in_type, type_name, type_text,
};
use crate::source::{Layer, Place, SourceFile};

/// What was not read of `use_case`, said by `what`.
fn not_read_at(use_case: &UseCase, what: &str) -> NotRead {
    NotRead {
        what: what.to_owned(),
        place: use_case.place.clone(),
    }
}

/// The facts of `use_case`.
pub(super) fn read(known: &Known<'_>, use_case: &UseCase) -> UseCaseFacts {
    let file = &known.workspace.files[use_case.file_index];
    let mut facts = bare(use_case);
    let Some(block) = use_case_impl(file, &use_case.name, use_case.kind.as_str()) else {
        let what = "the use case's `impl`: its file does not parse";
        facts.not_read.push(not_read_at(use_case, what));
        return facts;
    };
    facts.caller = associated(block, "Caller");
    facts.input = associated(block, "Input");
    facts.output = associated(block, "Output");
    let Some(execute) = impl_fns(block).find(|function| function.sig.ident == "execute") else {
        let what = "`execute`: the `impl` does not write it";
        facts.not_read.push(not_read_at(use_case, what));
        return facts;
    };
    facts.documented_errors = documented_errors(&execute.attrs);
    let fields = self_fields(known, file, &use_case.name);
    let start = FnRef::of_impl(file, Some(&use_case.name), execute);
    let held = Held {
        ports: use_case.ports_struct.as_ref(),
        fields: &fields,
    };
    let end = Place::of(file, &execute.sig.ident);
    let (found, flow) = traced(known, start, &fields);
    join(known, &mut facts, &held, found);
    facts.order = order::lines(&facts, &flow, &end);
    facts.flow = flow;
    facts.end = end;
    facts
}

/// What a use case holds: its `*Ports` struct and what its own fields are.
struct Held<'h> {
    ports: Option<&'h AppItem>,
    fields: &'h BTreeMap<String, Local>,
}

/// What each function of the app's `services/` calls on ports and on the
/// domain.
pub(super) fn read_services(known: &Known<'_>) -> Vec<ServiceFacts> {
    let none = BTreeMap::new();
    known
        .workspace
        .layer(Layer::App)
        .filter(|file| file.path.starts_with("services/"))
        .flat_map(functions_of)
        .filter_map(|function| {
            let read = body::read(known, &function, &none, &[]);
            service_facts(&function, &read.seen)
        })
        .collect()
}

fn service_facts(function: &FnRef<'_>, seen: &[SeenAt]) -> Option<ServiceFacts> {
    let port_calls: Vec<(AppItem, String, Place)> = seen
        .iter()
        .filter_map(|found| match &found.seen {
            Seen::PortCall { port, method, .. } => {
                Some((port.port.clone()?, method.clone(), found.place.clone()))
            }
            _ => None,
        })
        .collect();
    let changes: Vec<(String, String, Place)> = seen
        .iter()
        .filter_map(|found| match &found.seen {
            Seen::Change { owner, name, .. } => {
                Some((owner.clone(), name.clone(), found.place.clone()))
            }
            _ => None,
        })
        .collect();
    if port_calls.is_empty() && changes.is_empty() {
        return None;
    }
    Some(ServiceFacts {
        function: function.label(),
        place: Place::of(function.file, &function.sig.ident),
        port_calls,
        changes,
    })
}

fn bare(use_case: &UseCase) -> UseCaseFacts {
    UseCaseFacts {
        name: use_case.name.clone(),
        kind: use_case.kind.as_str(),
        context: use_case.context.clone(),
        place: use_case.place.clone(),
        caller: None,
        input: None,
        output: None,
        ports_struct: use_case.ports_struct.as_ref().map(|item| item.name.clone()),
        ports: Vec::new(),
        changes: Vec::new(),
        rights: Vec::new(),
        limits: Vec::new(),
        dispatches: Vec::new(),
        documented_errors: Vec::new(),
        written_errors: Vec::new(),
        not_read: Vec::new(),
        order: Vec::new(),
        flow: Flow::Nothing,
        end: use_case.place.clone(),
    }
}

/// The `impl Command for name` or `impl Query for name` block in `file`.
fn use_case_impl<'f>(file: &'f SourceFile, name: &str, kind: &str) -> Option<&'f ItemImpl> {
    items_of(file.syntax()?)
        .into_iter()
        .find_map(|item| match item {
            Item::Impl(block)
                if type_name(&block.self_ty).as_deref() == Some(name)
                    && implemented_trait(block)
                        .is_some_and(|found| found.eq_ignore_ascii_case(kind)) =>
            {
                Some(block)
            }
            _ => None,
        })
}

/// The type `type <name> = ..;` of `block` as written.
fn associated(block: &ItemImpl, name: &str) -> Option<String> {
    block.items.iter().find_map(|item| match item {
        ImplItem::Type(declared) if declared.ident == name => type_text(&declared.ty),
        _ => None,
    })
}

/// What the fields of the struct `name` in `file` hold: a `*Ports` struct,
/// a port, or a value of a type the reader knows. A field of any other
/// type is left out, so a call on it is not read.
fn self_fields(known: &Known<'_>, file: &SourceFile, name: &str) -> BTreeMap<String, Local> {
    let Some(syntax) = file.syntax() else {
        return BTreeMap::new();
    };
    let declared = items_of(syntax).into_iter().find_map(|item| match item {
        Item::Struct(declared) if declared.ident == name => Some(declared),
        _ => None,
    });
    let mut fields: BTreeMap<String, Local> = declared
        .into_iter()
        .flat_map(|declared| declared.fields.iter())
        .filter_map(|field| {
            let field_name = field.ident.as_ref()?.to_string();
            let held = field_local(known, file, &field_name, &field.ty)?;
            Some((field_name, held))
        })
        .collect();
    let typed = known
        .app_type(name)
        .map(|(_, typed)| typed)
        .unwrap_or_default();
    let known_here = |held: &Local| match held {
        Local::Type(type_name) => known.knows_type(type_name),
        _ => true,
    };
    for (field_name, held) in typed.into_iter().filter(|(_, held)| known_here(held)) {
        fields.entry(field_name).or_insert(held);
    }
    fields
}

fn field_local(known: &Known<'_>, file: &SourceFile, field: &str, ty: &syn::Type) -> Option<Local> {
    let names = names_in_type(ty);
    if let Some(ports) = names.iter().find_map(|name| known.ports_item(file, name)) {
        return Some(Local::Ports {
            item: ports,
            prefix: String::new(),
        });
    }
    let lookup = known.port_in_type(file, ty);
    (lookup != PortLookup::NotAPort)
        .then(|| Local::Port(PortRef::held(Some(field.to_owned()), &lookup)))
}

/// A fact with the helpers it was found through.
struct Traced {
    seen: SeenAt,
    via: Option<String>,
}

/// One function to read, and how it was reached.
struct Step<'a> {
    function: FnRef<'a>,
    args: Vec<Option<Local>>,
    via: Option<String>,
    depth: usize,
    fields: BTreeMap<String, Local>,
}

/// Every fact of `start` and of the helpers it calls, at most
/// [`FOLLOW_DEPTH`] calls away, each helper read once, with the flow they
/// make together.
fn traced<'a>(
    known: &Known<'a>,
    start: FnRef<'a>,
    fields: &BTreeMap<String, Local>,
) -> (Vec<Traced>, Flow) {
    let start_key = start.key();
    let mut tracer = Tracer {
        known,
        visited: BTreeSet::from([start.key()]),
        found: Vec::new(),
        bodies: BTreeMap::new(),
    };
    let mut queue = vec![Step {
        function: start,
        args: Vec::new(),
        via: None,
        depth: 0,
        fields: fields.clone(),
    }];
    while let Some(step) = queue.pop() {
        queue.extend(tracer.read(&step));
    }
    let flow = flow::join(&tracer.bodies, &start_key);
    (tracer.found, flow)
}

/// What tracing a use case has gathered: the helpers read so far, their
/// facts, and each body's flow.
struct Tracer<'k, 'a> {
    known: &'k Known<'a>,
    visited: BTreeSet<(String, Option<String>, String)>,
    found: Vec<Traced>,
    bodies: BTreeMap<FnKey, BodyFlow>,
}

impl<'a> Tracer<'_, 'a> {
    /// Reads the body `step` names, keeping its facts and flow, and hands
    /// back the steps that read the helpers it calls.
    fn read(&mut self, step: &Step<'a>) -> Vec<Step<'a>> {
        let read = body::read(self.known, &step.function, &step.fields, &step.args);
        let helpers = read
            .helpers
            .iter()
            .map(|helper| HelperAt {
                key: helper.target.key(),
                too_deep: step.depth == FOLLOW_DEPTH,
                label: label_of(helper),
                place: helper.place.clone(),
                values: helper.values.clone(),
                futures: helper.futures.clone(),
            })
            .collect();
        self.bodies.insert(
            step.function.key(),
            BodyFlow {
                shape: read.shape,
                seen: read.seen.clone(),
                helpers,
                params: body::param_names(step.function.sig),
            },
        );
        self.found.extend(read.seen.into_iter().map(|seen| Traced {
            seen,
            via: step.via.clone(),
        }));
        (read.helpers.into_iter())
            .filter_map(|helper| self.next_step(step, helper))
            .collect()
    }

    /// The step that reads `helper`, called from `step`: none when it was
    /// read already, or when it is too deep, which is noted.
    fn next_step(&mut self, step: &Step<'a>, helper: HelperCall<'a>) -> Option<Step<'a>> {
        let label = label_of(&helper);
        let fields = match &helper.receiver {
            HelperSelf::Own => step.fields.clone(),
            HelperSelf::Ports { item, prefix } => self.known.fields_of_ports(item, prefix),
            HelperSelf::Holder(fields) => fields.clone(),
            HelperSelf::Free => BTreeMap::new(),
        };
        if step.depth == FOLLOW_DEPTH {
            self.found.push(Traced {
                seen: SeenAt {
                    seen: Seen::Unfollowed { name: label },
                    place: helper.place,
                },
                via: step.via.clone(),
            });
            return None;
        }
        if !self.visited.insert(helper.target.key()) {
            return None;
        }
        Some(Step {
            via: Some(chained(step.via.as_deref(), &label)),
            depth: step.depth + 1,
            fields,
            function: helper.target,
            args: helper.args,
        })
    }
}

/// The name `via` shows `helper` under: a method of the use case or of its
/// `*Ports` struct by its name, anything else with its type.
fn label_of(helper: &HelperCall<'_>) -> String {
    match helper.receiver {
        HelperSelf::Own | HelperSelf::Ports { .. } => helper.target.name.clone(),
        HelperSelf::Holder(_) | HelperSelf::Free => helper.target.label(),
    }
}

/// Joins the traced facts into `facts`.
fn join(known: &Known<'_>, facts: &mut UseCaseFacts, held: &Held<'_>, mut traced: Vec<Traced>) {
    traced.sort_by(|a, b| a.seen.place.cmp(&b.seen.place));
    facts.ports = port_uses(known, held, &traced);
    facts.changes = change_calls(known, &traced);
    facts.rights = rights(known, &traced);
    facts.limits = limits(&traced);
    facts.dispatches = dispatches(known, &facts.changes, &traced);
    facts.written_errors = written_errors(&traced);
    facts.not_read.extend(not_read(&traced));
    if facts.ports_struct.is_none() {
        facts.not_read.push(NotRead {
            what: "its ports: it holds no `*Ports` struct the audit found".to_owned(),
            place: facts.place.clone(),
        });
    }
}

fn port_uses(known: &Known<'_>, held: &Held<'_>, traced: &[Traced]) -> Vec<PortUse> {
    let mut uses = declared_ports(known, held);
    for (port, call) in traced.iter().filter_map(port_call) {
        let field = port.field.clone().or_else(|| only_field(&uses, port));
        add_call(&mut uses, field, port, call);
    }
    uses
}

/// The ports the use case's `*Ports` struct and its own fields hold.
fn declared_ports(known: &Known<'_>, held: &Held<'_>) -> Vec<PortUse> {
    let from_struct = held
        .ports
        .map(|item| known.ports_fields(item))
        .unwrap_or_default()
        .into_iter()
        .map(|field| PortUse {
            field: Some(field.path),
            trait_name: field.port.name().map(str::to_owned),
            port: field.port.found().cloned(),
            written: field.written,
            calls: Vec::new(),
        });
    let own = held.fields.values().filter_map(|local| match local {
        Local::Port(port) => Some(PortUse {
            field: port.field.clone(),
            trait_name: port.trait_name.clone(),
            port: port.port.clone(),
            written: None,
            calls: Vec::new(),
        }),
        _ => None,
    });
    from_struct.chain(own).collect()
}

fn port_call(traced: &Traced) -> Option<(&PortRef, Call)> {
    let Seen::PortCall { port, method, .. } = &traced.seen.seen else {
        return None;
    };
    Some((
        port,
        Call {
            name: method.clone(),
            place: traced.seen.place.clone(),
            via: traced.via.clone(),
        },
    ))
}

/// The one field holding the port `port` is, when exactly one does.
fn only_field(uses: &[PortUse], port: &PortRef) -> Option<String> {
    let holding: Vec<&PortUse> = uses
        .iter()
        .filter(|found| found.field.is_some() && holds(found, port))
        .collect();
    match holding.as_slice() {
        [only] => only.field.clone(),
        _ => None,
    }
}

/// Whether `found` holds the port `port`: the same trait, when the reader
/// placed both, or the same name, when it placed neither.
fn holds(found: &PortUse, port: &PortRef) -> bool {
    found.port == port.port && found.trait_name == port.trait_name
}

fn add_call(uses: &mut Vec<PortUse>, field: Option<String>, port: &PortRef, call: Call) {
    let existing = uses.iter_mut().find(|found| match &field {
        Some(_) => found.field == field,
        None => found.field.is_none() && holds(found, port),
    });
    match existing {
        Some(found) => found.calls.push(call),
        None => uses.push(PortUse {
            field,
            trait_name: port.trait_name.clone(),
            port: port.port.clone(),
            written: None,
            calls: vec![call],
        }),
    }
}

fn change_calls(known: &Known<'_>, traced: &[Traced]) -> Vec<ChangeCall> {
    let mut seen = BTreeSet::new();
    traced
        .iter()
        .filter_map(|found| match &found.seen.seen {
            Seen::Change { owner, name, .. } => Some((owner, name, found)),
            _ => None,
        })
        .filter(|(owner, name, found)| {
            seen.insert(((*owner).clone(), (*name).clone(), found.via.clone()))
        })
        .map(|(owner, name, found)| ChangeCall {
            kind: known
                .behaviour(owner, name)
                .map_or("change", BehaviourKind::as_str),
            takes: known.proofs_taken(owner, name),
            rights: known.raising().rights_of(Some(owner), name).to_vec(),
            events: events_of(known, Some(owner), name),
            owner: owner.clone(),
            name: name.clone(),
            place: found.seen.place.clone(),
            via: found.via.clone(),
        })
        .collect()
}

fn rights(known: &Known<'_>, traced: &[Traced]) -> Vec<RightFound> {
    let found: BTreeSet<RightFound> = traced
        .iter()
        .filter_map(|found| match &found.seen.seen {
            Seen::Right(check) => Some(known.raising().resolve(
                check,
                &found.seen.place,
                found.via.as_deref(),
            )),
            _ => None,
        })
        .flatten()
        .collect();
    found.into_iter().collect()
}

fn limits(traced: &[Traced]) -> Vec<LimitCheck> {
    traced
        .iter()
        .filter_map(|found| match &found.seen.seen {
            Seen::Limit { kind, call } => Some(LimitCheck {
                kind: kind.clone(),
                call: call.clone(),
                place: found.seen.place.clone(),
                via: found.via.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn dispatches(known: &Known<'_>, changes: &[ChangeCall], traced: &[Traced]) -> Vec<Dispatch> {
    traced
        .iter()
        .filter_map(|found| match &found.seen.seen {
            Seen::Dispatch { method, sources } => Some(Dispatch {
                method: method.clone(),
                place: found.seen.place.clone(),
                via: found.via.clone(),
                events: dispatched_events(known, changes, sources),
                not_read: unread_sources(changes, sources),
            }),
            _ => None,
        })
        .collect()
}

/// The events `sources` hand over: those the changes of each value's type
/// this use case calls raise, and those each observation builds.
fn dispatched_events(
    known: &Known<'_>,
    changes: &[ChangeCall],
    sources: &[Source],
) -> Vec<EventFact> {
    let events: BTreeSet<EventFact> = sources
        .iter()
        .flat_map(|source| match source {
            Source::Taken {
                type_name: Some(owner),
                ..
            } => raised_on(changes, owner),
            Source::Taken {
                type_name: None, ..
            } => Vec::new(),
            Source::Observed { owner, name } => events_of(known, Some(owner), name),
        })
        .collect();
    events.into_iter().collect()
}

fn raised_on(changes: &[ChangeCall], owner: &str) -> Vec<EventFact> {
    changes
        .iter()
        .filter(|change| change.owner == owner)
        .flat_map(|change| change.events.iter().cloned())
        .collect()
}

/// What of `sources` the reader could not turn into events.
fn unread_sources(changes: &[ChangeCall], sources: &[Source]) -> Vec<String> {
    if sources.is_empty() {
        return vec![
            "the events it is handed: not taken from a value the reader followed".to_owned(),
        ];
    }
    sources
        .iter()
        .filter_map(|source| match source {
            Source::Taken {
                type_name: Some(owner),
                receiver,
            } => raised_on(changes, owner).is_empty().then(|| {
                format!(
                    "`{receiver}.take_events()`: no change of `{owner}` raising an event is read in this use case"
                )
            }),
            Source::Taken {
                type_name: None,
                receiver,
            } => Some(format!(
                "`{receiver}.take_events()`: the type of `{receiver}` was not read"
            )),
            Source::Observed { .. } => None,
        })
        .collect()
}

fn written_errors(traced: &[Traced]) -> Vec<String> {
    let written: BTreeSet<String> = traced
        .iter()
        .filter_map(|found| match &found.seen.seen {
            Seen::Error(variant) => Some(variant.clone()),
            _ => None,
        })
        .collect();
    written.into_iter().collect()
}

fn not_read(traced: &[Traced]) -> Vec<NotRead> {
    traced
        .iter()
        .filter_map(|found| {
            let what = found.seen.seen.unread_what()?;
            let what = match &found.via {
                Some(via) => format!("{what} (via {via})"),
                None => what,
            };
            Some(NotRead {
                what,
                place: found.seen.place.clone(),
            })
        })
        .collect()
}

/// The `AppError` variants a `# Errors` section names, each with the entry
/// it is named in.
fn documented_errors(attributes: &[Attribute]) -> Vec<DocumentedError> {
    let lines = doc_lines(attributes);
    let section = lines
        .iter()
        .skip_while(|line| line.trim() != "# Errors")
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('#'));
    entries(section)
        .into_iter()
        .flat_map(|entry| {
            variants_in(&entry)
                .into_iter()
                .map(move |variant| DocumentedError {
                    variant,
                    text: entry.clone(),
                })
        })
        .collect()
}

/// The entries of a doc section: each `- ` item with the lines after it,
/// or each paragraph line run when there are no items.
fn entries<'l>(lines: impl Iterator<Item = &'l String>) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in lines
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
    {
        if let Some(start) = line.strip_prefix("- ").or_else(|| line.strip_prefix("* ")) {
            found.push(start.to_owned());
            continue;
        }
        match found.last_mut() {
            Some(open) => {
                open.push(' ');
                open.push_str(line);
            }
            None => found.push(line.to_owned()),
        }
    }
    found
}

/// Every `AppError::Variant` written in `text`, once each.
fn variants_in(text: &str) -> Vec<String> {
    let prefix = "AppError::";
    let found: BTreeSet<String> = text
        .match_indices(prefix)
        .map(|(at, _)| {
            text[at + prefix.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .filter(|variant| variant.starts_with(|c: char| c.is_ascii_uppercase()))
        .collect();
    found.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_error_item_is_read_with_the_lines_that_carry_it_on() {
        let item: syn::ItemFn = syn::parse_str(
            "/// Does it.
             ///
             /// # Errors
             ///
             /// - `AppError::Forbidden` when the caller may not, or
             ///   `AppError::NotFound` when it is gone.
             /// - `AppError::Internal` on storage failure.
             ///
             /// # Panics
             ///
             /// - `AppError::Never` is not an error section.
             fn execute() {}",
        )
        .unwrap();

        let found: Vec<(String, String)> = documented_errors(&item.attrs)
            .into_iter()
            .map(|error| (error.variant, error.text))
            .collect();

        let first = "`AppError::Forbidden` when the caller may not, or `AppError::NotFound` when it is gone.";
        assert_eq!(
            found,
            [
                ("Forbidden".to_owned(), first.to_owned()),
                ("NotFound".to_owned(), first.to_owned()),
                (
                    "Internal".to_owned(),
                    "`AppError::Internal` on storage failure.".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn a_section_without_items_is_one_entry() {
        let item: syn::ItemFn = syn::parse_str(
            "/// # Errors
             ///
             /// `AppError::Internal` when no secret can be made.
             fn execute() {}",
        )
        .unwrap();

        let found = documented_errors(&item.attrs);

        assert_eq!(found[0].variant, "Internal");
    }
}
