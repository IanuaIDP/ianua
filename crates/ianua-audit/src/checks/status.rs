//! Status machines: changes that move a status out of a state no move
//! leaves.
//!
//! The machines and their final states are read from the domain (see
//! [`crate::model::machines`]). A field of an aggregate holds a status
//! when its type is a machine, or a state enum mapped onto one. A public
//! change of the aggregate, with the functions of the aggregate it calls,
//! writes that field: `self.status = ..` or `mem::replace(&mut
//! self.status, ..)`. The write keeps the machine's word when the change
//! asks the machine (`try_transition`, `can_transition_to`) anywhere on
//! its way. One that does not, and writes a state other than a final one,
//! moves a value that is in that final state out of it.
//!
//! A finding must be true, so these are left unsaid and counted: a write
//! whose new state the reader cannot name, a machine whose moves it could
//! not work out, a state enum variant it could not map, and a change that
//! reads the status anywhere on its way (it may refuse a final state
//! there), hands `self` to something it does not follow, or calls what it
//! cannot find.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::{self, Visit};
use syn::{Expr, FnArg, ImplItemFn, Item, Member};

use crate::finding::{Check, Finding, Found, Unsaid};
use crate::model::Model;
use crate::model::evaluate::{Evaluator, Index, Value};
use crate::model::machines::{Machine, Machines, TRANSITION};
use crate::source::syntax::{for_tests_only, impl_fns, is_public, items_of, type_name};
use crate::source::{Layer, Place, SourceFile, Workspace};

/// Calls that ask the machine whether a move is allowed.
const ASKING: &[&str] = &[TRANSITION, "can_transition_to", "allowed_transitions"];

/// How many of its own functions deep a change is followed.
const CALL_DEPTH: usize = 4;

/// Every status finding.
pub(crate) fn run(workspace: &Workspace, model: &Model) -> Found {
    let files: Vec<&SourceFile> = workspace.layer(Layer::Domain).collect();
    let index = Index::of(&files);
    let evaluator = Evaluator::new(&index);
    let guards = Guards::new(&index, &evaluator);
    let machines = &model.domain.machines;
    let mut found = Found::default();
    for aggregate in &model.domain.aggregates {
        let fields = status_fields(&files, &aggregate.name, machines);
        if fields.is_empty() {
            continue;
        }
        let own = Own::of(&files, &aggregate.name);
        for change in own.public_changes() {
            let walked = walk(&own, change, &fields);
            for write in &walked.writes {
                let judged = Judged {
                    owner: &aggregate.name,
                    change,
                    write,
                    walked: &walked,
                    fields: &fields,
                    machines,
                    guards,
                };
                judge(&judged, &mut found);
            }
        }
    }
    found
}

/// What the guards on a change's way are worked out with.
#[derive(Clone, Copy)]
struct Guards<'g, 'f> {
    index: &'g Index<'f>,
    evaluator: &'g Evaluator<'g, 'f>,
}

impl<'g, 'f> Guards<'g, 'f> {
    /// Guards worked out over `index` by `evaluator`.
    fn new(index: &'g Index<'f>, evaluator: &'g Evaluator<'g, 'f>) -> Self {
        Self { index, evaluator }
    }
}

/// The fields of the struct `owner` holding a status, by name, with their
/// type's name.
fn status_fields(
    files: &[&SourceFile],
    owner: &str,
    machines: &Machines,
) -> BTreeMap<String, String> {
    let declared = files.iter().find_map(|file| {
        items_of(file.syntax()?)
            .into_iter()
            .find_map(|item| match item {
                Item::Struct(declared) if declared.ident == owner => Some(declared),
                _ => None,
            })
    });
    declared
        .into_iter()
        .flat_map(|declared| declared.fields.iter())
        .filter_map(|field| {
            let ty = type_name(&field.ty).filter(|ty| machines.holds_status(ty))?;
            Some((field.ident.as_ref()?.to_string(), ty))
        })
        .collect()
}

/// A function of an aggregate, with its file.
#[derive(Clone, Copy)]
struct OwnFn<'f> {
    file: &'f SourceFile,
    function: &'f ImplItemFn,
    /// Whether it sits in an inherent `impl`.
    inherent: bool,
}

impl OwnFn<'_> {
    fn name(&self) -> String {
        self.function.sig.ident.to_string()
    }

    fn place(&self) -> Place {
        Place::of(self.file, &self.function.sig.ident)
    }

    /// Whether it is a public change: `pub`, taking `&mut self`.
    fn is_public_change(&self) -> bool {
        let takes_mut_self = self.function.sig.inputs.iter().any(|input| {
            matches!(input, FnArg::Receiver(receiver)
                if receiver.reference.is_some() && receiver.mutability.is_some())
        });
        self.inherent
            && takes_mut_self
            && is_public(&self.function.vis)
            && !for_tests_only(&self.function.attrs)
    }

    /// The names of its parameters with their type's name.
    fn params(&self) -> BTreeMap<String, String> {
        self.function
            .sig
            .inputs
            .iter()
            .filter_map(|input| match input {
                FnArg::Typed(typed) => match typed.pat.as_ref() {
                    syn::Pat::Ident(name) => Some((name.ident.to_string(), type_name(&typed.ty)?)),
                    _ => None,
                },
                FnArg::Receiver(_) => None,
            })
            .collect()
    }
}

/// Every function of one aggregate, in every `impl` of it.
struct Own<'f> {
    functions: Vec<OwnFn<'f>>,
}

impl<'f> Own<'f> {
    fn of(files: &[&'f SourceFile], owner: &str) -> Self {
        let mut functions = Vec::new();
        for file in files {
            let Some(syntax) = file.syntax() else {
                continue;
            };
            for item in items_of(syntax) {
                let Item::Impl(block) = item else {
                    continue;
                };
                if type_name(&block.self_ty).as_deref() != Some(owner) {
                    continue;
                }
                functions.extend(impl_fns(block).map(|function| OwnFn {
                    file,
                    function,
                    inherent: block.trait_.is_none(),
                }));
            }
        }
        Self { functions }
    }

    fn public_changes(&self) -> impl Iterator<Item = &OwnFn<'f>> {
        self.functions.iter().filter(|own| own.is_public_change())
    }

    fn named(&self, name: &str) -> Vec<OwnFn<'f>> {
        self.functions
            .iter()
            .filter(|own| own.function.sig.ident == name)
            .copied()
            .collect()
    }
}

/// Where a change on its way may look at the status, and how: it reads it,
/// so a guard may refuse a final state there, or the reader cannot tell,
/// since `self` is handed on or a call is not found. `None` when nothing
/// on its way can.
type Reads = Option<(Place, String)>;

/// One write of a status field.
struct Write<'f> {
    field: String,
    value: &'f Expr,
    place: Place,
    /// The function it is in.
    within: OwnFn<'f>,
    /// The functions between the change and it.
    via: Vec<String>,
}

/// What a change does on its way, its own functions followed.
struct Walked<'f> {
    writes: Vec<Write<'f>>,
    asks: bool,
    reads: Reads,
}

fn walk<'f>(own: &Own<'f>, change: &OwnFn<'f>, fields: &BTreeMap<String, String>) -> Walked<'f> {
    let mut walker = Walker {
        own,
        fields,
        seen: BTreeSet::from([change.place()]),
        walked: Walked {
            writes: Vec::new(),
            asks: false,
            reads: None,
        },
    };
    let mut layer = vec![(*change, Vec::<String>::new())];
    for depth in 0..=CALL_DEPTH {
        layer = (layer.into_iter())
            .flat_map(|(function, via)| walker.read(function, &via, depth))
            .collect();
    }
    walker.walked
}

/// A walk of a change and the aggregate's own functions it calls: the
/// functions, the status fields, the functions reached so far, and what
/// the walk found.
struct Walker<'w, 'f> {
    own: &'w Own<'f>,
    fields: &'w BTreeMap<String, String>,
    seen: BTreeSet<Place>,
    walked: Walked<'f>,
}

impl<'f> Walker<'_, 'f> {
    /// Reads `function`, reached through `via` at `depth`, and hands back
    /// the own functions it calls that the walk has not reached yet.
    fn read(
        &mut self,
        function: OwnFn<'f>,
        via: &[String],
        depth: usize,
    ) -> Vec<(OwnFn<'f>, Vec<String>)> {
        let body = Body::read(function, self.fields);
        self.walked.asks |= body.asks;
        self.walked.reads = self.walked.reads.take().or(body.reads);
        let writes = body.writes.into_iter().map(|(field, value, place)| Write {
            field,
            value,
            place,
            within: function,
            via: via.to_vec(),
        });
        self.walked.writes.extend(writes);
        let mut next = Vec::new();
        for (called, place) in body.calls {
            let targets = self.own.named(&called);
            if targets.is_empty() || depth == CALL_DEPTH {
                let why = format!(
                    "it calls `{called}`, which the reader does not find among the aggregate's own functions or follows no deeper"
                );
                self.walked.reads = self.walked.reads.take().or(Some((place, why)));
                continue;
            }
            let deeper = [via, &[called]].concat();
            let fresh = targets
                .into_iter()
                .filter(|target| self.seen.insert(target.place()));
            next.extend(fresh.map(|target| (target, deeper.clone())));
        }
        next
    }
}

/// What one function body does with the status fields.
struct Body<'b, 'f> {
    fields: &'b BTreeMap<String, String>,
    writes: Vec<(String, &'f Expr, Place)>,
    calls: BTreeMap<String, Place>,
    asks: bool,
    reads: Reads,
    file: &'f SourceFile,
}

impl<'b, 'f> Body<'b, 'f> {
    fn read(function: OwnFn<'f>, fields: &'b BTreeMap<String, String>) -> Self {
        let mut body = Self {
            fields,
            writes: Vec::new(),
            calls: BTreeMap::new(),
            asks: false,
            reads: None,
            file: function.file,
        };
        body.visit_block(&function.function.block);
        body
    }

    /// Notes the first place on its way that may look at the status.
    fn may_read(&mut self, place: Place, why: impl Into<String>) {
        if self.reads.is_none() {
            self.reads = Some((place, why.into()));
        }
    }

    /// Notes a call of the aggregate's own function `name`.
    fn calls_own(&mut self, name: String, place: Place) {
        self.calls.entry(name).or_insert(place);
    }

    /// The status field `expr` is, as `self.field`.
    fn status_field(&self, expr: &Expr) -> Option<String> {
        let Expr::Field(field) = expr else {
            return None;
        };
        self.status_member(field)
    }

    /// The status field `field` names, when it is `self.field`.
    fn status_member(&self, field: &syn::ExprField) -> Option<String> {
        let Member::Named(member) = &field.member else {
            return None;
        };
        let name = member.to_string();
        (is_self(&field.base) && self.fields.contains_key(&name)).then_some(name)
    }

    /// The status field `std::mem::replace(&mut self.field, value)` writes,
    /// with the value.
    fn replaced(&self, call: &'f syn::ExprCall) -> Option<(String, &'f Expr)> {
        let Expr::Path(function) = call.func.as_ref() else {
            return None;
        };
        if function.path.segments.last()?.ident != "replace" {
            return None;
        }
        let [target, value] = call.args.iter().collect::<Vec<_>>()[..] else {
            return None;
        };
        let Expr::Reference(target) = target else {
            return None;
        };
        Some((self.status_field(&target.expr)?, value))
    }

    fn hands_self(&mut self, args: impl IntoIterator<Item = &'f Expr>) {
        if let Some(handed) = args.into_iter().find(|arg| is_self(arg)) {
            let place = Place::of(self.file, handed);
            self.may_read(
                place,
                "it hands `self` to a call the reader does not follow",
            );
        }
    }
}

impl<'f> Visit<'f> for Body<'_, 'f> {
    fn visit_expr_assign(&mut self, assign: &'f syn::ExprAssign) {
        let Some(field) = self.status_field(&assign.left) else {
            visit::visit_expr_assign(self, assign);
            return;
        };
        let place = Place::of(self.file, &assign.left);
        self.writes.push((field, &assign.right, place));
        self.visit_expr(&assign.right);
    }

    fn visit_expr_call(&mut self, call: &'f syn::ExprCall) {
        if let Some((field, value)) = self.replaced(call) {
            self.writes.push((field, value, Place::of(self.file, call)));
            self.visit_expr(value);
            return;
        }
        if let Expr::Path(function) = call.func.as_ref() {
            let names: Vec<String> = function
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            if let [owner, name] = names.as_slice()
                && owner == "Self"
            {
                self.calls_own(name.clone(), Place::of(self.file, call));
            }
        }
        self.hands_self(&call.args);
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'f syn::ExprMethodCall) {
        let name = call.method.to_string();
        self.asks |= ASKING.contains(&name.as_str());
        if is_self(&call.receiver) {
            self.calls_own(name, Place::of(self.file, &call.method));
        }
        self.hands_self(&call.args);
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'f syn::ExprField) {
        if let Some(name) = self.status_member(field) {
            let place = Place::of(self.file, field);
            self.may_read(
                place,
                format!("it reads `self.{name}`, and a guard there may refuse the final state"),
            );
        }
        visit::visit_expr_field(self, field);
    }

    fn visit_macro(&mut self, invoked: &'f syn::Macro) {
        let mut names = Vec::new();
        token_idents(invoked.tokens.clone(), &mut names);
        let names_self = names.iter().any(|name| name == "self");
        let names_status = names.iter().any(|name| self.fields.contains_key(name));
        self.asks |= names.iter().any(|name| ASKING.contains(&name.as_str()));
        let place = Place::of(self.file, &invoked.path);
        match (names_self, names_status) {
            (true, true) => self.may_read(
                place,
                "a macro reads the status, and a guard there may refuse the final state",
            ),
            (true, false) => self.may_read(
                place,
                "a macro is handed `self`, and its calls are not read",
            ),
            (false, _) => {}
        }
    }

    fn visit_item(&mut self, _item: &'f Item) {}
}

/// Every identifier in `stream`, groups included.
fn token_idents(stream: proc_macro2::TokenStream, found: &mut Vec<String>) {
    for tree in stream {
        match tree {
            proc_macro2::TokenTree::Ident(ident) => found.push(ident.to_string()),
            proc_macro2::TokenTree::Group(group) => token_idents(group.stream(), found),
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
        }
    }
}

fn is_self(expr: &Expr) -> bool {
    match expr {
        Expr::Paren(inner) => is_self(&inner.expr),
        Expr::Reference(inner) => is_self(&inner.expr),
        Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => is_self(&unary.expr),
        Expr::Path(path) => path.path.is_ident("self"),
        _ => false,
    }
}

/// The state a write sets.
enum Target {
    /// This variant of the field's type.
    Variant(String),
    /// Whatever the change's caller hands in, by this parameter.
    Handed(String),
}

/// The state `value`, written to a field of type `ty` in `write`, sets.
fn target(value: &Expr, ty: &str, write: &Write<'_>, change: &OwnFn<'_>) -> Option<Target> {
    let path = match value {
        Expr::Path(path) => &path.path,
        Expr::Call(call) => match call.func.as_ref() {
            Expr::Path(path) => &path.path,
            _ => return None,
        },
        Expr::Struct(literal) => &literal.path,
        Expr::Paren(inner) => return target(&inner.expr, ty, write, change),
        _ => return None,
    };
    let names: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    match names.as_slice() {
        [.., owner, variant] if owner == ty => Some(Target::Variant(variant.clone())),
        [name] if write.via.is_empty() => {
            let handed = change.params().get(name).is_some_and(|param| param == ty);
            handed.then(|| Target::Handed(name.clone()))
        }
        _ => None,
    }
}

/// One write, as a change on its way makes it.
struct Judged<'j, 'f> {
    owner: &'j str,
    change: &'j OwnFn<'f>,
    write: &'j Write<'f>,
    walked: &'j Walked<'f>,
    fields: &'j BTreeMap<String, String>,
    machines: &'j Machines,
    guards: Guards<'j, 'f>,
}

/// Reports `judged` when it moves a status out of a final state, counts it
/// when that rests on what was not read, and leaves it otherwise.
fn judge(judged: &Judged<'_, '_>, found: &mut Found) {
    if judged.walked.asks {
        return;
    }
    let reopened = match reopened(judged) {
        Ok(Some(reopened)) => reopened,
        Ok(None) => return,
        Err(unsaid) => {
            found.leave_unsaid(unsaid);
            return;
        }
    };
    let Some((place, why)) = &judged.walked.reads else {
        found.findings.push(finding(judged, &reopened));
        return;
    };
    if let Some(unsaid) = unread_reopening(judged, &reopened, place, why) {
        found.leave_unsaid(unsaid);
    }
}

/// The final states the write of `judged` moves its status out of, when
/// its field is a machine's and any are left; what the reader could not
/// tell, when it could not.
fn reopened<'j>(judged: &Judged<'j, '_>) -> Result<Option<Reopened<'j>>, Unsaid> {
    let typed = judged.fields.get(&judged.write.field);
    let Some((ty, machine)) = typed.and_then(|ty| Some((ty, judged.machines.machine_of(ty)?)))
    else {
        return Ok(None);
    };
    if machine.moves.is_none() {
        let why = format!(
            "the moves of `{}::{TRANSITION}` are written in a shape the reader does not work out",
            machine.name
        );
        return Err(unsaid(judged, machine.place.clone(), why));
    }
    let finals = machine.finals();
    if finals.is_empty() {
        return Ok(None);
    }
    let unnamed = || format!("the `{ty}` it writes is not one the reader can name");
    let (target, lands) = target(judged.write.value, ty, judged.write, judged.change)
        .ok_or_else(unnamed)
        .and_then(|target| landing(judged, machine, ty, target))
        .map_err(|why| unsaid(judged, judged.write.place.clone(), why))?;
    let left: Vec<&(String, Place)> = (finals.into_iter())
        .filter(|(state, _)| lands.as_deref() != Some(state.as_str()))
        .collect();
    Ok((!left.is_empty()).then_some(Reopened {
        machine,
        ty,
        target,
        left,
    }))
}

/// `target`, the value the write sets, with the state of the machine it
/// lands in, when it names one; why not, when the reader cannot tell.
fn landing(
    judged: &Judged<'_, '_>,
    machine: &Machine,
    ty: &str,
    target: Target,
) -> Result<(Target, Option<String>), String> {
    let Target::Variant(variant) = &target else {
        return Ok((target, None));
    };
    match judged.machines.status_of(ty, variant) {
        Some(status) => Ok((target, Some(status))),
        None => Err(format!(
            "the reader could not work out which state of `{}` `{ty}::{variant}` is",
            machine.name
        )),
    }
}

/// A write that moves a status out of final states: the machine, the
/// field's type, the value it sets, and the final states it leaves.
struct Reopened<'r> {
    machine: &'r Machine,
    ty: &'r str,
    target: Target,
    left: Vec<&'r (String, Place)>,
}

/// What is left unsaid of `reopened` when the walk to the write passed
/// what was not read, at `place` for `why`; nothing when a guard before
/// the write refuses every final state it leaves.
fn unread_reopening(
    judged: &Judged<'_, '_>,
    reopened: &Reopened<'_>,
    place: &Place,
    why: &str,
) -> Option<Unsaid> {
    let open: Vec<&String> = (reopened.left.iter())
        .map(|(state, _)| state)
        .filter(|state| !refused(judged, reopened.ty, state))
        .collect();
    if open.is_empty() {
        return None;
    }
    let states = (open.iter())
        .map(|state| format!("`{}::{state}`", reopened.machine.name))
        .collect::<Vec<_>>()
        .join(" or ");
    let why = format!("{why}; no guard before the write was shown to refuse {states}");
    Some(unsaid(judged, place.clone(), why))
}

/// Whether every value of the field's type `ty` that stands for the final
/// state `state` is turned away before the write: by a guard of the change
/// before it calls its way to the write, or by one of the function that
/// writes, before the write.
fn refused(judged: &Judged<'_, '_>, ty: &str, state: &str) -> bool {
    let standing = standing_for(judged, ty, state);
    !standing.is_empty()
        && standing
            .iter()
            .all(|variant| turned_away(judged, Value::variant(ty, variant)))
}

/// The variants of `ty` that stand for the machine's state `state`.
fn standing_for(judged: &Judged<'_, '_>, ty: &str, state: &str) -> Vec<String> {
    let Some(info) = judged.guards.index.enum_named(ty) else {
        return Vec::new();
    };
    info.variants
        .iter()
        .filter(|variant| judged.machines.status_of(ty, &variant.name).as_deref() == Some(state))
        .map(|variant| variant.name.clone())
        .collect()
}

/// Whether an aggregate whose status field holds `held` is turned away
/// before the write.
fn turned_away(judged: &Judged<'_, '_>, held: Value) -> bool {
    let guards = judged.guards;
    let receiver = Value::Record {
        ty: judged.owner.to_owned(),
        fields: BTreeMap::from([(judged.write.field.clone(), held)]),
    };
    let body_of = |function: &OwnFn<'_>| guards.index.method(judged.owner, &function.name());
    let before = match judged.write.via.first() {
        None => Some(judged.write.place.line),
        Some(first) => first_call_line(judged.change, first),
    };
    let in_change = body_of(judged.change)
        .zip(before)
        .is_some_and(|(body, line)| guards.evaluator.turned_away(body, receiver.clone(), line));
    let in_writer = !judged.write.via.is_empty()
        && body_of(&judged.write.within).is_some_and(|body| {
            guards
                .evaluator
                .turned_away(body, receiver, judged.write.place.line)
        });
    in_change || in_writer
}

/// The line `change` first calls its own function `name` on.
fn first_call_line(change: &OwnFn<'_>, name: &str) -> Option<usize> {
    let mut finder = FirstCall { name, line: None };
    finder.visit_block(&change.function.block);
    finder.line
}

/// Finds the first `self.name(..)` or `Self::name(..)` in a body.
struct FirstCall<'n> {
    name: &'n str,
    line: Option<usize>,
}

impl<'f> Visit<'f> for FirstCall<'_> {
    fn visit_expr_method_call(&mut self, call: &'f syn::ExprMethodCall) {
        if self.line.is_none() && call.method == self.name && is_self(&call.receiver) {
            self.line = Some(crate::source::syntax::line_of(&call.method));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'f syn::ExprPath) {
        let named = path.path.segments.len() == 2
            && path.path.segments[0].ident == "Self"
            && path.path.segments[1].ident == self.name;
        if self.line.is_none() && named {
            self.line = Some(crate::source::syntax::line_of(&path.path.segments[1].ident));
        }
        visit::visit_expr_path(self, path);
    }
}

/// A conclusion about `judged` left unsaid, resting on what `why` says at
/// `place`.
fn unsaid(judged: &Judged<'_, '_>, place: Place, why: String) -> Unsaid {
    Unsaid::new(
        Check::ReopenedFinalState,
        format!(
            "{}::{} {}",
            judged.owner,
            judged.change.name(),
            judged.write.field
        ),
        place,
        why,
    )
}

fn finding(judged: &Judged<'_, '_>, reopened: &Reopened<'_>) -> Finding {
    let Reopened {
        machine,
        ty,
        target,
        left,
    } = reopened;
    let change = judged.change.name();
    let field = &judged.write.field;
    let owner = judged.owner;
    let finals: Vec<String> = (left.iter())
        .map(|(state, _)| format!("`{}::{state}`", machine.name))
        .collect();
    let sets = match target {
        Target::Variant(variant) => format!("to `{ty}::{variant}`"),
        Target::Handed(param) => format!("to the `{ty}` its caller hands in as `{param}`"),
    };
    let message = format!(
        "`{owner}::{change}` sets `{field}` {sets} without asking `{}::{TRANSITION}` or reading the status, though {} no move leaves: a `{owner}` there is moved out of it",
        machine.name,
        finals.join(" and ")
    );
    Finding::new(
        Check::ReopenedFinalState,
        judged.write.place.clone(),
        format!("{owner}::{change} {field}"),
        message,
    )
    .with_detail(reopened_detail(judged, reopened))
}

/// Where `judged` writes and changes, the final states `reopened` leaves,
/// and why and how to fix it.
fn reopened_detail(judged: &Judged<'_, '_>, reopened: &Reopened<'_>) -> Vec<String> {
    let machine = reopened.machine;
    let (owner, field, change) = (judged.owner, &judged.write.field, judged.change.name());
    let within = judged.write.within.name();
    let via = match judged.write.via.as_slice() {
        [] => String::new(),
        steps => format!(" (via {})", steps.join(" > ")),
    };
    let mut detail = vec![
        format!(
            "write:  {}  {owner}::{within} sets {field}{via}",
            location(&judged.write.place)
        ),
        format!(
            "change: {}  pub fn {change}(&mut self, ..)",
            location(&judged.change.place())
        ),
    ];
    let (name, declared) = (&machine.name, location(&machine.place));
    detail.extend(reopened.left.iter().map(|(state, place)| {
        let at = location(place);
        format!("final:  {at}  {name}::{state}, which {name}::{TRANSITION} ({declared}) lets nothing leave")
    }));
    detail.push(format!(
        "why: the machine is the one place that says which moves exist; a write around it lets a {owner} that has finished start again, so what its final state promised no longer holds"
    ));
    detail.push(format!(
        "fix: ask the machine before the write, `self.{field} = self.{field}.{TRANSITION}(..)?` or, for a state enum, `self.status().{TRANSITION}(to.status())?`, as the other changes do"
    ));
    detail
}

fn location(place: &Place) -> String {
    format!("{}:{}", place.file, place.line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{domain, workspace};

    const MACHINE: &str = r"
        pub enum ExportStatus { Pending, Ready, Expired }
        impl ExportStatus {
            pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
                checked(self, to, |from, to| {
                    matches!((from, to), (Self::Pending, Self::Ready) | (Self::Ready, Self::Expired))
                })
            }
        }
    ";

    /// An export with `changes` among its functions.
    fn found(changes: &str) -> Found {
        let export = format!(
            "pub struct Export {{ status: ExportStatus, note: Note }}
             impl Export {{
                 pub fn reconstitute(row: ExportRow) -> Result<Self, DomainError> {{ make() }}
                 {changes}
             }}"
        );
        let ws = workspace(vec![
            domain("domains/audit/status.rs", MACHINE),
            domain("domains/audit/export.rs", &export),
        ]);
        run(&ws, &Model::build(&ws, &DomainLists::default()))
    }

    #[test]
    fn a_status_written_around_its_machine_out_of_a_final_state_is_reported() {
        let found = found(
            "pub fn renew(&mut self, by: &AuditControl<'_>) -> Result<(), DomainError> {
                 by.ensure_may(AuditAction::Export)?;
                 self.mark_ready();
                 Ok(())
             }
             fn mark_ready(&mut self) { self.status = ExportStatus::Ready; }",
        );

        let finding = &found.findings[0];
        assert_eq!(finding.subject, "Export::renew status");
        assert_eq!(
            finding.message,
            "`Export::renew` sets `status` to `ExportStatus::Ready` without asking `ExportStatus::try_transition` or reading the status, though `ExportStatus::Expired` no move leaves: a `Export` there is moved out of it"
        );
        assert!(finding.detail[0].ends_with("Export::mark_ready sets status (via mark_ready)"));
        assert!(
            finding.detail[2]
                .starts_with("final:  crates/ianua-domain/src/domains/audit/status.rs:2")
        );
    }

    #[test]
    fn a_change_that_asks_the_machine_stays_quiet() {
        let found = found(
            "pub fn expire(&mut self) -> Result<(), DomainError> {
                 let next = self.status.try_transition(ExportStatus::Expired)?;
                 self.status = next;
                 Ok(())
             }",
        );

        assert!(found.findings.is_empty());
        assert!(found.silenced.is_empty());
    }

    /// The change refuses an expired export before it writes: the guard is
    /// worked out for the final state, so nothing is left unsaid.
    #[test]
    fn a_guard_that_refuses_the_final_state_before_the_write_keeps_it_quiet() {
        let found = found(
            "pub fn reset(&mut self) -> Result<(), DomainError> {
                 if self.status == ExportStatus::Expired { return Err(gone()); }
                 self.status = ExportStatus::Pending;
                 Ok(())
             }",
        );

        assert!(found.findings.is_empty());
        assert!(found.silenced.is_empty());
    }

    /// The final state is refused in a helper the change tries first, by a
    /// `let .. else` on the status.
    #[test]
    fn a_guard_in_an_own_function_tried_first_counts() {
        let found = found(
            "pub fn reset(&mut self) -> Result<(), DomainError> {
                 self.ensure_open()?;
                 self.status = ExportStatus::Pending;
                 Ok(())
             }
             fn ensure_open(&self) -> Result<(), DomainError> {
                 let ExportStatus::Pending | ExportStatus::Ready = self.status else {
                     return Err(gone());
                 };
                 Ok(())
             }",
        );

        assert!(found.findings.is_empty());
        assert!(found.silenced.is_empty());
    }

    /// The change reads the status, but its guard leaves on another state:
    /// whether something else refuses the final one is not shown, so it
    /// stays quiet and counts, naming the state.
    #[test]
    fn a_read_that_refuses_no_final_state_keeps_it_quiet_and_is_counted() {
        let found = found(
            "pub fn reset(&mut self) -> Result<(), DomainError> {
                 if self.status == ExportStatus::Ready { return Ok(()); }
                 self.status = ExportStatus::Pending;
                 Ok(())
             }",
        );

        assert!(found.findings.is_empty());
        assert_eq!(found.silenced.get(&Check::ReopenedFinalState), Some(&1));
        assert!(
            found.unsaid[0]
                .why
                .ends_with("no guard before the write was shown to refuse `ExportStatus::Expired`")
        );
    }

    #[test]
    fn a_new_state_the_reader_cannot_name_keeps_it_quiet_and_is_counted() {
        let found = found(
            "pub fn restore(&mut self, row: &ExportRow) {
                 self.status = row.status();
             }",
        );

        assert!(found.findings.is_empty());
        assert_eq!(found.silenced.get(&Check::ReopenedFinalState), Some(&1));
    }

    #[test]
    fn a_status_set_to_what_the_caller_hands_in_is_reported() {
        let found = found(
            "pub fn force(&mut self, to: ExportStatus) {
                 self.status = to;
             }",
        );

        assert!(
            found.findings[0]
                .message
                .contains("sets `status` to the `ExportStatus` its caller hands in as `to`")
        );
    }
}
