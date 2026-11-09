//! Which events the domain raises, and from where.
//!
//! An aggregate raises an event as it changes: a mutator builds the event
//! and hands it to `raise` or one of the aggregate's `raise_*` helpers, and
//! the application takes it with `take_events` after the save. An operation
//! value such as `DirectoryBindAttempt` raises the same way. An event no
//! aggregate raises is built whole by a constructor the domain's
//! conventions list in `OBSERVATIONS`, such as `HoneypotHit::observed`.
//!
//! So an event counts as raised when a function that raises, or a listed
//! observation, builds it: written out (`Self { .. }` in the event's own
//! `impl` too), as a tuple struct (`Granted(change)`), through one of the
//! event's own functions (`StepStarted::new(..)`), or in a helper the
//! function calls, at most [`HELPER_DEPTH`] calls away. A function raises
//! when it calls `raise` or a `raise_*` helper, or hands what it built to
//! a function that does or to a listed observation, as
//! `Self::raising(event)` and `self.recorded(event)` do. Calls are matched
//! by name, as everywhere in the audit: a path by `Owner::name`, with
//! `Self` read as the `impl`'s type and a module path as a free function,
//! a method called on `self` as a function of the `impl`'s type, and a
//! method called on any other value as a method of the caller's own file,
//! where the small types a change builds its records with live. A listed
//! observation's method counts by its name wherever it is called, as
//! `self.login.recorded(event)`.
//!
//! The same reading keeps the rights each function checks (see
//! [`crate::model::rights`]), itself or in a helper it calls, at most
//! [`HELPER_DEPTH`] calls away, followed the same way. A check whose right
//! is not written at the call, such as `control.ensure_may_change()`, is
//! looked up by name: when every domain function of that name that checks
//! a right checks the same written ones, those count, through it.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Delimiter, Ident, TokenStream, TokenTree};
use serde::Serialize;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Expr, ExprCall, ExprMethodCall, ExprStruct, ImplItemFn, ItemFn, ItemImpl, ItemTrait, Macro,
    Token, TraitItemFn,
};

use crate::model::rights::{self, RightCheck};
use crate::source::syntax::{line_of, type_name};
use crate::source::usage::{follows_a_dot, opens, path_head, struct_literal_at};
use crate::source::{Place, SourceFile};

/// How many calls away from a raising function an event may be built and
/// still count as raised by it.
const HELPER_DEPTH: usize = 2;

/// Why a function counts as raising.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RaiseKind {
    /// It hands an event to `raise` or a `raise_*` helper: a change of an
    /// aggregate or an operation value.
    Change,
    /// The domain's conventions list it in `OBSERVATIONS`.
    Observation,
}

/// A function that raises an event.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Raiser {
    /// The type whose `impl` holds it, if any.
    pub(crate) owner: Option<String>,
    /// Its name.
    pub(crate) name: String,
    /// Why it counts.
    pub(crate) kind: RaiseKind,
    /// Where it is declared.
    pub(crate) place: Place,
}

impl Raiser {
    /// `Owner::name`, or the bare name of a free function.
    pub(crate) fn subject(&self) -> String {
        self.owner.as_ref().map_or_else(
            || self.name.clone(),
            |owner| format!("{owner}::{}", self.name),
        )
    }
}

/// A right a function checks, itself or through a helper.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct RightFound {
    /// The check.
    #[serde(flatten)]
    pub(crate) check: RightCheck,
    /// Where the check is written.
    pub(crate) place: Place,
    /// The helpers it goes through, as `a > b`; `None` when the function
    /// checks it itself.
    pub(crate) via: Option<String>,
}

/// A function by its owner (`None` for a free function) and name.
type FunctionKey = (Option<String>, String);

/// The functions that raise each event the domain raises, and the rights
/// each domain function checks.
#[derive(Debug, Default)]
pub(crate) struct Raising {
    by_event: BTreeMap<String, Vec<Raiser>>,
    rights: BTreeMap<FunctionKey, Vec<RightFound>>,
    named_rights: BTreeMap<String, Vec<RightFound>>,
    rights_open: BTreeSet<FunctionKey>,
}

impl Raising {
    /// Reads `files` for the functions that raise one of `events`.
    /// `observations` are the listed constructors, as `(type, function)`,
    /// or `(file below src/, function)` for a free function.
    pub(crate) fn read(
        files: &[&SourceFile],
        events: &BTreeSet<&str>,
        observations: &[(String, String)],
    ) -> Self {
        let functions: Vec<Function> = files.iter().flat_map(|file| functions_in(file)).collect();
        let index = Index::of(&functions);
        let named = named_rights(&functions);
        Self {
            by_event: index.raisers_of(events, observations),
            rights: rights_by_function(&functions, &index, &named),
            rights_open: (functions.iter().enumerate())
                .filter(|(at, _)| index.rights_open(*at))
                .map(|(_, function)| (function.owner.clone(), function.name.clone()))
                .collect(),
            named_rights: named,
        }
    }

    /// Whether the rights the function `name` of `owner` checks may lie
    /// beyond what the reader followed: a helper too deep, or a method of
    /// another file called on a value of unknown type.
    pub(crate) fn rights_unread(&self, owner: Option<&str>, name: &str) -> bool {
        self.rights_open
            .contains(&(owner.map(str::to_owned), name.to_owned()))
    }

    /// The functions that raise `event`; none when nothing does.
    pub(crate) fn raisers_of(&self, event: &str) -> &[Raiser] {
        self.by_event.get(event).map_or(&[], Vec::as_slice)
    }

    /// The events the function `name` of `owner` raises, by name.
    pub(crate) fn raised_by(&self, owner: Option<&str>, name: &str) -> Vec<&str> {
        self.by_event
            .iter()
            .filter(|(_, raisers)| {
                raisers
                    .iter()
                    .any(|raiser| raiser.owner.as_deref() == owner && raiser.name == name)
            })
            .map(|(event, _)| event.as_str())
            .collect()
    }

    /// Whether the function `name` of `owner` is a listed observation that
    /// builds an event.
    pub(crate) fn is_observation(&self, owner: Option<&str>, name: &str) -> bool {
        self.by_event.values().flatten().any(|raiser| {
            raiser.kind == RaiseKind::Observation
                && raiser.owner.as_deref() == owner
                && raiser.name == name
        })
    }

    /// The rights the function `name` of `owner` checks, itself or through
    /// its helpers.
    pub(crate) fn rights_of(&self, owner: Option<&str>, name: &str) -> &[RightFound] {
        self.rights
            .get(&(owner.map(str::to_owned), name.to_owned()))
            .map_or(&[], Vec::as_slice)
    }

    /// `check`, written outside the domain at `place` through `via`; when
    /// its right is not written, the written rights every domain function
    /// of its call's name that checks one agrees on, through it, if any.
    pub(crate) fn resolve(
        &self,
        check: &RightCheck,
        place: &Place,
        via: Option<&str>,
    ) -> Vec<RightFound> {
        resolved_right(check, place, via, &self.named_rights)
    }
}

/// The rights each function checks, by its owner and name.
fn rights_by_function(
    functions: &[Function],
    index: &Index<'_>,
    named: &BTreeMap<String, Vec<RightFound>>,
) -> BTreeMap<FunctionKey, Vec<RightFound>> {
    let mut found: BTreeMap<FunctionKey, BTreeSet<RightFound>> = BTreeMap::new();
    for (at, function) in functions.iter().enumerate() {
        found
            .entry((function.owner.clone(), function.name.clone()))
            .or_default()
            .extend(index.rights_from(at, named));
    }
    found
        .into_iter()
        .filter(|(_, rights)| !rights.is_empty())
        .map(|(key, rights)| (key, rights.into_iter().collect()))
        .collect()
}

/// For each function name, the written rights all functions of that name
/// that check a right agree on.
fn named_rights(functions: &[Function]) -> BTreeMap<String, Vec<RightFound>> {
    let mut by_name: BTreeMap<&str, Vec<&Function>> = BTreeMap::new();
    for function in functions
        .iter()
        .filter(|function| !function.rights.is_empty())
    {
        by_name
            .entry(function.name.as_str())
            .or_default()
            .push(function);
    }
    by_name
        .into_iter()
        .filter_map(|(name, checking)| Some((name.to_owned(), agreed_rights(name, &checking)?)))
        .collect()
}

fn agreed_rights(name: &str, checking: &[&Function]) -> Option<Vec<RightFound>> {
    let first = checking.first()?;
    let wanted = written_rights(first)?;
    let agree = checking
        .iter()
        .all(|function| written_rights(function).as_ref() == Some(&wanted));
    if !agree {
        return None;
    }
    let via = match checking {
        [only] => only.subject(),
        _ => format!("{name} ({} definitions)", checking.len()),
    };
    Some(
        first
            .rights
            .iter()
            .map(|(check, place)| RightFound {
                check: check.clone(),
                place: place.clone(),
                via: Some(via.clone()),
            })
            .collect(),
    )
}

/// The rights `function` checks itself, when every one is written.
fn written_rights(function: &Function) -> Option<BTreeSet<&RightCheck>> {
    function
        .rights
        .iter()
        .map(|(check, _)| check.right.as_ref().map(|_| check))
        .collect()
}

/// The helper chain `via` followed by `next`, as `a > b`.
pub(crate) fn chained(via: Option<&str>, next: &str) -> String {
    match via {
        Some(before) => format!("{before} > {next}"),
        None => next.to_owned(),
    }
}

/// Why `function` raises on its own: it is a listed observation, or it
/// calls `raise` or a `raise_*` helper.
fn own_raise_kind(function: &Function, observations: &[(String, String)]) -> Option<RaiseKind> {
    let listed = observations.iter().any(|(owner, name)| {
        let owned = match &function.owner {
            Some(found) => found == owner,
            None => function.file == *owner,
        };
        *name == function.name && owned
    });
    match (listed, function.raises) {
        (true, _) => Some(RaiseKind::Observation),
        (false, true) => Some(RaiseKind::Change),
        (false, false) => None,
    }
}

/// A function a function calls.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Callee {
    /// `Owner::name(..)`, `self.name(..)` as a function of the `impl`'s own
    /// type, or `name(..)` with no owner.
    Path(Option<String>, String),
    /// `value.name(..)` on a value of a type the reader does not know,
    /// looked for among the methods of the caller's own file, where the
    /// small types a function builds its records with live.
    Nearby(String, String),
}

/// What a method is called on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Receiver {
    /// `self`, so the method is one of the `impl`'s own type.
    OwnSelf,
    /// Anything else, whose type the reader does not know.
    Other,
}

/// What one domain function builds and calls.
#[derive(Debug)]
struct Function {
    owner: Option<String>,
    name: String,
    file: String,
    place: Place,
    built: BTreeSet<String>,
    calls: BTreeSet<Callee>,
    raises: bool,
    rights: Vec<(RightCheck, Place)>,
}

impl Function {
    fn subject(&self) -> String {
        self.owner.as_ref().map_or_else(
            || self.name.clone(),
            |owner| format!("{owner}::{}", self.name),
        )
    }

    fn as_raiser(&self, kind: RaiseKind) -> Raiser {
        Raiser {
            owner: self.owner.clone(),
            name: self.name.clone(),
            kind,
            place: self.place.clone(),
        }
    }
}

/// Whether a call named `name` hands an event over to be raised.
fn is_raise(name: &str) -> bool {
    name == "raise" || name.starts_with("raise_")
}

/// The functions by name, to follow calls.
struct Index<'a> {
    functions: &'a [Function],
    by_name: BTreeMap<&'a str, Vec<usize>>,
}

impl<'a> Index<'a> {
    /// The functions that raise each of `events`, themselves or by handing
    /// on to one that does; `observations` are the listed constructors.
    fn raisers_of(
        &self,
        events: &BTreeSet<&str>,
        observations: &[(String, String)],
    ) -> BTreeMap<String, Vec<Raiser>> {
        let kinds: Vec<Option<RaiseKind>> = (self.functions.iter())
            .map(|function| own_raise_kind(function, observations))
            .collect();
        let observed_methods: BTreeSet<&str> = (observations.iter())
            .filter(|(owner, _)| starts_upper(owner))
            .map(|(_, name)| name.as_str())
            .collect();
        let mut by_event: BTreeMap<String, BTreeSet<Raiser>> = BTreeMap::new();
        for (at, function) in self.functions.iter().enumerate() {
            let handed = || self.hands_to_a_raiser(function, &kinds, &observed_methods);
            let Some(kind) = kinds[at].or_else(handed) else {
                continue;
            };
            let raiser = function.as_raiser(kind);
            for event in self.built_from(at).intersection(events) {
                let raisers = by_event.entry((*event).to_owned()).or_default();
                raisers.insert(raiser.clone());
            }
        }
        (by_event.into_iter())
            .map(|(event, raisers)| (event, raisers.into_iter().collect()))
            .collect()
    }

    fn of(functions: &'a [Function]) -> Self {
        let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (at, function) in functions.iter().enumerate() {
            by_name.entry(function.name.as_str()).or_default().push(at);
        }
        Self { functions, by_name }
    }

    /// The functions `callee` may name, by their place in the index.
    fn targets(&self, callee: &Callee) -> Vec<usize> {
        self.by_name
            .get(callee.name())
            .into_iter()
            .flatten()
            .copied()
            .filter(|at| callee.may_name(&self.functions[*at]))
            .collect()
    }

    /// Whether `function` hands what it builds to a function that raises
    /// on its own, such as `Self::raising(event)`, or to a listed
    /// observation, such as `self.login.recorded(event)`, whose method is
    /// matched by name alone: it then raises as a change.
    fn hands_to_a_raiser(
        &self,
        function: &Function,
        kinds: &[Option<RaiseKind>],
        observed_methods: &BTreeSet<&str>,
    ) -> Option<RaiseKind> {
        let to_a_raiser = function
            .calls
            .iter()
            .flat_map(|callee| self.targets(callee))
            .any(|at| kinds[at].is_some());
        let to_an_observation = function.calls.iter().any(|callee| {
            matches!(callee, Callee::Nearby(..)) && observed_methods.contains(callee.name())
        });
        (to_a_raiser || to_an_observation).then_some(RaiseKind::Change)
    }

    /// Every type the function at `start` builds, itself or through the
    /// helpers it calls, at most [`HELPER_DEPTH`] calls away.
    fn built_from(&self, start: usize) -> BTreeSet<&'a str> {
        let mut built = BTreeSet::new();
        let mut seen = BTreeSet::from([start]);
        let mut layer = vec![start];
        for depth in 0..=HELPER_DEPTH {
            built.extend(
                layer
                    .iter()
                    .flat_map(|at| self.functions[*at].built.iter())
                    .map(String::as_str),
            );
            if depth == HELPER_DEPTH {
                break;
            }
            layer = layer
                .iter()
                .flat_map(|at| self.functions[*at].calls.iter())
                .flat_map(|callee| self.targets(callee))
                .filter(|at| seen.insert(*at))
                .collect();
        }
        built
    }

    /// Whether the rights of the function at `start` may be checked
    /// somewhere the reader did not follow: a domain function more than
    /// [`HELPER_DEPTH`] calls away, or a method of that name defined in
    /// another file, called on a value whose type the reader does not know.
    fn rights_open(&self, start: usize) -> bool {
        let mut seen = BTreeSet::from([start]);
        let mut layer = vec![start];
        for depth in 0..=HELPER_DEPTH {
            let mut next = Vec::new();
            for at in &layer {
                let function = &self.functions[*at];
                for callee in &function.calls {
                    let targets = self.targets(callee);
                    if self.elsewhere(callee, function, &targets) {
                        return true;
                    }
                    let unseen: Vec<usize> = targets
                        .into_iter()
                        .filter(|target| !seen.contains(target))
                        .collect();
                    if depth == HELPER_DEPTH && !unseen.is_empty() {
                        return true;
                    }
                    for target in unseen {
                        seen.insert(target);
                        next.push(target);
                    }
                }
            }
            layer = next;
        }
        false
    }

    /// Whether `callee`, a method called on a value of unknown type in
    /// `function` with `targets` in its own file, names a domain method
    /// defined elsewhere, which it may be.
    fn elsewhere(&self, callee: &Callee, function: &Function, targets: &[usize]) -> bool {
        let Callee::Nearby(_, name) = callee else {
            return false;
        };
        targets.is_empty()
            && self.by_name.get(name.as_str()).is_some_and(|defined| {
                defined.iter().any(|at| {
                    let found = &self.functions[*at];
                    found.owner.is_some() && found.file != function.file
                })
            })
    }

    /// Every right the function at `start` checks, itself or through the
    /// helpers it calls, at most [`HELPER_DEPTH`] calls away. A check whose
    /// right is not written takes the rights `named` agrees on for its
    /// call, when there are any.
    fn rights_from(
        &self,
        start: usize,
        named: &BTreeMap<String, Vec<RightFound>>,
    ) -> Vec<RightFound> {
        let mut found = Vec::new();
        let mut seen = BTreeSet::from([start]);
        let mut layer: Vec<(usize, Option<String>)> = vec![(start, None)];
        for depth in 0..=HELPER_DEPTH {
            for (at, via) in &layer {
                found.extend(
                    self.functions[*at]
                        .rights
                        .iter()
                        .flat_map(|(check, place)| {
                            resolved_right(check, place, via.as_deref(), named)
                        }),
                );
            }
            if depth == HELPER_DEPTH {
                break;
            }
            layer = (self.called_from(&layer).into_iter())
                .filter(|(target, _)| seen.insert(*target))
                .collect();
        }
        found
    }

    /// The functions each function of `layer` calls, each with the chain
    /// of calls it is reached through.
    fn called_from(&self, layer: &[(usize, Option<String>)]) -> Vec<(usize, Option<String>)> {
        (layer.iter())
            .flat_map(|(at, via)| {
                (self.functions[*at].calls.iter())
                    .flat_map(|callee| self.targets(callee))
                    .map(|target| {
                        let next = self.functions[target].subject();
                        (target, Some(chained(via.as_deref(), &next)))
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// `check` as found at `place` through `via`; when its right is not
/// written, the rights `named` agrees on for its call instead, if any.
fn resolved_right(
    check: &RightCheck,
    place: &Place,
    via: Option<&str>,
    named: &BTreeMap<String, Vec<RightFound>>,
) -> Vec<RightFound> {
    let agreed = named.get(&check.call).filter(|_| check.right.is_none());
    let Some(agreed) = agreed else {
        return vec![RightFound {
            check: check.clone(),
            place: place.clone(),
            via: via.map(str::to_owned),
        }];
    };
    agreed
        .iter()
        .map(|right| RightFound {
            check: right.check.clone(),
            place: right.place.clone(),
            via: right.via.as_deref().map(|through| chained(via, through)),
        })
        .collect()
}

impl Callee {
    fn name(&self) -> &str {
        let (Self::Path(_, name) | Self::Nearby(_, name)) = self;
        name
    }

    /// Whether this call may be of `found`: a free function, a function of
    /// the type the path names, a free function reached through a module
    /// path, or a method in the caller's file.
    fn may_name(&self, found: &Function) -> bool {
        match (self, &found.owner) {
            (Self::Path(None, _), owner) => owner.is_none(),
            (Self::Path(Some(wanted), _), Some(owner)) => owner == wanted,
            (Self::Path(Some(wanted), _), None) => !starts_upper(wanted),
            (Self::Nearby(file, _), owner) => owner.is_some() && found.file == *file,
        }
    }
}

/// Every function with a body in `file`, with what it builds and calls.
fn functions_in(file: &SourceFile) -> Vec<Function> {
    let Some(syntax) = file.syntax() else {
        return Vec::new();
    };
    let mut reader = Reader {
        file,
        owners: Vec::new(),
        open: Vec::new(),
        done: Vec::new(),
    };
    reader.visit_file(syntax);
    reader.done
}

/// Walks a file, keeping the `impl` and function it is in.
struct Reader<'f> {
    file: &'f SourceFile,
    owners: Vec<String>,
    open: Vec<Function>,
    done: Vec<Function>,
}

impl Reader<'_> {
    fn within(&mut self, owner: String, walk: impl FnOnce(&mut Self)) {
        self.owners.push(owner);
        walk(self);
        self.owners.pop();
    }

    fn in_function(&mut self, ident: &Ident, walk: impl FnOnce(&mut Self)) {
        self.open.push(Function {
            owner: self.owners.last().cloned(),
            name: ident.to_string(),
            file: self.file.path.clone(),
            place: Place::of(self.file, ident),
            built: BTreeSet::new(),
            calls: BTreeSet::new(),
            raises: false,
            rights: Vec::new(),
        });
        walk(self);
        self.done.extend(self.open.pop());
    }

    /// The rights the call `call` handed `args` at `line` checks.
    fn checked(&mut self, call: &str, args: &Punctuated<Expr, Token![,]>, line: usize) {
        let place = Place::at(self.file, line);
        let found = rights::checks_in(call, args);
        if let Some(function) = self.open.last_mut() {
            function
                .rights
                .extend(found.into_iter().map(|check| (check, place.clone())));
        }
    }

    /// `name`, with `Self` read as the type of the `impl` it is in.
    fn resolved(&self, name: String) -> String {
        match (name.as_str(), self.owners.last()) {
            ("Self", Some(owner)) => owner.clone(),
            _ => name,
        }
    }

    fn built(&mut self, name: String) {
        let name = self.resolved(name);
        if let Some(function) = self.open.last_mut() {
            function.built.insert(name);
        }
    }

    /// The type `name`, written after the path `before`, is built: unless
    /// it is a variant, as in `SignalEvent::SessionRevoked`, whose path
    /// ends in a type rather than a module.
    fn built_at_path(&mut self, name: &str, before: &[String]) {
        let a_variant = before.last().is_some_and(|owner| starts_upper(owner));
        if !a_variant {
            self.built(name.to_owned());
        }
    }

    fn called(&mut self, callee: Callee) {
        let raises = is_raise(callee.name());
        if let Some(function) = self.open.last_mut() {
            function.raises |= raises;
            function.calls.insert(callee);
        }
    }

    /// A method called by `name`: on `self`, a function of the `impl`'s
    /// type; on anything else, one of the methods of this file.
    fn method_called(&mut self, name: String, on: Receiver) {
        let callee = match (on, self.owners.last()) {
            (Receiver::OwnSelf, Some(owner)) => Callee::Path(Some(owner.clone()), name),
            _ => Callee::Nearby(self.file.path.clone(), name),
        };
        self.called(callee);
    }

    /// A call of the path `segments`: a type built when it names one, a
    /// function called otherwise. A function of a type, such as
    /// `TopicPaused::new`, builds that type too: an event's own functions
    /// are its constructors, some of them written by a macro the reader
    /// does not see into.
    fn path_called(&mut self, segments: &[String]) {
        let Some((last, before)) = segments.split_last() else {
            return;
        };
        if starts_upper(last) {
            self.built_at_path(last, before);
            return;
        }
        let owner = before.last().map(|owner| self.resolved(owner.clone()));
        if let Some(owner) = owner.as_ref().filter(|owner| starts_upper(owner)) {
            self.built(owner.clone());
        }
        self.called(Callee::Path(owner, last.clone()));
    }

    fn tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Ident(ident) => self.ident_token(&trees, at, ident),
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }

    fn ident_token(&mut self, trees: &[TokenTree], at: usize, ident: &Ident) {
        if let Some(literal) = struct_literal_at(trees, at, ident) {
            let before: Vec<String> = path_head(trees, at).into_iter().collect();
            self.built_at_path(&literal.name, &before);
        }
        if !opens(trees.get(at + 1), Delimiter::Parenthesis) {
            return;
        }
        let name = ident.to_string();
        if !follows_a_dot(trees, at) {
            let mut segments: Vec<String> = path_head(trees, at).into_iter().collect();
            segments.push(name);
            self.path_called(&segments);
            return;
        }
        let on_self = at >= 2 && matches!(&trees[at - 2], TokenTree::Ident(word) if word == "self");
        let receiver = match on_self {
            true => Receiver::OwnSelf,
            false => Receiver::Other,
        };
        self.method_called(name, receiver);
    }
}

fn starts_upper(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_uppercase())
}

impl<'ast> Visit<'ast> for Reader<'_> {
    fn visit_item_impl(&mut self, block: &'ast ItemImpl) {
        let owner = type_name(&block.self_ty).unwrap_or_default();
        self.within(owner, |this| visit::visit_item_impl(this, block));
    }

    fn visit_item_trait(&mut self, declared: &'ast ItemTrait) {
        self.within(declared.ident.to_string(), |this| {
            visit::visit_item_trait(this, declared);
        });
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.in_function(&item.sig.ident, |this| visit::visit_item_fn(this, item));
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.in_function(&item.sig.ident, |this| {
            visit::visit_impl_item_fn(this, item);
        });
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        self.in_function(&item.sig.ident, |this| {
            visit::visit_trait_item_fn(this, item);
        });
    }

    fn visit_expr_struct(&mut self, literal: &'ast ExprStruct) {
        let segments: Vec<String> = literal
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if let Some((last, before)) = segments.split_last() {
            self.built_at_path(last, before);
        }
        visit::visit_expr_struct(self, literal);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(path) = call.func.as_ref() {
            let segments: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            if let Some(last) = path.path.segments.last() {
                self.checked(&last.ident.to_string(), &call.args, line_of(&last.ident));
            }
            self.path_called(&segments);
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let receiver = match call.receiver.as_ref() {
            Expr::Path(path) if path.path.is_ident("self") => Receiver::OwnSelf,
            _ => Receiver::Other,
        };
        self.checked(&call.method.to_string(), &call.args, line_of(&call.method));
        self.method_called(call.method.to_string(), receiver);
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::planted::domain;

    const EVENTS: &[&str] = &[
        "TopicPaused",
        "TopicArchived",
        "TopicRenamed",
        "TopicMoved",
        "RelationGranted",
        "HoneypotHit",
        "StepStarted",
        "TopicForgotten",
        "TopicDeep",
        "MetadataUpdated",
        "LockedOut",
        "StepSkipped",
        "SessionRevoked",
    ];

    fn raising(text: &str, observations: &[(&str, &str)]) -> Raising {
        let file = domain("domains/messaging/topic.rs", text);
        let observations: Vec<(String, String)> = observations
            .iter()
            .map(|(owner, name)| ((*owner).to_owned(), (*name).to_owned()))
            .collect();
        Raising::read(&[&file], &EVENTS.iter().copied().collect(), &observations)
    }

    fn subjects(found: &Raising, event: &str) -> Vec<String> {
        found
            .raisers_of(event)
            .iter()
            .map(Raiser::subject)
            .collect()
    }

    #[test]
    fn an_event_written_out_and_raised_by_a_mutator_is_raised_by_it() {
        let found = raising(
            "impl Topic { pub fn pause(&mut self) { self.raised.raise(TopicPaused { at: now() }); } }",
            &[],
        );

        assert_eq!(subjects(&found, "TopicPaused"), ["Topic::pause"]);
        assert_eq!(found.raisers_of("TopicPaused")[0].kind, RaiseKind::Change);
    }

    #[test]
    fn a_tuple_struct_event_counts_as_built() {
        let found = raising(
            "impl<T> RelationChange<T> {
                pub fn grant() -> Self {
                    let event = RelationGranted(change.recorded());
                    change.raised.raise(event);
                    change
                }
            }",
            &[],
        );

        assert_eq!(
            subjects(&found, "RelationGranted"),
            ["RelationChange::grant"]
        );
    }

    #[test]
    fn an_event_built_in_a_helper_the_mutator_calls_is_raised_by_the_mutator() {
        let found = raising(
            "impl Topic {
                pub fn archive(&mut self) { let event = self.archived(); self.raised.raise(event); }
                fn archived(&self) -> TopicArchived { TopicArchived { at: now() } }
            }",
            &[],
        );

        assert_eq!(subjects(&found, "TopicArchived"), ["Topic::archive"]);
    }

    #[test]
    fn a_raise_helper_counts_as_raising() {
        let found = raising(
            "impl Topic { pub fn rename(&mut self) { self.raised.raise_latest(TopicRenamed { at: now() }); } }",
            &[],
        );

        assert_eq!(subjects(&found, "TopicRenamed"), ["Topic::rename"]);
    }

    #[test]
    fn an_event_written_inside_a_macro_counts_as_built() {
        let found = raising(
            "impl Topic { pub fn moved(&mut self) { self.raise_all(vec![TopicMoved { at: now() }]); } }",
            &[],
        );

        assert_eq!(subjects(&found, "TopicMoved"), ["Topic::moved"]);
    }

    #[test]
    fn a_listed_observation_building_self_raises_its_event() {
        let text = "impl HoneypotHit { pub fn observed(t: TenantId) -> DomainEvent { scoped(t, Self { at: now() }) } }";

        let listed = raising(text, &[("HoneypotHit", "observed")]);
        let unlisted = raising(text, &[]);

        assert_eq!(subjects(&listed, "HoneypotHit"), ["HoneypotHit::observed"]);
        assert_eq!(
            listed.raisers_of("HoneypotHit")[0].kind,
            RaiseKind::Observation
        );
        assert!(unlisted.raisers_of("HoneypotHit").is_empty());
    }

    #[test]
    fn a_listed_free_function_is_found_by_its_file_and_follows_the_constructor_it_calls() {
        let found = raising(
            "fn step_event(t: TenantId) -> DomainEvent { scoped(t, StepStarted::new(now())) }
             impl StepStarted { fn new(at: OffsetDateTime) -> Self { Self { at } } }",
            &[("domains/messaging/topic.rs", "step_event")],
        );

        assert_eq!(subjects(&found, "StepStarted"), ["step_event"]);
    }

    #[test]
    fn an_event_handed_to_a_function_that_raises_is_raised_by_the_caller() {
        let found = raising(
            "impl<T> MetadataChange<T> {
                pub fn one_value(user_id: UserId) -> Self { Self::raising(MetadataUpdated { user_id }) }
                fn raising(event: impl TenantEventBody) -> Self {
                    let mut raised = Raised::default();
                    raised.raise(event);
                    Self { raised }
                }
            }",
            &[],
        );

        assert_eq!(
            subjects(&found, "MetadataUpdated"),
            ["MetadataChange::one_value"]
        );
    }

    #[test]
    fn an_event_handed_to_a_listed_observation_elsewhere_is_raised_by_the_caller() {
        let login = domain(
            "domains/authentication/operations/password_login/mod.rs",
            "impl PasswordLogin {
                fn recorded(&self, body: impl TenantEventBody) -> DomainEvent { scoped(self.tenant, body) }
            }",
        );
        let conclude = domain(
            "domains/authentication/operations/password_login/conclude.rs",
            "impl VerifiedLogin {
                fn locked(&self) -> Vec<DomainEvent> { vec![self.login.recorded(LockedOut { at: now() })] }
            }",
        );
        let observations = [("PasswordLogin".to_owned(), "recorded".to_owned())];

        let found = Raising::read(
            &[&login, &conclude],
            &EVENTS.iter().copied().collect(),
            &observations,
        );

        assert_eq!(subjects(&found, "LockedOut"), ["VerifiedLogin::locked"]);
    }

    #[test]
    fn an_event_built_by_a_method_of_a_value_in_the_same_file_is_followed() {
        let found = raising(
            "pub(super) fn decision(request: &mut Request) {
                let named = Named { at: now() };
                request.raised.raise_latest(named.renamed());
            }
            impl Named {
                fn renamed(self) -> TopicRenamed { TopicRenamed { at: self.at } }
            }",
            &[],
        );

        assert_eq!(subjects(&found, "TopicRenamed"), ["decision"]);
    }

    #[test]
    fn a_constructor_the_reader_cannot_see_still_builds_its_event() {
        let found = raising(
            "fn step_event(t: TenantId) -> DomainEvent { scoped(t, StepSkipped::new(step, now())) }",
            &[("domains/messaging/topic.rs", "step_event")],
        );

        assert_eq!(subjects(&found, "StepSkipped"), ["step_event"]);
    }

    #[test]
    fn a_variant_named_like_an_event_is_not_the_event() {
        let found = raising(
            "impl SignalSet {
                pub fn note(&mut self) {
                    self.raised.raise(Noted { kind: SignalEvent::SessionRevoked });
                    self.raised.raise(Kind::SessionRevoked(at));
                    self.raised.raise(Shape::SessionRevoked { at });
                }
            }",
            &[],
        );

        assert!(found.raisers_of("SessionRevoked").is_empty());
    }

    #[test]
    fn an_event_built_where_nothing_raises_it_is_not_raised() {
        let found = raising(
            "impl Topic { pub fn forget(&mut self) -> TopicForgotten { TopicForgotten { at: now() } } }",
            &[],
        );

        assert!(found.raisers_of("TopicForgotten").is_empty());
    }

    fn rights(found: &Raising, owner: &str, name: &str) -> Vec<(Option<String>, Option<String>)> {
        found
            .rights_of(Some(owner), name)
            .iter()
            .map(|right| (right.check.right.clone(), right.via.clone()))
            .collect()
    }

    #[test]
    fn a_change_checks_the_right_it_hands_its_control() {
        let found = raising(
            "impl Topic {
                pub fn pause(&mut self, control: &TopicControl<'_>) -> Result<(), DomainError> {
                    control.ensure_may(MessagingAction::Update)?;
                    self.raised.raise(TopicPaused { at: now() });
                    Ok(())
                }
            }",
            &[],
        );

        assert_eq!(
            rights(&found, "Topic", "pause"),
            [(Some("MessagingAction::Update".to_owned()), None)]
        );
        assert_eq!(found.raised_by(Some("Topic"), "pause"), ["TopicPaused"]);
    }

    #[test]
    fn a_right_checked_in_a_helper_is_the_changes_through_it() {
        let found = raising(
            "impl Topic {
                pub fn archive(&mut self, by: &TopicControl<'_>) { self.allowed(by); }
                fn allowed(&self, by: &TopicControl<'_>) { by.ensure_may(MessagingAction::Delete); }
            }",
            &[],
        );

        assert_eq!(
            rights(&found, "Topic", "archive"),
            [(
                Some("MessagingAction::Delete".to_owned()),
                Some("Topic::allowed".to_owned())
            )]
        );
    }

    #[test]
    fn a_check_without_its_right_written_takes_the_one_its_definition_names() {
        let control = domain(
            "domains/branding/control.rs",
            "impl BrandingControl<'_> {
                pub fn ensure_may_change(&self) -> Result<(), DomainError> {
                    self.authority.ensure_holds(SystemPermission::Branding(BrandingAction::Update))
                }
            }",
        );
        let theme = domain(
            "domains/branding/theme.rs",
            "impl Theme { pub fn recolour(&mut self, by: &BrandingControl<'_>) { by.ensure_may_change(); } }",
        );

        let found = Raising::read(&[&control, &theme], &BTreeSet::new(), &[]);

        assert_eq!(
            rights(&found, "Theme", "recolour"),
            [(
                Some("SystemPermission::Branding(BrandingAction::Update)".to_owned()),
                Some("BrandingControl::ensure_may_change".to_owned())
            )]
        );
    }

    #[test]
    fn a_check_whose_definitions_disagree_keeps_its_right_unread() {
        let controls = domain(
            "domains/messaging/control.rs",
            "impl A { fn ensure_may_go(&self) { self.x.ensure_holds(SystemPermission::One); } }
             impl B { fn ensure_may_go(&self) { self.x.ensure_holds(SystemPermission::Two); } }",
        );
        let topic = domain(
            "domains/messaging/topic.rs",
            "impl Topic { pub fn go(&mut self, by: &Other) { by.ensure_may_go(); } }",
        );

        let found = Raising::read(&[&controls, &topic], &BTreeSet::new(), &[]);

        assert_eq!(
            rights(&found, "Topic", "go"),
            [(None::<String>, None::<String>)]
        );
    }

    #[test]
    fn an_event_built_beyond_the_helper_depth_is_not_counted() {
        let found = raising(
            "impl Topic {
                pub fn sink(&mut self) { self.raised.raise(self.one()); }
                fn one(&self) -> TopicDeep { self.two() }
                fn two(&self) -> TopicDeep { self.three() }
                fn three(&self) -> TopicDeep { TopicDeep { at: now() } }
            }",
            &[],
        );

        assert!(found.raisers_of("TopicDeep").is_empty());
    }
}
