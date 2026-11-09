//! Reading one function body: the ports it calls, the domain changes, the
//! rights and plan limits it checks, what it dispatches and the `AppError`
//! variants it writes, with the helpers it calls for the caller to follow.
//!
//! A value's type is known only when the reader can follow it: a parameter
//! or `let` with its type written, a port method, helper or domain function
//! whose signature says what it hands back, a struct written out, or a
//! creator called by its path. `?`, `.await`, `map_err`, `or_*` and
//! `as_ref` keep the type they are handed. Anything else stays unknown,
//! and a call on it that has the name of a domain change is reported as
//! not read rather than matched by name.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::Ident;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Expr, ExprCall, ExprField, ExprMethodCall, ExprPath, FnArg, Item, Member, Pat, PatType,
    ReturnType, Signature, Token, Type,
};

use super::FOLLOW_DEPTH;
use super::flow::{Exit, Unread, writes_to_store};
use super::known::Known;
use super::scope::{FnRef, Lookup, Scope};
use super::shape::{Builder, Handed, Node, UNIT_PORT, UNITS, address, called, exit_of, tails};
use crate::model::app::PortLookup;
use crate::model::domain::BehaviourKind;
use crate::model::paths::{AppItem, Origin};
use crate::model::rights::{self, RightCheck};
use crate::source::syntax::{
    core_type, item_type, line_of, names_in_expr, names_in_type, returned_core, returned_items,
    type_name,
};
use crate::source::{Layer, Place};

/// The auditor methods that dispatch events.
const DISPATCHING: &[&str] = &["dispatch", "dispatch_by"];

/// The method that hands over the events a value raised.
const TAKING: &str = "take_events";

/// The enum whose variants are the plan's counted resources.
const LIMIT_KINDS: &str = "ResourceKind";

/// The app's error enum.
const ERRORS: &str = "AppError";

/// The app's auditor, whose own methods other than [`DISPATCHING`] only
/// scope it.
const AUDITOR: &str = "RequestAuditor";

/// Calls known not to act on what they are handed: constructors and
/// conversions of the standard library.
const HARMLESS: &[&str] = &[
    "Arc", "Box", "Rc", "Some", "Ok", "Err", "Vec", "String", "Option", "Result", "drop", "Cow",
    "Mutex", "RwLock", "matches", "From", "Into", "Default",
];

/// Why a call on `self` was not followed.
const NO_OWN_METHOD: &str = "no method of that name on its own type was found";

/// Why a call on a `*Ports` struct was not followed.
const NO_PORTS_METHOD: &str = "no method of that name on its `*Ports` struct was found";

/// Why a call on a field that is not a port was not followed.
const NOT_A_PORT: &str = "the field holds no port trait, and its type's methods are not followed";

/// Why a plan limit check was not read.
const LIMIT_UNREAD: &str = "it checks a plan limit whose `ResourceKind` the reader did not read";

/// Why a call on a port whose trait shares its name was not placed.
const UNPLACED_PORT: &str =
    "its trait shares its name with another port, and the reader cannot tell which it is";

/// Why a call on an unread field of `self` was not followed.
const SELF_FIELD: &str = "the type of that field of `self` was not read";

/// Why a call on a value holding ports was not followed.
const NO_HOLDER_METHOD: &str =
    "it is called on a value holding ports, and no method of that name on its type was found";

/// What a call named `name` on items of `item` hands back: the same
/// items, through the adapters that keep them, or one of them, through
/// those that pick one.
fn items_after(name: &str, item: String) -> Option<Local> {
    match name {
        "into_iter" | "iter" | "iter_mut" | "filter" | "rev" | "skip" | "take" | "cloned"
        | "copied" | "peekable" | "chain" | "skip_while" | "take_while" => Some(Local::Items(item)),
        "find" | "next" | "last" | "first" | "nth" | "pop" | "max_by_key" | "min_by_key"
        | "max_by" | "min_by" => Some(Local::Type(item)),
        _ => None,
    }
}

/// Methods of an `Option` or a `Result` that hand back one holding the same
/// value, or none.
const KEEPS_WHAT_IT_HOLDS: &[&str] = &[
    "filter", "inspect", "or", "or_else", "take", "copied", "cloned", "flatten",
];

/// Methods that turn a result's error into a value and go on.
const RECOVERING: &[&str] = &["unwrap_or_else", "unwrap_or", "unwrap_or_default", "ok"];

/// Methods that run the closure they are handed for each item, or at most
/// once for an `Option` or a `Result`: any number of times, none included.
const RUNS_CLOSURES: &[&str] = &[
    "map",
    "filter",
    "filter_map",
    "flat_map",
    "for_each",
    "try_for_each",
    "any",
    "all",
    "find",
    "find_map",
    "position",
    "inspect",
    "take_while",
    "skip_while",
    "fold",
    "try_fold",
    "partition",
    "map_while",
    "retain",
    "and_then",
    "map_or",
    "map_or_else",
    "or_else",
    "is_some_and",
    "is_ok_and",
    "is_none_or",
    "then",
    "max_by_key",
    "min_by_key",
    "sort_by_key",
    "sort_by",
];

/// What a condition says of an enum's value: the enum, the variants when
/// it holds, the variants when it does not.
type Narrowing = (String, BTreeSet<String>, BTreeSet<String>);

/// The enum and variant a path to a variant names, such as
/// `("SecondFactor", "Verify")` for `SecondFactor::Verify`.
fn enum_variant(path: &syn::Path) -> Option<(String, String)> {
    let names = segments(path);
    let [.., owner, variant] = names.as_slice() else {
        return None;
    };
    Some((owner.clone(), variant.clone()))
}

/// The variant `expr` names, when it is a path to one.
fn variant_path(expr: &Expr) -> Option<(String, String)> {
    match expr {
        Expr::Path(path) => enum_variant(&path.path),
        Expr::Reference(inner) => variant_path(&inner.expr),
        Expr::Paren(inner) => variant_path(&inner.expr),
        _ => None,
    }
}

/// The parts of `matches!(expr, pattern)`.
fn matched_parts(invoked: &syn::Macro) -> Option<(Expr, Pat)> {
    invoked
        .parse_body_with(|input: syn::parse::ParseStream<'_>| {
            let expr: Expr = input.parse()?;
            input.parse::<Token![,]>()?;
            let pattern = Pat::parse_multi_with_leading_vert(input)?;
            let _: proc_macro2::TokenStream = input.parse()?;
            Ok((expr, pattern))
        })
        .ok()
}

/// What a closure is handed, and as which of its parameters.
struct Handing {
    /// What the reader knows of it.
    local: Option<Local>,
    /// The parameter's position.
    at: usize,
}

/// `pattern` without the `&` and the type written around a name.
fn unreferenced(pattern: &Pat) -> &Pat {
    match pattern {
        Pat::Reference(inner) => unreferenced(&inner.pat),
        Pat::Type(typed) => unreferenced(&typed.pat),
        other => other,
    }
}

/// How often a closure handed to a call runs.
#[derive(Clone, Copy)]
enum Runs {
    /// At most once, where it is handed.
    Once,
    /// Any number of times, none included.
    Repeatedly,
}

impl Runs {
    /// Where an exit inside a closure that runs this often leaves to: the
    /// end of the closure, or the next round of the loop it is.
    fn leaving(self) -> Node {
        match self {
            Self::Once => Node::Seq(Vec::new()),
            Self::Repeatedly => Node::LoopExit,
        }
    }
}

/// `node` with each exit replaced by `leaving`: inside a closure, `?` and
/// `return` leave the closure, not the function.
fn exits_replaced(node: Node, leaving: &Node) -> Node {
    let each = |parts: Vec<Node>| -> Vec<Node> {
        parts
            .into_iter()
            .map(|part| exits_replaced(part, leaving))
            .collect()
    };
    match node {
        Node::Exit(..) => leaving.clone(),
        Node::Seq(parts) => Node::Seq(each(parts)),
        Node::Choice(parts) => Node::Choice(each(parts)),
        Node::Split { head, ok, err } => Node::Split {
            head: Box::new(exits_replaced(*head, leaving)),
            ok: Box::new(exits_replaced(*ok, leaving)),
            err: Box::new(exits_replaced(*err, leaving)),
        },
        Node::Unit { name, place, inner } => Node::Unit {
            name,
            place,
            inner: Box::new(exits_replaced(*inner, leaving)),
        },
        Node::Loop {
            body,
            at_least_once,
        } => Node::Loop {
            body: Box::new(exits_replaced(*body, leaving)),
            at_least_once,
        },
        other => other,
    }
}

/// Methods that add to a list.
const COLLECTING: &[&str] = &["extend", "push", "append", "extend_from_slice"];

/// Methods that hand back the value, or the same kind of value, they are
/// called on.
const PASSING: &[&str] = &[
    "map_err",
    "ok_or",
    "ok_or_else",
    "context",
    "with_context",
    "as_ref",
    "as_mut",
    "clone",
    "borrow",
    "borrow_mut",
];

/// What the reader knows a name holds.
#[derive(Clone, Debug)]
pub(super) enum Local {
    /// A value of this type, by its last name.
    Type(String),
    /// A struct written out with ports or the auditor in its fields, such
    /// as `Answering { exports: self.ports.exports.as_ref(), .. }`.
    Holder {
        /// Its type, when the reader followed it to the app.
        item: Option<AppItem>,
        /// Its type's last name.
        type_name: String,
        /// What the reader knows each field holds.
        fields: BTreeMap<String, Local>,
    },
    /// A port.
    Port(PortRef),
    /// This `*Ports` struct, held at `prefix` (such as `sending.`) inside
    /// the use case's own.
    Ports {
        /// The struct.
        item: AppItem,
        /// The fields before it, each followed by a dot.
        prefix: String,
    },
    /// Events taken from these.
    Events(Vec<Source>),
    /// A collection or an iterator, of items of this type, by its last
    /// name.
    Items(String),
    /// A plan's counted resource the reader read, such as `Users` for
    /// `ResourceKind::Users`.
    LimitKind {
        /// The `ResourceKind` variant.
        kind: String,
        /// Whether the caller handed it in, and so already counted it as
        /// checked where it handed it.
        handed: bool,
    },
}

/// A port, by the field it is held in and its trait, as far as known.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PortRef {
    /// The field of the `*Ports` struct.
    pub(super) field: Option<String>,
    /// The port trait's name.
    pub(super) trait_name: Option<String>,
    /// The port trait, when the reader knows which of the ports of that
    /// name it is.
    pub(super) port: Option<AppItem>,
}

impl PortRef {
    /// The port held in `field`, as `lookup` found its trait.
    pub(super) fn held(field: Option<String>, lookup: &PortLookup) -> Self {
        Self {
            field,
            trait_name: lookup.name().map(str::to_owned),
            port: lookup.found().cloned(),
        }
    }

    /// What its trait was found to be.
    pub(super) fn lookup(&self) -> PortLookup {
        match (&self.port, &self.trait_name) {
            (Some(item), _) => PortLookup::Found(item.clone()),
            (None, Some(name)) => PortLookup::Unplaced(name.clone()),
            (None, None) => PortLookup::NotAPort,
        }
    }
}

/// Where dispatched events come from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Source {
    /// `receiver.take_events(..)`, with the receiver's type when known.
    Taken {
        /// The receiver's type.
        type_name: Option<String>,
        /// The receiver as written.
        receiver: String,
    },
    /// A listed observation called by its path, such as
    /// `HoneypotHit::observed(..)`.
    Observed {
        /// Its type.
        owner: String,
        /// Its function.
        name: String,
    },
}

/// One fact a body states.
#[derive(Clone, Debug)]
pub(super) enum Seen {
    /// A port method called.
    PortCall {
        /// The port.
        port: PortRef,
        /// The method.
        method: String,
        /// The value each argument names, such as `domain` for `&mut
        /// domain`; `None` for one that names none.
        values: Vec<Option<String>>,
    },
    /// A domain creator or change called.
    Change {
        /// The aggregate.
        owner: String,
        /// The creator or change.
        name: String,
        /// The value it changes, or the name a creator's value is bound to,
        /// when the body names one.
        value: Option<String>,
    },
    /// A call named like a domain change on a value of unknown type.
    UnreadReceiver {
        /// The value as written.
        receiver: String,
        /// The method.
        method: String,
        /// The aggregates with a change of that name.
        owners: Vec<String>,
    },
    /// A right checked.
    Right(RightCheck),
    /// A plan limit checked.
    Limit {
        /// The `ResourceKind` variant.
        kind: String,
        /// The function handed it.
        call: String,
    },
    /// Events dispatched.
    Dispatch {
        /// The auditor method.
        method: String,
        /// Where the events come from.
        sources: Vec<Source>,
    },
    /// An `AppError` variant written.
    Error(String),
    /// A function imported from the app that the reader could not find.
    UnreadHelper {
        /// Its name.
        name: String,
        /// The module it is imported from.
        module: String,
    },
    /// A helper too many calls deep to follow.
    Unfollowed {
        /// Its name.
        name: String,
    },
    /// A call the reader did not follow that can reach a port or the
    /// auditor: what it may do is not on the card.
    Unresolved {
        /// The call as written, such as `self.ports.settle(..)`.
        call: String,
        /// Why it was not followed.
        why: String,
    },
}

impl Seen {
    /// What the reader could not read, in words, when the fact is a
    /// not-read point.
    pub(super) fn unread_what(&self) -> Option<String> {
        match self {
            Self::UnreadReceiver {
                receiver,
                method,
                owners,
            } => Some(format!(
                "`{receiver}.{method}(..)`: the type of `{receiver}` was not read; domain changes named `{method}`: {}",
                owners_named(owners, method)
            )),
            Self::UnreadHelper { name, module } => Some(format!(
                "`{name}`, imported from `{module}`: not found there"
            )),
            Self::Unfollowed { name } => Some(format!(
                "`{name}`: more than {FOLLOW_DEPTH} helpers from `execute`, not followed"
            )),
            Self::Unresolved { call, why } => Some(format!("`{call}`: {why}")),
            _ => None,
        }
    }

    /// Whether it is a step that takes no effect when its own call fails:
    /// a port call, a domain change or a dispatch.
    fn is_step(&self) -> bool {
        matches!(
            self,
            Self::PortCall { .. } | Self::Change { .. } | Self::Dispatch { .. }
        )
    }
}

/// How many aggregates a "not read" note names before it counts the rest.
const OWNERS_SHOWN: usize = 4;

fn owners_named(owners: &[String], method: &str) -> String {
    let shown: Vec<String> = owners
        .iter()
        .take(OWNERS_SHOWN)
        .map(|owner| format!("{owner}::{method}"))
        .collect();
    match owners.len().saturating_sub(OWNERS_SHOWN) {
        0 => shown.join(", "),
        more => format!("{} and {more} more", shown.join(", ")),
    }
}

/// What `self` is inside a helper the reader follows.
#[derive(Clone, Debug)]
pub(super) enum HelperSelf {
    /// The same `self` as the caller's: a method of its own type.
    Own,
    /// A `*Ports` struct, held at `prefix` inside the use case's own.
    Ports {
        /// The struct.
        item: AppItem,
        /// The fields before it, each followed by a dot.
        prefix: String,
    },
    /// A struct holding ports or the auditor, with what its fields hold.
    Holder(BTreeMap<String, Local>),
    /// No `self`: a free function.
    Free,
}

/// A fact with where it is written.
#[derive(Clone, Debug)]
pub(super) struct SeenAt {
    /// The fact.
    pub(super) seen: Seen,
    /// Where.
    pub(super) place: Place,
}

/// A helper the body calls, with what the reader knows of each argument.
pub(super) struct HelperCall<'a> {
    /// The helper.
    pub(super) target: FnRef<'a>,
    /// What each argument holds, by position, the receiver left out.
    pub(super) args: Vec<Option<Local>>,
    /// The value each argument names, by position, as the flow tells
    /// values apart.
    pub(super) values: Vec<Option<String>>,
    /// The helpers of the caller handed in as futures not yet run, as the
    /// argument's position and the caller's helper.
    pub(super) futures: Vec<(usize, usize)>,
    /// What `self` is inside it.
    pub(super) receiver: HelperSelf,
    /// Where it is called.
    pub(super) place: Place,
}

/// What one body states, and the helpers it calls.
pub(super) struct Read<'a> {
    /// The facts.
    pub(super) seen: Vec<SeenAt>,
    /// The helpers.
    pub(super) helpers: Vec<HelperCall<'a>>,
    /// The order they run in, with the branches, loops, units and exits.
    pub(super) shape: Node,
}

/// Reads `function`, whose `self` holds `self_fields`, called with `args`.
pub(super) fn read<'a>(
    known: &Known<'a>,
    function: &FnRef<'a>,
    self_fields: &BTreeMap<String, Local>,
    args: &[Option<Local>],
) -> Read<'a> {
    let scope = Scope::of(function.file, function.owner.as_deref());
    let mut reading = Reading {
        known,
        scope: &scope,
        self_fields,
        locals: BTreeMap::new(),
        seen: Vec::new(),
        helpers: Vec::new(),
        shape: Builder::default(),
        tails: tails(function.block),
        returns: Returns::of(function.sig),
        calls: Calls {
            params: param_names(function.sig),
            ..Calls::default()
        },
    };
    reading.bind_params(function.sig, args);
    reading.visit_block(function.block);
    let mut shape = reading.shape.finish();
    shape.hold(&reading.calls.held);
    Read {
        seen: reading.seen,
        helpers: reading.helpers,
        shape,
    }
}

/// What a function hands back, as far as its exits go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Returns {
    /// A `Result`, or a type the reader cannot name: it succeeds or fails.
    Result,
    /// An `Option`: a `?` in it hands back `None`, a value its caller goes
    /// on with.
    Option,
    /// Any other value, or nothing: it never fails.
    Plain,
}

impl Returns {
    /// What `signature` hands back.
    fn of(signature: &Signature) -> Self {
        let ReturnType::Type(_, ty) = &signature.output else {
            return Self::Plain;
        };
        match type_name(ty).as_deref() {
            None => Self::Result,
            Some("Option") => Self::Option,
            Some(name) if name.ends_with("Result") => Self::Result,
            Some(_) => Self::Plain,
        }
    }

    /// How a `?` leaves the function.
    fn tried(self) -> Exit {
        match self {
            Self::Result => Exit::Err,
            Self::Option | Self::Plain => Exit::Value,
        }
    }
}

/// What a method is called on.
enum Recv {
    /// A port.
    Port(PortRef),
    /// `self`.
    OwnSelf,
    /// A `*Ports` struct.
    Ports {
        /// The struct.
        item: AppItem,
        /// The fields before it.
        prefix: String,
    },
    /// A value of a known type.
    Typed(String),
    /// A struct holding ports or the auditor.
    Holder {
        /// Its type, when followed to the app.
        item: Option<AppItem>,
        /// Its type's last name.
        type_name: String,
        /// What its fields hold.
        fields: BTreeMap<String, Local>,
    },
    /// Anything else, as written.
    Unknown(String),
}

/// The arguments a call is handed, and where the call is.
struct CallArgs<'c> {
    args: &'c Punctuated<Expr, Token![,]>,
    place: Place,
}

/// A method call being read: the call, how it is written in a finding,
/// and where it is.
struct CallSite<'c> {
    call: &'c ExprMethodCall,
    written: String,
    place: Place,
}

struct Reading<'r, 'a> {
    known: &'r Known<'a>,
    scope: &'r Scope<'a>,
    self_fields: &'r BTreeMap<String, Local>,
    locals: BTreeMap<String, Local>,
    seen: Vec<SeenAt>,
    helpers: Vec<HelperCall<'a>>,
    shape: Builder,
    tails: BTreeSet<usize>,
    returns: Returns,
    calls: Calls,
}

/// Which call each fact, helper and unit of a body came from, to know the
/// one whose result a `?`, a tail or a `match` is about.
#[derive(Default)]
struct Calls {
    /// The call being read, by its address.
    current: Option<usize>,
    /// The call each fact came from, by the fact's index.
    facts: Vec<Option<usize>>,
    /// The call each helper came from, by the helper's index.
    helpers: Vec<Option<usize>>,
    /// The call that opened the newest unit of work.
    unit: Option<usize>,
    /// The name a `let` just bound to a call's result.
    bound: Option<Bound>,
    /// The body's parameters, by position, `self` left out.
    params: Vec<Option<String>>,
    /// The closures whose bodies were read as part of the flow, by address.
    closures: BTreeSet<usize>,
    /// The calls whose answer a statement drops, by address.
    discarded: BTreeSet<usize>,
    /// The helper whose result a `let` bound to each name, while the name
    /// still holds it.
    kept_in: BTreeMap<String, usize>,
    /// The helpers whose result is held in a name the body later hands
    /// back as its own or passes on with `?`.
    held: BTreeSet<usize>,
}

/// A name a `let` bound to what a call hands back.
struct Bound {
    /// The name.
    name: String,
    /// Where the builder stood right after the `let`.
    mark: (usize, usize),
    /// Whether the call was not awaited, so the name holds a future.
    future: bool,
}

/// Which side of a result a pattern takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    /// `Ok(..)`.
    Ok,
    /// `Err(..)`.
    Err,
    /// `_` or a name: either.
    Both,
}

impl<'a> Reading<'_, 'a> {
    fn note(&mut self, seen: Seen, place: Place) {
        self.seen.push(SeenAt { seen, place });
        self.calls.facts.push(self.calls.current);
        self.shape.push(Node::Fact(self.seen.len() - 1));
    }

    fn bind_params(&mut self, signature: &Signature, args: &[Option<Local>]) {
        let typed = signature.inputs.iter().filter_map(|input| match input {
            FnArg::Typed(typed) => Some(typed),
            FnArg::Receiver(_) => None,
        });
        for (position, input) in typed.enumerate() {
            let given = args.get(position).cloned().flatten().map(handed_in);
            let local = given.or_else(|| self.local_of_type(&input.ty));
            self.bind_local(&input.pat, local);
        }
    }

    /// Binds `pattern` to what the reader knows of its value: a name to
    /// it, a struct pattern to the fields of a holder.
    fn bind_local(&mut self, pattern: &Pat, local: Option<Local>) {
        match (pattern, local) {
            (Pat::Ident(name), Some(local)) => {
                self.locals.insert(name.ident.to_string(), local);
            }
            (Pat::Struct(parts), Some(Local::Holder { fields, .. })) => {
                self.bind_parts(parts, &fields);
            }
            (Pat::Struct(parts), Some(Local::Type(name))) => {
                let fields = self
                    .known
                    .app_type(&name)
                    .map(|(_, fields)| fields)
                    .unwrap_or_default();
                self.bind_parts(parts, &fields);
            }
            (_, _) => self.forget(pattern),
        }
    }

    fn bind_parts(&mut self, parts: &syn::PatStruct, fields: &BTreeMap<String, Local>) {
        for part in &parts.fields {
            let held = match &part.member {
                Member::Named(member) => fields.get(&member.to_string()).cloned(),
                Member::Unnamed(_) => None,
            };
            self.bind_local(&part.pat, held);
        }
    }

    /// What a value of type `ty` is to the reader.
    fn local_of_type(&self, ty: &Type) -> Option<Local> {
        let file = self.scope.file();
        let lookup = self.known.port_in_type(file, ty);
        if lookup != PortLookup::NotAPort {
            return Some(Local::Port(PortRef::held(None, &lookup)));
        }
        let names = names_in_type(ty);
        if let Some(ports) = names
            .iter()
            .find_map(|name| self.known.ports_item(file, name))
        {
            return Some(Local::Ports {
                item: ports,
                prefix: String::new(),
            });
        }
        if let Some(items) = item_type(ty, self.scope.owner()) {
            return Some(Local::Items(items));
        }
        core_type(ty, self.scope.owner())
            .map(Local::Type)
            .or_else(|| self.known.trait_object(ty))
    }

    fn bind(&mut self, pattern: &Pat, init: Option<&Expr>) {
        match pattern {
            Pat::Ident(name) => self.bind_name(&name.ident, None, init),
            Pat::Type(typed) => self.bind_typed(typed, init),
            Pat::TupleStruct(wrapped) if unwraps(wrapped) => self.bind(&wrapped.elems[0], init),
            Pat::Struct(_) => {
                let local = init.and_then(|expr| self.local_of(expr));
                self.bind_local(pattern, local);
            }
            _ => self.forget(pattern),
        }
    }

    fn bind_typed(&mut self, typed: &PatType, init: Option<&Expr>) {
        let Pat::Ident(name) = typed.pat.as_ref() else {
            self.forget(&typed.pat);
            return;
        };
        self.bind_name(&name.ident, Some(&typed.ty), init);
    }

    fn bind_name(&mut self, name: &Ident, ty: Option<&Type>, init: Option<&Expr>) {
        let local = ty
            .and_then(|ty| self.local_of_type(ty))
            .or_else(|| init.and_then(|expr| self.local_of(expr)));
        let name = name.to_string();
        match local {
            Some(local) => {
                self.locals.insert(name, local);
            }
            None => {
                self.locals.remove(&name);
            }
        }
    }

    fn forget(&mut self, pattern: &Pat) {
        let mut names = PatNames::default();
        names.visit_pat(pattern);
        for name in names.found {
            self.locals.remove(&name);
        }
    }

    /// What the value of `expr` is to the reader: events when it takes
    /// any, its type otherwise.
    fn local_of(&self, expr: &Expr) -> Option<Local> {
        let sources = self.sources_in([expr]);
        if !sources.is_empty() {
            return Some(Local::Events(sources));
        }
        self.expr_local(expr)
    }

    fn expr_local(&self, expr: &Expr) -> Option<Local> {
        if let Some(kind) = limit_kind(expr) {
            return Some(Local::LimitKind {
                kind,
                handed: false,
            });
        }
        match expr {
            Expr::Try(inner) => self.expr_local(&inner.expr),
            Expr::Await(inner) => self.expr_local(&inner.base),
            Expr::Paren(inner) => self.expr_local(&inner.expr),
            Expr::Group(inner) => self.expr_local(&inner.expr),
            Expr::Reference(inner) => self.expr_local(&inner.expr),
            Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|name| self.locals.get(&name.to_string()).cloned()),
            Expr::Field(field) => self.field_local(field),
            Expr::Struct(literal) => self.literal_local(literal),
            Expr::MethodCall(call) => self.method_local(call),
            Expr::Call(call) => self.call_local(call),
            _ => None,
        }
    }

    /// A struct written out: a holder when a field holds a port, ports, the
    /// auditor or events; its type otherwise.
    fn literal_local(&self, literal: &syn::ExprStruct) -> Option<Local> {
        let path = segments(&literal.path);
        let type_name = self.owner_named(path.last()?);
        let fields: BTreeMap<String, Local> = literal
            .fields
            .iter()
            .filter_map(|field| {
                let Member::Named(member) = &field.member else {
                    return None;
                };
                Some((member.to_string(), self.local_of(&field.expr)?))
            })
            .collect();
        if !fields.values().any(reaches_out) {
            return Some(Local::Type(type_name));
        }
        let item = match self.known.modules().origin(self.scope.file(), &path) {
            Origin::Declared(item) => Some(item),
            Origin::Missing(_) | Origin::Outside => self.local_type(&type_name),
        };
        Some(Local::Holder {
            item,
            type_name,
            fields,
        })
    }

    /// The app type `name` declared in the body's own file.
    fn local_type(&self, name: &str) -> Option<AppItem> {
        let file = self.scope.file();
        (file.layer == Layer::App).then(|| AppItem::in_file(file, name))
    }

    fn field_local(&self, field: &ExprField) -> Option<Local> {
        let member = match &field.member {
            Member::Named(member) => member.to_string(),
            Member::Unnamed(index) => index.index.to_string(),
        };
        if is_self(&field.base) {
            return self.self_fields.get(&member).cloned();
        }
        let base = self.expr_local(&field.base);
        if let Some(Local::Holder { fields, .. }) = &base {
            return fields.get(&member).cloned();
        }
        if let Some(Local::Type(name)) = &base {
            return self.known.app_type(name)?.1.get(&member).cloned();
        }
        let Some(Local::Ports { item, prefix }) = base else {
            return None;
        };
        self.known
            .ports_field_local(&item, &member, &prefix)
            .or_else(|| {
                Some(Local::Port(PortRef::held(
                    Some(format!("{prefix}{member}")),
                    &PortLookup::NotAPort,
                )))
            })
    }

    fn method_local(&self, call: &ExprMethodCall) -> Option<Local> {
        let name = call.method.to_string();
        if passes_through(&name) || RECOVERING.contains(&name.as_str()) {
            return self.expr_local(&call.receiver);
        }
        match self.expr_local(&call.receiver) {
            Some(Local::Items(item)) => return items_after(&name, item),
            Some(Local::Events(sources)) => return Some(Local::Events(sources)),
            Some(Local::Type(held)) if KEEPS_WHAT_IT_HOLDS.contains(&name.as_str()) => {
                return Some(Local::Type(held));
            }
            _ => {}
        }
        self.received_local(self.receiver(&call.receiver), &name)
    }

    /// What calling `name` on `receiver` hands back, read from the port,
    /// the use case's own method, or the type the receiver is.
    fn received_local(&self, receiver: Recv, name: &str) -> Option<Local> {
        match receiver {
            Recv::Port(port) => {
                let port = port.port.as_ref()?;
                match self.known.port_items(port, name) {
                    Some(items) => Some(Local::Items(items)),
                    None => self.known.port_returns(port, name).map(Local::Type),
                }
            }
            Recv::OwnSelf => self
                .scope
                .own_method(name)
                .and_then(|found| self.returned_local(&found)),
            Recv::Typed(owner) => self
                .known
                .app_type(&owner)
                .and_then(|(item, _)| self.known.method_of(&item, name))
                .and_then(|found| self.returned_local(&found))
                .or_else(|| self.known.returns(&owner, name).map(Local::Type)),
            Recv::Ports { item, .. } => self
                .known
                .method_of(&item, name)
                .and_then(|found| self.returned_local(&found)),
            Recv::Holder {
                item, type_name, ..
            } => item
                .and_then(|item| self.known.method_of(&item, name))
                .and_then(|found| self.returned_local(&found))
                .or_else(|| self.known.returns(&type_name, name).map(Local::Type)),
            Recv::Unknown(_) => None,
        }
    }

    /// What the app function `found` hands back: a port when its return
    /// type names one, such as `&Arc<dyn TlsProvisioner>`, items when it is
    /// a collection, its core type otherwise.
    fn returned_local(&self, found: &FnRef<'_>) -> Option<Local> {
        let syn::ReturnType::Type(_, returned) = &found.sig.output else {
            return None;
        };
        let lookup = self.known.port_in_type(found.file, returned);
        if lookup != PortLookup::NotAPort {
            return Some(Local::Port(PortRef::held(None, &lookup)));
        }
        let owner = found.owner.as_deref();
        returned_items(&found.sig.output, owner)
            .map(Local::Items)
            .or_else(|| returned_core(&found.sig.output, owner).map(Local::Type))
    }

    /// What a closure handed to a call on `receiver` is handed: an item of
    /// a collection, or what an `Option` or a `Result` holds.
    fn handed_to_closure(&self, receiver: &Expr) -> Option<Local> {
        match self.expr_local(receiver)? {
            Local::Items(item) | Local::Type(item) => Some(Local::Type(item)),
            _ => None,
        }
    }

    fn call_local(&self, call: &ExprCall) -> Option<Local> {
        let Expr::Path(function) = call.func.as_ref() else {
            return None;
        };
        match segments(&function.path).as_slice() {
            [name] => self.helper_returns(name),
            [.., owner, name] => self.path_returns(owner, name),
            [] => None,
        }
    }

    fn helper_returns(&self, name: &str) -> Option<Local> {
        let Lookup::Found(found) = self.scope.free_fn(self.known, name) else {
            return None;
        };
        returned_core(&found.sig.output, found.owner.as_deref()).map(Local::Type)
    }

    fn path_returns(&self, written: &str, name: &str) -> Option<Local> {
        let owner = self.owner_named(written);
        if self.known.behaviour(&owner, name) == Some(BehaviourKind::Create) {
            return Some(Local::Type(owner));
        }
        let returned = match self.own_function(&owner, name) {
            Some(found) => returned_core(&found.sig.output, found.owner.as_deref()),
            None => self.known.returns(&owner, name),
        };
        returned.map(Local::Type)
    }

    /// The function `name` of the body's own type, when `owner` is it.
    fn own_function(&self, owner: &str, name: &str) -> Option<FnRef<'a>> {
        self.scope
            .own_method(name)
            .filter(|_| self.scope.owner() == Some(owner))
    }

    /// The type `written` stands for here, `Self` read as the body's own.
    fn owner_named(&self, written: &str) -> String {
        match (written, self.scope.owner()) {
            ("Self", Some(owner)) => owner.to_owned(),
            _ => self.known.owner_named(written, self.scope.file().usage()),
        }
    }

    fn receiver(&self, expr: &Expr) -> Recv {
        if is_self(expr) {
            return Recv::OwnSelf;
        }
        match self.expr_local(expr) {
            Some(Local::Port(port)) => Recv::Port(port),
            Some(Local::Type(owner)) => Recv::Typed(owner),
            Some(Local::Ports { item, prefix }) => Recv::Ports { item, prefix },
            Some(Local::Holder {
                item,
                type_name,
                fields,
            }) => Recv::Holder {
                item,
                type_name,
                fields,
            },
            _ => Recv::Unknown(described(expr)),
        }
    }

    /// The helper a method call on `receiver` reaches, with what `self`
    /// is inside it.
    fn method_helper(&self, receiver: &Recv, name: &str) -> Option<(FnRef<'a>, HelperSelf)> {
        match receiver {
            Recv::OwnSelf => self
                .scope
                .own_method(name)
                .or_else(|| self.known.app_method(self.scope.owner()?, name))
                .map(|target| (target, HelperSelf::Own)),
            Recv::Ports { item, prefix } => self.known.method_of(item, name).map(|target| {
                let inside = HelperSelf::Ports {
                    item: item.clone(),
                    prefix: prefix.clone(),
                };
                (target, inside)
            }),
            Recv::Holder {
                item: Some(item),
                fields,
                ..
            } => self
                .known
                .method_of(item, name)
                .map(|target| (target, HelperSelf::Holder(fields.clone()))),
            Recv::Typed(owner) if owner != AUDITOR => {
                let (item, fields) = self.known.app_type(owner)?;
                let target = self.known.method_of(&item, name)?;
                Some((target, HelperSelf::Holder(fields)))
            }
            _ => None,
        }
    }

    fn method_call(&mut self, call: &ExprMethodCall) {
        let outer = self
            .calls
            .current
            .replace(std::ptr::from_ref(call) as usize);
        self.method_call_read(call);
        self.calls.current = outer;
    }

    fn method_call_read(&mut self, call: &ExprMethodCall) {
        let name = call.method.to_string();
        if passes_through(&name) || self.collected(call) || self.only_looks_at_events(call) {
            return;
        }
        let handed = CallArgs {
            args: &call.args,
            place: Place::of(self.scope.file(), &call.method),
        };
        let receiver = self.receiver(&call.receiver);
        let helper = self.method_helper(&receiver, &name);
        self.checks(&name, &handed, helper.is_some());
        if let Some((target, inside)) = helper {
            self.helper(target, handed, inside);
            return;
        }
        let site = CallSite {
            call,
            written: format!("{}.{name}(..)", described(&call.receiver)),
            place: handed.place,
        };
        self.limit_unread_at(&receiver, &site);
        self.call_on(receiver, site);
    }

    /// Notes a limit the call at `site` may check without reading, when
    /// `receiver` is a port method that takes one.
    fn limit_unread_at(&mut self, receiver: &Recv, site: &CallSite<'_>) {
        let limit_port = match receiver {
            Recv::Port(PortRef {
                port: Some(port), ..
            }) => self
                .known
                .port_takes(port, &site.call.method.to_string(), LIMIT_KINDS),
            _ => false,
        };
        let handed = CallArgs {
            args: &site.call.args,
            place: site.place.clone(),
        };
        self.limit_unread(&site.written, &handed, limit_port);
    }

    /// Reads the method call at `site` on `receiver`, which no helper
    /// answers: a dispatch, a port's method, a typed value's or one not
    /// followed.
    fn call_on(&mut self, receiver: Recv, site: CallSite<'_>) {
        let name = site.call.method.to_string();
        if DISPATCHING.contains(&name.as_str()) && !matches!(receiver, Recv::Port(_)) {
            let sources = self.sources_in(&site.call.args);
            self.note(
                Seen::Dispatch {
                    method: name,
                    sources,
                },
                site.place,
            );
            return;
        }
        match receiver {
            Recv::Port(port) => self.port_call(port, site),
            Recv::Typed(owner) => self.typed_call(owner, site),
            Recv::Unknown(receiver) => self.unknown_call(receiver, site.call, site.place),
            Recv::OwnSelf => self.unresolved(site.written, NO_OWN_METHOD, site.place),
            Recv::Ports { .. } => self.unresolved(site.written, NO_PORTS_METHOD, site.place),
            Recv::Holder { .. } => self.unresolved(site.written, NO_HOLDER_METHOD, site.place),
        }
    }

    /// Whether `call` is made on a list of events, such as
    /// `events.is_empty()` or `raised.map(..)`: a list sends nothing
    /// itself, only the auditor it is handed to does.
    fn only_looks_at_events(&self, call: &ExprMethodCall) -> bool {
        matches!(self.expr_local(&call.receiver), Some(Local::Events(_)))
    }

    /// Whether `call` gathers events into a local list, such as
    /// `events.extend(review.take_events())`: the list then holds them too,
    /// and those the reader cannot place say so.
    fn collected(&mut self, call: &ExprMethodCall) -> bool {
        if !COLLECTING.contains(&call.method.to_string().as_str()) {
            return false;
        }
        let Some(list) = bound_name(&call.receiver) else {
            return false;
        };
        let mut sources = match self.locals.get(&list) {
            Some(Local::Events(held)) => held.clone(),
            _ => Vec::new(),
        };
        let added = self.sources_in(&call.args);
        if added.is_empty() && sources.is_empty() {
            return false;
        }
        if added.is_empty() {
            sources.extend(call.args.iter().map(|arg| Source::Taken {
                type_name: None,
                receiver: described(arg),
            }));
        }
        sources.extend(added);
        self.locals.insert(list, Local::Events(sources));
        true
    }

    /// A call on a field of a `*Ports` struct: a port method, or a method of
    /// a value that is not a port, which the reader does not follow.
    fn port_call(&mut self, port: PortRef, site: CallSite<'_>) {
        let (call, written, place) = (site.call, site.written, site.place);
        match port.lookup() {
            PortLookup::NotAPort => self.unresolved(written.clone(), NOT_A_PORT, place.clone()),
            PortLookup::Unplaced(_) => {
                self.unresolved(written.clone(), UNPLACED_PORT, place.clone());
            }
            PortLookup::Found(_) => {}
        }
        let values = call.args.iter().map(value_path).collect();
        let method = call.method.to_string();
        let answers_whether = self.answers_whether_written(&port, &method);
        self.note(
            Seen::PortCall {
                port,
                method,
                values,
            },
            place.clone(),
        );
        if answers_whether {
            self.shape.push(Node::Unread(Unread {
                place,
                what: format!(
                    "`{written}` hands back whether it wrote anything, and the paths that branch on it are not told apart"
                ),
            }));
        }
    }

    /// Whether `port::method` writes to a store and hands back a `bool`:
    /// whether it wrote anything at all.
    fn answers_whether_written(&self, port: &PortRef, method: &str) -> bool {
        let answers = port
            .port
            .as_ref()
            .and_then(|item| self.known.port_returns(item, method));
        answers.as_deref() == Some("bool") && writes_to_store(port.trait_name.as_deref(), method)
    }

    fn typed_call(&mut self, owner: String, site: CallSite<'_>) {
        let name = site.call.method.to_string();
        if self.known.behaviour(&owner, &name) == Some(BehaviourKind::Change) {
            self.change_call(owner, name, site);
            return;
        }
        if owner == AUDITOR {
            return;
        }
        if self.known.holding_type(&owner).is_some() {
            self.unresolved(site.written, NO_HOLDER_METHOD, site.place);
            return;
        }
        self.handed_on(&site.written, &site.call.args, site.place);
    }

    /// A call of `owner`'s method `name` that changes it: noted, and its
    /// answer flagged when whether it raised events may hang on it.
    fn change_call(&mut self, owner: String, name: String, site: CallSite<'_>) {
        let CallSite {
            call,
            written,
            place,
        } = site;
        let kept = self
            .calls
            .current
            .is_none_or(|at| !self.calls.discarded.contains(&at));
        let answer = self
            .known
            .returns(&owner, &name)
            .filter(|returned| kept && !returned.ends_with("Error"))
            .filter(|returned| self.known.is_domain_enum(returned));
        let value = value_path(&call.receiver);
        self.note(Seen::Change { owner, name, value }, place.clone());
        if let Some(answer) = answer {
            self.shape.push(Node::Unread(Unread {
                place,
                what: format!(
                    "`{written}` hands back a `{answer}`, and whether it raised events may hang on it, which the reader does not follow"
                ),
            }));
        }
    }

    fn unknown_call(&mut self, receiver: String, call: &ExprMethodCall, place: Place) {
        let method = call.method.to_string();
        let written = format!("{receiver}.{method}(..)");
        if let Some(root) = self.reaching_root(&call.receiver) {
            let why = match root.as_str() {
                "self" => SELF_FIELD.to_owned(),
                _ => format!(
                    "it is called on a part of `{root}`, which holds ports or the auditor, whose type was not read"
                ),
            };
            self.note(Seen::Unresolved { call: written, why }, place);
            return;
        }
        let owners = self.known.change_owners(&method).to_vec();
        if owners.is_empty() {
            self.handed_on(&written, &call.args, place);
            return;
        }
        self.note(
            Seen::UnreadReceiver {
                receiver,
                method,
                owners,
            },
            place,
        );
    }

    /// The name `expr` is a part of, when it is `self` or a value that can
    /// reach a port or the auditor: `certificates` for
    /// `certificates.queue`.
    fn reaching_root(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Field(field) => self.reaching_root(&field.base),
            Expr::MethodCall(call) => {
                let answer = self.method_local(call);
                match self.receiver(&call.receiver) {
                    Recv::Port(_) => None,
                    _ if answer.as_ref().is_some_and(|local| !reaches_out(local)) => None,
                    _ => self.reaching_root(&call.receiver),
                }
            }
            Expr::Index(index) => self.reaching_root(&index.expr),
            Expr::Reference(inner) => self.reaching_root(&inner.expr),
            Expr::Paren(inner) => self.reaching_root(&inner.expr),
            Expr::Try(inner) => self.reaching_root(&inner.expr),
            Expr::Await(inner) => self.reaching_root(&inner.base),
            Expr::Path(path) => {
                let name = path.path.get_ident()?.to_string();
                let reaches = name == "self" || self.locals.get(&name).is_some_and(reaches_out);
                reaches.then_some(name)
            }
            _ => None,
        }
    }

    fn unresolved(&mut self, call: String, why: &str, place: Place) {
        let why = why.to_owned();
        self.note(Seen::Unresolved { call, why }, place);
    }

    /// Notes `written`, a call the reader does not follow, when one of
    /// `args` can reach a port, a `*Ports` struct, the auditor, events or
    /// `self`.
    fn handed_on(&mut self, written: &str, args: &Punctuated<Expr, Token![,]>, place: Place) {
        let Some(reaching) = args.iter().find_map(|arg| self.reaching(arg)) else {
            return;
        };
        let why = format!("it is handed `{reaching}`, and the reader does not follow it");
        self.note(
            Seen::Unresolved {
                call: written.to_owned(),
                why,
            },
            place,
        );
    }

    /// `arg` as written, when it can reach a port, a `*Ports` struct, the
    /// auditor, events or `self`: itself, or inside a closure.
    fn reaching(&self, arg: &Expr) -> Option<String> {
        if let Expr::Closure(closure) = arg {
            if self
                .calls
                .closures
                .contains(&(std::ptr::from_ref(closure) as usize))
            {
                return None;
            }
            let names = names_in_expr(&closure.body);
            let reaches = names
                .iter()
                .any(|name| name == "self" || self.locals.get(name).is_some_and(reaches_out));
            return reaches.then(|| "a closure".to_owned());
        }
        let held = is_self(arg) || self.expr_local(arg).as_ref().is_some_and(reaches_out);
        held.then(|| described(arg))
    }

    fn function_call(&mut self, call: &ExprCall) {
        let outer = self
            .calls
            .current
            .replace(std::ptr::from_ref(call) as usize);
        self.function_call_read(call);
        self.calls.current = outer;
    }

    fn function_call_read(&mut self, call: &ExprCall) {
        let Expr::Path(function) = call.func.as_ref() else {
            return;
        };
        let Some(last) = function.path.segments.last() else {
            return;
        };
        let handed = CallArgs {
            args: &call.args,
            place: Place::of(self.scope.file(), &last.ident),
        };
        match segments(&function.path).as_slice() {
            [name] => self.bare_call(name, handed),
            [type_path @ .., name] => self.path_call(type_path, name, handed),
            [] => {}
        }
    }

    fn bare_call(&mut self, name: &str, handed: CallArgs<'_>) {
        let lookup = match name.starts_with(|c: char| c.is_ascii_lowercase()) {
            true => self.scope.free_fn(self.known, name),
            false => Lookup::Elsewhere,
        };
        self.checks(name, &handed, matches!(lookup, Lookup::Found(_)));
        match lookup {
            Lookup::Found(target) => self.helper(target, handed, HelperSelf::Free),
            Lookup::NotRead(module) => self.note(
                Seen::UnreadHelper {
                    name: name.to_owned(),
                    module,
                },
                handed.place,
            ),
            Lookup::Elsewhere if HARMLESS.contains(&name) || builds_a_value(name) => {}
            Lookup::Elsewhere => {
                let written = format!("{name}(..)");
                self.limit_unread(&written, &handed, false);
                self.handed_on(&written, handed.args, handed.place);
            }
        }
    }

    /// Notes `written`, a call the reader does not follow, when the plan
    /// limit it checks is not read: a port method taking a `ResourceKind`
    /// handed none the reader read, or any call handed a `ResourceKind`
    /// whose variant the reader did not read.
    fn limit_unread(&mut self, written: &str, handed: &CallArgs<'_>, limit_port: bool) {
        let locals: Vec<Option<Local>> =
            handed.args.iter().map(|arg| self.expr_local(arg)).collect();
        let read = locals
            .iter()
            .any(|local| matches!(local, Some(Local::LimitKind { .. })));
        let unread = locals
            .iter()
            .any(|local| matches!(local, Some(Local::Type(name)) if name == LIMIT_KINDS));
        if !unread && (read || !limit_port) {
            return;
        }
        self.unresolved(written.to_owned(), LIMIT_UNREAD, handed.place.clone());
    }

    fn path_call(&mut self, type_path: &[String], name: &str, handed: CallArgs<'_>) {
        let Some(written) = type_path.last() else {
            return;
        };
        let owner = self.owner_named(written);
        let own = self.own_function(&owner, name);
        let app = match own {
            Some(_) => None,
            None => self.app_function(type_path, name),
        };
        self.checks(name, &handed, own.is_some() || app.is_some());
        if let Some(target) = own {
            self.helper(target, handed, HelperSelf::Own);
            return;
        }
        if let Some(target) = app {
            self.helper(target, handed, HelperSelf::Free);
            return;
        }
        if self.known.behaviour(&owner, name) == Some(BehaviourKind::Create) {
            let name = name.to_owned();
            let value = None;
            self.note(Seen::Change { owner, name, value }, handed.place);
            return;
        }
        if HARMLESS.contains(&owner.as_str()) {
            return;
        }
        let shown = format!("{written}::{name}(..)");
        self.limit_unread(&shown, &handed, false);
        self.handed_on(&shown, handed.args, handed.place);
    }

    /// The app function a path names where the body writes it: one a
    /// module path leads to, such as `sign_in_gate::admit`, or the function
    /// `name` of the app type `type_path` names, such as
    /// `TenantBatches::over`, declared in the type's own file. The app's
    /// error constructors build a value and are not followed.
    fn app_function(&self, type_path: &[String], name: &str) -> Option<FnRef<'a>> {
        if type_path.last().is_some_and(|owner| owner == ERRORS) {
            return None;
        }
        let full: Vec<String> = type_path.iter().cloned().chain([name.to_owned()]).collect();
        if let Some(found) = self.scope.path_fn(self.known, &full) {
            return Some(found);
        }
        let file = self.scope.file();
        let item = match self.known.modules().origin(file, type_path) {
            Origin::Declared(item) => item,
            Origin::Missing(_) | Origin::Outside => match type_path {
                [only] => self.local_type(only)?,
                _ => return None,
            },
        };
        self.known.method_of(&item, name)
    }

    /// The rights and limits the call `name` handed `args` checks. A call
    /// the reader follows keeps only the rights written at it: the rest it
    /// reads inside.
    fn checks(&mut self, name: &str, handed: &CallArgs<'_>, followed: bool) {
        let checked = rights::checks_in(name, handed.args)
            .into_iter()
            .filter(|check| !followed || check.right.is_some());
        for check in checked {
            self.note(Seen::Right(check), handed.place.clone());
        }
        let kinds: Vec<String> = handed
            .args
            .iter()
            .filter_map(|arg| self.limit_read(arg))
            .collect();
        for kind in kinds {
            let call = name.to_owned();
            self.note(Seen::Limit { kind, call }, handed.place.clone());
        }
    }

    /// The plan limit `arg` names, written at the call or bound in this
    /// body; one a caller handed in was counted where it was handed.
    fn limit_read(&self, arg: &Expr) -> Option<String> {
        match self.expr_local(arg)? {
            Local::LimitKind {
                kind,
                handed: false,
            } => Some(kind),
            _ => None,
        }
    }

    fn helper(&mut self, target: FnRef<'a>, handed: CallArgs<'_>, receiver: HelperSelf) {
        let CallArgs { args, place } = handed;
        let futures = self.futures_handed(args);
        let values = args.iter().map(value_path).collect();
        let args = args.iter().map(|arg| self.local_of(arg)).collect();
        self.helpers.push(HelperCall {
            target,
            args,
            values,
            futures,
            receiver,
            place,
        });
        self.calls.helpers.push(self.calls.current);
        self.shape.push(Node::Helper {
            index: self.helpers.len() - 1,
            handed: Handed::Kept,
        });
    }

    /// The helpers `args` hand in as futures not yet run, by the argument's
    /// position: a helper called right there without `.await`, or one a
    /// `let` bound just before. Each is taken out of this body's shape, since
    /// it runs where the called helper runs it.
    fn futures_handed(&mut self, args: &Punctuated<Expr, Token![,]>) -> Vec<(usize, usize)> {
        let mut found = Vec::new();
        for (position, arg) in args.iter().enumerate().rev() {
            let future = self.calls.bound.as_ref().is_some_and(|bound| bound.future);
            let head = match (bound_name(arg), future) {
                (Some(name), true) => self.bound_head(&name),
                (None, _) if matches!(arg, Expr::Call(_) | Expr::MethodCall(_)) => {
                    self.split_head(arg)
                }
                (_, _) => None,
            };
            match head {
                Some(Node::Helper { index, .. }) if self.is_async(index) => {
                    found.push((position, index));
                }
                Some(other) => self.shape.push(other),
                None => {}
            }
        }
        found
    }

    /// Whether the helper at `index` is an `async fn`, whose call makes a
    /// future that runs only where it is awaited.
    fn is_async(&self, index: usize) -> bool {
        self.helpers
            .get(index)
            .is_some_and(|helper| helper.target.sig.asyncness.is_some())
    }

    fn errors_written(&mut self, path: &syn::Path) {
        let names = segments(path);
        let written: Vec<String> = names
            .windows(2)
            .filter(|pair| {
                pair[0] == ERRORS && pair[1].starts_with(|c: char| c.is_ascii_uppercase())
            })
            .map(|pair| pair[1].clone())
            .collect();
        let Some(first) = path.segments.first() else {
            return;
        };
        let place = Place::at(self.scope.file(), line_of(&first.ident));
        for variant in written {
            self.note(Seen::Error(variant), place.clone());
        }
    }

    fn sources_in<'e>(&self, exprs: impl IntoIterator<Item = &'e Expr>) -> Vec<Source> {
        let mut finder = Sources {
            reading: self,
            found: Vec::new(),
        };
        for expr in exprs {
            finder.visit_expr(expr);
        }
        finder.found
    }

    /// The listed observation `call` calls by its path, if it is one.
    fn observation(&self, call: &ExprCall) -> Option<Source> {
        let Expr::Path(function) = call.func.as_ref() else {
            return None;
        };
        let names = segments(&function.path);
        let [.., written, name] = names.as_slice() else {
            return None;
        };
        let owner = self.owner_named(written);
        self.known
            .raising()
            .is_observation(Some(&owner), name)
            .then(|| Source::Observed {
                owner,
                name: name.clone(),
            })
    }
}

impl<'ast> Visit<'ast> for Reading<'_, '_> {
    fn visit_item(&mut self, _item: &'ast Item) {}

    fn visit_expr(&mut self, expr: &'ast Expr) {
        let before = self.helpers.len();
        visit::visit_expr(self, expr);
        if self.tails.contains(&address(expr)) {
            let place = Place::of(self.scope.file(), expr);
            self.hand_back(expr, before, place);
        }
    }

    fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
        if let syn::Stmt::Expr(expr, Some(_)) = statement {
            let dropped = match expr {
                Expr::Try(tried) => call_address(&tried.expr),
                other => call_address(other),
            };
            self.calls.discarded.extend(dropped);
        }
        visit::visit_stmt(self, statement);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        self.mark_bound(&local.pat);
        let Some(init) = &local.init else {
            self.forget_kept(&local.pat);
            self.bind(&local.pat, None);
            return;
        };
        let first_fact = self.seen.len();
        self.visit_expr(&init.expr);
        self.forget_kept(&local.pat);
        self.name_created(first_fact, &local.pat);
        let side = result_side(&local.pat);
        let head = self.local_head(local, init, side);
        let otherwise = (init.diverge.as_ref()).map(|(_, diverge)| self.diverging(diverge));
        let carried_on = Node::Seq(Vec::new());
        match (head, side, otherwise) {
            (Some(head), Some(Side::Err), Some(otherwise)) => {
                self.push_split(head, otherwise, carried_on)
            }
            (Some(head), _, Some(otherwise)) => self.push_split(head, carried_on, otherwise),
            (Some(head), _, None) => self.push_split(head, carried_on, Node::Seq(Vec::new())),
            (None, _, Some(otherwise)) => {
                self.shape.push(Node::Choice(vec![otherwise, carried_on]))
            }
            (None, _, None) => {
                self.remember_bound(&local.pat, &init.expr);
                self.remember_kept(&local.pat, &init.expr);
            }
        }
        self.bind(&local.pat, Some(&init.expr));
    }

    fn visit_expr_let(&mut self, binding: &'ast syn::ExprLet) {
        self.visit_expr(&binding.expr);
        self.bind(&binding.pat, Some(&binding.expr));
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if RECOVERING.contains(&call.method.to_string().as_str()) {
            self.recovered(call);
            return;
        }
        if drops_the_answer(call) {
            self.calls.discarded.extend(call_address(&call.receiver));
        }
        if RUNS_CLOSURES.contains(&call.method.to_string().as_str()) {
            self.closures_run(call);
            return;
        }
        if !self.opens_unit_by_port(call) {
            visit::visit_expr_method_call(self, call);
            self.method_call(call);
            return;
        }
        self.visit_expr(&call.receiver);
        let place = Place::of(self.scope.file(), &call.method);
        self.shape.open();
        for arg in &call.args {
            self.unit_work(arg);
        }
        self.method_call(call);
        let inner = Box::new(self.shape.close());
        self.shape.push(Node::Unit {
            name: call.method.to_string(),
            place,
            inner,
        });
        self.calls.unit = Some(std::ptr::from_ref(call) as usize);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        let unit = match call.func.as_ref() {
            Expr::Path(path) => path
                .path
                .segments
                .last()
                .map(|last| last.ident.to_string())
                .filter(|name| UNITS.contains(&name.as_str())),
            _ => None,
        };
        let Some(name) = unit else {
            visit::visit_expr_call(self, call);
            self.function_call(call);
            return;
        };
        let place = Place::of(self.scope.file(), call);
        let made_before = self.made_before(call);
        self.shape.open();
        for (arg, made) in call.args.iter().zip(made_before) {
            match made {
                Some(work) => self.shape.push(handed_back(work)),
                None => self.unit_work(arg),
            }
        }
        let inner = Box::new(self.shape.close());
        self.shape.push(Node::Unit { name, place, inner });
        self.calls.unit = Some(std::ptr::from_ref(call) as usize);
    }

    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        self.visit_expr(&branch.cond);
        let head = self.matched_head(&branch.cond);
        let narrowed = self.narrowing(&branch.cond, 0);
        let place = Place::of(self.scope.file(), &branch.cond);
        self.shape.open();
        self.push_narrow(narrowed.as_ref().map(|found| (&found.0, &found.1)), &place);
        self.visit_block(&branch.then_branch);
        let then = self.shape.close();
        self.shape.open();
        self.push_narrow(narrowed.as_ref().map(|found| (&found.0, &found.2)), &place);
        if let Some((_, otherwise)) = &branch.else_branch {
            self.visit_expr(otherwise);
        }
        let otherwise = self.shape.close();
        match head {
            Some((head, Side::Err)) => self.push_split(head, otherwise, then),
            Some((head, _)) => self.push_split(head, then, otherwise),
            None => self.shape.push(Node::Choice(vec![then, otherwise])),
        }
    }

    fn visit_expr_match(&mut self, choice: &'ast syn::ExprMatch) {
        self.visit_expr(&choice.expr);
        let sides = arm_sides(&choice.arms);
        let head = sides.as_ref().and_then(|_| self.split_head(&choice.expr));
        let mut arms = Vec::new();
        for arm in &choice.arms {
            self.shape.open();
            let named = self.pattern_variants(&arm.pat);
            let place = Place::of(self.scope.file(), &arm.pat);
            self.push_narrow(
                named.as_ref().map(|(name, variants)| (name, variants)),
                &place,
            );
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            arms.push(self.shape.close());
        }
        let (Some(head), Some(sides)) = (head, sides) else {
            self.shape.push(Node::Choice(arms));
            return;
        };
        let (ok, err) = by_side(arms, &sides);
        self.push_split(head, Node::Choice(ok), Node::Choice(err));
    }

    fn visit_expr_for_loop(&mut self, looped: &'ast syn::ExprForLoop) {
        self.visit_expr(&looped.expr);
        let item = match self.expr_local(&looped.expr) {
            Some(Local::Items(item)) => Some(Local::Type(item)),
            _ => None,
        };
        self.bind_local(unreferenced(&looped.pat), item);
        self.shape.open();
        self.mark_bound(&looped.pat);
        self.visit_block(&looped.body);
        let body = Box::new(self.shape.close());
        self.shape.push(Node::Loop {
            body,
            at_least_once: false,
        });
    }

    fn visit_expr_while(&mut self, looped: &'ast syn::ExprWhile) {
        self.shape.open();
        self.visit_expr(&looped.cond);
        self.visit_block(&looped.body);
        let body = Box::new(self.shape.close());
        self.shape.push(Node::Loop {
            body,
            at_least_once: false,
        });
    }

    fn visit_expr_loop(&mut self, looped: &'ast syn::ExprLoop) {
        self.shape.open();
        self.visit_block(&looped.body);
        let body = Box::new(self.shape.close());
        self.shape.push(Node::Loop {
            body,
            at_least_once: true,
        });
    }

    fn visit_expr_break(&mut self, leaving: &'ast syn::ExprBreak) {
        visit::visit_expr_break(self, leaving);
        self.shape.push(Node::LoopExit);
    }

    fn visit_expr_continue(&mut self, _leaving: &'ast syn::ExprContinue) {
        self.shape.push(Node::LoopExit);
    }

    fn visit_expr_return(&mut self, back: &'ast syn::ExprReturn) {
        let before = self.helpers.len();
        visit::visit_expr_return(self, back);
        let place = Place::of(self.scope.file(), back);
        match &back.expr {
            Some(value) => self.hand_back(value, before, place),
            None => self.shape.push(Node::Exit(Exit::Value, place)),
        }
    }

    fn visit_expr_try(&mut self, tried: &'ast syn::ExprTry) {
        let before = self.helpers.len();
        self.visit_expr(&tried.expr);
        if self.hand_newest(&tried.expr, before, Handed::Tried) {
            return;
        }
        let place = Place::of(self.scope.file(), &tried.question_token);
        let leaves = Node::Seq(vec![Node::Exit(self.returns.tried(), place)]);
        let Some(head) = self.split_head(&tried.expr) else {
            self.hold_kept(&tried.expr);
            self.shape
                .push(Node::Choice(vec![leaves, Node::Seq(Vec::new())]));
            return;
        };
        self.push_split(head, Node::Seq(Vec::new()), leaves);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.shape.open();
        visit::visit_expr_closure(self, closure);
        self.unread_inside(closure, "a closure");
    }

    fn visit_expr_async(&mut self, block: &'ast syn::ExprAsync) {
        self.shape.open();
        visit::visit_expr_async(self, block);
        self.unread_inside(block, "an async block");
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.errors_written(path);
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.macro_call(mac);
        visit::visit_macro(self, mac);
    }
}

impl<'ast> Reading<'_, '_> {
    /// The call a `let` binding `local` matches on, when its pattern is a
    /// result side, or `_` with no `else`.
    fn local_head(
        &mut self,
        local: &syn::Local,
        init: &syn::LocalInit,
        side: Option<Side>,
    ) -> Option<Node> {
        match (&local.pat, side, &init.diverge) {
            (_, Some(Side::Ok | Side::Err), _) | (Pat::Wild(_), _, None) => {
                self.split_head(&init.expr)
            }
            _ => None,
        }
    }

    /// The flow of a `let .. else` block, which never carries on.
    fn diverging(&mut self, diverge: &'ast Expr) -> Node {
        self.shape.open();
        self.visit_expr(diverge);
        self.shape.push(Node::Halt);
        self.shape.close()
    }

    /// Reads `call`, whose closures run once for each item it goes over.
    fn closures_run(&mut self, call: &'ast ExprMethodCall) {
        self.visit_expr(&call.receiver);
        let handed = Handing {
            local: self.handed_to_closure(&call.receiver),
            at: match call.method.to_string().as_str() {
                "fold" | "try_fold" => 1,
                _ => 0,
            },
        };
        for arg in &call.args {
            self.closure_or_expr(arg, Runs::Repeatedly, &handed);
        }
        self.method_call(call);
    }

    /// For each argument of a unit of work's `call`, the work bound to it
    /// as a future before, if it names one.
    fn made_before(&mut self, call: &ExprCall) -> Vec<Option<Node>> {
        let future = self.calls.bound.as_ref().is_some_and(|bound| bound.future);
        (call.args.iter())
            .map(|arg| {
                bound_name(arg)
                    .filter(|_| future)
                    .and_then(|name| self.bound_head(&name))
            })
            .collect()
    }

    /// Marks the helper call `expr` is, the newest one since there were
    /// `before`, as `handed`; whether it was one.
    fn hand_newest(&mut self, expr: &Expr, before: usize, handed: Handed) -> bool {
        let address = result_address(expr);
        let newest = self.helpers.len();
        if address.is_none() || newest == before {
            return false;
        }
        let Some(Node::Helper {
            index,
            handed: marked,
        }) = self.shape.last_mut()
        else {
            return false;
        };
        if *index + 1 != newest || self.calls.helpers.get(*index) != Some(&address) {
            return false;
        }
        *marked = handed;
        true
    }

    /// Closes the shape of a closure or async block: whether or when it
    /// runs is not read, so one with facts inside is a not-read point.
    fn unread_inside(&mut self, node: &impl syn::spanned::Spanned, what: &str) {
        let inside = self.shape.close();
        if !self.holds_steps(&inside) {
            return;
        }
        self.shape.push(Node::Unread(Unread {
            place: Place::of(self.scope.file(), node),
            what: format!("{what} with steps inside: whether and when it runs is not read"),
        }));
    }

    /// Marks that from here on a value of `enum_name` is one of `variants`.
    fn push_narrow(&mut self, narrowed: Option<(&String, &BTreeSet<String>)>, place: &Place) {
        let Some((enum_name, variants)) = narrowed else {
            return;
        };
        self.shape.push(Node::Narrow {
            enum_name: enum_name.clone(),
            variants: variants.clone(),
            place: place.clone(),
        });
    }

    /// What `condition` says of a value of one of the domain's or the app's
    /// enums: the enum, the variants it is when the condition holds, and
    /// those it is when it does not. It reads `matches!(x, E::A | E::B)`,
    /// `x == E::A`, `!=`, `!`, and a call of a function whose body is such
    /// a condition, such as `owes_email_confirmation(owed)`.
    fn narrowing(&self, condition: &Expr, depth: usize) -> Option<Narrowing> {
        match condition {
            Expr::Paren(inner) => self.narrowing(&inner.expr, depth),
            Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Not(_)) => self
                .narrowing(&unary.expr, depth)
                .map(|(name, holds, fails)| (name, fails, holds)),
            Expr::Binary(binary) => self.compared(binary),
            Expr::Macro(invoked) if invoked.mac.path.is_ident("matches") => {
                let (_, pattern) = matched_parts(&invoked.mac)?;
                let (name, holds) = self.pattern_variants(&pattern)?;
                self.split_variants(name, holds)
            }
            Expr::Call(call) if depth == 0 => self.called_narrowing(call),
            Expr::MethodCall(call) if call.args.is_empty() => {
                let Some(Local::Type(name)) = self.expr_local(&call.receiver) else {
                    return None;
                };
                let holds = self.known.answers_true(&name, &call.method.to_string())?;
                self.split_variants(name, holds)
            }
            _ => None,
        }
    }

    fn compared(&self, binary: &syn::ExprBinary) -> Option<Narrowing> {
        let equal = match binary.op {
            syn::BinOp::Eq(_) => true,
            syn::BinOp::Ne(_) => false,
            _ => return None,
        };
        let (name, variant) = variant_path(&binary.right).or_else(|| variant_path(&binary.left))?;
        self.known.enum_variants(&name)?;
        let (name, holds, fails) = self.split_variants(name, BTreeSet::from([variant]))?;
        match equal {
            true => Some((name, holds, fails)),
            false => Some((name, fails, holds)),
        }
    }

    /// The narrowing of a function `call` calls whose body is one
    /// condition.
    fn called_narrowing(&self, call: &ExprCall) -> Option<Narrowing> {
        let Expr::Path(function) = call.func.as_ref() else {
            return None;
        };
        let name = function.path.get_ident()?.to_string();
        let Lookup::Found(target) = self.scope.free_fn(self.known, &name) else {
            return None;
        };
        let [syn::Stmt::Expr(condition, None)] = target.block.stmts.as_slice() else {
            return None;
        };
        self.narrowing(condition, 1)
    }

    /// `holds` of the enum `name` with the rest of its variants.
    fn split_variants(&self, name: String, holds: BTreeSet<String>) -> Option<Narrowing> {
        let all = self.known.enum_variants(&name)?;
        let fails = all
            .iter()
            .filter(|variant| !holds.contains(*variant))
            .cloned()
            .collect();
        Some((name, holds, fails))
    }

    /// The enum and its variants a pattern names, such as
    /// `SecondFactor::ConfirmByEmail | SecondFactor::ConfirmThenEnrol`.
    fn pattern_variants(&self, pattern: &Pat) -> Option<(String, BTreeSet<String>)> {
        let found = match pattern {
            Pat::Path(path) => vec![enum_variant(&path.path)?],
            Pat::TupleStruct(tuple) => vec![enum_variant(&tuple.path)?],
            Pat::Struct(fields) => vec![enum_variant(&fields.path)?],
            Pat::Paren(inner) => return self.pattern_variants(&inner.pat),
            Pat::Reference(inner) => return self.pattern_variants(&inner.pat),
            Pat::Or(choices) => choices
                .cases
                .iter()
                .map(|case| self.pattern_variants(case))
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .flat_map(|(name, variants)| {
                    variants
                        .into_iter()
                        .map(move |variant| (name.clone(), variant))
                })
                .collect(),
            _ => return None,
        };
        let name = found.first()?.0.clone();
        let all = self.known.enum_variants(&name)?;
        let same = found
            .iter()
            .all(|(enum_name, variant)| *enum_name == name && all.contains(variant));
        let variants = found.into_iter().map(|(_, variant)| variant).collect();
        same.then_some((name, variants))
    }

    /// Marks the name `pattern` binds as holding a new value from here on.
    fn mark_bound(&mut self, pattern: &Pat) {
        let Some(name) = bound_ident(unreferenced(pattern)) else {
            return;
        };
        self.shape
            .push(Node::Bound(name, Place::of(self.scope.file(), pattern)));
    }

    /// Names the values the creators called since the fact `first` made by
    /// the name `pattern` binds them to.
    fn name_created(&mut self, first: usize, pattern: &Pat) {
        let Some(name) = bound_ident(pattern) else {
            return;
        };
        let known = self.known;
        for found in self.seen.iter_mut().skip(first) {
            let Seen::Change {
                owner,
                name: change,
                value: value @ None,
            } = &mut found.seen
            else {
                continue;
            };
            if known.behaviour(owner, change) == Some(BehaviourKind::Create) {
                *value = Some(name.clone());
            }
        }
    }

    /// Whether `node` holds anything a question of the flow asks about: a
    /// step, a helper, a unit or a not-read point. Rights checked and
    /// errors written are on the card, not in the flow.
    fn holds_steps(&self, node: &Node) -> bool {
        match node {
            Node::Fact(index) => self
                .seen
                .get(*index)
                .is_some_and(|found| !matches!(found.seen, Seen::Right(_) | Seen::Error(_))),
            Node::Seq(parts) | Node::Choice(parts) => {
                parts.iter().any(|part| self.holds_steps(part))
            }
            Node::Loop { body, .. } => self.holds_steps(body),
            Node::Helper { .. }
            | Node::Unit { .. }
            | Node::Split { .. }
            | Node::Future(_)
            | Node::Unread(_) => true,
            Node::Exit(..)
            | Node::LoopExit
            | Node::Halt
            | Node::Bound(..)
            | Node::Narrow { .. } => false,
        }
    }

    /// Ends the path with what `expr` hands back, at `place`. A helper's
    /// exits become the caller's; a step's own result leaves with an error
    /// before the step and with success after it.
    fn hand_back(&mut self, expr: &Expr, before: usize, place: Place) {
        if self.hand_newest(expr, before, Handed::Back) {
            self.shape.push(Node::Exit(exit_of(expr), place));
            return;
        }
        let exit = exit_of(expr);
        let head = (exit == Exit::Value && self.returns == Returns::Result)
            .then(|| self.split_head(expr))
            .flatten();
        let Some(head) = head else {
            self.hold_kept(expr);
            self.shape.push(Node::Exit(exit, place));
            return;
        };
        let succeeded = Node::Seq(vec![Node::Exit(Exit::Ok, place.clone())]);
        let failed = Node::Seq(vec![Node::Exit(Exit::Err, place)]);
        self.push_split(head, succeeded, failed);
    }

    /// Takes out the node whose result `expr` is, when the shape ends with
    /// it: a step's fact, a helper or a unit of work called by `expr`
    /// itself, or one a `let` just bound to the name `expr` is.
    fn split_head(&mut self, expr: &Expr) -> Option<Node> {
        if let Some(name) = bound_name(expr) {
            return self.bound_head(&name);
        }
        let address = call_address(expr)?;
        let matches = match self.shape.last()? {
            Node::Fact(index) => {
                self.calls.facts.get(*index) == Some(&Some(address))
                    && self
                        .seen
                        .get(*index)
                        .is_some_and(|found| found.seen.is_step())
            }
            Node::Helper { index, .. } => self.calls.helpers.get(*index) == Some(&Some(address)),
            Node::Unit { .. } => self.calls.unit == Some(address),
            _ => false,
        };
        matches.then(|| self.shape.pop()).flatten()
    }

    /// The node a `let` bound to `name` right before, when nothing ran
    /// since.
    fn bound_head(&mut self, name: &str) -> Option<Node> {
        let bound = self.calls.bound.take()?;
        (bound.name == name && bound.mark == self.shape.mark())
            .then(|| self.shape.pop())
            .flatten()
    }

    /// Remembers that `pattern`, a plain name, holds what the call the
    /// shape ends with hands back, so a `match` on it, or a unit or helper
    /// it is handed to, right after picks the call up.
    fn remember_bound(&mut self, pattern: &Pat, init: &Expr) {
        let Pat::Ident(name) = pattern else {
            return;
        };
        if call_address(init).is_none() {
            return;
        }
        self.calls.bound = Some(Bound {
            name: name.ident.to_string(),
            mark: self.shape.mark(),
            future: matches!(init, Expr::Call(_) | Expr::MethodCall(_)),
        });
    }

    /// Remembers that `pattern`, a plain name, holds what the newest
    /// helper hands back, when `init` is that helper's call.
    fn remember_kept(&mut self, pattern: &Pat, init: &Expr) {
        let Pat::Ident(name) = pattern else {
            return;
        };
        let Some(index) = self.helpers.len().checked_sub(1) else {
            return;
        };
        let address = result_address(init);
        if address.is_none() || self.calls.helpers.get(index) != Some(&address) {
            return;
        }
        self.calls.kept_in.insert(name.ident.to_string(), index);
    }

    /// Forgets the helper a name `pattern` binds anew held before.
    fn forget_kept(&mut self, pattern: &Pat) {
        if let Some(name) = bound_ident(unreferenced(pattern)) {
            self.calls.kept_in.remove(&name);
        }
    }

    /// Marks the helper whose result the name `expr` holds as held: the
    /// body hands the name back as its own, or passes its error on.
    fn hold_kept(&mut self, expr: &Expr) {
        let Some(index) = bound_name(expr).and_then(|name| self.calls.kept_in.get(&name).copied())
        else {
            return;
        };
        self.calls.held.insert(index);
    }

    /// The node and side an `if let Ok(..) = call` or `if let Err(..) =
    /// call` condition is about.
    fn matched_head(&mut self, condition: &Expr) -> Option<(Node, Side)> {
        let Expr::Let(binding) = condition else {
            return None;
        };
        let side = result_side(&binding.pat).filter(|side| *side != Side::Both)?;
        Some((self.split_head(&binding.expr)?, side))
    }

    /// Reads `call`, which turns an error into a value and goes on, such as
    /// `helper().await.unwrap_or_else(|error| ..)`: what it is handed runs
    /// only once its receiver failed.
    fn recovered(&mut self, call: &'ast ExprMethodCall) {
        self.visit_expr(&call.receiver);
        let head = self.split_head(&call.receiver);
        self.shape.open();
        let handed = Handing { local: None, at: 0 };
        for arg in &call.args {
            self.closure_or_expr(arg, Runs::Once, &handed);
        }
        let failed = self.shape.close();
        match head {
            Some(head) => self.push_split(head, Node::Seq(Vec::new()), failed),
            None => self
                .shape
                .push(Node::Choice(vec![failed, Node::Seq(Vec::new())])),
        }
    }

    /// Reads `arg`: a closure's body as a part of the flow that runs as
    /// `runs` says, its own exits leaving only the closure; anything else
    /// as it is.
    fn closure_or_expr(&mut self, arg: &'ast Expr, runs: Runs, handed: &Handing) {
        let Expr::Closure(closure) = arg else {
            self.visit_expr(arg);
            return;
        };
        let outside = self.locals.clone();
        for (position, input) in closure.inputs.iter().enumerate() {
            let local = handed.local.clone().filter(|_| position == handed.at);
            self.bind_local(unreferenced(input), local);
        }
        self.shape.open();
        for input in &closure.inputs {
            self.mark_bound(input);
        }
        self.visit_expr(&closure.body);
        self.locals = outside;
        let body = exits_replaced(self.shape.close(), &runs.leaving());
        self.calls
            .closures
            .insert(std::ptr::from_ref(closure) as usize);
        if !self.holds_steps(&body) {
            return;
        }
        match runs {
            Runs::Once => self.shape.push(body),
            Runs::Repeatedly => self.shape.push(Node::Loop {
                body: Box::new(body),
                at_least_once: false,
            }),
        }
    }

    fn push_split(&mut self, head: Node, ok: Node, err: Node) {
        self.shape.push(Node::Split {
            head: Box::new(head),
            ok: Box::new(ok),
            err: Box::new(err),
        });
    }

    /// Whether `call` is `run` on the unit-of-work port.
    fn opens_unit_by_port(&self, call: &ExprMethodCall) -> bool {
        call.method == "run"
            && matches!(
                self.receiver(&call.receiver),
                Recv::Port(PortRef { trait_name: Some(name), .. }) if name == UNIT_PORT
            )
    }

    /// Reads what a unit of work is handed as running inside it: a
    /// closure's or async block's body, through `Box::pin`, as part of the
    /// unit rather than as something unread; a helper it is handed hands
    /// its result back as the unit's.
    fn unit_work(&mut self, arg: &'ast Expr) {
        let before = self.helpers.len();
        match arg {
            Expr::Closure(closure) => self.unit_work(&closure.body),
            Expr::Async(block) => self.visit_block(&block.block),
            Expr::Call(call) if pins(call) => {
                for inner in &call.args {
                    self.unit_work(inner);
                }
            }
            other => match self.handed_future(other) {
                Some(param) => self.shape.push(Node::Future(param)),
                None => {
                    self.visit_expr(other);
                    self.hand_newest(other, before, Handed::Back);
                }
            },
        }
    }

    /// The parameter `expr` names, when it is a plain parameter of the body,
    /// which a caller may have handed a future in.
    fn handed_future(&self, expr: &Expr) -> Option<String> {
        let name = bound_name(expr)?;
        self.calls
            .params
            .iter()
            .flatten()
            .any(|param| *param == name)
            .then_some(name)
    }
}

/// The name of each parameter of `signature`, by position, `self` left out;
/// `None` for one taken apart by a pattern.
pub(super) fn param_names(signature: &Signature) -> Vec<Option<String>> {
    signature
        .inputs
        .iter()
        .filter_map(|input| match input {
            FnArg::Typed(typed) => Some(bound_ident(&typed.pat)),
            FnArg::Receiver(_) => None,
        })
        .collect()
}

/// The one name `pattern` binds a value to: `x`, `mut x`, `x: T`, or the
/// `x` of `Some(x)` or `Ok(x)`.
fn bound_ident(pattern: &Pat) -> Option<String> {
    match pattern {
        Pat::Ident(name) if name.subpat.is_none() => Some(name.ident.to_string()),
        Pat::Type(typed) => bound_ident(&typed.pat),
        Pat::TupleStruct(wrapped) if unwraps(wrapped) => bound_ident(&wrapped.elems[0]),
        _ => None,
    }
}

/// The value `expr` names, as a place in memory: a name, or fields of one,
/// such as `domain` for `&mut domain` and `within.tenant`; `None` for any
/// other expression.
fn value_path(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reference(inner) => value_path(&inner.expr),
        Expr::Paren(inner) => value_path(&inner.expr),
        Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => value_path(&unary.expr),
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        Expr::Field(field) => {
            let Member::Named(member) = &field.member else {
                return None;
            };
            Some(format!("{}.{member}", value_path(&field.base)?))
        }
        _ => None,
    }
}

/// `work`, a future made before the unit it runs in, as the unit runs it: a
/// helper hands its result back as the unit's.
fn handed_back(work: Node) -> Node {
    match work {
        Node::Helper { index, .. } => Node::Helper {
            index,
            handed: Handed::Back,
        },
        other => other,
    }
}

/// The address of the call `expr` is, once what only passes its value on
/// is taken off.
fn call_address(expr: &Expr) -> Option<usize> {
    match called(expr, passes_through) {
        Expr::MethodCall(call) => Some(std::ptr::from_ref(call) as usize),
        Expr::Call(call) => Some(std::ptr::from_ref(call) as usize),
        _ => None,
    }
}

/// Whether `call` drops what its receiver answers: `.map(drop)`.
fn drops_the_answer(call: &ExprMethodCall) -> bool {
    call.method == "map"
        && matches!(call.args.first(), Some(Expr::Path(path)) if path.path.is_ident("drop"))
}

/// Whether a call of the bare name `name` builds a value: a tuple struct or
/// a variant, written with a capital, which holds what it is handed and
/// calls nothing.
fn builds_a_value(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_uppercase())
}

/// The address of the call whose result `expr` hands on: through what only
/// passes a value on, and through `.map(..)`, which keeps a result's error.
fn result_address(expr: &Expr) -> Option<usize> {
    match called(expr, |name| passes_through(name) || name == "map") {
        Expr::MethodCall(call) => Some(std::ptr::from_ref(call) as usize),
        Expr::Call(call) => Some(std::ptr::from_ref(call) as usize),
        _ => None,
    }
}

/// The plain name `expr` is, as a scrutinee.
fn bound_name(expr: &Expr) -> Option<String> {
    let Expr::Path(path) = called(expr, passes_through) else {
        return None;
    };
    path.path.get_ident().map(ToString::to_string)
}

/// The side of a result `pattern` takes: `Ok(..)`, `Err(..)`, or either
/// for `_` and a plain name; `None` for any other pattern.
fn result_side(pattern: &Pat) -> Option<Side> {
    match pattern {
        Pat::TupleStruct(wrapped) => match wrapped.path.segments.last()?.ident.to_string().as_str()
        {
            "Ok" => Some(Side::Ok),
            "Err" => Some(Side::Err),
            _ => None,
        },
        Pat::Wild(_) => Some(Side::Both),
        Pat::Ident(name) if name.subpat.is_none() => Some(Side::Both),
        _ => None,
    }
}

/// The side each arm takes, when every arm takes one and some arm names
/// `Ok` or `Err`.
fn arm_sides(arms: &[syn::Arm]) -> Option<Vec<Side>> {
    let sides: Vec<Side> = arms
        .iter()
        .map(|arm| result_side(&arm.pat))
        .collect::<Option<_>>()?;
    sides
        .iter()
        .any(|side| *side != Side::Both)
        .then_some(sides)
}

/// The arms' shapes sorted by the side each takes, those of either side in
/// both.
fn by_side(arms: Vec<Node>, sides: &[Side]) -> (Vec<Node>, Vec<Node>) {
    let mut ok = Vec::new();
    let mut err = Vec::new();
    for (arm, side) in arms.into_iter().zip(sides) {
        match side {
            Side::Ok => ok.push(arm),
            Side::Err => err.push(arm),
            Side::Both => {
                ok.push(arm.clone());
                err.push(arm);
            }
        }
    }
    (ok, err)
}

/// Whether `call` is `Box::pin(..)`.
fn pins(call: &ExprCall) -> bool {
    matches!(call.func.as_ref(), Expr::Path(path)
        if path.path.segments.last().is_some_and(|last| last.ident == "pin"))
}

impl Reading<'_, '_> {
    /// Notes a macro whose tokens name `self` or a value that can reach a
    /// port or the auditor: the calls inside it are not read.
    fn macro_call(&mut self, mac: &syn::Macro) {
        let Some(name) = mac.path.segments.last().map(|last| last.ident.to_string()) else {
            return;
        };
        if TEXT_MACROS.contains(&name.as_str()) {
            return;
        }
        let mut names = Vec::new();
        token_idents(mac.tokens.clone(), &mut names);
        let reaches = names
            .iter()
            .any(|found| found == "self" || self.locals.get(found).is_some_and(reaches_out));
        if !reaches {
            return;
        }
        let place = Place::at(self.scope.file(), line_of(&mac.path));
        self.unresolved(format!("{name}!(..)"), IN_A_MACRO, place);
    }
}

/// Macros that only build text, compare or check, and call nothing.
const TEXT_MACROS: &[&str] = &[
    "format",
    "write",
    "writeln",
    "println",
    "eprintln",
    "debug",
    "info",
    "warn",
    "error",
    "trace",
    "matches",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "concat",
    "panic",
];

/// Why the calls of a macro were not followed.
const IN_A_MACRO: &str = "calls inside a macro are not read";

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

/// Finds where the events in an expression come from.
struct Sources<'s, 'r, 'a> {
    reading: &'s Reading<'r, 'a>,
    found: Vec<Source>,
}

impl<'ast> Visit<'ast> for Sources<'_, '_, '_> {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == TAKING {
            let type_name = match self.reading.receiver(&call.receiver) {
                Recv::Typed(owner) => Some(owner),
                _ => None,
            };
            self.found.push(Source::Taken {
                type_name,
                receiver: described(&call.receiver),
            });
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        self.found.extend(self.reading.observation(call));
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        let held = path
            .path
            .get_ident()
            .and_then(|name| self.reading.locals.get(&name.to_string()));
        if let Some(Local::Events(sources)) = held {
            self.found.extend(sources.iter().cloned());
        }
        visit::visit_expr_path(self, path);
    }
}

/// Every name a pattern binds.
#[derive(Default)]
struct PatNames {
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for PatNames {
    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        self.found.push(pattern.ident.to_string());
        visit::visit_pat_ident(self, pattern);
    }
}

/// Whether a value can reach a port, the auditor or events to dispatch.
pub(super) fn reaches_out(local: &Local) -> bool {
    match local {
        Local::Port(_) | Local::Ports { .. } | Local::Events(_) | Local::Holder { .. } => true,
        Local::Type(name) => name == AUDITOR,
        Local::Items(_) | Local::LimitKind { .. } => false,
    }
}

/// `local` as a helper's parameter holds it: a plan limit the caller
/// handed in was counted where it was handed.
fn handed_in(local: Local) -> Local {
    match local {
        Local::LimitKind { kind, .. } => Local::LimitKind { kind, handed: true },
        other => other,
    }
}

fn passes_through(name: &str) -> bool {
    name.starts_with("or_") || PASSING.contains(&name)
}

/// Whether `pattern` is `Some(x)` or `Ok(x)`, which binds what the value
/// wraps.
fn unwraps(pattern: &syn::PatTupleStruct) -> bool {
    let wrapper = pattern
        .path
        .segments
        .last()
        .is_some_and(|last| last.ident == "Some" || last.ident == "Ok");
    wrapper && pattern.elems.len() == 1
}

fn is_self(expr: &Expr) -> bool {
    match expr {
        Expr::Paren(inner) => is_self(&inner.expr),
        Expr::Reference(inner) => is_self(&inner.expr),
        Expr::Path(path) => path.path.is_ident("self"),
        _ => false,
    }
}

/// An expression as a card shows it: `subscription`, `self.ports.store`,
/// `member.account()`, or `a value`.
fn described(expr: &Expr) -> String {
    match expr {
        Expr::Paren(inner) => described(&inner.expr),
        Expr::Reference(inner) => described(&inner.expr),
        Expr::Path(path) => segments(&path.path).join("::"),
        Expr::Field(field) => match &field.member {
            Member::Named(member) => format!("{}.{member}", described(&field.base)),
            Member::Unnamed(index) => format!("{}.{}", described(&field.base), index.index),
        },
        Expr::MethodCall(call) => format!("{}.{}()", described(&call.receiver), call.method),
        _ => "a value".to_owned(),
    }
}

fn segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

/// The `ResourceKind` variant an argument names, as `ResourceKind::Users`
/// or a reference to it.
fn limit_kind(arg: &Expr) -> Option<String> {
    match arg {
        Expr::Reference(inner) => limit_kind(&inner.expr),
        Expr::Paren(inner) => limit_kind(&inner.expr),
        Expr::Path(path) => match segments(&path.path).as_slice() {
            [.., owner, kind] if owner == LIMIT_KINDS => Some(kind.clone()),
            _ => None,
        },
        _ => None,
    }
}
