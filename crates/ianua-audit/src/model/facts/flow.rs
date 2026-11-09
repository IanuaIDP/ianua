//! A use case's flow: its body and the helpers it follows joined into one
//! tree of the steps it takes, in order, with its branches, loops, units
//! of work and exits, and the questions asked of it.
//!
//! Each body the facts read keeps its shape (see [`super::shape`]): its
//! facts and helper calls in the order they run, `if` and `match` as
//! choices, loops as bodies run any number of times (`loop` at least
//! once), and every early exit (`?`, `return`, the end of a `let .. else`,
//! `break` and `continue` for the loop they leave). A helper the facts
//! followed is put in at its call, as far down as they followed it; its
//! own exits hand back to the caller, and its error passes on when the
//! caller writes `?` after it. What the reader could not read is a not-read
//! point on the path: a call it did not follow, a closure, async block or
//! macro with facts inside, a helper too deep.
//!
//! A step whose own call fails took no effect: the error of `?` written
//! right on a port call, a domain change or a dispatch leaves before it,
//! and so does the error a body hands back as that call's own result. A
//! result the caller keeps and matches on (`match`, `if let`, `let ..
//! else`, `let _ =`) splits the path: what follows its `Ok` side runs only
//! after it succeeded, and what follows its `Err` side only after it
//! failed.
//!
//! A question asked of the flow answers yes or no only along paths with
//! no not-read point. When the answer would rest on one, it is unknown,
//! and says which point it rested on.

use std::collections::{BTreeMap, BTreeSet};

use super::UseCaseFacts;
use super::body::{Seen, SeenAt};
pub(crate) use super::shape::Handed;
use super::shape::Node;
use crate::model::paths::AppItem;
use crate::source::Place;

/// A point the reader did not read: where it is, and what it is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Unread {
    /// Where.
    pub(crate) place: Place,
    /// What, in words.
    pub(crate) what: String,
}

/// How a function leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Exit {
    /// It hands back `Ok(..)`.
    Ok,
    /// It hands back `Err(..)`, or passes an error on with `?`.
    Err,
    /// It hands back a value the reader does not know: `Ok` or `Err`.
    Value,
}

/// One step a use case takes that the questions ask about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// A port method called.
    Port {
        /// The port trait's name, when known.
        trait_name: Option<String>,
        /// The port trait, when the reader knows which.
        port: Option<AppItem>,
        /// The method.
        method: String,
        /// The value each argument names, told apart across helpers;
        /// `None` for one the reader cannot name.
        values: Vec<Option<String>>,
    },
    /// A domain creator or change called.
    Change {
        /// The aggregate.
        owner: String,
        /// The creator or change.
        name: String,
        /// The value it changes or makes, when named.
        value: Option<String>,
    },
    /// A plan limit checked.
    Limit {
        /// The `ResourceKind` variant.
        kind: String,
    },
    /// Events dispatched.
    Dispatch,
    /// A name bound to a new value: what it named before is another value.
    Bound {
        /// The value it names from here on.
        value: Option<String>,
    },
    /// From here on a value of this enum is one of these variants: the
    /// path went through a branch that said so.
    Narrow {
        /// The enum, by its last name.
        enum_name: String,
        /// The variants it may still be.
        variants: BTreeSet<String>,
    },
}

/// A step, where it is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Point {
    /// The step.
    pub(crate) step: Step,
    /// Where.
    pub(crate) place: Place,
}

/// A use case's flow.
#[derive(Clone, Debug, Default)]
pub(crate) enum Flow {
    /// A step.
    Point(Point),
    /// Nothing the questions ask about.
    #[default]
    Nothing,
    /// Parts in order.
    Seq(Vec<Flow>),
    /// One of these runs.
    Choice(Vec<Flow>),
    /// A loop's body, run any number of times, or at least once.
    Loop {
        /// The body.
        body: Box<Flow>,
        /// Whether it runs at least once.
        at_least_once: bool,
    },
    /// The function leaves.
    Exit(Exit, Place),
    /// This run of a loop's body ends.
    LoopExit,
    /// The path goes no further.
    Halt,
    /// A helper's body, put in at its call.
    Call {
        /// The body.
        inner: Box<Flow>,
        /// What the caller does with what it hands back.
        handed: Handed,
        /// The helper, as it is called.
        called: Called,
    },
    /// A call whose result the caller matches on: what follows its success
    /// and what follows its failure.
    Split {
        /// The call: a step, or a helper's body.
        head: Box<Flow>,
        /// What runs once it succeeded.
        ok: Box<Flow>,
        /// What runs once it failed.
        err: Box<Flow>,
    },
    /// A unit of work around what it runs.
    Unit {
        /// The function or method that opens it.
        name: String,
        /// Where.
        place: Place,
        /// What runs inside.
        inner: Box<Flow>,
    },
    /// Something the reader did not read.
    Unread(Unread),
}

impl Flow {
    /// This flow with each part inside it mapped by `part`, its shape and
    /// every step in it kept.
    pub(crate) fn with_parts(&self, part: impl Fn(&Flow) -> Flow) -> Flow {
        match self {
            Self::Seq(parts) => Self::Seq(parts.iter().map(&part).collect()),
            Self::Choice(parts) => Self::Choice(parts.iter().map(&part).collect()),
            Self::Split { head, ok, err } => Self::Split {
                head: Box::new(part(head)),
                ok: Box::new(part(ok)),
                err: Box::new(part(err)),
            },
            Self::Loop { .. } | Self::Call { .. } | Self::Unit { .. } => self.with_inner(part),
            Self::Point(_)
            | Self::Nothing
            | Self::Exit(..)
            | Self::LoopExit
            | Self::Halt
            | Self::Unread(_) => self.clone(),
        }
    }

    /// This loop, call or unit of work with what runs inside it mapped by
    /// `part`; any other flow as it is.
    fn with_inner(&self, part: impl Fn(&Flow) -> Flow) -> Flow {
        match self {
            Self::Loop {
                body,
                at_least_once,
            } => Self::Loop {
                body: Box::new(part(body)),
                at_least_once: *at_least_once,
            },
            Self::Call {
                inner,
                handed,
                called,
            } => Self::Call {
                inner: Box::new(part(inner)),
                handed: *handed,
                called: called.clone(),
            },
            Self::Unit { name, place, inner } => Self::Unit {
                name: name.clone(),
                place: place.clone(),
                inner: Box::new(part(inner)),
            },
            _ => self.clone(),
        }
    }
}

/// A helper put into the flow, as its caller calls it.
#[derive(Clone, Debug)]
pub(crate) struct Called {
    /// Its name as `via` shows it.
    label: String,
    /// Where it is called.
    place: Place,
}

impl Called {
    /// The point an error the caller keeps becomes: what it does with it is
    /// not read.
    fn kept_error(&self) -> Unread {
        self.unread("the caller keeps its error, and what it does with it is not read")
    }

    fn unread(&self, why: &str) -> Unread {
        Unread {
            place: self.place.clone(),
            what: format!("`{}`: {why}", self.label),
        }
    }
}

/// A function the facts read, by its file, owner and name.
pub(super) type FnKey = (String, Option<String>, String);

/// One helper a body calls, as the flow joins it.
pub(super) struct HelperAt {
    /// The helper.
    pub(super) key: FnKey,
    /// Whether the facts went no further because it was too deep.
    pub(super) too_deep: bool,
    /// Its name as `via` shows it.
    pub(super) label: String,
    /// Where it is called.
    pub(super) place: Place,
    /// The value each argument names, by position.
    pub(super) values: Vec<Option<String>>,
    /// The caller's helpers handed in as futures, as the argument's
    /// position and the caller's helper.
    pub(super) futures: Vec<(usize, usize)>,
}

/// One body as the facts read it, to join into a flow.
pub(super) struct BodyFlow {
    /// Its shape.
    pub(super) shape: Node,
    /// Its facts.
    pub(super) seen: Vec<SeenAt>,
    /// Each helper it calls.
    pub(super) helpers: Vec<HelperAt>,
    /// The name of each of its parameters, by position, `self` left out.
    pub(super) params: Vec<Option<String>>,
}

/// How the values one body names are told apart from another's: a
/// helper's parameter is the value its caller handed in, a name of its own
/// is its own, and `self` is shared.
#[derive(Clone, Debug, Default)]
struct Values {
    /// Each parameter, with the caller's value it holds, if named.
    handed: BTreeMap<String, Option<String>>,
    /// What the body's own names are prefixed with.
    own: String,
}

impl Values {
    /// The value `path`, written in this body, names across the flow.
    fn of(&self, path: &str) -> Option<String> {
        let (root, rest) = path
            .split_once('.')
            .map_or((path, None), |(root, rest)| (root, Some(rest)));
        let root = match self.handed.get(root) {
            Some(handed) => handed.clone()?,
            None if root == "self" => root.to_owned(),
            None => format!("{}{root}", self.own),
        };
        Some(match rest {
            Some(rest) => format!("{root}.{rest}"),
            None => root,
        })
    }

    /// The values inside `helper`, whose parameters are `params`.
    fn inside(&self, helper: &HelperAt, params: &[Option<String>]) -> Self {
        let handed = params
            .iter()
            .zip(&helper.values)
            .filter_map(|(param, value)| {
                let value = value.as_ref().and_then(|value| self.of(value));
                Some((param.clone()?, value))
            })
            .collect();
        Self {
            handed,
            own: format!("{}{}>", self.own, helper.label),
        }
    }
}

/// What a body is joined with: how its values are told apart, and the
/// futures its caller handed in, by parameter.
#[derive(Default)]
struct Context {
    values: Values,
    futures: BTreeMap<String, Flow>,
}

/// Joins the body `start` and the helpers it calls into one flow.
pub(super) fn join(bodies: &BTreeMap<FnKey, BodyFlow>, start: &FnKey) -> Flow {
    let mut path = vec![start.clone()];
    bodies.get(start).map_or(Flow::Nothing, |body| {
        let joining = Joining {
            bodies,
            body,
            context: &Context::default(),
        };
        joining.joined(&body.shape, &mut path)
    })
}

/// One body being joined with the helpers it calls: every body read, the
/// one at hand, and what its caller handed it.
struct Joining<'j> {
    bodies: &'j BTreeMap<FnKey, BodyFlow>,
    body: &'j BodyFlow,
    context: &'j Context,
}

/// The futures a helper call hands in: those its body runs, by parameter,
/// and those it keeps without running, which run where they are handed.
struct HandedFutures {
    placed: BTreeMap<String, Flow>,
    unplaced: Vec<Flow>,
}

impl Joining<'_> {
    /// The flow of `node`, with the helpers it calls put in; `path` holds
    /// the helpers open around it.
    fn joined(&self, node: &Node, path: &mut Vec<FnKey>) -> Flow {
        match node {
            Node::Fact(index) => self.fact(*index),
            Node::Helper { index, handed } => self.helper_flow(*index, *handed, path),
            Node::Future(param) => self.future(param),
            Node::Bound(..) | Node::Narrow { .. } => self.point(node),
            Node::Seq(parts) => Flow::Seq(self.each(parts, path)),
            Node::Choice(parts) => Flow::Choice(self.each(parts, path)),
            Node::Loop {
                body: inner,
                at_least_once,
            } => Flow::Loop {
                body: Box::new(self.joined(inner, path)),
                at_least_once: *at_least_once,
            },
            Node::Exit(exit, place) => Flow::Exit(*exit, place.clone()),
            Node::LoopExit => Flow::LoopExit,
            Node::Halt => Flow::Halt,
            Node::Unit { name, place, inner } => Flow::Unit {
                name: name.clone(),
                place: place.clone(),
                inner: Box::new(self.joined(inner, path)),
            },
            Node::Split { head, ok, err } => Flow::Split {
                head: Box::new(self.joined(head, path)),
                ok: Box::new(self.joined(ok, path)),
                err: Box::new(self.joined(err, path)),
            },
            Node::Unread(unread) => Flow::Unread(unread.clone()),
        }
    }

    /// The step the fact at `index` is, its values told apart.
    fn fact(&self, index: usize) -> Flow {
        (self.body.seen.get(index)).map_or(Flow::Nothing, |found| {
            fact_flow(found, &self.context.values)
        })
    }

    /// The flow of the future the caller handed in as `param`, nothing
    /// when it handed none.
    fn future(&self, param: &str) -> Flow {
        (self.context.futures.get(param).cloned()).unwrap_or(Flow::Nothing)
    }

    /// The flows of `parts`, in order.
    fn each(&self, parts: &[Node], path: &mut Vec<FnKey>) -> Vec<Flow> {
        parts.iter().map(|inner| self.joined(inner, path)).collect()
    }

    /// The step a binding or a narrowing is, its value told apart; nothing
    /// for any other node.
    fn point(&self, node: &Node) -> Flow {
        let (step, place) = match node {
            Node::Bound(name, place) => {
                let value = self.context.values.of(name);
                (Step::Bound { value }, place)
            }
            Node::Narrow {
                enum_name,
                variants,
                place,
            } => {
                let enum_name = enum_name.clone();
                let variants = variants.clone();
                (
                    Step::Narrow {
                        enum_name,
                        variants,
                    },
                    place,
                )
            }
            _ => return Flow::Nothing,
        };
        Flow::Point(Point {
            step,
            place: place.clone(),
        })
    }

    /// The call of the helper at `index`, its body put in when the flow
    /// follows it, handed back as `handed` says.
    fn helper_flow(&self, index: usize, handed: Handed, path: &mut Vec<FnKey>) -> Flow {
        let Some(helper) = self.body.helpers.get(index) else {
            return Flow::Nothing;
        };
        let Some(inner) = followed(self.bodies, helper, path) else {
            return Flow::Unread(unfollowed(helper, path));
        };
        let HandedFutures {
            placed,
            mut unplaced,
        } = self.futures_of(helper, inner, path);
        path.push(helper.key.clone());
        let joining = Joining {
            bodies: self.bodies,
            body: inner,
            context: &Context {
                values: self.context.values.inside(helper, &inner.params),
                futures: placed,
            },
        };
        let flow = joining.joined(&inner.shape, path);
        path.pop();
        let flow = match unplaced.is_empty() {
            true => flow,
            false => {
                unplaced.push(flow);
                Flow::Seq(unplaced)
            }
        };
        call_of(helper, flow, handed)
    }

    /// The futures `helper` is handed, each placed where `inner`, its body,
    /// runs it, or kept to run before it.
    fn futures_of(
        &self,
        helper: &HelperAt,
        inner: &BodyFlow,
        path: &mut Vec<FnKey>,
    ) -> HandedFutures {
        let mut handed = HandedFutures {
            placed: BTreeMap::new(),
            unplaced: Vec::new(),
        };
        let mut run = BTreeSet::new();
        inner.shape.futures_run(&mut run);
        for (position, made) in &helper.futures {
            let param = inner.params.get(*position).cloned().flatten();
            match param.filter(|param| run.contains(param)) {
                Some(param) => {
                    let flow = self.helper_flow(*made, Handed::Back, path);
                    handed.placed.insert(param, flow);
                }
                None => handed
                    .unplaced
                    .push(self.helper_flow(*made, Handed::Kept, path)),
            }
        }
        handed
    }
}

/// The call of `helper`, whose flow inside is `flow`, handed back as
/// `handed` says.
fn call_of(helper: &HelperAt, flow: Flow, handed: Handed) -> Flow {
    Flow::Call {
        inner: Box::new(flow),
        handed,
        called: Called {
            label: helper.label.clone(),
            place: helper.place.clone(),
        },
    }
}

/// The body of `helper`, when the flow puts it in: read, not too deep, and
/// not already open on this path.
fn followed<'b>(
    bodies: &'b BTreeMap<FnKey, BodyFlow>,
    helper: &HelperAt,
    path: &[FnKey],
) -> Option<&'b BodyFlow> {
    bodies
        .get(&helper.key)
        .filter(|_| !helper.too_deep && !path.contains(&helper.key))
}

/// The not-read point a helper the flow does not put in becomes.
fn unfollowed(helper: &HelperAt, path: &[FnKey]) -> Unread {
    let why = match (helper.too_deep, path.contains(&helper.key)) {
        (true, _) => "more helpers from `execute` than the reader follows",
        (false, true) => "it calls itself again, and the reader does not unroll it",
        (false, false) => "its body was not read",
    };
    Unread {
        place: helper.place.clone(),
        what: format!("`{}`: {why}", helper.label),
    }
}

/// The step a fact is, its values told apart by `values`, a not-read
/// point, or nothing the questions ask.
fn fact_flow(found: &SeenAt, values: &Values) -> Flow {
    if let Some(what) = found.seen.unread_what() {
        return Flow::Unread(Unread {
            place: found.place.clone(),
            what,
        });
    }
    let Some(step) = step_of(&found.seen, values) else {
        return Flow::Nothing;
    };
    Flow::Point(Point {
        step,
        place: found.place.clone(),
    })
}

/// The step `seen` is, its values told apart by `values`; none for a fact
/// the questions do not ask about.
fn step_of(seen: &Seen, values: &Values) -> Option<Step> {
    let named = |value: &Option<String>| value.as_deref().and_then(|value| values.of(value));
    let step = match seen {
        Seen::PortCall {
            port,
            method,
            values: handed,
        } => Step::Port {
            trait_name: port.trait_name.clone(),
            port: port.port.clone(),
            method: method.clone(),
            values: handed.iter().map(named).collect(),
        },
        Seen::Change { owner, name, value } => Step::Change {
            owner: owner.clone(),
            name: name.clone(),
            value: named(value),
        },
        Seen::Limit { kind, .. } => Step::Limit { kind: kind.clone() },
        Seen::Dispatch { .. } => Step::Dispatch,
        Seen::UnreadReceiver { .. }
        | Seen::UnreadHelper { .. }
        | Seen::Unfollowed { .. }
        | Seen::Unresolved { .. }
        | Seen::Right(_)
        | Seen::Error(_) => return None,
    };
    Some(step)
}

/// What a question tracks along each path.
pub(crate) trait Question {
    /// What it knows on one path so far.
    type State: Clone + Ord;
    /// The state after `point`.
    fn point(&mut self, state: &Self::State, point: &Point) -> Self::State;
    /// The state after the not-read point `unread`.
    fn unread(&mut self, state: &Self::State, unread: &Unread) -> Self::State;
}

/// Where the paths of a part of the flow end.
struct Ends<S> {
    /// Those that go on after it.
    on: BTreeSet<S>,
    /// Those that leave the function inside it.
    exits: Vec<(Exit, S, Place)>,
    /// Those that end a run of the loop around it.
    loop_exits: BTreeSet<S>,
}

impl<S> Ends<S> {
    fn none() -> Self {
        Self {
            on: BTreeSet::new(),
            exits: Vec::new(),
            loop_exits: BTreeSet::new(),
        }
    }
}

/// How many times a loop's body is walked before its states settle.
const LOOP_ROUNDS: usize = 4;

/// Every way `flow` leaves, starting in `start`: its exits, and the end
/// of its body, read as handing back what the function hands back there,
/// at `end`.
pub(crate) fn exits<Q: Question>(
    flow: &Flow,
    question: &mut Q,
    start: Q::State,
    end: &Place,
) -> Vec<(Exit, Q::State, Place)> {
    let ends = walk(flow, question, BTreeSet::from([start]));
    let mut found = ends.exits;
    found.extend(
        ends.on
            .into_iter()
            .chain(ends.loop_exits)
            .map(|state| (Exit::Value, state, end.clone())),
    );
    found
}

fn walk<Q: Question>(flow: &Flow, question: &mut Q, states: BTreeSet<Q::State>) -> Ends<Q::State> {
    let mut ends = Ends::none();
    match flow {
        Flow::Nothing => ends.on = states,
        Flow::Point(point) => ends.on = each(&states, |state| question.point(state, point)),
        Flow::Unread(unread) => ends.on = each(&states, |state| question.unread(state, unread)),
        Flow::Seq(parts) => return walk_in_order(parts, question, states),
        Flow::Choice(parts) if parts.is_empty() => ends.on = states,
        Flow::Choice(parts) => return walk_each(parts, question, &states),
        Flow::Loop {
            body,
            at_least_once,
        } => return looped(body, *at_least_once, question, states),
        Flow::Exit(exit, place) => ends.exits = leaving(states, *exit, place),
        Flow::LoopExit => ends.loop_exits = states,
        Flow::Halt => {}
        Flow::Call {
            inner,
            handed,
            called,
        } => return called_ends(walk(inner, question, states), *handed, called, question),
        Flow::Split { head, ok, err } => {
            return split(&Branches { head, ok, err }, question, states);
        }
        Flow::Unit { inner, .. } => {
            let outcome = unit_outcomes(inner, question, states);
            ends.on = outcome.succeeded;
            ends.on.extend(outcome.failed);
        }
    }
    ends
}

/// Each of `states` leaving the function by `exit` at `place`.
fn leaving<S>(states: BTreeSet<S>, exit: Exit, place: &Place) -> Vec<(Exit, S, Place)> {
    (states.into_iter())
        .map(|state| (exit, state, place.clone()))
        .collect()
}

/// `step` taken from each of `states`.
fn each<S: Ord>(states: &BTreeSet<S>, step: impl FnMut(&S) -> S) -> BTreeSet<S> {
    states.iter().map(step).collect()
}

/// The paths through `parts`, one after another, from `states`.
fn walk_in_order<Q: Question>(
    parts: &[Flow],
    question: &mut Q,
    states: BTreeSet<Q::State>,
) -> Ends<Q::State> {
    let mut ends = Ends::none();
    let mut current = states;
    for part in parts {
        let reached = walk(part, question, current);
        ends.exits.extend(reached.exits);
        ends.loop_exits.extend(reached.loop_exits);
        current = reached.on;
    }
    ends.on = current;
    ends
}

/// The paths through whichever of `parts` runs, each from `states`.
fn walk_each<Q: Question>(
    parts: &[Flow],
    question: &mut Q,
    states: &BTreeSet<Q::State>,
) -> Ends<Q::State> {
    let mut ends = Ends::none();
    for part in parts {
        let reached = walk(part, question, states.clone());
        ends.on.extend(reached.on);
        ends.exits.extend(reached.exits);
        ends.loop_exits.extend(reached.loop_exits);
    }
    ends
}

/// The paths after a call of `called`, given those `reached` inside it and
/// what the caller does with what it hands back.
fn called_ends<Q: Question>(
    reached: Ends<Q::State>,
    handed: Handed,
    called: &Called,
    question: &mut Q,
) -> Ends<Q::State> {
    let mut ends = Ends::none();
    ends.on = reached.on;
    ends.on.extend(reached.loop_exits);
    for (exit, state, place) in reached.exits {
        match (exit, handed) {
            (_, Handed::Back) | (Exit::Err, Handed::Tried) => ends.exits.push((exit, state, place)),
            (Exit::Err, Handed::Kept) => {
                ends.on
                    .insert(question.unread(&state, &called.kept_error()));
            }
            (Exit::Ok | Exit::Value, Handed::Tried | Handed::Kept) | (_, Handed::Held) => {
                ends.on.insert(state);
            }
        }
    }
    ends
}

fn looped<Q: Question>(
    body: &Flow,
    at_least_once: bool,
    question: &mut Q,
    states: BTreeSet<Q::State>,
) -> Ends<Q::State> {
    let mut ends = Ends::none();
    if !at_least_once {
        ends.on.extend(states.iter().cloned());
    }
    let mut entering = states;
    let mut entered = BTreeSet::new();
    for _ in 0..LOOP_ROUNDS {
        let fresh: BTreeSet<Q::State> = entering.difference(&entered).cloned().collect();
        if fresh.is_empty() {
            break;
        }
        entered.extend(fresh.iter().cloned());
        let reached = walk(body, question, fresh);
        ends.exits.extend(reached.exits);
        ends.on.extend(reached.loop_exits);
        ends.on.extend(reached.on.iter().cloned());
        entering = reached.on;
    }
    ends
}

/// A call whose result the caller matches on, and the flows after its
/// success and after its failure.
struct Branches<'f> {
    head: &'f Flow,
    ok: &'f Flow,
    err: &'f Flow,
}

/// The paths of a call whose result the caller matches on: those after its
/// success go on through `ok`, those after its failure through `err`.
fn split<Q: Question>(
    branches: &Branches<'_>,
    question: &mut Q,
    states: BTreeSet<Q::State>,
) -> Ends<Q::State> {
    let outcome = outcomes(branches.head, question, states);
    let mut ends = walk(branches.ok, question, outcome.succeeded);
    let failing = walk(branches.err, question, outcome.failed);
    ends.on.extend(failing.on);
    ends.exits.extend(failing.exits);
    ends.exits.extend(outcome.exits);
    ends.loop_exits.extend(failing.loop_exits);
    ends
}

/// The states once a call succeeded and once it failed, with the paths that
/// leave before either.
struct Outcomes<S> {
    succeeded: BTreeSet<S>,
    failed: BTreeSet<S>,
    exits: Vec<(Exit, S, Place)>,
}

/// What `head` comes to: a step that fails took no effect; a helper fails
/// where it hands back an error, and a value the reader cannot tell apart
/// may be either, after every step it took.
fn outcomes<Q: Question>(
    head: &Flow,
    question: &mut Q,
    states: BTreeSet<Q::State>,
) -> Outcomes<Q::State> {
    match head {
        Flow::Point(point) => Outcomes {
            succeeded: states
                .iter()
                .map(|state| question.point(state, point))
                .collect(),
            failed: states,
            exits: Vec::new(),
        },
        Flow::Call { inner, .. } => helper_outcomes(inner, question, states),
        Flow::Unit { inner, .. } => unit_outcomes(inner, question, states),
        other => {
            let reached = walk(other, question, states);
            let mut on = reached.on;
            on.extend(reached.loop_exits);
            Outcomes {
                succeeded: on.clone(),
                failed: on,
                exits: reached.exits,
            }
        }
    }
}

/// What a unit of work comes to: it succeeds where its work hands back
/// anything but an error, and once it fails everything it wrote and
/// recorded is dropped, so its failure leaves the path as it was before.
fn unit_outcomes<Q: Question>(
    inner: &Flow,
    question: &mut Q,
    states: BTreeSet<Q::State>,
) -> Outcomes<Q::State> {
    let reached = walk(inner, question, states.clone());
    let mut succeeded = reached.on;
    succeeded.extend(reached.loop_exits);
    succeeded.extend(
        reached
            .exits
            .into_iter()
            .filter(|(exit, _, _)| *exit != Exit::Err)
            .map(|(_, state, _)| state),
    );
    Outcomes {
        succeeded,
        failed: states,
        exits: Vec::new(),
    }
}

fn helper_outcomes<Q: Question>(
    inner: &Flow,
    question: &mut Q,
    states: BTreeSet<Q::State>,
) -> Outcomes<Q::State> {
    let reached = walk(inner, question, states);
    let mut outcome = Outcomes {
        succeeded: reached.on,
        failed: BTreeSet::new(),
        exits: Vec::new(),
    };
    outcome.succeeded.extend(reached.loop_exits);
    for (exit, state, _) in reached.exits {
        match exit {
            Exit::Ok => {
                outcome.succeeded.insert(state);
            }
            Exit::Err => {
                outcome.failed.insert(state);
            }
            Exit::Value => {
                outcome.failed.insert(state.clone());
                outcome.succeeded.insert(state);
            }
        }
    }
    outcome
}

/// An answer the flow gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    /// Yes, along a path through no not-read point, shown by these places.
    Yes(Vec<Place>),
    /// No, on every path.
    No,
    /// A path that would decide it passes this not-read point.
    Unknown(Unread),
}

/// The first not-read point a path passed, if any.
type Unsure = Option<Unread>;

/// The answer once no path said yes: unknown at the first point of
/// `unsure`, no when there is none.
fn no_or_unknown<'u>(unsure: impl IntoIterator<Item = &'u Unsure>) -> Answer {
    unsure
        .into_iter()
        .flatten()
        .min()
        .cloned()
        .map_or(Answer::No, Answer::Unknown)
}

/// Whether some path reaches a step `reached` picks without passing one
/// `passed` picks first. Yes names where it is reached.
pub(crate) fn reaches_without(
    flow: &Flow,
    passed: impl Fn(&Step) -> bool,
    reached: impl Fn(&Step) -> bool,
    end: &Place,
) -> Answer {
    let mut question = Without {
        passed,
        reached,
        hits: BTreeSet::new(),
    };
    let ends = exits(flow, &mut question, (false, None), end);
    if let Some((_, place)) = question.hits.iter().find(|(unknown, _)| unknown.is_none()) {
        return Answer::Yes(vec![place.clone()]);
    }
    let open = ends
        .iter()
        .filter(|(_, (passed, _), _)| !passed)
        .map(|(_, (_, unknown), _)| unknown);
    no_or_unknown(question.hits.iter().map(|(unknown, _)| unknown).chain(open))
}

/// Tracks, on each path, whether the step was passed and the first
/// not-read point; notes where the other step is reached unpassed.
struct Without<P, R> {
    passed: P,
    reached: R,
    hits: BTreeSet<(Unsure, Place)>,
}

impl<P: Fn(&Step) -> bool, R: Fn(&Step) -> bool> Question for Without<P, R> {
    type State = (bool, Unsure);

    fn point(&mut self, state: &Self::State, point: &Point) -> Self::State {
        let (passed, unknown) = state.clone();
        if !passed && (self.reached)(&point.step) {
            self.hits.insert((unknown.clone(), point.place.clone()));
        }
        (passed || (self.passed)(&point.step), unknown)
    }

    fn unread(&mut self, state: &Self::State, unread: &Unread) -> Self::State {
        (state.0, state.1.clone().or_else(|| Some(unread.clone())))
    }
}

/// The steps [`kept_unchecked`] asks about: those that check a value,
/// make it, and keep it.
pub(crate) struct StepPicks<C, M, K> {
    pub(crate) checked: C,
    pub(crate) made: M,
    pub(crate) kept: K,
}

/// Whether a path takes a step `made` picks and then keeps it, by a step
/// `kept` picks or by handing back anything but an error, without passing
/// a step `checked` picks before. A value made in memory before its check
/// is fine as long as the check comes before it is kept. Yes names where
/// it was made and where it was kept.
pub(crate) fn kept_unchecked<C, M, K>(flow: &Flow, picks: StepPicks<C, M, K>, end: &Place) -> Answer
where
    C: Fn(&Step) -> bool,
    M: Fn(&Step) -> bool,
    K: Fn(&Step) -> bool,
{
    let StepPicks {
        checked,
        made,
        kept,
    } = picks;
    let mut question = Unchecked {
        checked,
        made,
        kept,
        hits: BTreeSet::new(),
    };
    let ends = exits(flow, &mut question, (false, None, None), end);
    let mut hits = question.hits;
    for (exit, (passed, made_at, unknown), place) in ends {
        if let (false, Some(made_at), true) = (passed, made_at, exit != Exit::Err) {
            hits.insert((unknown, made_at, place));
        }
    }
    if let Some((_, made_at, kept_at)) = hits.iter().find(|(unknown, _, _)| unknown.is_none()) {
        return Answer::Yes(vec![made_at.clone(), kept_at.clone()]);
    }
    no_or_unknown(hits.iter().map(|(unknown, _, _)| unknown))
}

/// Tracks, on each path, whether the check was passed, where the value
/// was first made unchecked, and the first not-read point passed; notes
/// where it is kept unchecked.
struct Unchecked<C, M, K> {
    checked: C,
    made: M,
    kept: K,
    hits: BTreeSet<(Unsure, Place, Place)>,
}

impl<C, M, K> Question for Unchecked<C, M, K>
where
    C: Fn(&Step) -> bool,
    M: Fn(&Step) -> bool,
    K: Fn(&Step) -> bool,
{
    type State = (bool, Option<Place>, Unsure);

    fn point(&mut self, state: &Self::State, point: &Point) -> Self::State {
        let (passed, made_at, unknown) = state.clone();
        if let (false, Some(made_at)) = (passed, &made_at)
            && (self.kept)(&point.step)
        {
            self.hits
                .insert((unknown.clone(), made_at.clone(), point.place.clone()));
        }
        let made_at = match made_at {
            None if !passed && (self.made)(&point.step) => Some(point.place.clone()),
            other => other,
        };
        (passed || (self.checked)(&point.step), made_at, unknown)
    }

    fn unread(&mut self, state: &Self::State, unread: &Unread) -> Self::State {
        let (passed, made_at, unknown) = state.clone();
        (passed, made_at, unknown.or_else(|| Some(unread.clone())))
    }
}

/// A plain test of a step.
pub(crate) type Pick = fn(&Step) -> bool;

/// What `use_case` owes a record for: a change it calls that raises
/// events, then kept by a store write, answered by a dispatch.
pub(crate) fn owed(use_case: &UseCaseFacts) -> Owed<impl Fn(&Step) -> bool + '_, Pick, Pick> {
    let raises = move |step: &Step| {
        let Step::Change { owner, name, .. } = step else {
            return false;
        };
        use_case.changes.iter().any(|change| {
            change.owner == *owner && change.name == *name && !change.events.is_empty()
        })
    };
    Owed {
        raises,
        saves: is_store_write,
        answers: |step| matches!(step, Step::Dispatch),
    }
}

/// The steps [`succeeds_without`] asks about.
pub(crate) struct Owed<R, S, A> {
    /// A step that owes a record: a change that raises events.
    pub(crate) raises: R,
    /// A step that keeps what was owed: a store write.
    pub(crate) saves: S,
    /// A step that answers it: a dispatch.
    pub(crate) answers: A,
}

/// Whether a path takes a step `raises` picks, then one `saves` picks,
/// then hands back `Ok` (or a value that may be `Ok`) without a step
/// `answers` picks anywhere on it. Yes names the save and the exit.
pub(crate) fn succeeds_without<R, S, A>(flow: &Flow, owed: Owed<R, S, A>, end: &Place) -> Answer
where
    R: Fn(&Step) -> bool,
    S: Fn(&Step) -> bool,
    A: Fn(&Step) -> bool,
{
    let mut question = Unanswered { owed };
    let ends = exits(
        flow,
        &mut question,
        (BTreeSet::new(), None, false, None),
        end,
    );
    let succeeding: Vec<&(Exit, UnansweredState, Place)> = ends
        .iter()
        .filter(|(exit, (_, saved, answered, _), _)| {
            *exit != Exit::Err && saved.is_some() && !answered
        })
        .collect();
    for (_, (_, saved, _, unknown), place) in &succeeding {
        if unknown.is_none()
            && let Some(saved) = saved
        {
            return Answer::Yes(vec![saved.clone(), place.clone()]);
        }
    }
    no_or_unknown(succeeding.iter().map(|(_, (_, _, _, unknown), _)| unknown))
}

/// The values that raised events (`None` for one the reader cannot name),
/// the first save of one of them, whether it was answered, and the first
/// not-read point passed.
type UnansweredState = (BTreeSet<Option<String>>, Option<Place>, bool, Unsure);

/// Whether the store write `step` may keep one of the `raised` values: it
/// is handed one of them, or a value the reader cannot name, or one of them
/// is a value the reader could not name.
fn keeps_raised(raised: &BTreeSet<Option<String>>, step: &Step) -> bool {
    let Step::Port { values, .. } = step else {
        return false;
    };
    !raised.is_empty()
        && (raised.contains(&None)
            || values
                .iter()
                .any(|value| value.is_none() || raised.contains(value)))
}

/// The value `step` changes or makes, as [`UnansweredState`] keeps it.
fn changed_value(step: &Step) -> Option<String> {
    match step {
        Step::Change { value, .. } => value.clone(),
        _ => None,
    }
}

/// Tracks [`UnansweredState`] on each path.
struct Unanswered<R, S, A> {
    owed: Owed<R, S, A>,
}

impl<R, S, A> Question for Unanswered<R, S, A>
where
    R: Fn(&Step) -> bool,
    S: Fn(&Step) -> bool,
    A: Fn(&Step) -> bool,
{
    type State = UnansweredState;

    fn point(&mut self, state: &Self::State, point: &Point) -> Self::State {
        let (mut raised, saved, answered, unknown) = state.clone();
        let saved = match saved {
            None if (self.owed.saves)(&point.step) && keeps_raised(&raised, &point.step) => {
                Some(point.place.clone())
            }
            other => other,
        };
        if (self.owed.raises)(&point.step) {
            raised.insert(changed_value(&point.step));
        }
        if let Step::Bound { value: Some(value) } = &point.step {
            raised.remove(&Some(value.clone()));
        }
        (
            raised,
            saved,
            answered || (self.owed.answers)(&point.step),
            unknown,
        )
    }

    fn unread(&mut self, state: &Self::State, unread: &Unread) -> Self::State {
        let (raised, saved, answered, unknown) = state.clone();
        (
            raised,
            saved,
            answered,
            unknown.or_else(|| Some(unread.clone())),
        )
    }
}

/// Whether one unit of work holds a step `first` picks and one `second`
/// picks. Yes names the unit.
pub(crate) fn inside_one_unit(
    flow: &Flow,
    first: &impl Fn(&Step) -> bool,
    second: &impl Fn(&Step) -> bool,
) -> Option<(String, Place, Answer)> {
    let mut units = Vec::new();
    collect_units(flow, &mut units);
    let mut unsure = None;
    for (name, place, inner) in units {
        let (has_first, has_second, unread) = contents(inner, first, second);
        if has_first && has_second {
            return Some((
                name.to_owned(),
                place.clone(),
                Answer::Yes(vec![place.clone()]),
            ));
        }
        if let Some(unread) = unread.filter(|_| has_first || has_second) {
            unsure = Some((name.to_owned(), place.clone(), Answer::Unknown(unread)));
        }
    }
    unsure
}

fn collect_units<'f>(flow: &'f Flow, found: &mut Vec<(&'f str, &'f Place, &'f Flow)>) {
    match flow {
        Flow::Unit { name, place, inner } => found.push((name, place, inner)),
        Flow::Seq(parts) | Flow::Choice(parts) => {
            for part in parts {
                collect_units(part, found);
            }
        }
        Flow::Loop { body, .. } => collect_units(body, found),
        Flow::Call { inner, .. } => collect_units(inner, found),
        Flow::Split { head, ok, err } => {
            for part in [head, ok, err] {
                collect_units(part, found);
            }
        }
        _ => {}
    }
}

/// Whether `flow` holds a step `pick` picks anywhere.
pub(crate) fn holds(flow: &Flow, pick: &impl Fn(&Step) -> bool) -> bool {
    contents(flow, pick, &|_: &Step| false).0
}

/// Whether `flow` holds a step each picks, and its first not-read point.
fn contents(
    flow: &Flow,
    first: &impl Fn(&Step) -> bool,
    second: &impl Fn(&Step) -> bool,
) -> (bool, bool, Unsure) {
    let all = |parts: &mut dyn Iterator<Item = &Flow>| {
        parts.fold((false, false, None), |all: (bool, bool, Unsure), part| {
            let found = contents(part, first, second);
            (all.0 || found.0, all.1 || found.1, all.2.or(found.2))
        })
    };
    match flow {
        Flow::Point(point) => (first(&point.step), second(&point.step), None),
        Flow::Unread(unread) => (false, false, Some(unread.clone())),
        Flow::Seq(parts) | Flow::Choice(parts) => all(&mut parts.iter()),
        Flow::Split { head, ok, err } => all(&mut [head, ok, err].into_iter().map(Box::as_ref)),
        Flow::Loop { body: inner, .. } | Flow::Call { inner, .. } | Flow::Unit { inner, .. } => {
            contents(inner, first, second)
        }
        Flow::Nothing | Flow::Exit(..) | Flow::LoopExit | Flow::Halt => (false, false, None),
    }
}

/// Whether `step` calls the domain function `owner::name`.
pub(crate) fn creates(step: &Step, owner: &str, name: &str) -> bool {
    matches!(step, Step::Change { owner: called, name: change, .. } if called == owner && change == name)
}

/// The port methods that write to a store: `save`, `insert`, `update`,
/// `upsert`, `delete`, `remove`, `put`, `replace`, `append`, `create` and
/// `add`, alone or with a suffix such as `save_all`.
const WRITES: &[&str] = &[
    "save", "insert", "update", "upsert", "delete", "remove", "put", "replace", "append", "create",
    "add",
];

/// Whether `step` writes to a store: a method of a `*Store` port that
/// [`WRITES`] names.
pub(crate) fn is_store_write(step: &Step) -> bool {
    let Step::Port {
        trait_name, method, ..
    } = step
    else {
        return false;
    };
    writes_to_store(trait_name.as_deref(), method)
}

/// Whether `method` of the port trait `trait_name` writes to a store.
pub(crate) fn writes_to_store(trait_name: Option<&str>, method: &str) -> bool {
    trait_name.is_some_and(|port| port.ends_with("Store"))
        && WRITES
            .iter()
            .any(|write| method == *write || method.starts_with(&format!("{write}_")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn place(line: usize) -> Place {
        Place {
            file: "a.rs".to_owned(),
            line,
        }
    }

    fn limit(line: usize) -> Flow {
        Flow::Point(Point {
            step: Step::Limit {
                kind: "Users".to_owned(),
            },
            place: place(line),
        })
    }

    fn create(line: usize) -> Flow {
        Flow::Point(Point {
            step: Step::Change {
                owner: "User".to_owned(),
                name: "create".to_owned(),
                value: Some("user".to_owned()),
            },
            place: place(line),
        })
    }

    fn ask(flow: &Flow) -> Answer {
        reaches_without(
            flow,
            |step| matches!(step, Step::Limit { .. }),
            |step| matches!(step, Step::Change { .. }),
            &place(99),
        )
    }

    #[test]
    fn a_check_on_one_branch_leaves_a_path_without_it() {
        let flow = Flow::Seq(vec![Flow::Choice(vec![limit(1), Flow::Nothing]), create(2)]);

        assert_eq!(ask(&flow), Answer::Yes(vec![place(2)]));
    }

    #[test]
    fn a_check_before_on_every_path_answers_no() {
        let flow = Flow::Seq(vec![limit(1), Flow::Choice(vec![create(2), Flow::Nothing])]);

        assert_eq!(ask(&flow), Answer::No);
    }

    #[test]
    fn an_early_exit_before_the_check_counts_only_if_it_reaches_the_create() {
        let leaves = Flow::Seq(vec![
            Flow::Choice(vec![Flow::Exit(Exit::Ok, place(1)), Flow::Nothing]),
            limit(2),
            create(3),
        ]);
        let creates_first = Flow::Seq(vec![
            Flow::Choice(vec![
                Flow::Seq(vec![create(1), Flow::Exit(Exit::Ok, place(1))]),
                Flow::Nothing,
            ]),
            limit(2),
            create(3),
        ]);

        assert_eq!(ask(&leaves), Answer::No);
        assert_eq!(ask(&creates_first), Answer::Yes(vec![place(1)]));
    }

    fn unread(line: usize) -> Unread {
        Unread {
            place: place(line),
            what: "`external::prepare(..)`: not followed".to_owned(),
        }
    }

    fn called(line: usize) -> Called {
        Called {
            label: "helper".to_owned(),
            place: place(line),
        }
    }

    #[test]
    fn a_not_read_point_before_the_check_leaves_it_unknown_and_names_it() {
        let flow = Flow::Seq(vec![
            Flow::Choice(vec![limit(1), Flow::Unread(unread(7))]),
            create(2),
        ]);

        assert_eq!(ask(&flow), Answer::Unknown(unread(7)));
    }

    /// A helper may fail before its check. Through `?` that failure leaves
    /// the caller; kept by the caller, what happens next is not read.
    #[test]
    fn a_helpers_error_passes_on_through_question_mark_and_is_unread_when_kept() {
        let helper = Flow::Seq(vec![
            Flow::Choice(vec![Flow::Exit(Exit::Err, place(1)), Flow::Nothing]),
            limit(2),
        ]);
        let call = |handed| {
            Flow::Seq(vec![
                Flow::Call {
                    inner: Box::new(helper.clone()),
                    handed,
                    called: called(5),
                },
                create(3),
            ])
        };

        assert_eq!(ask(&call(Handed::Tried)), Answer::No);
        assert_eq!(
            ask(&call(Handed::Kept)),
            Answer::Unknown(called(5).kept_error())
        );
    }

    /// The caller matches on what the helper hands back and logs its error.
    /// The helper saved, then failed before it dispatched: that failure goes
    /// on through the error arm to a success, unrecorded.
    #[test]
    fn a_helper_failing_after_its_save_is_followed_through_the_error_arm() {
        let helper = Flow::Seq(vec![
            save(1),
            Flow::Choice(vec![Flow::Exit(Exit::Err, place(2)), Flow::Nothing]),
            dispatch(3),
            Flow::Exit(Exit::Ok, place(4)),
        ]);
        let flow = Flow::Seq(vec![
            Flow::Split {
                head: Box::new(Flow::Call {
                    inner: Box::new(helper),
                    handed: Handed::Kept,
                    called: called(5),
                }),
                ok: Box::new(Flow::Nothing),
                err: Box::new(Flow::Nothing),
            },
            Flow::Exit(Exit::Ok, place(6)),
        ]);

        assert_eq!(unanswered(&flow), Answer::Yes(vec![place(1), place(6)]));
    }

    /// A save whose own call failed kept nothing: its error arm goes on as
    /// if it had not been called.
    #[test]
    fn a_failed_step_matched_on_took_no_effect_on_its_error_arm() {
        let flow = Flow::Seq(vec![
            Flow::Split {
                head: Box::new(save(1)),
                ok: Box::new(dispatch(2)),
                err: Box::new(Flow::Nothing),
            },
            Flow::Exit(Exit::Ok, place(3)),
        ]);

        assert_eq!(unanswered(&flow), Answer::No);
    }

    /// The caller hands back what the helper hands back: an error after the
    /// helper's save is the caller's error, not a success.
    #[test]
    fn a_helper_handed_back_leaves_with_its_own_exits() {
        let helper = Flow::Seq(vec![
            save(1),
            Flow::Choice(vec![Flow::Exit(Exit::Err, place(2)), Flow::Nothing]),
            dispatch(3),
            Flow::Exit(Exit::Ok, place(4)),
        ]);
        let flow = Flow::Seq(vec![
            Flow::Call {
                inner: Box::new(helper),
                handed: Handed::Back,
                called: called(5),
            },
            Flow::Exit(Exit::Value, place(5)),
        ]);

        assert_eq!(unanswered(&flow), Answer::No);
    }

    fn save(line: usize) -> Flow {
        Flow::Point(Point {
            step: Step::Port {
                trait_name: Some("UserStore".to_owned()),
                port: None,
                method: "save".to_owned(),
                values: vec![Some("tenant".to_owned()), Some("user".to_owned())],
            },
            place: place(line),
        })
    }

    fn dispatch(line: usize) -> Flow {
        Flow::Point(Point {
            step: Step::Dispatch,
            place: place(line),
        })
    }

    /// Whether `flow`, run after a change that raises events, saves and
    /// succeeds without dispatching them.
    fn unanswered(flow: &Flow) -> Answer {
        let raised = Flow::Seq(vec![create(0), flow.clone()]);
        succeeds_without(
            &raised,
            Owed {
                raises: |step: &Step| matches!(step, Step::Change { .. }),
                saves: is_store_write,
                answers: |step: &Step| matches!(step, Step::Dispatch),
            },
            &place(99),
        )
    }

    #[test]
    fn a_save_of_nothing_raised_owes_no_dispatch() {
        let flow = Flow::Seq(vec![save(1), Flow::Exit(Exit::Ok, place(2))]);

        let answer = succeeds_without(
            &flow,
            Owed {
                raises: |step: &Step| matches!(step, Step::Change { .. }),
                saves: is_store_write,
                answers: |step: &Step| matches!(step, Step::Dispatch),
            },
            &place(99),
        );

        assert_eq!(answer, Answer::No);
    }

    /// The user that raised events is never saved: what is saved is another
    /// value, read from the store. Nothing raised is kept.
    #[test]
    fn a_save_of_another_value_than_the_one_that_raised_owes_no_dispatch() {
        let other = Flow::Point(Point {
            step: Step::Port {
                trait_name: Some("UserStore".to_owned()),
                port: None,
                method: "save".to_owned(),
                values: vec![Some("tenant".to_owned()), Some("known".to_owned())],
            },
            place: place(1),
        });
        let flow = Flow::Seq(vec![other, Flow::Exit(Exit::Ok, place(2))]);

        assert_eq!(unanswered(&flow), Answer::No);
    }

    /// A loop binds `user` afresh on each run: the user that raised in an
    /// earlier run is not the one saved in a later one.
    #[test]
    fn a_name_bound_again_names_another_value() {
        let bound = Flow::Point(Point {
            step: Step::Bound {
                value: Some("user".to_owned()),
            },
            place: place(1),
        });
        let flow = Flow::Seq(vec![bound, save(2), Flow::Exit(Exit::Ok, place(3))]);

        assert_eq!(unanswered(&flow), Answer::No);
    }

    #[test]
    fn a_save_then_ok_without_a_dispatch_is_found() {
        let flow = Flow::Seq(vec![
            save(1),
            Flow::Choice(vec![
                Flow::Exit(Exit::Ok, place(2)),
                Flow::Seq(vec![dispatch(3), Flow::Exit(Exit::Ok, place(4))]),
            ]),
        ]);

        assert_eq!(unanswered(&flow), Answer::Yes(vec![place(1), place(2)]));
    }

    #[test]
    fn a_save_followed_by_a_dispatch_on_every_path_answers_no() {
        let flow = Flow::Seq(vec![save(1), dispatch(2), Flow::Exit(Exit::Ok, place(3))]);

        assert_eq!(unanswered(&flow), Answer::No);
    }

    #[test]
    fn a_unit_holding_both_steps_is_found() {
        let flow = Flow::Seq(vec![Flow::Unit {
            name: "kept_together".to_owned(),
            place: place(1),
            inner: Box::new(Flow::Seq(vec![save(2), dispatch(3)])),
        }]);

        let found = inside_one_unit(&flow, &is_store_write, &|step: &Step| {
            matches!(step, Step::Dispatch)
        });

        assert_eq!(
            found.map(|(name, _, _)| name).as_deref(),
            Some("kept_together")
        );
    }
}
