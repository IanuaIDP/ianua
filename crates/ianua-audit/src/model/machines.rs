//! The domain's status machines, read from their code.
//!
//! A status machine is an enum with a `try_transition(self, to: Self)`, as
//! the domain's conventions require. The moves it allows are read by
//! working its body out for every pair of its variants: `matches!` over
//! `(self, to)`, comparisons, `&&`, `||` and `!`, `let`, `if`, `match` and
//! early returns, `Ok` and `Err`, the shared `checked(self, to, rule)`
//! with a closure or a function of the enum, and the enum's own functions
//! it calls, such as `can_transition_to` over `allowed_transitions`. A
//! body in any other shape is not read, and the machine says so. A state
//! no allowed move leaves is final.
//!
//! A state enum carries more than the status, such as `RunState` with the
//! call a run waits on, and maps onto a machine through its own
//! `status(&self) -> Machine`, read the same way for each of its variants.

use std::collections::{BTreeMap, BTreeSet};

use syn::parse::{ParseStream, Parser};
use syn::{
    BinOp, Block, Expr, ExprCall, ExprMethodCall, FnArg, ImplItemFn, Item, ItemEnum, Pat, Stmt,
    UnOp,
};

use crate::source::syntax::{impl_fns, inherent_impl_of, items_of, type_name};
use crate::source::{Place, SourceFile};

/// The function every status machine moves through.
pub(crate) const TRANSITION: &str = "try_transition";

/// The function a state enum maps onto its machine with.
const STATUS: &str = "status";

/// How many of its own functions deep a body is worked out.
const CALL_DEPTH: usize = 4;

/// One status machine.
#[derive(Clone, Debug)]
pub(crate) struct Machine {
    /// The enum.
    pub(crate) name: String,
    /// Where its `try_transition` is declared.
    pub(crate) place: Place,
    /// Its variants, with where each is declared.
    pub(crate) variants: Vec<(String, Place)>,
    /// The moves it allows, as `(from, to)`; `None` when its body is in a
    /// shape the reader does not work out.
    pub(crate) moves: Option<BTreeSet<(String, String)>>,
}

impl Machine {
    /// The states no allowed move leaves; none when the moves are not read.
    pub(crate) fn finals(&self) -> Vec<&(String, Place)> {
        let Some(moves) = &self.moves else {
            return Vec::new();
        };
        self.variants
            .iter()
            .filter(|(from, _)| !moves.iter().any(|(at, to)| at == from && to != from))
            .collect()
    }
}

/// A state enum that maps onto a status machine.
#[derive(Clone, Debug)]
pub(crate) struct StateMap {
    /// The state enum.
    pub(crate) name: String,
    /// The machine its `status()` hands back.
    pub(crate) machine: String,
    /// Each of its variants with the machine's variant it maps to, `None`
    /// where the reader could not work it out.
    pub(crate) statuses: BTreeMap<String, Option<String>>,
}

/// The status machines and the state enums mapped onto them.
#[derive(Clone, Debug, Default)]
pub(crate) struct Machines {
    /// The machines.
    pub(crate) machines: Vec<Machine>,
    /// The state enums.
    pub(crate) states: Vec<StateMap>,
}

impl Machines {
    /// Reads the machines of the domain's `files`.
    pub(crate) fn read(files: &[&SourceFile]) -> Self {
        let enums = enums(files);
        let functions = functions(files);
        let machines: Vec<Machine> = enums
            .iter()
            .filter_map(|(name, declared)| machine(name, declared.as_ref()?, &functions))
            .collect();
        let names: BTreeSet<&str> = machines.iter().map(|found| found.name.as_str()).collect();
        let states = enums
            .iter()
            .filter(|(name, _)| !names.contains(name.as_str()))
            .filter_map(|(name, declared)| state_map(name, declared.as_ref()?, &functions, &names))
            .collect();
        Self { machines, states }
    }

    /// The machine named `name`.
    pub(crate) fn machine(&self, name: &str) -> Option<&Machine> {
        self.machines.iter().find(|found| found.name == name)
    }

    /// The machine a field of type `ty` moves through: the type itself, or
    /// the machine a state enum maps onto.
    pub(crate) fn machine_of(&self, ty: &str) -> Option<&Machine> {
        self.machine(ty).or_else(|| {
            let state = self.states.iter().find(|found| found.name == ty)?;
            self.machine(&state.machine)
        })
    }

    /// The machine's variant a value `variant` of the type `ty` stands for:
    /// itself for a machine, its mapping for a state enum. `None` when
    /// unread.
    pub(crate) fn status_of(&self, ty: &str, variant: &str) -> Option<String> {
        if let Some(machine) = self.machine(ty) {
            return machine
                .variants
                .iter()
                .any(|(name, _)| name == variant)
                .then(|| variant.to_owned());
        }
        let state = self.states.iter().find(|found| found.name == ty)?;
        state.statuses.get(variant).cloned().flatten()
    }

    /// Whether `ty` is a machine or a state enum mapped onto one.
    pub(crate) fn holds_status(&self, ty: &str) -> bool {
        self.machine_of(ty).is_some()
    }
}

/// An enum, with the file declaring it.
struct Declared<'f> {
    file: &'f SourceFile,
    item: &'f ItemEnum,
}

/// Every enum by name; `None` for a name declared more than once, which
/// the reader cannot tell apart.
fn enums<'f>(files: &[&'f SourceFile]) -> BTreeMap<String, Option<Declared<'f>>> {
    let mut found: BTreeMap<String, Option<Declared<'f>>> = BTreeMap::new();
    for file in files {
        let Some(syntax) = file.syntax() else {
            continue;
        };
        for item in items_of(syntax) {
            let Item::Enum(declared) = item else {
                continue;
            };
            found
                .entry(declared.ident.to_string())
                .and_modify(|seen| *seen = None)
                .or_insert(Some(Declared {
                    file,
                    item: declared,
                }));
        }
    }
    found
}

/// Every function of every inherent `impl`, by type and name.
type Functions<'f> = BTreeMap<String, BTreeMap<String, Vec<&'f ImplItemFn>>>;

fn functions<'f>(files: &[&'f SourceFile]) -> Functions<'f> {
    let mut found: Functions<'f> = BTreeMap::new();
    for file in files {
        let Some(syntax) = file.syntax() else {
            continue;
        };
        for item in items_of(syntax) {
            let Item::Impl(block) = item else {
                continue;
            };
            let Some(owner) = inherent_impl_of(block) else {
                continue;
            };
            for function in impl_fns(block) {
                found
                    .entry(owner.clone())
                    .or_default()
                    .entry(function.sig.ident.to_string())
                    .or_default()
                    .push(function);
            }
        }
    }
    found
}

fn machine(name: &str, declared: &Declared<'_>, functions: &Functions<'_>) -> Option<Machine> {
    let own = functions.get(name)?;
    let [transition] = own.get(TRANSITION)?.as_slice() else {
        return None;
    };
    let reader = Evaluator::new(declared.item, own, &[name]);
    let variants: Vec<String> = variant_names(declared.item);
    let moves = variants
        .iter()
        .flat_map(|from| variants.iter().map(move |to| (from, to)))
        .map(|(from, to)| allows(&reader, transition, from, to))
        .collect::<Option<Vec<_>>>()
        .map(|moves| moves.into_iter().flatten().collect());
    Some(Machine {
        name: name.to_owned(),
        place: Place::of(declared.file, &transition.sig.ident),
        variants: (declared.item.variants.iter())
            .map(|variant| {
                let place = Place::of(declared.file, &variant.ident);
                (variant.ident.to_string(), place)
            })
            .collect(),
        moves,
    })
}

/// The move from `from` to `to`, when `transition` read by `reader`
/// allows it; `None` when the answer is not worked out.
fn allows(
    reader: &Evaluator<'_>,
    transition: &ImplItemFn,
    from: &str,
    to: &str,
) -> Option<Option<(String, String)>> {
    let called = Called::on(
        Value::Variant(from.to_owned()),
        vec![Value::Variant(to.to_owned())],
    );
    match reader.call(transition, called, 0)? {
        Value::Moved(true) => Some(Some((from.to_owned(), to.to_owned()))),
        Value::Moved(false) => Some(None),
        _ => None,
    }
}

fn state_map(
    name: &str,
    declared: &Declared<'_>,
    functions: &Functions<'_>,
    machines: &BTreeSet<&str>,
) -> Option<StateMap> {
    let own = functions.get(name)?;
    let [status] = own.get(STATUS)?.as_slice() else {
        return None;
    };
    let syn::ReturnType::Type(_, returned) = &status.sig.output else {
        return None;
    };
    let machine = type_name(returned).filter(|found| machines.contains(found.as_str()))?;
    let reader = Evaluator::new(declared.item, own, &[name, machine.as_str()]);
    let statuses = variant_names(declared.item)
        .into_iter()
        .map(|variant| {
            let status = reader.call(
                status,
                Called::on(Value::Variant(variant.clone()), Vec::new()),
                0,
            );
            let mapped = match status {
                Some(Value::Variant(found)) => Some(found),
                _ => None,
            };
            (variant, mapped)
        })
        .collect();
    Some(StateMap {
        name: name.to_owned(),
        machine,
        statuses,
    })
}

fn variant_names(declared: &ItemEnum) -> Vec<String> {
    declared
        .variants
        .iter()
        .map(|variant| variant.ident.to_string())
        .collect()
}

/// A value the evaluator works with.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    /// A variant of an enum, by name.
    Variant(String),
    /// A tuple.
    Tuple(Vec<Value>),
    /// A list, such as `&[Self::Active, Self::Closed]`.
    List(Vec<Value>),
    /// A truth value.
    Bool(bool),
    /// `Ok(..)` (true) or `Err(..)` (false).
    Moved(bool),
    /// Nothing.
    Unit,
}

/// Where a body goes on: on with a value, or back to its caller.
enum Flow {
    On(Value),
    Back(Value),
}

/// Local names and what they hold.
type Env = BTreeMap<String, Value>;

/// Whether a pattern matched, with what it bound.
enum Matched {
    Yes(Vec<(String, Value)>),
    No,
}

/// What a function is called with: the value it is called on, if any,
/// and its arguments in order.
struct Called {
    receiver: Option<Value>,
    args: Vec<Value>,
}

impl Called {
    /// A call with no value to call it on.
    fn free(args: Vec<Value>) -> Self {
        Self {
            receiver: None,
            args,
        }
    }

    /// A method call on `receiver`.
    fn on(receiver: Value, args: Vec<Value>) -> Self {
        Self {
            receiver: Some(receiver),
            args,
        }
    }
}

/// Works out bodies of one enum's functions for concrete variants.
struct Evaluator<'e> {
    functions: &'e BTreeMap<String, Vec<&'e ImplItemFn>>,
    enums: Vec<String>,
    data_variants: BTreeSet<String>,
}

impl<'e> Evaluator<'e> {
    fn new(
        declared: &ItemEnum,
        functions: &'e BTreeMap<String, Vec<&'e ImplItemFn>>,
        enums: &[&str],
    ) -> Self {
        Self {
            functions,
            enums: enums.iter().map(|name| (*name).to_owned()).collect(),
            data_variants: declared
                .variants
                .iter()
                .filter(|variant| !variant.fields.is_empty())
                .map(|variant| variant.ident.to_string())
                .collect(),
        }
    }

    /// `function` called as `called` says, as a value.
    fn call(&self, function: &ImplItemFn, called: Called, depth: usize) -> Option<Value> {
        if depth > CALL_DEPTH {
            return None;
        }
        let Called { mut receiver, args } = called;
        let mut vars = Env::new();
        let mut args = args.into_iter();
        for input in &function.sig.inputs {
            match input {
                FnArg::Receiver(_) => {
                    vars.insert("self".to_owned(), receiver.take()?);
                }
                FnArg::Typed(typed) => {
                    let value = args.next()?;
                    bind_pattern(&typed.pat, value, &mut vars)?;
                }
            }
        }
        match self.block(&function.block, &mut vars, depth)? {
            Flow::On(value) | Flow::Back(value) => Some(value),
        }
    }

    fn block(&self, block: &Block, vars: &mut Env, depth: usize) -> Option<Flow> {
        let mut last = Value::Unit;
        for statement in &block.stmts {
            last = match statement {
                Stmt::Local(local) => {
                    let init = local.init.as_ref()?;
                    if init.diverge.is_some() {
                        return None;
                    }
                    let value = self.value(&init.expr, vars, depth)?;
                    bind_pattern(&local.pat, value, vars)?;
                    Value::Unit
                }
                Stmt::Expr(expr, semi) => match self.expr(expr, vars, depth)? {
                    Flow::Back(value) => return Some(Flow::Back(value)),
                    Flow::On(_) if semi.is_some() => Value::Unit,
                    Flow::On(value) => value,
                },
                Stmt::Macro(invoked) => {
                    let value = self.macro_value(&invoked.mac, vars, depth)?;
                    match invoked.semi_token {
                        Some(_) => Value::Unit,
                        None => value,
                    }
                }
                Stmt::Item(_) => return None,
            };
        }
        Some(Flow::On(last))
    }

    fn value(&self, expr: &Expr, vars: &mut Env, depth: usize) -> Option<Value> {
        match self.expr(expr, vars, depth)? {
            Flow::On(value) => Some(value),
            Flow::Back(_) => None,
        }
    }

    fn expr(&self, expr: &Expr, vars: &mut Env, depth: usize) -> Option<Flow> {
        let value = match expr {
            Expr::Paren(inner) => return self.expr(&inner.expr, vars, depth),
            Expr::Group(inner) => return self.expr(&inner.expr, vars, depth),
            Expr::Block(inner) => return self.block(&inner.block, &mut vars.clone(), depth),
            Expr::If(branch) => return self.branch(branch, vars, depth),
            Expr::Match(choice) => return self.choice(choice, vars, depth),
            Expr::Return(back) => {
                let value = match &back.expr {
                    Some(inner) => self.value(inner, vars, depth)?,
                    None => Value::Unit,
                };
                return Some(Flow::Back(value));
            }
            Expr::Reference(inner) => self.value(&inner.expr, vars, depth)?,
            Expr::Unary(unary) => self.unary(unary, vars, depth)?,
            Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Bool(truth),
                ..
            }) => Value::Bool(truth.value),
            Expr::Path(path) => self.path_value(&path.path, vars)?,
            Expr::Tuple(tuple) => Value::Tuple(self.values(tuple.elems.iter(), vars, depth)?),
            Expr::Array(array) => Value::List(self.values(array.elems.iter(), vars, depth)?),
            Expr::Binary(binary) => self.binary(binary, vars, depth)?,
            Expr::Call(call) => self.function_call(call, vars, depth)?,
            Expr::MethodCall(call) => self.method_call(call, vars, depth)?,
            Expr::Macro(invoked) => self.macro_value(&invoked.mac, vars, depth)?,
            _ => return None,
        };
        Some(Flow::On(value))
    }

    fn branch(&self, branch: &syn::ExprIf, vars: &mut Env, depth: usize) -> Option<Flow> {
        let Value::Bool(holds) = self.value(&branch.cond, vars, depth)? else {
            return None;
        };
        if holds {
            return self.block(&branch.then_branch, &mut vars.clone(), depth);
        }
        match &branch.else_branch {
            Some((_, otherwise)) => self.expr(otherwise, vars, depth),
            None => Some(Flow::On(Value::Unit)),
        }
    }

    fn choice(&self, choice: &syn::ExprMatch, vars: &mut Env, depth: usize) -> Option<Flow> {
        let scrutinee = self.value(&choice.expr, vars, depth)?;
        for arm in &choice.arms {
            if arm.guard.is_some() {
                return None;
            }
            let Matched::Yes(bound) = self.matches(&arm.pat, &scrutinee)? else {
                continue;
            };
            let mut inner = vars.clone();
            inner.extend(bound);
            return self.expr(&arm.body, &mut inner, depth);
        }
        None
    }

    fn unary(&self, unary: &syn::ExprUnary, vars: &mut Env, depth: usize) -> Option<Value> {
        let inner = self.value(&unary.expr, vars, depth)?;
        match (unary.op, inner) {
            (UnOp::Not(_), Value::Bool(truth)) => Some(Value::Bool(!truth)),
            (UnOp::Deref(_), value) => Some(value),
            _ => None,
        }
    }

    fn binary(&self, binary: &syn::ExprBinary, vars: &mut Env, depth: usize) -> Option<Value> {
        let left = self.value(&binary.left, vars, depth)?;
        match (binary.op, &left) {
            (BinOp::And(_), Value::Bool(false)) => return Some(Value::Bool(false)),
            (BinOp::Or(_), Value::Bool(true)) => return Some(Value::Bool(true)),
            _ => {}
        }
        let right = self.value(&binary.right, vars, depth)?;
        match binary.op {
            BinOp::And(_) | BinOp::Or(_) => match right {
                Value::Bool(truth) => Some(Value::Bool(truth)),
                _ => None,
            },
            BinOp::Eq(_) => self.equal(&left, &right).map(Value::Bool),
            BinOp::Ne(_) => self.equal(&left, &right).map(|same| Value::Bool(!same)),
            _ => None,
        }
    }

    /// Whether two values are equal; `None` for two variants of one name
    /// that carry data the reader does not hold.
    fn equal(&self, left: &Value, right: &Value) -> Option<bool> {
        match (left, right) {
            (Value::Variant(a), Value::Variant(b)) if a == b && self.data_variants.contains(a) => {
                None
            }
            (Value::Variant(a), Value::Variant(b)) => Some(a == b),
            (Value::Bool(a), Value::Bool(b)) => Some(a == b),
            (Value::Tuple(a), Value::Tuple(b)) if a.len() == b.len() => a
                .iter()
                .zip(b)
                .try_fold(true, |all, (x, y)| Some(all && self.equal(x, y)?)),
            _ => None,
        }
    }

    fn path_value(&self, path: &syn::Path, vars: &Env) -> Option<Value> {
        let names: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        match names.as_slice() {
            [name] => vars.get(name).cloned(),
            [.., owner, variant] if self.names_enum(owner) => Some(Value::Variant(variant.clone())),
            _ => None,
        }
    }

    /// Whether `owner`, written before a variant, is one of the enums read.
    fn names_enum(&self, owner: &str) -> bool {
        owner == "Self" || self.enums.iter().any(|name| name == owner)
    }

    fn function_call(&self, call: &ExprCall, vars: &mut Env, depth: usize) -> Option<Value> {
        let Expr::Path(function) = call.func.as_ref() else {
            return None;
        };
        let names: Vec<String> = function
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        match names.as_slice() {
            [name] if name == "Ok" => Some(Value::Moved(true)),
            [name] if name == "Err" => Some(Value::Moved(false)),
            [.., name] if name == "checked" => self.checked(call, vars, depth),
            [owner, name] if self.names_enum(owner) => {
                let args = self.values(call.args.iter(), vars, depth)?;
                let [own] = self.functions.get(name)?.as_slice() else {
                    return None;
                };
                self.call(own, Called::free(args), depth + 1)
            }
            _ => None,
        }
    }

    /// `checked(from, to, rule)`: the move is made when the rule, a
    /// closure or a function of the enum, allows it.
    fn checked(&self, call: &ExprCall, vars: &mut Env, depth: usize) -> Option<Value> {
        let [from, to, rule] = call.args.iter().collect::<Vec<_>>()[..] else {
            return None;
        };
        let ends = vec![self.value(from, vars, depth)?, self.value(to, vars, depth)?];
        let allowed = match rule {
            Expr::Closure(closure) => {
                let mut inner = Env::new();
                for (input, value) in closure.inputs.iter().zip(ends) {
                    bind_pattern(input, value, &mut inner)?;
                }
                self.value(&closure.body, &mut inner, depth + 1)?
            }
            Expr::Path(path) => {
                let name = path.path.segments.last()?.ident.to_string();
                let [own] = self.functions.get(&name)?.as_slice() else {
                    return None;
                };
                self.call(own, Called::free(ends), depth + 1)?
            }
            _ => return None,
        };
        match allowed {
            Value::Bool(truth) => Some(Value::Moved(truth)),
            _ => None,
        }
    }

    fn method_call(&self, call: &ExprMethodCall, vars: &mut Env, depth: usize) -> Option<Value> {
        let receiver = self.value(&call.receiver, vars, depth)?;
        let name = call.method.to_string();
        let args = self.values(call.args.iter(), vars, depth)?;
        match (name.as_str(), &receiver, args.as_slice()) {
            ("contains", Value::List(items), [wanted]) => {
                let mut found = false;
                for item in items {
                    found |= self.equal(item, wanted)?;
                }
                Some(Value::Bool(found))
            }
            ("is_ok", Value::Moved(made), []) => Some(Value::Bool(*made)),
            ("is_err", Value::Moved(made), []) => Some(Value::Bool(!made)),
            ("clone" | "to_owned", _, []) => Some(receiver),
            _ => {
                let [own] = self.functions.get(&name)?.as_slice() else {
                    return None;
                };
                self.call(own, Called::on(receiver, args), depth + 1)
            }
        }
    }

    fn values<'x>(
        &self,
        exprs: impl Iterator<Item = &'x Expr>,
        vars: &mut Env,
        depth: usize,
    ) -> Option<Vec<Value>> {
        exprs.map(|expr| self.value(expr, vars, depth)).collect()
    }

    /// `matches!(value, pattern)`; any other macro is not read.
    fn macro_value(&self, invoked: &syn::Macro, vars: &mut Env, depth: usize) -> Option<Value> {
        if !invoked.path.is_ident("matches") {
            return None;
        }
        let (expr, pattern) = matches_parts.parse2(invoked.tokens.clone()).ok()?;
        let value = self.value(&expr, vars, depth)?;
        match self.matches(&pattern, &value)? {
            Matched::Yes(_) => Some(Value::Bool(true)),
            Matched::No => Some(Value::Bool(false)),
        }
    }

    /// Whether `pattern` matches `value`; `None` for a pattern the reader
    /// cannot decide.
    fn matches(&self, pattern: &Pat, value: &Value) -> Option<Matched> {
        match pattern {
            Pat::Wild(_) => Some(Matched::Yes(Vec::new())),
            Pat::Paren(inner) => self.matches(&inner.pat, value),
            Pat::Reference(inner) => self.matches(&inner.pat, value),
            Pat::Ident(binding) if binding.subpat.is_none() => {
                let name = binding.ident.to_string();
                if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                    return variant_matches(&name, value);
                }
                Some(Matched::Yes(vec![(name, value.clone())]))
            }
            Pat::Path(path) => variant_matches(&last_name(&path.path)?, value),
            Pat::TupleStruct(tuple) if takes_any_fields(tuple) => {
                variant_matches(&last_name(&tuple.path)?, value)
            }
            Pat::Struct(fields) if fields.fields.is_empty() || fields.rest.is_some() => {
                variant_matches(&last_name(&fields.path)?, value)
            }
            Pat::Tuple(tuple) => self.tuple_matches(tuple, value),
            Pat::Or(choices) => self.any_matches(&choices.cases, value),
            Pat::Lit(syn::PatLit {
                lit: syn::Lit::Bool(truth),
                ..
            }) => match value {
                Value::Bool(held) if *held == truth.value => Some(Matched::Yes(Vec::new())),
                Value::Bool(_) => Some(Matched::No),
                _ => None,
            },
            _ => None,
        }
    }

    fn tuple_matches(&self, tuple: &syn::PatTuple, value: &Value) -> Option<Matched> {
        let Value::Tuple(parts) = value else {
            return None;
        };
        if parts.len() != tuple.elems.len() {
            return None;
        }
        let mut bound = Vec::new();
        for (pattern, part) in tuple.elems.iter().zip(parts) {
            match self.matches(pattern, part)? {
                Matched::Yes(more) => bound.extend(more),
                Matched::No => return Some(Matched::No),
            }
        }
        Some(Matched::Yes(bound))
    }

    fn any_matches<'p>(
        &self,
        cases: impl IntoIterator<Item = &'p Pat>,
        value: &Value,
    ) -> Option<Matched> {
        for case in cases {
            if let Matched::Yes(bound) = self.matches(case, value)? {
                return Some(Matched::Yes(bound));
            }
        }
        Some(Matched::No)
    }
}

/// Whether the variant named `name` matches `value`.
fn variant_matches(name: &str, value: &Value) -> Option<Matched> {
    let Value::Variant(held) = value else {
        return None;
    };
    Some(match held == name {
        true => Matched::Yes(Vec::new()),
        false => Matched::No,
    })
}

/// Whether `tuple` binds nothing of its variant: each of its parts is `_`
/// or `..`.
fn takes_any_fields(tuple: &syn::PatTupleStruct) -> bool {
    (tuple.elems.iter()).all(|part| matches!(part, Pat::Wild(_) | Pat::Rest(_)))
}

fn last_name(path: &syn::Path) -> Option<String> {
    path.segments
        .last()
        .map(|segment| segment.ident.to_string())
}

/// Binds `value` to a parameter or `let` pattern: a name, `_`, or a name
/// with its type written.
fn bind_pattern(pattern: &Pat, value: Value, vars: &mut Env) -> Option<()> {
    match pattern {
        Pat::Ident(binding) if binding.subpat.is_none() => {
            vars.insert(binding.ident.to_string(), value);
            Some(())
        }
        Pat::Type(typed) => bind_pattern(&typed.pat, value, vars),
        Pat::Wild(_) => Some(()),
        _ => None,
    }
}

/// The parts of `matches!(expr, pattern)`; a guard is refused.
fn matches_parts(input: ParseStream<'_>) -> syn::Result<(Expr, Pat)> {
    let expr: Expr = input.parse()?;
    input.parse::<syn::Token![,]>()?;
    let pattern = Pat::parse_multi_with_leading_vert(input)?;
    if input.peek(syn::Token![if]) {
        return Err(input.error("a guard"));
    }
    input.parse::<Option<syn::Token![,]>>()?;
    Ok((expr, pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::planted::domain;

    fn read(text: &str) -> Machines {
        let file = domain("domains/messaging/status.rs", text);
        Machines::read(&[&file])
    }

    fn finals(machines: &Machines, name: &str) -> Vec<String> {
        machines
            .machine(name)
            .unwrap()
            .finals()
            .into_iter()
            .map(|(variant, _)| variant.clone())
            .collect()
    }

    #[test]
    fn a_matches_over_both_ends_is_read_and_its_final_states_found() {
        let found = read(
            "pub enum OrgStatus { Active, Suspended, Closed }
             impl OrgStatus {
                 pub fn try_transition(self, to: Self) -> Result<Self, Invalid> {
                     let allowed = matches!(
                         (self, to),
                         (Self::Active, Self::Suspended | Self::Closed)
                             | (Self::Suspended, Self::Active | Self::Closed)
                     );
                     if allowed { Ok(to) } else { Err(Invalid { from: self, to }) }
                 }
             }",
        );

        assert_eq!(finals(&found, "OrgStatus"), ["Closed"]);
    }

    #[test]
    fn a_rule_handed_to_checked_is_read_with_its_comparisons() {
        let found = read(
            "pub enum KeyStatus { Active, Revoked }
             impl KeyStatus {
                 pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
                     checked(self, to, |from, to| from == Self::Active && to == Self::Revoked)
                 }
             }",
        );

        let moves = found.machine("KeyStatus").unwrap().moves.clone().unwrap();
        assert_eq!(
            moves.into_iter().collect::<Vec<_>>(),
            [("Active".to_owned(), "Revoked".to_owned())]
        );
        assert_eq!(finals(&found, "KeyStatus"), ["Revoked"]);
    }

    #[test]
    fn a_list_of_allowed_moves_is_followed_through_the_enums_own_functions() {
        let found = read(
            "pub enum TenantStatus { Active, Archived, Deleted }
             impl TenantStatus {
                 pub fn allowed_transitions(&self) -> &'static [TenantStatus] {
                     match self {
                         Self::Active => &[Self::Archived],
                         Self::Archived => &[Self::Active, Self::Deleted],
                         Self::Deleted => &[],
                     }
                 }
                 pub fn can_transition_to(&self, target: TenantStatus) -> bool {
                     self.allowed_transitions().contains(&target)
                 }
                 pub fn try_transition(self, to: Self) -> Result<Self, Invalid> {
                     if !self.can_transition_to(to) {
                         return Err(Invalid { from: self, to });
                     }
                     Ok(to)
                 }
             }",
        );

        assert_eq!(finals(&found, "TenantStatus"), ["Deleted"]);
    }

    #[test]
    fn a_rule_of_the_enum_matching_on_one_end_is_read() {
        let found = read(
            "pub enum RunStatus { Running, Paused, Completed }
             impl RunStatus {
                 pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
                     checked(self, to, Self::permits)
                 }
                 fn permits(from: Self, to: Self) -> bool {
                     let ends = matches!(to, Self::Completed);
                     match from {
                         Self::Running => ends || to == Self::Paused,
                         Self::Paused => to == Self::Running,
                         Self::Completed => false,
                     }
                 }
             }",
        );

        assert_eq!(finals(&found, "RunStatus"), ["Completed"]);
    }

    #[test]
    fn a_body_in_another_shape_is_not_read() {
        let found = read(
            "pub enum Odd { A, B }
             impl Odd {
                 pub fn try_transition(self, to: Self) -> Result<Self, Invalid> {
                     RULES.check(self, to)
                 }
             }",
        );

        let odd = found.machine("Odd").unwrap();
        assert!(odd.moves.is_none());
        assert!(odd.finals().is_empty());
    }

    #[test]
    fn a_state_enum_maps_its_variants_onto_its_machine() {
        let found = read(
            "pub enum JobStatus { Running, Done }
             impl JobStatus {
                 pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
                     checked(self, to, |from, to| matches!((from, to), (Self::Running, Self::Done)))
                 }
             }
             pub enum JobState { Running(Step), Done { at: Time } }
             impl JobState {
                 pub fn status(&self) -> JobStatus {
                     match self {
                         Self::Running(_) => JobStatus::Running,
                         Self::Done { .. } => JobStatus::Done,
                     }
                 }
             }",
        );

        assert_eq!(found.status_of("JobState", "Done").as_deref(), Some("Done"));
        assert_eq!(found.machine_of("JobState").unwrap().name, "JobStatus");
    }
}
