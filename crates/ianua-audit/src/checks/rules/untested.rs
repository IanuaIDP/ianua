//! `rules.table-untested`: rows of a worked-out rule no test calls it with.
//!
//! The tests read are every `#[test]` function of the workspace: the
//! `#[cfg(test)]` items of each file, the files of modules built only for
//! tests, and the files under each crate's `tests/`. A call of the rule
//! counts with the inputs it is given when each is written out: a variant
//! or `true`/`false`, a name a `let` or a `for` loop over a written list
//! binds, or a parameter of a helper of the same file the test calls with
//! one. A call with an input not read this way, and a test calling a
//! domain function that calls the rule, may reach any row; those rows are
//! left unsaid.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::{self, Visit};
use syn::{Expr, File, Item, ItemFn, Pat};

use crate::finding::{Check, Finding, Found, Unsaid};
use crate::model::evaluate::Index;
use crate::model::rules::Rules;
use crate::model::rules::decisions::{Decision, Reading, Row};
use crate::source::Workspace;

/// How many sets of loop values one test is read with, at most; past it
/// the loop's names are not read.
const MOST_WORLDS: usize = 4096;

/// How many helpers deep a test is followed.
const HELPER_DEPTH: usize = 2;

/// Every finding of the check.
pub(super) fn run(workspace: &Workspace, index: &Index<'_>, rules: &Rules) -> Found {
    let decisions: Vec<&Decision> = rules
        .decisions
        .iter()
        .filter(|decision| decision.reading == Reading::WorkedOut)
        .collect();
    let targets: Vec<Target> = decisions
        .iter()
        .map(|decision| Target::of(decision))
        .collect();
    let callers = callers(index, &targets);
    let mut reached = vec![Reached::default(); targets.len()];
    for file in workspace.tests() {
        read_file(file, &targets, &callers, &mut reached);
    }
    let mut found = Found::default();
    for ((decision, target), reached) in decisions.iter().zip(&targets).zip(&reached) {
        judge(decision, target, reached, &mut found);
    }
    found
}

/// A rule as its calls are matched: its owner, name and inputs.
struct Target {
    owner: Option<String>,
    name: String,
    takes_self: bool,
    inputs: Vec<BTreeSet<String>>,
}

impl Target {
    fn of(decision: &Decision) -> Self {
        let (owner, name) = match decision.subject.rsplit_once("::") {
            Some((owner, name)) => (Some(owner.to_owned()), name.to_owned()),
            None => (None, decision.subject.clone()),
        };
        Self {
            owner,
            name,
            takes_self: decision
                .inputs
                .first()
                .is_some_and(|input| input.name == "self"),
            inputs: decision
                .inputs
                .iter()
                .map(|input| input.values.iter().cloned().collect())
                .collect(),
        }
    }

    /// Whether a call through the path `segments` names it.
    fn named_by(&self, segments: &[String]) -> bool {
        match (segments, &self.owner) {
            ([.., owner, name], Some(own)) => owner == own && *name == self.name,
            ([name], None) => *name == self.name,
            _ => false,
        }
    }
}

/// What the tests do with one rule.
#[derive(Clone, Default)]
struct Reached {
    /// Each call's inputs, `None` for one not read.
    calls: BTreeSet<Vec<Option<String>>>,
    /// The functions tests call that call the rule.
    through: BTreeSet<String>,
}

/// The domain functions that call each rule, by the rule's position, as
/// `Owner::name` or the bare name of a free function.
fn callers(index: &Index<'_>, targets: &[Target]) -> Vec<BTreeSet<String>> {
    let mut found = vec![BTreeSet::new(); targets.len()];
    for body in index.bodies() {
        let owner = body.owner.map(ToString::to_string);
        let mut calls = Calls::default();
        calls.visit_block(body.block);
        for (position, target) in targets.iter().enumerate() {
            if body.name() == target.name && owner == target.owner {
                continue;
            }
            if calls.reach(target, owner.as_deref()) {
                found[position].insert(body.subject());
            }
        }
    }
    found
}

/// The calls a body makes: through a path, by its names, and of methods,
/// by name.
#[derive(Default)]
struct Calls {
    paths: BTreeSet<Vec<String>>,
    methods: BTreeSet<String>,
}

impl Calls {
    /// Whether one of them may call `target`, from a body of `owner`: a
    /// path naming it, `Self::name` in its own type, or a method of its
    /// name when it takes `self`.
    fn reach(&self, target: &Target, owner: Option<&str>) -> bool {
        let by_path = self.paths.iter().any(|path| match path.as_slice() {
            [.., first, name] if first == "Self" => {
                *name == target.name && owner.is_some() && owner == target.owner.as_deref()
            }
            _ => target.named_by(path),
        });
        by_path || (target.takes_self && self.methods.contains(&target.name))
    }
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Some(path) = path_of(&call.func) {
            self.paths.insert(path);
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.insert(call.method.to_string());
        visit::visit_expr_method_call(self, call);
    }
}

/// Reads every test of `file`.
fn read_file(
    file: &File,
    targets: &[Target],
    callers: &[BTreeSet<String>],
    reached: &mut [Reached],
) {
    let mut functions = Vec::new();
    collect_functions(&file.items, &mut functions);
    let mut helpers: BTreeMap<String, Option<&ItemFn>> = BTreeMap::new();
    for function in &functions {
        helpers
            .entry(function.sig.ident.to_string())
            .and_modify(|seen| *seen = None)
            .or_insert(Some(function));
    }
    let mut reader = Reader {
        targets,
        callers,
        helpers: &helpers,
        reached,
        worlds: vec![World::new()],
        depth: 0,
    };
    for test in functions.iter().filter(|function| is_test(function)) {
        reader.worlds = vec![World::new()];
        reader.visit_block(&test.block);
    }
}

fn collect_functions<'f>(items: &'f [Item], found: &mut Vec<&'f ItemFn>) {
    for item in items {
        match item {
            Item::Fn(function) => found.push(function),
            Item::Mod(module) => {
                if let Some((_, inner)) = &module.content {
                    collect_functions(inner, found);
                }
            }
            _ => {}
        }
    }
}

/// Whether `function` is a test: an attribute whose last name is `test`.
fn is_test(function: &ItemFn) -> bool {
    function.attrs.iter().any(|attribute| {
        attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
    })
}

/// What the names in scope hold on one way through a test.
type World = BTreeMap<String, Expr>;

/// Walks one test, with every set of values its loops give its names.
struct Reader<'r, 'f> {
    targets: &'r [Target],
    callers: &'r [BTreeSet<String>],
    helpers: &'r BTreeMap<String, Option<&'f ItemFn>>,
    reached: &'r mut [Reached],
    worlds: Vec<World>,
    depth: usize,
}

impl Reader<'_, '_> {
    /// Notes a call of a rule, or of a function calling one, by `path`
    /// with `args`, `receiver` first for a method call.
    fn called(&mut self, name: &[String], receiver: Option<&Expr>, args: &[&Expr]) {
        for (position, target) in self.targets.iter().enumerate() {
            let through = self.callers[position]
                .iter()
                .find(|caller| named_like(caller, name))
                .cloned();
            if let Some(through) = through {
                self.reached[position].through.insert(through);
                continue;
            }
            let given = match receiver {
                Some(receiver) if target.takes_self && name.last() == Some(&target.name) => {
                    std::iter::once(receiver)
                        .chain(args.iter().copied())
                        .collect()
                }
                None if target.named_by(name) => args.to_vec(),
                _ => continue,
            };
            if given.len() != target.inputs.len() {
                continue;
            }
            let calls: Vec<Vec<Option<String>>> = self
                .worlds
                .iter()
                .map(|world| inputs_given(target, &given, world))
                .collect();
            self.reached[position].calls.extend(calls);
        }
    }

    /// Follows a call of a helper of the test's file, its parameters bound
    /// to what the call hands it.
    fn helper(&mut self, name: &str, args: &[&Expr]) {
        if self.depth >= HELPER_DEPTH {
            return;
        }
        let Some(Some(helper)) = self.helpers.get(name).copied() else {
            return;
        };
        let params = params_of(helper);
        let inside: Vec<World> = self
            .worlds
            .iter()
            .map(|world| {
                params
                    .iter()
                    .zip(args)
                    .filter_map(|(param, arg)| Some((param.clone()?, resolved(arg, world).clone())))
                    .collect()
            })
            .collect();
        let outer = std::mem::replace(&mut self.worlds, inside);
        self.depth += 1;
        self.visit_block(&helper.block);
        self.depth -= 1;
        self.worlds = outer;
    }

    /// Binds `pattern` to `value` in every world, or forgets its names.
    fn bind(&mut self, pattern: &Pat, value: Option<&Expr>) {
        for world in &mut self.worlds {
            let held = value.map(|value| resolved(value, world).clone());
            bind_in(world, pattern, held.as_ref());
        }
    }

    /// The worlds a `for` loop over `iterated` binding `pattern` runs its
    /// body in: one per element of a written list, the names forgotten
    /// where the list is not written out or the worlds grow too many.
    fn looped(&self, pattern: &Pat, iterated: &Expr) -> Vec<World> {
        let mut worlds = Vec::new();
        for world in &self.worlds {
            let Some(elements) = elements_of(iterated, world) else {
                let mut forgot = world.clone();
                bind_in(&mut forgot, pattern, None);
                worlds.push(forgot);
                continue;
            };
            for element in elements {
                let mut bound = world.clone();
                bind_in(&mut bound, pattern, Some(&element));
                worlds.push(bound);
            }
        }
        if worlds.len() <= MOST_WORLDS {
            return worlds;
        }
        self.worlds
            .iter()
            .map(|world| {
                let mut forgot = world.clone();
                bind_in(&mut forgot, pattern, None);
                forgot
            })
            .collect()
    }
}

impl<'ast> Visit<'ast> for Reader<'_, '_> {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        let outer = self.worlds.clone();
        visit::visit_block(self, block);
        self.worlds = outer;
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        visit::visit_local(self, local);
        let value = local.init.as_ref().map(|init| init.expr.as_ref());
        self.bind(&local.pat, value);
    }

    fn visit_expr_for_loop(&mut self, looping: &'ast syn::ExprForLoop) {
        self.visit_expr(&looping.expr);
        let inside = self.looped(&looping.pat, &looping.expr);
        let outer = std::mem::replace(&mut self.worlds, inside);
        self.visit_block(&looping.body);
        self.worlds = outer;
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        visit::visit_expr_call(self, call);
        let Some(path) = path_of(&call.func) else {
            return;
        };
        let args: Vec<&Expr> = call.args.iter().collect();
        self.called(&path, None, &args);
        if let [name] = path.as_slice() {
            self.helper(name, &args);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        visit::visit_expr_method_call(self, call);
        let args: Vec<&Expr> = call.args.iter().collect();
        self.called(&[call.method.to_string()], Some(&call.receiver), &args);
    }

    fn visit_macro(&mut self, called: &'ast syn::Macro) {
        let parsed = called
            .parse_body_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated);
        if let Ok(parsed) = parsed {
            for expr in &parsed {
                self.visit_expr(expr);
            }
        }
    }
}

/// Whether the function `caller`, as `Owner::name` or `name`, is what a
/// call by `name` reaches: the same last two names, or for a method call
/// the same name.
fn named_like(caller: &str, name: &[String]) -> bool {
    let (owner, own) = caller.rsplit_once("::").unwrap_or(("", caller));
    match name {
        [.., called_owner, called] => called_owner == owner && called == own,
        [called] => called == own,
        [] => false,
    }
}

/// The inputs `given` hand `target` in `world`, each `None` when not read.
fn inputs_given(target: &Target, given: &[&Expr], world: &World) -> Vec<Option<String>> {
    given
        .iter()
        .zip(&target.inputs)
        .map(|(expr, values)| value_of(resolved(expr, world), values))
        .collect()
}

/// What `expr` stands for: the value a name holds in `world`, through
/// references and brackets.
fn resolved<'e>(expr: &'e Expr, world: &'e World) -> &'e Expr {
    let mut current = expr;
    for _ in 0..8 {
        let next = match current {
            Expr::Reference(inner) => inner.expr.as_ref(),
            Expr::Paren(inner) => inner.expr.as_ref(),
            Expr::Group(inner) => inner.expr.as_ref(),
            Expr::Path(path) => match path
                .path
                .get_ident()
                .and_then(|name| world.get(&name.to_string()))
            {
                Some(held) => held,
                None => return current,
            },
            _ => return current,
        };
        current = next;
    }
    current
}

/// The value among `values` `expr` is written as: a variant by its last
/// name, or `true` or `false`.
fn value_of(expr: &Expr, values: &BTreeSet<String>) -> Option<String> {
    let written = match expr {
        Expr::Path(path) => path.path.segments.last()?.ident.to_string(),
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Bool(flag),
            ..
        }) => flag.value.to_string(),
        _ => return None,
    };
    values.contains(&written).then_some(written)
}

/// The elements of a list written out: `[a, b]`, `&[a, b]`, or such a
/// list a name holds, iterated as it is or by `iter`, `into_iter` or
/// `copied`.
fn elements_of(expr: &Expr, world: &World) -> Option<Vec<Expr>> {
    match resolved(expr, world) {
        Expr::Array(list) => Some(list.elems.iter().cloned().collect()),
        Expr::MethodCall(call)
            if matches!(
                call.method.to_string().as_str(),
                "iter" | "into_iter" | "copied" | "cloned"
            ) =>
        {
            elements_of(&call.receiver, world)
        }
        _ => None,
    }
}

/// Binds the names of `pattern` to the parts of `value` in `world`;
/// forgets them where `value` is not known or its parts do not line up.
fn bind_in(world: &mut World, pattern: &Pat, value: Option<&Expr>) {
    match (pattern, value) {
        (Pat::Ident(name), Some(value)) => {
            world.insert(name.ident.to_string(), value.clone());
        }
        (Pat::Tuple(parts), Some(Expr::Tuple(values)))
            if parts.elems.len() == values.elems.len() =>
        {
            for (part, held) in parts.elems.iter().zip(&values.elems) {
                bind_in(world, part, Some(held));
            }
        }
        (Pat::Reference(inner), value) => bind_in(world, &inner.pat, value),
        (Pat::Type(typed), value) => bind_in(world, &typed.pat, value),
        (pattern, _) => forget(world, pattern),
    }
}

fn forget(world: &mut World, pattern: &Pat) {
    match pattern {
        Pat::Ident(name) => {
            world.remove(&name.ident.to_string());
        }
        Pat::Tuple(parts) => parts.elems.iter().for_each(|part| forget(world, part)),
        Pat::Reference(inner) => forget(world, &inner.pat),
        Pat::Type(typed) => forget(world, &typed.pat),
        _ => {}
    }
}

/// The plain name each parameter of `helper` binds, in order; none for
/// `self` or a pattern.
fn params_of(helper: &ItemFn) -> Vec<Option<String>> {
    (helper.sig.inputs.iter())
        .map(|input| match input {
            syn::FnArg::Typed(typed) => bound_name(&typed.pat),
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

/// The plain name `pattern` binds, if it is one.
fn bound_name(pattern: &Pat) -> Option<String> {
    match pattern {
        Pat::Ident(name) => Some(name.ident.to_string()),
        Pat::Type(typed) => bound_name(&typed.pat),
        _ => None,
    }
}

/// The names of a path a call is made through, such as `["SecondFactor",
/// "under"]`.
fn path_of(func: &Expr) -> Option<Vec<String>> {
    let Expr::Path(path) = func else {
        return None;
    };
    Some(
        path.path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
    )
}

/// What the tests leave of `decision`: rows no read call can reach are
/// findings, rows a call not read may reach are unsaid.
fn judge(decision: &Decision, target: &Target, reached: &Reached, found: &mut Found) {
    let open: Vec<&Row> = decision
        .rows
        .iter()
        .filter(|row| !reached.calls.iter().any(|call| reaches(call, row)))
        .collect();
    if open.is_empty() {
        return;
    }
    if let Some(through) = reached.through.first() {
        found.leave_unsaid(unsaid(decision, format!(
            "a test calls `{through}`, which calls it, and the inputs it hands on are not followed"
        )));
        return;
    }
    let (unsure, untested): (Vec<&Row>, Vec<&Row>) = open
        .into_iter()
        .partition(|row| reached.calls.iter().any(|call| may_reach(call, row)));
    if !unsure.is_empty() {
        found.leave_unsaid(unsaid(
            decision,
            format!(
                "{} of its rows may be reached by a test call whose inputs are not read",
                unsure.len()
            ),
        ));
    }
    if untested.is_empty() {
        return;
    }
    found.findings.push(finding(decision, target, &untested));
}

/// Whether `call`, with every input read, takes the values of `row`.
fn reaches(call: &[Option<String>], row: &Row) -> bool {
    call.iter()
        .zip(&row.when)
        .all(|(given, wanted)| match (given, wanted) {
            (_, None) => given.is_some(),
            (Some(given), Some(wanted)) => given == wanted,
            (None, Some(_)) => false,
        })
}

/// Whether `call`, its unread inputs taking any value, may take the
/// values of `row`.
fn may_reach(call: &[Option<String>], row: &Row) -> bool {
    call.iter()
        .zip(&row.when)
        .all(|(given, wanted)| match (given, wanted) {
            (Some(given), Some(wanted)) => given == wanted,
            _ => true,
        })
}

/// What is left unsaid of whether the tests reach every row of
/// `decision`, for `why`.
fn unsaid(decision: &Decision, why: String) -> Unsaid {
    Unsaid::new(
        Check::UntestedTable,
        decision.subject.clone(),
        decision.place.clone(),
        why,
    )
}

/// Where `row` of `decision` is, what it answers and when.
fn row_line(decision: &Decision, row: &Row) -> String {
    let at = row.place.clone().unwrap_or_else(|| decision.place.clone());
    format!(
        "row:     {}:{}  {} when {}",
        at.file,
        at.line,
        row.outcome.as_deref().unwrap_or("not read"),
        conditions(decision, row)
    )
}

fn finding(decision: &Decision, target: &Target, untested: &[&Row]) -> Finding {
    let total = decision.rows.len();
    let mut detail = vec![format!(
        "rule:    {}:{}  {}",
        decision.place.file, decision.place.line, decision.subject
    )];
    detail.extend(untested.iter().map(|row| row_line(decision, row)));
    detail.push(
        "read: tests calling it, directly or through a domain function; a use case's test that reaches it is not counted".to_owned(),
    );
    detail.push("why: a row no test reaches can change without any test failing".to_owned());
    detail.push(format!(
        "fix: call `{}` in a test with each of these inputs and assert the answer",
        target.owner.as_ref().map_or_else(
            || target.name.clone(),
            |owner| format!("{owner}::{}", target.name)
        )
    ));
    Finding::new(
        Check::UntestedTable,
        decision.place.clone(),
        decision.subject.clone(),
        format!(
            "`{}`: no test calls it with the inputs of {} of its {total} rows",
            decision.subject,
            untested.len()
        ),
    )
    .with_detail(detail)
}

/// A row's inputs, as `name = value`, `any` where it takes every value.
fn conditions(decision: &Decision, row: &Row) -> String {
    decision
        .inputs
        .iter()
        .zip(&row.when)
        .map(|(input, value)| format!("{} = {}", input.name, value.as_deref().unwrap_or("any")))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Model;
    use crate::model::domain::DomainLists;
    use crate::model::facts::Facts;
    use crate::source::Layer;
    use crate::source::planted::{domain, workspace};

    /// A rule of four rows; `TESTS` is replaced by its test module.
    const RULE: &str = "
        pub enum Policy { Off, On }
        pub enum Enrolment { Enrolled, NotEnrolled }
        pub enum Owed { Nothing, Verify, Enrol }
        impl Owed {
            pub fn under(policy: Policy, enrolment: Enrolment) -> Self {
                match (policy, enrolment) {
                    (Policy::Off, Enrolment::Enrolled | Enrolment::NotEnrolled) => Self::Nothing,
                    (Policy::On, Enrolment::Enrolled) => Self::Verify,
                    (Policy::On, Enrolment::NotEnrolled) => Self::Enrol,
                }
            }
        }
        TESTS";

    fn found(tests: &str) -> Found {
        let ws = workspace(vec![domain(
            "domains/authentication/owed.rs",
            &RULE.replace("TESTS", tests),
        )]);
        let model = Model::build(&ws, &DomainLists::default());
        let facts = Facts::build(&ws, &model);
        let rules = Rules::build(&ws, &model, &facts);
        let files: Vec<_> = ws.layer(Layer::Domain).collect();
        run(&ws, &Index::of(&files), &rules)
    }

    /// Two of the three rows are called with their inputs written out.
    #[test]
    fn a_row_no_test_calls_with_its_inputs_is_reported() {
        let found = found(
            "#[cfg(test)]
            mod tests {
                use super::*;
                #[test]
                fn off_owes_nothing() { assert_eq!(Owed::under(Policy::Off, Enrolment::Enrolled), Owed::Nothing); }
                #[test]
                fn on_verifies() { assert_eq!(Owed::under(Policy::On, Enrolment::Enrolled), Owed::Verify); }
            }",
        );

        assert_eq!(found.findings.len(), 1);
        assert_eq!(
            found.findings[0].message,
            "`Owed::under`: no test calls it with the inputs of 1 of its 3 rows"
        );
        assert!(
            found.findings[0].detail[1].contains("Enrol when policy = On, enrolment = NotEnrolled")
        );
    }

    /// One test loops over every pair, written out, through a helper.
    #[test]
    fn a_loop_over_written_cases_through_a_helper_reaches_every_row() {
        let found = found(
            "#[cfg(test)]
            mod tests {
                use super::*;
                use super::Enrolment::{Enrolled, NotEnrolled};
                fn owed(policy: Policy, enrolment: Enrolment) -> Owed { Owed::under(policy, enrolment) }
                #[test]
                fn every_cell() {
                    let cases = [(Policy::Off, Enrolled), (Policy::On, Enrolled), (Policy::On, NotEnrolled)];
                    for (policy, enrolment) in cases {
                        let _ = owed(policy, enrolment);
                    }
                }
            }",
        );

        assert!(found.findings.is_empty());
        assert!(found.unsaid.is_empty());
    }

    /// The test hands the rule an input it computes: the rows it may reach
    /// are left unsaid, not reported.
    #[test]
    fn a_call_with_an_input_not_read_leaves_its_rows_unsaid() {
        let found = found(
            "#[cfg(test)]
            mod tests {
                use super::*;
                #[test]
                fn drawn() { let _ = Owed::under(Policy::On, pick()); }
            }",
        );

        assert_eq!(found.findings.len(), 1);
        assert!(found.findings[0].message.ends_with("1 of its 3 rows"));
        assert_eq!(found.unsaid.len(), 1);
    }

    /// No test calls the rule at all.
    #[test]
    fn a_rule_no_test_calls_has_every_row_reported() {
        let found = found("");

        assert_eq!(
            found.findings[0].message,
            "`Owed::under`: no test calls it with the inputs of 3 of its 3 rows"
        );
    }

    /// A test calls a domain function that calls the rule: what it hands
    /// on is not followed, so the rows are left unsaid.
    #[test]
    fn a_test_reaching_the_rule_through_a_domain_function_leaves_it_unsaid() {
        let found = found(
            "pub fn owed_for(policy: Policy, enrolment: Enrolment) -> Owed { Owed::under(policy, enrolment) }
            #[cfg(test)]
            mod tests {
                use super::*;
                #[test]
                fn through() { let _ = owed_for(Policy::On, Enrolment::Enrolled); }
            }",
        );

        assert!(
            found
                .findings
                .iter()
                .all(|finding| finding.subject != "Owed::under")
        );
        assert!(
            found
                .unsaid
                .iter()
                .any(|unsaid| unsaid.subject == "Owed::under"
                    && unsaid.why.starts_with("a test calls `owed_for`"))
        );
    }

    /// The tests sit in a module file built only for tests.
    #[test]
    fn tests_in_a_module_file_built_only_for_tests_are_read() {
        let rule = RULE.replace("TESTS", "#[cfg(test)]\nmod tests;");
        let ws = workspace(vec![
            domain("domains/authentication/owed.rs", &rule),
            domain(
                "domains/authentication/owed/tests.rs",
                "use super::*;
                #[test]
                fn every_cell() {
                    for (policy, enrolment) in [(Policy::Off, Enrolment::Enrolled), (Policy::On, Enrolment::Enrolled), (Policy::On, Enrolment::NotEnrolled)] {
                        let _ = Owed::under(policy, enrolment);
                    }
                }",
            ),
        ]);
        let model = Model::build(&ws, &DomainLists::default());
        let facts = Facts::build(&ws, &model);
        let rules = Rules::build(&ws, &model, &facts);
        let files: Vec<_> = ws.layer(Layer::Domain).collect();

        let found = run(&ws, &Index::of(&files), &rules);

        assert!(found.findings.is_empty());
    }
}
