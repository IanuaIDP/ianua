//! The domain's decision rules: public functions whose answer, one of the
//! domain's enums, is chosen by a `match` or `if` over enums.
//!
//! A rule whose every input is one of the domain's enums whose variants
//! carry no data, or a `bool`, is worked out for every combination of its
//! inputs, at most [`MOST_ROWS`] of them, by the evaluator (see
//! [`crate::model::evaluate`]), through every function it calls; rows that
//! differ only in an input that does not change the answer are merged into
//! one that says "any". A combination the evaluator could not work out is
//! kept, marked not read. A rule with other inputs whose body ends in a
//! `match` over enum or `bool` patterns is shown arm by arm, as written.

use serde::Serialize;
use syn::{Expr, FnArg, Pat, Stmt};

use super::code;
use crate::model::context_of;
use crate::model::evaluate::{Body, Evaluator, Index, Value};
use crate::source::Place;
use crate::source::syntax::{core_type, doc_lines, for_tests_only, is_public, type_name};

/// The most combinations of inputs a rule is worked out for.
const MOST_ROWS: usize = 512;

/// Functions read elsewhere: a status machine's moves and a state's
/// status.
const NOT_RULES: &[&str] = &["try_transition", "status", "can_transition_to"];

/// One decision rule.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Decision {
    /// `Owner::name`, or the bare name of a free function.
    pub(crate) subject: String,
    /// The context it is in.
    pub(crate) context: String,
    /// Where it is declared.
    pub(crate) place: Place,
    /// The first line of its doc comment.
    pub(crate) summary: Option<String>,
    /// What it decides on.
    pub(crate) inputs: Vec<Input>,
    /// The enum its answer is.
    pub(crate) outcome: String,
    /// The variants of that enum, in the order they are declared.
    pub(crate) outcome_values: Vec<String>,
    /// How its rows were read.
    pub(crate) reading: Reading,
    /// Its rows.
    pub(crate) rows: Vec<Row>,
}

impl Decision {
    /// The position of its input of the type `ty`.
    pub(crate) fn input_of(&self, ty: &str) -> Option<usize> {
        self.inputs.iter().position(|input| input.ty == ty)
    }
}

/// How a rule's rows were read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reading {
    /// Worked out for every combination of its inputs.
    WorkedOut,
    /// Its last `match`, arm by arm, as written.
    Arms,
}

/// One input of a rule.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Input {
    /// Its name: the parameter, `self`, or the value a `match` is over.
    pub(crate) name: String,
    /// Its type: an enum, `bool`, or, for an arm-by-arm rule, what is known.
    pub(crate) ty: String,
    /// The values it takes, in the order they are declared.
    pub(crate) values: Vec<String>,
    /// How the rule works it out, for a value a `match` is over that a
    /// `let` defines.
    pub(crate) defined: Option<String>,
}

/// One row of a rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Row {
    /// Each input's value, `None` for any.
    pub(crate) when: Vec<Option<String>>,
    /// The answer, `None` when it was not read.
    pub(crate) outcome: Option<String>,
    /// The arm's guard, for an arm-by-arm rule.
    pub(crate) guard: Option<String>,
    /// Where the answer is decided: the last branch taken, or the arm.
    pub(crate) place: Option<Place>,
}

/// Every decision rule of the domain `index` reads.
pub(crate) fn find(index: &Index<'_>) -> Vec<Decision> {
    let evaluator = Evaluator::new(index);
    let mut found: Vec<Decision> = index
        .bodies()
        .filter(|body| is_public(body.vis) && !for_tests_only(body.attrs))
        .filter(|body| !NOT_RULES.contains(&body.name().as_str()))
        .filter_map(|body| {
            let outcome = outcome_of(index, body)?;
            let decision =
                worked_out(index, &evaluator, body, &outcome).or_else(|| arms(body, &outcome))?;
            Some(Decision {
                outcome_values: values_of(index, &outcome).unwrap_or_default(),
                ..decision
            })
        })
        .collect();
    found.sort_by(|a, b| (&a.context, &a.subject).cmp(&(&b.context, &b.subject)));
    found
}

/// The enum `body` answers with, when it is one of the domain's.
fn outcome_of(index: &Index<'_>, body: Body<'_>) -> Option<String> {
    let syn::ReturnType::Type(_, returned) = &body.sig.output else {
        return None;
    };
    let owner = body.owner.map(ToString::to_string);
    let core = core_type(returned, owner.as_deref())?;
    index.enum_named(&core).map(|info| info.name.clone())
}

fn worked_out(
    index: &Index<'_>,
    evaluator: &Evaluator<'_, '_>,
    body: Body<'_>,
    outcome: &str,
) -> Option<Decision> {
    let (inputs, takes_self) = plain_inputs(index, body)?;
    let size = inputs
        .iter()
        .try_fold(1usize, |all, input| all.checked_mul(input.values.len()))?;
    if inputs.is_empty() || size > MOST_ROWS {
        return None;
    }
    let asked = Asked {
        body,
        inputs: &inputs,
        takes_self,
    };
    let rows: Vec<Row> = combinations(&inputs)
        .into_iter()
        .map(|values| row_of(evaluator, &asked, values))
        .collect();
    if rows.iter().all(|row| row.outcome.is_none()) {
        return None;
    }
    let mut rows = compressed(rows, &inputs);
    rows.sort_by_key(|row| declared_order(row, &inputs));
    Some(Decision {
        rows,
        reading: Reading::WorkedOut,
        ..bare(body, inputs, outcome)
    })
}

/// Where each of a row's values stands among its input's, "any" last, to
/// list rows in the order the inputs are declared.
fn declared_order(row: &Row, inputs: &[Input]) -> Vec<usize> {
    row.when
        .iter()
        .zip(inputs)
        .map(|(value, input)| {
            value
                .as_ref()
                .and_then(|value| input.values.iter().position(|known| known == value))
                .unwrap_or(input.values.len())
        })
        .collect()
}

fn bare(body: Body<'_>, inputs: Vec<Input>, outcome: &str) -> Decision {
    Decision {
        subject: body.subject(),
        context: context_of(body.file),
        place: body.place(),
        summary: doc_lines(body.attrs)
            .into_iter()
            .take_while(|line| !line.trim().is_empty())
            .collect::<Vec<_>>()
            .join(" ")
            .split_inclusive(". ")
            .next()
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty()),
        inputs,
        outcome: outcome.to_owned(),
        outcome_values: Vec::new(),
        reading: Reading::WorkedOut,
        rows: Vec::new(),
    }
}

/// The inputs of `body` when each is a plain enum of the domain or a
/// `bool`, `self` first when it takes one, with whether it does.
fn plain_inputs(index: &Index<'_>, body: Body<'_>) -> Option<(Vec<Input>, bool)> {
    let mut inputs = Vec::new();
    let mut takes_self = false;
    for input in &body.sig.inputs {
        let (name, ty) = match input {
            FnArg::Receiver(_) => {
                takes_self = true;
                ("self".to_owned(), body.owner?.to_string())
            }
            FnArg::Typed(typed) => {
                let Pat::Ident(name) = typed.pat.as_ref() else {
                    return None;
                };
                let owner = body.owner.map(ToString::to_string);
                let ty = type_name(&typed.ty)
                    .filter(|name| name == "bool")
                    .or_else(|| core_type(&typed.ty, owner.as_deref()))?;
                (name.ident.to_string(), ty)
            }
        };
        inputs.push(Input {
            values: values_of(index, &ty)?,
            name,
            ty,
            defined: None,
        });
    }
    Some((inputs, takes_self))
}

/// The values of the type `ty`: a plain enum's variants, or `false` and
/// `true`.
fn values_of(index: &Index<'_>, ty: &str) -> Option<Vec<String>> {
    if ty == "bool" {
        return Some(vec!["false".to_owned(), "true".to_owned()]);
    }
    let info = index.enum_named(ty).filter(|info| info.is_plain())?;
    Some(
        info.variants
            .iter()
            .map(|variant| variant.name.clone())
            .collect(),
    )
}

/// Every combination of the inputs' values, the first input changing
/// slowest.
fn combinations(inputs: &[Input]) -> Vec<Vec<String>> {
    inputs.iter().fold(vec![Vec::new()], |made, input| {
        made.iter()
            .flat_map(|start| {
                input.values.iter().map(move |value| {
                    let mut longer = start.clone();
                    longer.push(value.clone());
                    longer
                })
            })
            .collect()
    })
}

/// A function whose answers are worked out row by row: its body, its
/// plain inputs, and whether the first of them is `self`.
struct Asked<'a> {
    body: Body<'a>,
    inputs: &'a [Input],
    takes_self: bool,
}

/// The row for `values`, one for each of the inputs `asked` takes.
fn row_of(evaluator: &Evaluator<'_, '_>, asked: &Asked<'_>, values: Vec<String>) -> Row {
    let mut args: Vec<Value> = (asked.inputs.iter())
        .zip(&values)
        .map(|(input, value)| value_of(&input.ty, value))
        .collect();
    let receiver = asked.takes_self.then(|| args.remove(0));
    let outcome = evaluator.run(asked.body, receiver, args);
    Row {
        when: values.into_iter().map(Some).collect(),
        outcome: outcome.as_ref().and_then(|found| answer_text(&found.value)),
        guard: None,
        place: outcome.and_then(|found| found.decided_at),
    }
}

fn value_of(ty: &str, value: &str) -> Value {
    match (ty, value) {
        ("bool", "true") => Value::Bool(true),
        ("bool", _) => Value::Bool(false),
        _ => Value::variant(ty, value),
    }
}

/// An answer as a row shows it: a variant by its name, through `Ok`, and
/// `Err` as a refusal.
fn answer_text(value: &Value) -> Option<String> {
    match value {
        Value::Variant { name, .. } => Some(name.clone()),
        Value::Ok(inner) => answer_text(inner),
        Value::Err => Some("refused".to_owned()),
        Value::Bool(truth) => Some(truth.to_string()),
        _ => None,
    }
}

/// `rows` with those that differ only in one input, and together take
/// every value of it, merged into one that says "any" for it.
fn compressed(mut rows: Vec<Row>, inputs: &[Input]) -> Vec<Row> {
    loop {
        let before = rows.len();
        for (column, input) in inputs.iter().enumerate() {
            rows = merged_on(rows, column, input.values.len());
        }
        if rows.len() == before {
            return rows;
        }
    }
}

fn merged_on(rows: Vec<Row>, column: usize, values: usize) -> Vec<Row> {
    let mut groups: Vec<(Row, Vec<Row>)> = Vec::new();
    for row in rows {
        let mut key = row.clone();
        key.when[column] = None;
        key.place = None;
        match groups.iter_mut().find(|(seen, _)| *seen == key) {
            Some((_, taken)) => taken.push(row),
            None => groups.push((key, vec![row])),
        }
    }
    groups
        .into_iter()
        .flat_map(|(mut key, taken)| {
            let every = taken.iter().any(|row| row.when[column].is_none()) || taken.len() == values;
            if !every {
                return taken;
            }
            key.place = taken.into_iter().find_map(|row| row.place);
            vec![key]
        })
        .collect()
}

/// A rule whose body ends in a `match` over enum or `bool` patterns, arm
/// by arm.
fn arms(body: Body<'_>, outcome: &str) -> Option<Decision> {
    let Some(Stmt::Expr(Expr::Match(choice), None)) = body.block.stmts.last() else {
        return None;
    };
    let scrutinee = match choice.expr.as_ref() {
        Expr::Tuple(tuple) => tuple.elems.iter().collect::<Vec<_>>(),
        other => vec![other],
    };
    if choice.arms.len() < 2 {
        return None;
    }
    let rows: Vec<Row> = choice
        .arms
        .iter()
        .map(|arm| arm_row(body, arm, scrutinee.len()))
        .collect::<Option<_>>()?;
    let inputs = scrutinee
        .iter()
        .map(|expr| Input {
            name: code(expr),
            ty: String::new(),
            values: Vec::new(),
            defined: defined_by(body, expr),
        })
        .collect();
    Some(Decision {
        rows,
        reading: Reading::Arms,
        ..bare(body, inputs, outcome)
    })
}

fn arm_row(body: Body<'_>, arm: &syn::Arm, width: usize) -> Option<Row> {
    let parts = match (&arm.pat, width) {
        (Pat::Tuple(tuple), _) if tuple.elems.len() == width => tuple.elems.iter().collect(),
        (other, 1) => vec![other],
        _ => return None,
    };
    let when = parts
        .into_iter()
        .map(pattern_cell)
        .collect::<Option<Vec<_>>>()?;
    Some(Row {
        when,
        outcome: Some(arm_answer(&arm.body)),
        guard: arm.guard.as_ref().map(|(_, guard)| code(guard.as_ref())),
        place: Some(Place::of(body.file, &arm.pat)),
    })
}

/// The cell a pattern of an enum or a `bool` makes: `None` for any value,
/// the pattern otherwise; `None` outside for a pattern of another kind.
fn pattern_cell(pattern: &Pat) -> Option<Option<String>> {
    match pattern {
        Pat::Wild(_) => Some(None),
        Pat::Ident(binding)
            if binding.subpat.is_none()
                && binding
                    .ident
                    .to_string()
                    .starts_with(|c: char| c.is_ascii_lowercase()) =>
        {
            Some(None)
        }
        Pat::Path(_) | Pat::Lit(_) | Pat::TupleStruct(_) | Pat::Struct(_) | Pat::Ident(_) => {
            plain_pattern(pattern).then(|| Some(code(pattern)))
        }
        Pat::Or(choices) => choices
            .cases
            .iter()
            .all(plain_pattern)
            .then(|| Some(code(pattern))),
        Pat::Paren(inner) => pattern_cell(&inner.pat),
        Pat::Reference(inner) => pattern_cell(&inner.pat),
        _ => None,
    }
}

/// Whether `pattern` names a variant or a `bool`, its fields left open.
fn plain_pattern(pattern: &Pat) -> bool {
    match pattern {
        Pat::Path(_) | Pat::Wild(_) => true,
        Pat::Lit(literal) => matches!(literal.lit, syn::Lit::Bool(_)),
        Pat::Ident(binding) => binding.subpat.is_none(),
        Pat::TupleStruct(tuple) => tuple
            .elems
            .iter()
            .all(|part| matches!(part, Pat::Wild(_) | Pat::Rest(_) | Pat::Ident(_))),
        Pat::Struct(fields) => fields.fields.is_empty() || fields.rest.is_some(),
        Pat::Or(choices) => choices.cases.iter().all(plain_pattern),
        Pat::Paren(inner) => plain_pattern(&inner.pat),
        Pat::Reference(inner) => plain_pattern(&inner.pat),
        _ => false,
    }
}

/// What an arm hands back: a variant by its name, anything else as
/// written.
fn arm_answer(expr: &Expr) -> String {
    match expr {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .map_or_else(|| code(expr), |last| last.ident.to_string()),
        Expr::Block(block) => match block.block.stmts.as_slice() {
            [Stmt::Expr(inner, None)] => arm_answer(inner),
            _ => code(expr),
        },
        other => code(other),
    }
}

/// How `body` works out `expr`, a name a `let` before its `match` binds.
fn defined_by(body: Body<'_>, expr: &Expr) -> Option<String> {
    let Expr::Path(path) = expr else {
        return None;
    };
    let name = path.path.get_ident()?;
    body.block.stmts.iter().find_map(|statement| {
        let Stmt::Local(local) = statement else {
            return None;
        };
        let Pat::Ident(bound) = &local.pat else {
            return None;
        };
        (bound.ident == *name)
            .then(|| local.init.as_ref().map(|init| code(init.expr.as_ref())))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::planted::domain;

    fn decisions(text: &str) -> Vec<Decision> {
        let file = domain("domains/authentication/mfa/owed.rs", text);
        let files = [&file];
        find(&Index::of(&files))
    }

    const OWED: &str = "
        pub enum MfaPolicy { Disabled, Required }
        pub enum Enrolment { Enrolled, NotEnrolled }
        pub enum MailReach { Available, NotSetUp }
        pub enum SecondFactor { NotOwed, Verify, Enrol, ConfirmByEmail }
        impl SecondFactor {
            /// What a sign-in owes. More words.
            pub fn under(policy: MfaPolicy, enrolment: Enrolment, mail: MailReach) -> Self {
                Self::with_mail(policy, enrolment).reached_by(mail, enrolment)
            }
            fn with_mail(policy: MfaPolicy, enrolment: Enrolment) -> Self {
                match (policy, enrolment) {
                    (MfaPolicy::Disabled, _) => Self::NotOwed,
                    (MfaPolicy::Required, Enrolment::Enrolled) => Self::Verify,
                    (MfaPolicy::Required, Enrolment::NotEnrolled) => Self::ConfirmByEmail,
                }
            }
            fn reached_by(self, mail: MailReach, enrolment: Enrolment) -> Self {
                match (self, mail) {
                    (Self::ConfirmByEmail, MailReach::NotSetUp) => Self::Enrol,
                    _ => self,
                }
            }
        }";

    /// Each row of `decision` as its inputs' values and its answer.
    fn rows_of(decision: &Decision) -> Vec<(Vec<Option<&str>>, Option<&str>)> {
        (decision.rows.iter())
            .map(|row| {
                let when = row.when.iter().map(Option::as_deref).collect();
                (when, row.outcome.as_deref())
            })
            .collect()
    }

    /// A rule delegating to helpers is worked out for every combination
    /// and merged where an input does not matter.
    #[test]
    fn a_rule_over_enums_is_worked_out_and_merged() {
        let found = decisions(OWED);

        let under = (found.iter())
            .find(|decision| decision.subject == "SecondFactor::under")
            .unwrap();
        let rows = rows_of(under);
        assert_eq!(under.reading, Reading::WorkedOut);
        assert_eq!(under.summary.as_deref(), Some("What a sign-in owes."));
        assert_eq!(
            rows,
            [
                (vec![Some("Disabled"), None, None], Some("NotOwed")),
                (
                    vec![Some("Required"), Some("Enrolled"), None],
                    Some("Verify")
                ),
                (
                    vec![Some("Required"), Some("NotEnrolled"), Some("Available")],
                    Some("ConfirmByEmail")
                ),
                (
                    vec![Some("Required"), Some("NotEnrolled"), Some("NotSetUp")],
                    Some("Enrol")
                ),
            ]
        );
    }

    /// The answer hangs on values worked out from a context the reader
    /// does not hold: the rule is shown arm by arm, with how each value is
    /// worked out.
    #[test]
    fn a_rule_over_values_it_works_out_itself_is_shown_arm_by_arm() {
        let found = decisions(
            "pub enum Demand { Signal, Policy, NotAsked }
             pub struct StepUpPolicy { level: u8 }
             impl StepUpPolicy {
                 pub fn demand(&self, ctx: &AuthenticationContext) -> Demand {
                     let signal_asks = ctx.risk() > self.level;
                     let policy_asks = ctx.sensitive();
                     match (signal_asks, policy_asks) {
                         (true, _) => Demand::Signal,
                         (false, true) => Demand::Policy,
                         (false, false) => Demand::NotAsked,
                     }
                 }
             }",
        );

        let demand = &found[0];
        assert_eq!(demand.reading, Reading::Arms);
        assert_eq!(demand.inputs[0].name, "signal_asks");
        assert_eq!(
            demand.inputs[0].defined.as_deref(),
            Some("ctx.risk() > self.level")
        );
        assert_eq!(demand.rows[0].when, [Some("true".to_owned()), None]);
        assert_eq!(demand.rows[1].outcome.as_deref(), Some("Policy"));
    }

    /// A combination that reaches what the evaluator cannot work out is
    /// kept, with no answer.
    #[test]
    fn a_combination_not_worked_out_is_kept_unread() {
        let found = decisions(
            "pub enum Mode { On, Off }
             pub enum Answer { Yes, No }
             impl Answer {
                 pub fn of(mode: Mode) -> Self {
                     match mode {
                         Mode::On => Self::Yes,
                         Mode::Off => outside(),
                     }
                 }
             }",
        );

        let rows = &found[0].rows;
        assert_eq!(rows[0].outcome.as_deref(), Some("Yes"));
        assert!(rows[1].outcome.is_none());
    }
}
