//! What each public creator and change of the domain refuses, and when.
//!
//! A refusal is an early exit with an error: `return Err(..)`, an arm or a
//! last expression that is `Err(..)`, the `else` of a `let .. else`, `?` on
//! an `ensure_*` rule, on `try_transition` or on `ok_or`. Its guard is
//! what leads to it as written: the `if` conditions around it, the `match`
//! arm it is in, the pattern a `let .. else` did not match, or the call
//! itself. The aggregate's own functions it tries with `?` are read the
//! same way, at most [`CALL_DEPTH`] deep, and say through which.

use serde::Serialize;
use syn::{Block, Expr, Stmt};

use super::code;
use crate::model::Model;
use crate::model::evaluate::{Body, Index};
use crate::model::machines::TRANSITION;
use crate::source::Place;
use crate::source::syntax::line_of;

/// How many of its own functions deep a change is read for its refusals.
const CALL_DEPTH: usize = 2;

/// The error types the domain's changes refuse with by a constructor, and
/// the variant each constructor makes.
const CONSTRUCTORS: &[(&str, &str)] = &[
    ("forbidden", "Forbidden"),
    ("conflict", "Conflict"),
    ("invalid", "Validation"),
    ("invalid_transition", "InvalidTransition"),
    ("unauthorized", "Unauthorized"),
    ("corrupt_row", "Infrastructure"),
    ("infra_msg", "Infrastructure"),
];

/// The refusals of one creator or change.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Refusals {
    /// `Owner::name`.
    pub(crate) change: String,
    /// The context it is in.
    pub(crate) context: String,
    /// Where it is declared.
    pub(crate) place: Place,
    /// Each refusal, in the order written.
    pub(crate) refusals: Vec<Refusal>,
}

/// One refusal.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Refusal {
    /// What leads to it, as written; empty when nothing but the call does.
    pub(crate) when: Vec<String>,
    /// The error, such as `Forbidden: the agent is not the run's agent`.
    pub(crate) error: String,
    /// Where it is.
    pub(crate) place: Place,
    /// The aggregate's own functions it is in, as `a > b`.
    pub(crate) via: Option<String>,
}

/// The refusals of every public creator and change of `model`'s
/// aggregates, read through `index`; those with none left out.
pub(crate) fn find(model: &Model, index: &Index<'_>) -> Vec<Refusals> {
    let mut found: Vec<Refusals> = model
        .domain
        .behaviours
        .iter()
        .filter_map(|behaviour| {
            let body = index.method(&behaviour.owner, &behaviour.name)?;
            let mut reader = Reader {
                index,
                owner: &behaviour.owner,
                guards: Vec::new(),
                found: Vec::new(),
            };
            reader.body(body, None, 0);
            (!reader.found.is_empty()).then(|| Refusals {
                change: behaviour.subject(),
                context: crate::model::context_of_path(&behaviour.place.file),
                place: behaviour.place.clone(),
                refusals: reader.found,
            })
        })
        .collect();
    found.sort_by(|a, b| (&a.context, &a.change).cmp(&(&b.context, &b.change)));
    found
}

/// Reads the refusals of one change.
struct Reader<'r, 'f> {
    index: &'r Index<'f>,
    owner: &'r str,
    /// The conditions that hold where the reader is, outermost first.
    guards: Vec<String>,
    found: Vec<Refusal>,
}

impl<'f> Reader<'_, 'f> {
    fn body(&mut self, body: Body<'f>, via: Option<&str>, depth: usize) {
        let at = Site { body, via, depth };
        self.block(body.block, at, true);
    }

    fn block(&mut self, block: &Block, at: Site<'_, 'f>, tail: bool) {
        let last = block.stmts.len().saturating_sub(1);
        for (position, statement) in block.stmts.iter().enumerate() {
            match statement {
                Stmt::Local(local) => self.local(local, at),
                Stmt::Expr(expr, semi) => {
                    self.expr(expr, at, tail && semi.is_none() && position == last);
                }
                Stmt::Item(_) | Stmt::Macro(_) => {}
            }
        }
    }

    fn local(&mut self, local: &syn::Local, at: Site<'_, 'f>) {
        let Some(init) = &local.init else {
            return;
        };
        self.expr(&init.expr, at, false);
        let Some((_, otherwise)) = &init.diverge else {
            return;
        };
        self.guards.push(format!(
            "`{}` is not `{}`",
            code(init.expr.as_ref()),
            code(&local.pat)
        ));
        self.expr(otherwise, at, true);
        self.guards.pop();
    }

    fn expr(&mut self, expr: &Expr, at: Site<'_, 'f>, tail: bool) {
        match expr {
            Expr::If(branch) => self.branch(branch, at, tail),
            Expr::Match(choice) => self.choice(choice, at, tail),
            Expr::Block(inner) => self.block(&inner.block, at, tail),
            Expr::Return(back) => {
                if let Some(error) = back.expr.as_deref().and_then(refused_with) {
                    self.refuse(error, back, at);
                }
            }
            Expr::Call(_) if tail => {
                if let Some(error) = refused_with(expr) {
                    self.refuse(error, expr, at);
                }
            }
            Expr::Try(tried) => self.tried(&tried.expr, at),
            _ => {}
        }
    }

    fn branch(&mut self, branch: &syn::ExprIf, at: Site<'_, 'f>, tail: bool) {
        self.guards
            .push(format!("`{}`", code(branch.cond.as_ref())));
        self.block(&branch.then_branch, at, true);
        self.guards.pop();
        if let Some((_, otherwise)) = &branch.else_branch {
            self.guards
                .push(format!("not `{}`", code(branch.cond.as_ref())));
            self.expr(otherwise, at, tail);
            self.guards.pop();
        }
    }

    fn choice(&mut self, choice: &syn::ExprMatch, at: Site<'_, 'f>, tail: bool) {
        let scrutinee = code(choice.expr.as_ref());
        for arm in &choice.arms {
            let when = match &arm.guard {
                Some((_, guard)) => format!(
                    "`{scrutinee}` is `{}` and `{}`",
                    code(&arm.pat),
                    code(guard.as_ref())
                ),
                None => format!("`{scrutinee}` is `{}`", code(&arm.pat)),
            };
            self.guards.push(when);
            self.expr(&arm.body, at, tail);
            self.guards.pop();
        }
    }

    /// `expr?`: a rule, a move or a missing value that refuses, or one of
    /// the aggregate's own functions, read for its own refusals.
    fn tried(&mut self, expr: &Expr, at: Site<'_, 'f>) {
        let inner = strip(expr);
        let Expr::MethodCall(call) = inner else {
            if let Expr::Call(called) = inner
                && let Expr::Path(path) = called.func.as_ref()
                && let Some(last) = path.path.segments.last()
                && last.ident.to_string().starts_with("ensure_")
            {
                self.refuse_by_rule(&last.ident.to_string(), inner, at);
            }
            return;
        };
        let name = call.method.to_string();
        match name.as_str() {
            TRANSITION => self.push(refused_move(call), inner, at),
            "ok_or" | "ok_or_else" => self.push(refused_missing(call), inner, at),
            _ if is_self(&call.receiver) && self.index.method(self.owner, &name).is_some() => {
                self.own(&name, inner, at);
            }
            _ if name.starts_with("ensure_") => self.refuse_by_rule(&name, inner, at),
            _ => {}
        }
    }

    /// The refusals of the aggregate's own function `name`, through it; one
    /// too deep to read says only that it may refuse.
    fn own(&mut self, name: &str, call: &Expr, at: Site<'_, 'f>) {
        let Some(body) = self.index.method(self.owner, name) else {
            return;
        };
        if at.depth >= CALL_DEPTH {
            let error = format!("what `{name}` refuses, not read this deep");
            let when = format!("`self.{name}(..)` refuses");
            self.push(Refused { when, error }, call, at);
            return;
        }
        let via = match at.via {
            Some(before) => format!("{before} > {name}"),
            None => name.to_owned(),
        };
        self.body(body, Some(&via), at.depth + 1);
    }

    fn refuse_by_rule(&mut self, rule: &str, expr: &Expr, at: Site<'_, 'f>) {
        let refused = Refused {
            when: format!("`{}` refuses", code(expr)),
            error: format!("what `{rule}` refuses"),
        };
        self.push(refused, expr, at);
    }

    fn refuse(&mut self, error: String, node: &impl syn::spanned::Spanned, at: Site<'_, 'f>) {
        self.found.push(Refusal {
            when: self.guards.clone(),
            error,
            place: Place::at(at.body.file, line_of(node)),
            via: at.via.map(str::to_owned),
        });
    }

    fn push(&mut self, refused: Refused, node: &Expr, at: Site<'_, 'f>) {
        self.guards.push(refused.when);
        self.refuse(refused.error, node, at);
        self.guards.pop();
    }
}

/// The refusal of a move the state machine may not make.
fn refused_move(call: &syn::ExprMethodCall) -> Refused {
    Refused {
        when: format!(
            "`{}` may not move to `{}`",
            code(call.receiver.as_ref()),
            args(call)
        ),
        error: "InvalidTransition".to_owned(),
    }
}

/// The refusal of `ok_or` or `ok_or_else` when the value is missing.
fn refused_missing(call: &syn::ExprMethodCall) -> Refused {
    let error = (call.args.first())
        .and_then(|arg| match arg {
            Expr::Closure(closure) => refused_with(&closure.body),
            other => refused_with(other),
        })
        .unwrap_or_else(|| "an error".to_owned());
    let when = format!("`{}` is missing", code(call.receiver.as_ref()));
    Refused { when, error }
}

/// A refusal found at a call: the condition under which it refuses, and
/// the error it gives.
struct Refused {
    when: String,
    error: String,
}

/// Where a body is read from.
#[derive(Clone, Copy)]
struct Site<'v, 'f> {
    body: Body<'f>,
    via: Option<&'v str>,
    depth: usize,
}

/// The error `expr` refuses with, when it is `Err(..)`.
fn refused_with(expr: &Expr) -> Option<String> {
    let Expr::Call(call) = expr else {
        return None;
    };
    let Expr::Path(function) = call.func.as_ref() else {
        return None;
    };
    if !function.path.is_ident("Err") {
        return None;
    }
    Some(
        call.args
            .first()
            .map_or_else(|| "an error".to_owned(), error_text),
    )
}

/// An error as a refusal shows it: `Variant: message` for the domain's
/// error, what is written otherwise.
fn error_text(error: &Expr) -> String {
    let Some((variant, message)) = domain_error(error) else {
        return format!("`{}`", code(error));
    };
    match message {
        Some(message) => format!("{variant}: {message}"),
        None => variant,
    }
}

/// The variant and message of a `DomainError` written out: through a
/// constructor such as `DomainError::forbidden("..")`, or a variant.
fn domain_error(error: &Expr) -> Option<(String, Option<String>)> {
    let (path, args) = match error {
        Expr::Call(call) => match call.func.as_ref() {
            Expr::Path(path) => (&path.path, Some(&call.args)),
            _ => return None,
        },
        Expr::Path(path) => (&path.path, None),
        _ => return None,
    };
    let names: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let [.., owner, name] = names.as_slice() else {
        return None;
    };
    if owner != "DomainError" {
        return None;
    }
    let variant = CONSTRUCTORS
        .iter()
        .find(|(constructor, _)| constructor == name)
        .map_or_else(|| name.clone(), |(_, variant)| (*variant).to_owned());
    let message = args.and_then(|args| args.iter().find_map(message_of));
    Some((variant, message))
}

/// The text of a message written as a string, or through `format!`.
fn message_of(arg: &Expr) -> Option<String> {
    match arg {
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) => Some(text.value()),
        Expr::Macro(invoked) if invoked.mac.path.is_ident("format") => {
            let text: syn::LitStr = invoked
                .mac
                .parse_body_with(|input: syn::parse::ParseStream<'_>| {
                    let first = input.parse()?;
                    let _: proc_macro2::TokenStream = input.parse()?;
                    Ok(first)
                })
                .ok()?;
            Some(text.value())
        }
        _ => None,
    }
}

fn args(call: &syn::ExprMethodCall) -> String {
    call.args.iter().map(code).collect::<Vec<_>>().join(", ")
}

/// `expr` without `.await` and `.map_err(..)`.
fn strip(expr: &Expr) -> &Expr {
    match expr {
        Expr::Await(inner) => strip(&inner.base),
        Expr::Paren(inner) => strip(&inner.expr),
        Expr::MethodCall(call) if call.method == "map_err" => strip(&call.receiver),
        other => other,
    }
}

fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(path) if path.path.is_ident("self"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{domain, workspace};

    /// An agent run paused only by its own agent and only while running.
    const AGENT_RUN: &str = "pub struct AgentRun { state: RunState, agent_id: AgentId }
             impl AgentRun {
                 pub fn reconstitute(row: AgentRunRow) -> Result<Self, DomainError> { make() }
                 pub fn pause(&mut self, by: &AgentControl<'_>) -> Result<(), DomainError> {
                     self.ensure_agent(by)?;
                     let RunState::Running(next) = &self.state else {
                         return Err(DomainError::invalid_transition(\"only a running run is paused\"));
                     };
                     self.state = RunState::Paused(next.clone());
                     Ok(())
                 }
                 fn ensure_agent(&self, by: &AgentControl<'_>) -> Result<(), DomainError> {
                     if by.agent() != &self.agent_id {
                         return Err(DomainError::forbidden(\"the agent is not the run's agent\"));
                     }
                     Ok(())
                 }
             }";

    #[test]
    fn each_refusal_is_read_with_what_leads_to_it() {
        let ws = workspace(vec![domain("domains/agents/run.rs", AGENT_RUN)]);
        let model = Model::build(&ws, &DomainLists::default());
        let files: Vec<_> = ws.layer(crate::source::Layer::Domain).collect();

        let found = find(&model, &Index::of(&files));

        let pause = &found[0].refusals;
        assert_eq!(
            pause[0].error,
            "Forbidden: the agent is not the run's agent"
        );
        assert_eq!(pause[0].when, ["`by.agent() != &self.agent_id`"]);
        assert_eq!(pause[0].via.as_deref(), Some("ensure_agent"));
        assert_eq!(
            pause[1].error,
            "InvalidTransition: only a running run is paused"
        );
        assert_eq!(
            pause[1].when,
            ["`&self.state` is not `RunState::Running(next)`"]
        );
    }
}
