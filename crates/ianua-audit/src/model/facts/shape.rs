//! The shape of one function body as the reader walks it: the facts and
//! helper calls in the order they run, with the branches, loops, units and
//! exits around them. [`super::flow`] joins the shapes of a use case and
//! its helpers into one flow.

use std::collections::BTreeSet;

use syn::{Block, Expr, Stmt};

use super::flow::{Exit, Unread};
use crate::source::Place;

/// One part of a body's shape.
#[derive(Clone, Debug)]
pub(super) enum Node {
    /// The fact at this index of the body's facts.
    Fact(usize),
    /// The helper call at this index of the body's helpers.
    Helper {
        /// The helper's index.
        index: usize,
        /// What the caller does with what it hands back.
        handed: Handed,
    },
    /// Parts in order.
    Seq(Vec<Node>),
    /// One of these runs.
    Choice(Vec<Node>),
    /// A loop's body, run any number of times, or at least once.
    Loop {
        /// The body.
        body: Box<Node>,
        /// Whether it runs at least once, as `loop` does.
        at_least_once: bool,
    },
    /// The function leaves here.
    Exit(Exit, Place),
    /// `break` or `continue`: this run of the loop's body ends.
    LoopExit,
    /// The path goes no further: the end of a `let .. else` block.
    Halt,
    /// A unit of work, such as `kept_together`, around what it runs.
    Unit {
        /// The function or method that opens it.
        name: String,
        /// Where.
        place: Place,
        /// What runs inside.
        inner: Box<Node>,
    },
    /// A call whose result the caller matches on: what follows its success
    /// and what follows its failure.
    Split {
        /// The call: a fact or a helper.
        head: Box<Node>,
        /// What runs once it succeeded.
        ok: Box<Node>,
        /// What runs once it failed.
        err: Box<Node>,
    },
    /// A future handed in as the parameter of this name, run here.
    Future(String),
    /// From here on a value of the enum is one of these variants: the path
    /// went through a branch that said so.
    Narrow {
        /// The enum.
        enum_name: String,
        /// The variants it may still be.
        variants: BTreeSet<String>,
        /// Where the branch is.
        place: Place,
    },
    /// The name is bound to a new value here, such as by a `let`: what it
    /// held before is another value.
    Bound(String, Place),
    /// Something the reader does not see into: a closure or async block
    /// with facts inside.
    Unread(Unread),
}

impl Node {
    /// Marks the helpers at `held` as held in a name handed back later.
    pub(super) fn hold(&mut self, held: &BTreeSet<usize>) {
        match self {
            Self::Helper { index, handed } if held.contains(index) => *handed = Handed::Held,
            Self::Seq(parts) | Self::Choice(parts) => {
                for part in parts {
                    part.hold(held);
                }
            }
            Self::Loop { body: inner, .. } | Self::Unit { inner, .. } => inner.hold(held),
            Self::Split { head, ok, err } => {
                for part in [head, ok, err] {
                    part.hold(held);
                }
            }
            Self::Fact(_)
            | Self::Helper { .. }
            | Self::Exit(..)
            | Self::LoopExit
            | Self::Halt
            | Self::Future(_)
            | Self::Bound(..)
            | Self::Narrow { .. }
            | Self::Unread(_) => {}
        }
    }

    /// The parameters whose futures it runs.
    pub(super) fn futures_run(&self, found: &mut BTreeSet<String>) {
        match self {
            Self::Future(name) => {
                found.insert(name.clone());
            }
            Self::Seq(parts) | Self::Choice(parts) => {
                for part in parts {
                    part.futures_run(found);
                }
            }
            Self::Loop { body: inner, .. } | Self::Unit { inner, .. } => inner.futures_run(found),
            Self::Split { head, ok, err } => {
                for part in [head, ok, err] {
                    part.futures_run(found);
                }
            }
            Self::Fact(_)
            | Self::Helper { .. }
            | Self::Exit(..)
            | Self::LoopExit
            | Self::Halt
            | Self::Bound(..)
            | Self::Narrow { .. }
            | Self::Unread(_) => {}
        }
    }
}

/// What a caller does with what a helper hands back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Handed {
    /// `?` passes its error on; on success the caller goes on.
    Tried,
    /// The caller hands it back as its own: the helper's exits are the
    /// caller's.
    Back,
    /// The caller keeps it, and what it does with an error is not read.
    Kept,
    /// The caller holds it in a name it later hands back as its own or
    /// passes on with `?`: an error goes on with the caller and leaves
    /// there.
    Held,
}

/// The functions and methods that open a unit of work.
pub(super) const UNITS: &[&str] = &["kept_together", "atomically", "scoped_holding"];

/// The port whose `run` opens a unit of work.
pub(super) const UNIT_PORT: &str = "UnitOfWork";

/// A body's shape as it is built: one open sequence per nesting.
#[derive(Debug)]
pub(super) struct Builder {
    open: Vec<Vec<Node>>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            open: vec![Vec::new()],
        }
    }
}

impl Builder {
    /// Adds `node` to the innermost open sequence.
    pub(super) fn push(&mut self, node: Node) {
        if let Some(open) = self.open.last_mut() {
            open.push(node);
        }
    }

    /// Opens a nested sequence.
    pub(super) fn open(&mut self) {
        self.open.push(Vec::new());
    }

    /// Closes the innermost sequence, handing it back.
    pub(super) fn close(&mut self) -> Node {
        Node::Seq(self.open.pop().unwrap_or_default())
    }

    /// The last node of the innermost open sequence.
    pub(super) fn last_mut(&mut self) -> Option<&mut Node> {
        self.open.last_mut()?.last_mut()
    }

    /// The last node of the innermost open sequence.
    pub(super) fn last(&self) -> Option<&Node> {
        self.open.last()?.last()
    }

    /// Takes the last node of the innermost open sequence out.
    pub(super) fn pop(&mut self) -> Option<Node> {
        self.open.last_mut()?.pop()
    }

    /// Where the builder stands: how deep it is nested and how long the
    /// innermost sequence is, to tell whether anything was added since.
    pub(super) fn mark(&self) -> (usize, usize) {
        (self.open.len(), self.open.last().map_or(0, Vec::len))
    }

    /// The whole shape.
    pub(super) fn finish(mut self) -> Node {
        let parts: Vec<Node> = self.open.drain(..).flatten().collect();
        Node::Seq(parts)
    }
}

/// The addresses of the expressions whose value `block` hands back: its
/// last expression, or the last expressions of the branches it ends in.
pub(super) fn tails(block: &Block) -> BTreeSet<usize> {
    let mut found = BTreeSet::new();
    block_tails(block, &mut found);
    found
}

fn block_tails(block: &Block, found: &mut BTreeSet<usize>) {
    if let Some(Stmt::Expr(expr, None)) = block.stmts.last() {
        expr_tails(expr, found);
    }
}

fn expr_tails(expr: &Expr, found: &mut BTreeSet<usize>) {
    match expr {
        Expr::If(branch) => {
            block_tails(&branch.then_branch, found);
            if let Some((_, otherwise)) = &branch.else_branch {
                expr_tails(otherwise, found);
            }
        }
        Expr::Match(choice) => {
            for arm in &choice.arms {
                expr_tails(&arm.body, found);
            }
        }
        Expr::Block(inner) => block_tails(&inner.block, found),
        Expr::Paren(inner) => expr_tails(&inner.expr, found),
        Expr::Return(_) => {}
        _ => {
            found.insert(address(expr));
        }
    }
}

/// An expression's address, to know it again.
pub(super) fn address(expr: &Expr) -> usize {
    std::ptr::from_ref(expr) as usize
}

/// How a function leaves when it hands back `expr`: `Ok(..)`, `Err(..)`,
/// or a value the reader does not know, which may be either.
pub(super) fn exit_of(expr: &Expr) -> Exit {
    match expr {
        Expr::Paren(inner) => exit_of(&inner.expr),
        Expr::Call(call) => match call.func.as_ref() {
            Expr::Path(path) if path.path.is_ident("Ok") => Exit::Ok,
            Expr::Path(path) if path.path.is_ident("Err") => Exit::Err,
            _ => Exit::Value,
        },
        _ => Exit::Value,
    }
}

/// `expr` without the calls that only pass its value on, such as
/// `.await`, `.map_err(..)` and `.or_internal()`: the call it is.
pub(super) fn called(expr: &Expr, passing: impl Fn(&str) -> bool + Copy) -> &Expr {
    match expr {
        Expr::Await(inner) => called(&inner.base, passing),
        Expr::Paren(inner) => called(&inner.expr, passing),
        Expr::MethodCall(call) if passing(&call.method.to_string()) => {
            called(&call.receiver, passing)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tails_of_a_body_are_its_branches_last_expressions() {
        let block: Block = syn::parse_str(
            "{ let x = 1; if ready { Ok(x) } else { match x { 1 => Err(e), _ => store.save() } } }",
        )
        .unwrap();

        let found = tails(&block);

        assert_eq!(found.len(), 3);
    }

    #[test]
    fn an_exit_is_read_from_what_is_handed_back() {
        let ok: Expr = syn::parse_str("Ok(())").unwrap();
        let err: Expr = syn::parse_str("Err(AppError::Conflict)").unwrap();
        let value: Expr = syn::parse_str("store.save(&x).await.or_internal()").unwrap();

        assert_eq!(exit_of(&ok), Exit::Ok);
        assert_eq!(exit_of(&err), Exit::Err);
        assert_eq!(exit_of(&value), Exit::Value);
    }
}
