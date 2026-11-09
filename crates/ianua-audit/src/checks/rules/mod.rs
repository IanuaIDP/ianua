//! Checks on the domain's decision rules (see
//! [`crate::model::rules::decisions`]): rules that must hold whatever a
//! deployment has set up, and rules whose tests leave rows out.
//!
//! - `rules.weaker-when-off`: a rule that takes a gate's answer (see
//!   [`crate::model::gates`]) and, with every other input the same, answers
//!   something weaker when the gate says not set up than when it says set
//!   up. Weaker is read from an order the code gives: the answer enum
//!   derives `PartialOrd`, so a variant declared earlier compares lower,
//!   or exactly one method of it maps each answer to such an enum. Lower
//!   counts as weaker. Where the code gives no order the two answers are
//!   not compared, and the conclusion is counted as unsaid.
//! - `rules.table-untested`: a row of a worked-out rule no test calls it
//!   with, read from the calls tests make with the inputs written out, through
//!   `let` names, `for` loops over written lists and the test file's own
//!   helpers. A call whose inputs are not read, or a test reaching the rule
//!   through another function, leaves the rows it may reach unsaid.

mod untested;
mod weaker;

use crate::finding::Found;
use crate::model::evaluate::Index;
use crate::model::gates::Gate;
use crate::model::rules::Rules;
use crate::source::{Layer, Workspace};

/// Every finding of the rule checks.
pub(crate) fn run(workspace: &Workspace, gates: &[Gate], rules: &Rules) -> Found {
    let files: Vec<_> = workspace.layer(Layer::Domain).collect();
    let index = Index::of(&files);
    let mut found = weaker::run(&index, gates, rules);
    found.absorb(untested::run(workspace, &index, rules));
    found
}
