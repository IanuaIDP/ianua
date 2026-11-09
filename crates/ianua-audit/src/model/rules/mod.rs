//! The domain's rules, read from its code: the decisions it makes by a
//! `match` over enums, its status machines with who moves them, and what
//! each creator and change refuses and when. `rules` prints them, and the
//! checks of rules that must hold whatever a deployment has set up read
//! them.

pub(crate) mod decisions;
pub(crate) mod moves;
pub(crate) mod refusals;

use std::collections::BTreeSet;

use quote::ToTokens;
use serde::Serialize;

use self::decisions::Decision;
use self::moves::MachineCard;
use self::refusals::Refusals;
use crate::model::Model;
use crate::model::evaluate::Index;
use crate::model::facts::Facts;
use crate::source::{Layer, Workspace};

/// Everything `rules` prints.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Rules {
    /// The decision rules.
    pub(crate) decisions: Vec<Decision>,
    /// The status machines.
    pub(crate) machines: Vec<MachineCard>,
    /// What each creator and change refuses.
    pub(crate) refusals: Vec<Refusals>,
}

impl Rules {
    /// The rules of the domain of `workspace`, as `model` and `facts` read
    /// it.
    pub(crate) fn build(workspace: &Workspace, model: &Model, facts: &Facts) -> Self {
        let files: Vec<_> = workspace.layer(Layer::Domain).collect();
        let index = Index::of(&files);
        Self {
            decisions: decisions::find(&index),
            machines: moves::cards(model, facts, &index),
            refusals: refusals::find(model, &index),
        }
    }

    /// Every context any rule is in.
    pub(crate) fn contexts(&self) -> BTreeSet<&str> {
        self.decisions
            .iter()
            .map(|decision| decision.context.as_str())
            .chain(self.machines.iter().map(|card| card.context.as_str()))
            .chain(self.refusals.iter().map(|found| found.context.as_str()))
            .collect()
    }

    /// The rules of `context` alone.
    pub(crate) fn of_context(self, context: &str) -> Self {
        Self {
            decisions: self
                .decisions
                .into_iter()
                .filter(|decision| decision.context == context)
                .collect(),
            machines: self
                .machines
                .into_iter()
                .filter(|card| card.context == context)
                .collect(),
            refusals: self
                .refusals
                .into_iter()
                .filter(|found| found.context == context)
                .collect(),
        }
    }
}

/// Code as it reads, from its tokens: `Demand::Signal`, `ctx.risk() > 3`.
pub(crate) fn code(node: &impl ToTokens) -> String {
    let spaced = node.to_token_stream().to_string();
    let joined = [
        (" :: ", "::"),
        (":: ", "::"),
        (" ::", "::"),
        (" (", "("),
        ("( ", "("),
        (" )", ")"),
        (" ,", ","),
        (" .", "."),
        (". ", "."),
        (" ?", "?"),
        ("& ", "&"),
        ("! ", "!"),
        (" [", "["),
        ("[ ", "["),
        (" ]", "]"),
        ("' ", "'"),
    ]
    .iter()
    .fold(spaced, |text, (from, to)| text.replace(from, to));
    let mut text = joined;
    for (tight, wide) in [("!=", " != "), ("&&", " && "), ("||", " || ")] {
        text = text.replace(tight, wide);
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use syn::parse::Parser;

    use super::*;

    #[test]
    fn code_reads_as_written() {
        let expr: syn::Expr =
            syn::parse_str("ctx.risk_level() >= self.threshold && !ctx.is_known(&device)").unwrap();
        let pattern: syn::Pat = syn::Pat::parse_multi_with_leading_vert
            .parse_str("Demand::Signal | Demand::Policy")
            .unwrap();

        assert_eq!(
            code(&expr),
            "ctx.risk_level() >= self.threshold && !ctx.is_known(&device)"
        );
        assert_eq!(code(&pattern), "Demand::Signal | Demand::Policy");
    }
}
