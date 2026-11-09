//! The checks, each in its own module, and running them all.
//!
//! The logic checks (`limits`, `status`, `rights`, `records`, `gates`,
//! `rules`) find places that should agree and do not. A finding must be
//! true: a conclusion that rests on something the reader marked not read
//! is not drawn, and is counted instead.

pub(crate) mod adapters;
pub(crate) mod flow;
pub(crate) mod gates;
pub(crate) mod limits;
pub(crate) mod reach;
pub(crate) mod records;
pub(crate) mod rights;
pub(crate) mod rules;
pub(crate) mod status;

use std::collections::BTreeSet;

use crate::finding::{Check, Finding, Found};
use crate::model::Model;
use crate::model::facts::Facts;
use crate::model::rules::Rules;
use crate::source::{Place, Workspace};

/// Every finding of every check, the most serious first, then by check,
/// file and line, with the conclusions left unsaid; `parked` names the
/// crates waiting for a rebuild.
pub(crate) fn run_all(workspace: &Workspace, model: &Model, parked: &BTreeSet<String>) -> Found {
    let facts = Facts::build(workspace, model);
    let rules = Rules::build(workspace, model, &facts);
    let gates = crate::model::gates::find(workspace, model);
    let mut found = Found::from(parse_failures(workspace));
    found.absorb(reach::run(model).into());
    found.absorb(adapters::run(workspace, model, parked));
    found.absorb(flow::run(workspace, model).into());
    found.absorb(limits::run(&facts));
    found.absorb(status::run(workspace, model));
    found.absorb(rights::run(model, &facts));
    found.absorb(records::run(model, &facts));
    found.absorb(gates::run(&gates, &rules, &facts));
    found.absorb(rules::run(workspace, &gates, &rules));
    sort(&mut found.findings);
    found
}

/// Orders findings the way reports list them.
pub(crate) fn sort(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        (a.severity, a.check, &a.place, &a.subject)
            .cmp(&(b.severity, b.check, &b.place, &b.subject))
    });
}

fn parse_failures(workspace: &Workspace) -> Vec<Finding> {
    workspace
        .files
        .iter()
        .filter_map(|file| {
            let failure = file.failure()?;
            Some(Finding::new(
                Check::ParseFailed,
                Place::at(file, failure.line),
                file.display_path(),
                format!("does not parse, read as text only: {}", failure.message),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{app, workspace};

    #[test]
    fn a_file_that_does_not_parse_is_reported() {
        let ws = workspace(vec![app("broken.rs", "fn broken( {}")]);

        let found = run_all(
            &ws,
            &Model::build(&ws, &DomainLists::default()),
            &BTreeSet::new(),
        )
        .findings;

        assert_eq!(found[0].check, Check::ParseFailed);
        assert_eq!(found[0].subject, "crates/ianua-app/src/broken.rs");
    }
}
