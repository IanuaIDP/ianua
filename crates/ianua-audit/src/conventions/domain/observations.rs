//! Only a listed function builds a whole event outside an aggregate.
//!
//! An event is raised by the aggregate that changed, and the application
//! takes it out with `take_events` once the change is saved, so a record
//! can never name a tenant other than the one written to, nor be built for
//! a change that did not happen. A few events have no aggregate to raise
//! them: the proxy sees a threat in traffic, a trigger fires a version that
//! may not start for its publisher, a member signs in and nothing they hold
//! changes. Those are built whole by a function listed in
//! [`OBSERVATIONS`] with the reason.
//!
//! Two kinds of function build one:
//!
//! - **Naming the tenant by hand**: any function calling `scoped`.
//! - **Handing one out**: any plain `pub` function returning a
//!   `DomainEvent`, or a list of them, which the application could call
//!   whenever it likes. An aggregate's `take_events` implements a trait,
//!   so it is not one.
//!
//! Any other function doing either is flagged, and so is a listed one that
//! no longer does.

use std::collections::BTreeSet;

use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprCall, ImplItem, ReturnType, Signature};

use crate::conventions::domain::lists::OBSERVATIONS;
use crate::conventions::domain::source::{
    Findings, Function, SourceFile, production_files, type_mentions, type_name,
};

/// Whether a block calls `scoped`.
#[derive(Default)]
struct StampsATenant {
    found: bool,
}

impl<'ast> Visit<'ast> for StampsATenant {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        self.found |= calls_scoped(&call.func);
        visit::visit_expr_call(self, call);
    }
}

fn calls_scoped(function: &Expr) -> bool {
    let Expr::Path(path) = function else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "scoped")
}

fn stamps_a_tenant(body: &Block) -> bool {
    let mut visitor = StampsATenant::default();
    visitor.visit_block(body);
    visitor.found
}

/// Whether `function` is plain `pub` and returns a `DomainEvent`, alone or
/// in a list.
fn hands_out_events(function: &Function<'_>) -> bool {
    let ReturnType::Type(_, returned) = &function.signature.output else {
        return false;
    };
    function.exported && type_mentions(returned, "DomainEvent")
}

fn builds_an_event(function: &Function<'_>) -> bool {
    stamps_a_tenant(function.body) || hands_out_events(function)
}

/// Every method in `file`, with the type its `impl` is for.
fn methods_of(file: &SourceFile) -> Vec<(&Signature, String)> {
    file.inventory()
        .impls
        .into_iter()
        .flat_map(|item| {
            let owner = type_name(&item.self_ty)
                .map(ToString::to_string)
                .unwrap_or_default();
            item.items.iter().filter_map(move |member| match member {
                ImplItem::Fn(function) => Some((&function.sig, owner.clone())),
                _ => None,
            })
        })
        .collect()
}

/// The functions in `file` that build an event, each with its signature
/// and what it is listed under: the type it is a method of, or the file a
/// free function sits in.
fn building_events(file: &SourceFile) -> Vec<(&Signature, String)> {
    let methods = methods_of(file);
    file.inventory()
        .functions
        .into_iter()
        .filter(builds_an_event)
        .map(|function| {
            let owner = methods
                .iter()
                .find(|(signature, _)| std::ptr::eq(*signature, function.signature))
                .map_or_else(|| file.path.clone(), |(_, owner)| owner.clone());
            (function.signature, owner)
        })
        .collect()
}

fn is_listed(owner: &str, name: &str) -> bool {
    OBSERVATIONS
        .iter()
        .any(|(listed_owner, listed_name, _)| *listed_owner == owner && *listed_name == name)
}

/// Every function found building an event, as `Owner::name`.
pub(crate) fn observations_found(files: &[SourceFile]) -> BTreeSet<String> {
    files
        .iter()
        .flat_map(building_events)
        .map(|(signature, owner)| format!("{owner}::{}", signature.ident))
        .collect()
}

/// Where the source breaks the convention this module holds it to.
pub(crate) fn events_built_outside_an_aggregate(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (signature, owner) in building_events(file) {
            let name = signature.ident.to_string();
            if is_listed(&owner, &name) {
                continue;
            }
            findings.flag(
                file,
                signature,
                format!(
                    "`{owner}::{name}` builds an event outside an aggregate; raise it on the aggregate that changed, or list it in OBSERVATIONS with the reason"
                ),
            );
        }
    }
    findings
}

/// Every function that builds an event outside an aggregate is listed with
/// the reason no aggregate raises it.
#[cfg_attr(test, test)]
pub(crate) fn only_listed_observations_build_an_event() {
    events_built_outside_an_aggregate(&production_files())
        .assert_none("events built outside an aggregate");
}

/// A listed function that no longer builds an event leaves an entry that
/// would let the next one through unread.
#[cfg_attr(test, test)]
pub(crate) fn every_listed_observation_still_builds_its_event() {
    let found = observations_found(&production_files());
    let stale: Vec<String> = OBSERVATIONS
        .iter()
        .map(|(owner, name, _)| format!("{owner}::{name}"))
        .filter(|listed| !found.contains(listed))
        .collect();

    assert!(
        stale.is_empty(),
        "observations listed but not found: {stale:?}"
    );
}
