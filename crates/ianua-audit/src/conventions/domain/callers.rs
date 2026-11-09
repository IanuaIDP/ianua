//! Every public creator and change of a stored type names who makes it.
//!
//! A rule that asks "may this person do it" needs the person, and what they
//! hold, as the domain worked them out. So a public function that creates
//! or changes a stored type takes one of the caller proofs in
//! [`CALLER_PROOFS`], or a parameter in [`CALLER_PROOF_CARRIERS`] that
//! carries one. A creation or change nobody makes, such as a clock running
//! out or the platform's own bookkeeping, is listed in [`UNCALLED_CHANGES`]
//! with the reason it needs no caller.
//!
//! A stored type is one the domain rebuilds from a row: it implements
//! `Aggregate` or has a `reconstitute`. Functions compiled only for tests
//! or the `test-support` feature are left out.

use std::collections::BTreeMap;

use syn::{Attribute, FnArg, ImplItem, ImplItemFn, ItemImpl, ReturnType, Visibility};

use crate::conventions::domain::lists::{CALLER_PROOF_CARRIERS, CALLER_PROOFS, UNCALLED_CHANGES};
use crate::conventions::domain::source::{Findings, SourceFile, type_mentions, type_name};

/// Whether a function makes a stored value or changes one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// It returns a new value of the type.
    Create,
    /// It takes `&mut self`.
    Change,
}

/// Public creators and changes of stored types that name no caller.
///
pub(crate) fn stored_changes_without_a_caller(files: &[SourceFile]) -> Findings {
    let stored = stored_types(files);
    let mut findings = Findings::default();
    for file in files {
        for item in file.inventory().impls {
            let Some(name) = inherent_impl_of(item).filter(|name| stored.contains_key(name)) else {
                continue;
            };
            for (function, kind) in creators_and_changes(item, &name) {
                if names_a_caller(&function.sig)
                    || is_listed(&name, &function.sig.ident.to_string())
                {
                    continue;
                }
                let verb = match kind {
                    Kind::Create => "creates",
                    Kind::Change => "changes",
                };
                findings.flag(
                    file,
                    &function.sig,
                    format!(
                        "`{name}::{}` {verb} a stored value without naming who does it",
                        function.sig.ident
                    ),
                );
            }
        }
    }
    findings
}

/// Every stored type, with the file that declares it.
pub(crate) fn stored_types(files: &[SourceFile]) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    for file in files {
        for item in file.inventory().impls {
            if !(implements(item, "Aggregate") || rebuilds_from_a_row(item)) {
                continue;
            }
            if let Some(name) = type_name(&item.self_ty) {
                found
                    .entry(name.to_string())
                    .or_insert_with(|| file.path.clone());
            }
        }
    }
    found
}

/// Whether an inherent `impl` has a `reconstitute`.
fn rebuilds_from_a_row(item: &ItemImpl) -> bool {
    item.trait_.is_none()
        && item.items.iter().any(|member| {
            matches!(member, ImplItem::Fn(function) if function.sig.ident == "reconstitute")
        })
}

/// The type an inherent `impl` is for.
pub(crate) fn inherent_impl_of(item: &ItemImpl) -> Option<String> {
    if item.trait_.is_some() {
        return None;
    }
    type_name(&item.self_ty).map(ToString::to_string)
}

/// Whether `item` implements the trait named `name`.
fn implements(item: &ItemImpl, name: &str) -> bool {
    item.trait_
        .as_ref()
        .and_then(|(_, path, _)| path.segments.last())
        .is_some_and(|segment| segment.ident == name)
}

/// The public creators and changes in `item`, an `impl` of `owner`.
pub(crate) fn creators_and_changes<'a>(
    item: &'a ItemImpl,
    owner: &str,
) -> Vec<(&'a ImplItemFn, Kind)> {
    item.items
        .iter()
        .filter_map(|member| match member {
            ImplItem::Fn(function) => Some(function),
            _ => None,
        })
        .filter(|function| matches!(function.vis, Visibility::Public(_)))
        .filter(|function| !for_tests_only(&function.attrs))
        .filter_map(|function| kind_of(function, owner).map(|kind| (function, kind)))
        .collect()
}

/// Whether a function is compiled only for tests or the `test-support`
/// feature.
pub(crate) fn for_tests_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string().contains("test"))
    })
}

/// Whether `function` creates a value of `owner`, changes one, or neither.
/// Rebuilding from a row is neither: storage, not a caller, makes it.
fn kind_of(function: &ImplItemFn, owner: &str) -> Option<Kind> {
    let mut receivers = function.sig.inputs.iter().filter_map(|input| match input {
        FnArg::Receiver(receiver) => Some(receiver),
        FnArg::Typed(_) => None,
    });
    if let Some(receiver) = receivers.next() {
        let changes = receiver.reference.is_some() && receiver.mutability.is_some();
        return changes.then_some(Kind::Change);
    }
    let makes = match &function.sig.output {
        ReturnType::Type(_, ty) => type_mentions(ty, "Self") || type_mentions(ty, owner),
        ReturnType::Default => false,
    };
    (makes && function.sig.ident != "reconstitute").then_some(Kind::Create)
}

/// The caller proofs `signature` takes, by name: as a type, as
/// `impl Proof`, as a generic bound to one, or inside a carrier parameter.
pub(crate) fn proofs_named(signature: &syn::Signature) -> Vec<String> {
    let bound = generics_bound_to_a_proof(signature);
    let mut named: Vec<String> = Vec::new();
    for input in &signature.inputs {
        let FnArg::Typed(typed) = input else {
            continue;
        };
        for proof in CALLER_PROOFS {
            let as_bound = bound
                .iter()
                .any(|(generic, bounded)| bounded == proof && type_mentions(&typed.ty, generic));
            if type_mentions(&typed.ty, proof) || as_bound {
                named.push((*proof).to_owned());
            }
        }
        for (carrier, _) in CALLER_PROOF_CARRIERS {
            if type_mentions(&typed.ty, carrier) {
                named.push((*carrier).to_owned());
            }
        }
    }
    named.sort();
    named.dedup();
    named
}

/// Whether `signature` takes a caller proof.
pub(crate) fn names_a_caller(signature: &syn::Signature) -> bool {
    !proofs_named(signature).is_empty()
}

/// The method's generic parameters bound to a caller proof, with the proof.
fn generics_bound_to_a_proof(signature: &syn::Signature) -> Vec<(String, String)> {
    signature
        .generics
        .type_params()
        .flat_map(|generic| {
            generic.bounds.iter().filter_map(move |bound| {
                proof_bound(bound).map(|proof| (generic.ident.to_string(), proof))
            })
        })
        .collect()
}

/// The caller proof `bound` names, if it names one.
fn proof_bound(bound: &syn::TypeParamBound) -> Option<String> {
    let syn::TypeParamBound::Trait(bound) = bound else {
        return None;
    };
    let last = bound.path.segments.last()?;
    CALLER_PROOFS
        .iter()
        .find(|proof| last.ident == proof)
        .map(|proof| (*proof).to_owned())
}

/// Why `method` of `stored` needs no caller, when it is listed.
pub(crate) fn listed_reason(stored: &str, method: &str) -> Option<&'static str> {
    UNCALLED_CHANGES
        .iter()
        .find(|(listed_type, listed_method, _)| *listed_type == stored && *listed_method == method)
        .map(|(_, _, reason)| *reason)
}

/// Whether `method` of `stored` is listed as nobody's.
fn is_listed(stored: &str, method: &str) -> bool {
    listed_reason(stored, method).is_some()
}
