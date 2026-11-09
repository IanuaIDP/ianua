//! Which way the domain's parts may depend on each other: each bounded
//! context on the contexts below it, and the shared kernel on none of them.

use crate::conventions::domain::lists::CONTEXT_LAYERS;
use crate::conventions::domain::source::{Findings, SourceFile};

const CONTEXT_PATH: &str = "crate::domains::";

/// Where a file sits: in the shared kernel, or in a bounded context.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place<'a> {
    /// `shared/`, `types/`, `isolation/` and the crate root.
    Kernel,
    /// The context a file under `domains/` belongs to.
    Context(&'a str),
}

impl<'a> Place<'a> {
    fn of(path: &'a str) -> Self {
        let Some(rest) = path.strip_prefix("domains/") else {
            return Self::Kernel;
        };
        let name = rest.split('/').next().unwrap_or(rest);
        Self::Context(name.strip_suffix(".rs").unwrap_or(name))
    }
}

/// The layer a context sits in, if it is placed in one.
pub(crate) fn layer_of(context: &str) -> Option<usize> {
    CONTEXT_LAYERS
        .iter()
        .position(|layer| layer.contains(&context))
}

/// Why `from` may not use `used`, if it may not.
fn refusal(from: Place<'_>, used: &str) -> Option<String> {
    let Place::Context(own) = from else {
        return Some(format!(
            "the shared kernel uses the `{used}` context; it sits below every context"
        ));
    };
    if own == used {
        return None;
    }
    let (Some(own_layer), Some(used_layer)) = (layer_of(own), layer_of(used)) else {
        return Some(format!(
            "`{own}` uses `{used}`, and a context not placed in `CONTEXT_LAYERS` may not be used or use one"
        ));
    };
    if used_layer < own_layer {
        return None;
    }
    Some(format!(
        "`{own}` uses `{used}`, which sits beside or above it in `CONTEXT_LAYERS`"
    ))
}

/// The contexts a line of code names through `crate::domains::`.
pub(crate) fn contexts_named(line: &str) -> impl Iterator<Item = &str> {
    line.match_indices(CONTEXT_PATH).map(|(at, _)| {
        let rest = &line[at + CONTEXT_PATH.len()..];
        let end = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        &rest[..end]
    })
}

/// Where a file uses a context it may not: a context reaching beside or
/// above its own layer in [`CONTEXT_LAYERS`], a context placed in no layer,
/// or the shared kernel reaching into any context. Doc comments may name any
/// part of the crate; only code is a dependency.
pub(crate) fn context_dependencies(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let from = Place::of(&file.path);
        for (index, line) in file.lines_before_tests().iter().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for used in contexts_named(line) {
                if let Some(message) = refusal(from, used) {
                    findings.flag_line(file, index + 1, message);
                }
            }
        }
    }
    findings
}

/// Contexts under `domains/` that `CONTEXT_LAYERS` does not place, or that
/// it names but no longer exist: the list must say exactly where every
/// context sits.
pub(crate) fn unplaced_contexts(files: &[SourceFile]) -> Vec<String> {
    let mut present: Vec<&str> = files
        .iter()
        .filter_map(|file| {
            let rest = file.path.strip_prefix("domains/")?;
            rest.split_once('/').map(|(context, _)| context)
        })
        .collect();
    present.sort_unstable();
    present.dedup();
    let unplaced = present
        .iter()
        .filter(|context| layer_of(context).is_none())
        .map(|context| format!("`{context}` is in no layer"));
    let gone = CONTEXT_LAYERS
        .iter()
        .flat_map(|layer| layer.iter())
        .filter(|context| !present.contains(context))
        .map(|context| format!("`{context}` is listed but has no folder"));
    unplaced.chain(gone).collect()
}
