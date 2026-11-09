//! Code written once. Everything the app builds outside its tests is read,
//! test support included, and two kinds of copy fail the build:
//!
//! - **Twin bodies**: two functions in different files whose bodies are the
//!   same, at least [`MIN_TWIN_LINES`] lines long. One of them belongs in a
//!   shared place the other calls.
//! - **Near twins**: free functions of the same name in different files
//!   whose bodies are at least [`NEAR_TWIN_SHARE`] percent the same. Two
//!   helpers named alike and written alike are one helper written twice,
//!   and the copies drift apart.
//!
//! A copy that must stay, say because the two belong to layers that may not
//! share code, is listed in [`COPIES_ALLOWED`] with the reason.

use std::collections::BTreeMap;

use syn::Item;
use syn::spanned::Spanned;

use crate::conventions::app::source::{Check, Findings, SourceFile, built_files, line_of};

/// The fewest lines a body must have for a twin of it to count.
const MIN_TWIN_LINES: usize = 4;

/// The share of the same tokens, in percent, from which two same-named
/// helpers count as one written twice.
const NEAR_TWIN_SHARE: usize = 90;

/// The fewest tokens a helper must have before it is compared at all;
/// shorter ones are too small to share.
const MIN_NEAR_TWIN_TOKENS: usize = 20;

/// Copies kept on purpose: the function's name, and why.
const COPIES_ALLOWED: &[(&str, &str)] = &[
    (
        "compare",
        "each fake orders its own record type by its own sort fields",
    ),
    (
        "status_key",
        "each fake writes its own status type the way storage keeps it",
    ),
    (
        "existing_subscription",
        "messaging and webhooks each load their own kind of subscription",
    ),
];

/// A function as the checks compare it.
struct Written<'a> {
    file: &'a SourceFile,
    name: String,
    line: usize,
    lines: usize,
    tokens: Vec<String>,
}

/// The words and marks a piece of source is made of, so layout and
/// comments do not count.
fn tokens_of(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    for c in text.chars() {
        if c.is_alphanumeric() || c == '_' {
            word.push(c);
            continue;
        }
        if !word.is_empty() {
            tokens.push(std::mem::take(&mut word));
        }
        if !c.is_whitespace() {
            tokens.push(c.to_string());
        }
    }
    if !word.is_empty() {
        tokens.push(word);
    }
    tokens
}

/// The source of a body without its line comments.
fn body_text(block: &syn::Block) -> String {
    block
        .span()
        .source_text()
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn written<'a>(file: &'a SourceFile, name: &syn::Ident, body: &syn::Block) -> Written<'a> {
    let span = body.span();
    Written {
        file,
        name: name.to_string(),
        line: line_of(body),
        lines: span.end().line.saturating_sub(span.start().line + 1),
        tokens: tokens_of(&body_text(body)),
    }
}

/// Every function with a body, methods included.
fn functions(files: &[SourceFile]) -> Vec<Written<'_>> {
    files
        .iter()
        .flat_map(|file| {
            file.inventory()
                .functions
                .into_iter()
                .map(move |function| written(file, &function.signature.ident, function.body))
        })
        .collect()
}

/// The free functions of each file, at its top level.
fn free_functions(files: &[SourceFile]) -> Vec<Written<'_>> {
    files
        .iter()
        .flat_map(|file| {
            file.items().iter().filter_map(move |item| match item {
                Item::Fn(function) => Some(written(file, &function.sig.ident, &function.block)),
                _ => None,
            })
        })
        .collect()
}

fn allowed(name: &str) -> bool {
    COPIES_ALLOWED.iter().any(|(listed, _)| *listed == name)
}

/// Functions in different files with the same body.
fn twin_bodies(files: &[SourceFile]) -> Findings {
    let mut by_body: BTreeMap<Vec<String>, Vec<Written<'_>>> = BTreeMap::new();
    for function in functions(files)
        .into_iter()
        .filter(|function| function.lines >= MIN_TWIN_LINES && !allowed(&function.name))
    {
        by_body
            .entry(function.tokens.clone())
            .or_default()
            .push(function);
    }
    let mut findings = Findings::default();
    for twins in by_body.values().filter(|twins| spans_files(twins)) {
        let first = &twins[0];
        for twin in &twins[1..] {
            findings.flag_line(
                twin.file,
                twin.line,
                format!(
                    "`{}` has the same body as `{}` in {}; write it once",
                    twin.name, first.name, first.file.path
                ),
            );
        }
    }
    findings
}

fn spans_files(twins: &[Written<'_>]) -> bool {
    twins
        .iter()
        .any(|twin| twin.file.path != twins[0].file.path)
}

/// The length of the longest run of tokens `a` and `b` have in common, in
/// order.
fn common_run(a: &[String], b: &[String]) -> usize {
    let mut previous = vec![0; b.len() + 1];
    for token in a {
        let mut current = vec![0; b.len() + 1];
        for (index, other) in b.iter().enumerate() {
            current[index + 1] = match token == other {
                true => previous[index] + 1,
                false => current[index].max(previous[index + 1]),
            };
        }
        previous = current;
    }
    previous[b.len()]
}

/// How much of `a` and `b` is the same, in percent.
fn share(a: &[String], b: &[String]) -> usize {
    let total = a.len() + b.len();
    if total == 0 {
        return 100;
    }
    200 * common_run(a, b) / total
}

/// Same-named free functions in different files written nearly alike.
fn near_twins(files: &[SourceFile]) -> Findings {
    let mut by_name: BTreeMap<String, Vec<Written<'_>>> = BTreeMap::new();
    for function in free_functions(files).into_iter().filter(|function| {
        function.tokens.len() >= MIN_NEAR_TWIN_TOKENS && !allowed(&function.name)
    }) {
        by_name
            .entry(function.name.clone())
            .or_default()
            .push(function);
    }
    let mut findings = Findings::default();
    for namesakes in by_name.values() {
        flag_near_twins(namesakes, &mut findings);
    }
    findings
}

fn flag_near_twins(namesakes: &[Written<'_>], findings: &mut Findings) {
    for (index, one) in namesakes.iter().enumerate() {
        let twin = namesakes[index + 1..].iter().find(|other| {
            other.file.path != one.file.path
                && one.tokens != other.tokens
                && share(&one.tokens, &other.tokens) >= NEAR_TWIN_SHARE
        });
        let Some(twin) = twin else {
            continue;
        };
        findings.flag_line(
            twin.file,
            twin.line,
            format!(
                "`{}` is written nearly as in {}; write it once",
                twin.name, one.file.path
            ),
        );
    }
}

#[cfg_attr(test, test)]
pub(crate) fn no_body_is_written_twice() {
    twin_bodies(&built_files()).assert_none("functions with the same body");
}

#[cfg_attr(test, test)]
pub(crate) fn no_helper_is_written_twice_under_one_name() {
    near_twins(&built_files()).assert_none("helpers written twice");
}

/// Each duplicate check, run over files that copy on purpose, finds the
/// copy.
#[cfg_attr(test, test)]
pub(crate) fn every_duplicate_check_finds_its_planted_copy() {
    let files = [
        SourceFile::planted("planted/one.rs", PLANTED_ONE),
        SourceFile::planted("planted/two.rs", PLANTED_TWO),
    ];
    let checks: [(&str, Check); 2] = [("twin body", twin_bodies), ("near twin", near_twins)];
    let missed: Vec<&str> = checks
        .iter()
        .filter(|(_, check)| check(&files).is_empty())
        .map(|(name, _)| *name)
        .collect();
    assert!(
        missed.is_empty(),
        "duplicate checks that missed their planted copy: {missed:?}"
    );
}

/// Bodies are compared as tokens, so two laid out differently but written
/// the same are the same.
#[cfg_attr(test, test)]
pub(crate) fn layout_does_not_change_what_counts_as_the_same() {
    let tight = tokens_of("let x = b(c, d); x");
    let loose = tokens_of("let x = b(\n    c,\n    d\n);\nx");

    assert_eq!(share(&tight, &loose), 100);
}

const PLANTED_ONE: &str = r#"
fn ensure_open(store: &Store, id: &Id) -> Result<Thing, AppError> {
    let thing = store.find(id).or_not_found("no such thing")?;
    if thing.is_closed() {
        return Err(AppError::Conflict("the thing is closed".to_owned()));
    }
    Ok(thing)
}

fn label(thing: &Thing) -> String {
    let name = thing.name().as_str();
    let id = thing.id().to_string();
    let joined = format!("{name} ({id})");
    joined.trim().to_owned()
}
"#;

const PLANTED_TWO: &str = r#"
fn ensure_open(store: &Store, id: &Id) -> Result<Thing, AppError> {
    let thing = store.find(id).or_not_found("no such record")?;
    if thing.is_closed() {
        return Err(AppError::Conflict("the thing is closed".to_owned()));
    }
    Ok(thing)
}

fn title(thing: &Thing) -> String {
    let name = thing.name().as_str();
    let id = thing.id().to_string();
    let joined = format!("{name} ({id})");
    joined.trim().to_owned()
}
"#;
