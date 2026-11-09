//! The house rules the integration crates under `integrations/` keep: the
//! style the adapters keep, checked the same way, and a doc comment on
//! every public item, since these crates are the SDK and the examples other
//! people build integrations from.
//!
//! - No comment inside a function body, no `if` directly inside another,
//!   and every `allow` says why.
//! - One test module, at the end of its file; no dividers, no em dashes,
//!   and no file past the adapters' length.
//! - Imports from `crate::`, at the top of a module, naming what they take,
//!   none held for another file; no function takes a `bool`.
//! - Every test says in a doc comment what it shows.
//! - Every public item, field and variant says in a doc comment what it is.

use crate::conventions::infra::source::{
    Check, Findings, SourceFile, integration_files, integration_production_files,
};
use crate::conventions::infra::style::{
    climbing_paths, comments_in_function_bodies, divider_comments, em_dashes, files_longer_than,
    flag_parameters, glob_imports, imports_held_for_others, imports_inside_functions,
    misplaced_test_modules, nested_ifs, parent_imports, undocumented_tests, unexplained_allows,
};

/// The most lines of code a file holds before its tests, as the adapters'.
const MAX_CODE_LINES: usize = 550;

/// What starts a line declaring a public item or field.
const PUBLIC: &[&str] = &["pub ", "pub(crate) "];

/// Public declarations a doc comment is not asked of: a module documents
/// itself inside its file, and a re-export is documented where it is made.
const SELF_DOCUMENTED: &[&str] = &["mod ", "use "];

/// Whether `line` declares a public item or field that needs a doc.
fn declares_public(line: &str) -> bool {
    let trimmed = line.trim_start();
    PUBLIC.iter().any(|public| {
        trimmed
            .strip_prefix(public)
            .is_some_and(|rest| !SELF_DOCUMENTED.iter().any(|kind| rest.starts_with(kind)))
    })
}

/// Whether the lines above line `index` (0-based), through attributes,
/// hold a doc comment.
fn documented_above(lines: &[&str], index: usize) -> bool {
    lines[..index]
        .iter()
        .rev()
        .map(|line| line.trim_start())
        .find(|line| !line.starts_with("#["))
        .is_some_and(|line| line.starts_with("///"))
}

/// Public items, fields and variants with no doc comment, in the code that
/// ships.
fn undocumented_public_items(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let lines = file.lines();
        for (index, line) in lines.iter().enumerate() {
            if declares_public(line) && !documented_above(&lines, index) {
                findings.flag_line(
                    file,
                    index + 1,
                    "a public item without a doc saying what it is",
                );
            }
        }
    }
    findings
}

#[cfg_attr(test, test)]
pub(crate) fn function_bodies_carry_no_comments() {
    comments_in_function_bodies(&integration_files())
        .assert_none("comments inside function bodies");
}

#[cfg_attr(test, test)]
pub(crate) fn no_if_is_nested_in_another() {
    nested_ifs(&integration_production_files()).assert_none("nested ifs");
}

#[cfg_attr(test, test)]
pub(crate) fn every_allow_says_why() {
    unexplained_allows(&integration_production_files()).assert_none("unexplained allows");
}

#[cfg_attr(test, test)]
pub(crate) fn the_test_module_comes_last_and_alone() {
    misplaced_test_modules(&integration_files()).assert_none("misplaced test modules");
}

#[cfg_attr(test, test)]
pub(crate) fn no_file_is_split_by_dividers() {
    divider_comments(&integration_files()).assert_none("section dividers");
}

#[cfg_attr(test, test)]
pub(crate) fn no_file_holds_an_em_dash() {
    em_dashes(&integration_files()).assert_none("em dashes");
}

#[cfg_attr(test, test)]
pub(crate) fn no_file_holds_more_than_one_topic() {
    files_longer_than(&integration_production_files(), MAX_CODE_LINES)
        .assert_none("files too long");
}

#[cfg_attr(test, test)]
pub(crate) fn imports_name_their_source_from_the_crate() {
    parent_imports(&integration_files()).assert_none("imports through `super::`");
}

#[cfg_attr(test, test)]
pub(crate) fn no_path_climbs_two_levels() {
    climbing_paths(&integration_files()).assert_none("paths through `super::super::`");
}

#[cfg_attr(test, test)]
pub(crate) fn imports_name_what_they_take() {
    glob_imports(&integration_production_files()).assert_none("glob imports");
}

#[cfg_attr(test, test)]
pub(crate) fn imports_sit_at_the_top_of_their_module() {
    imports_inside_functions(&integration_files()).assert_none("imports inside functions");
}

#[cfg_attr(test, test)]
pub(crate) fn each_file_imports_what_it_uses() {
    imports_held_for_others(&integration_production_files()).assert_none("imports held for others");
}

#[cfg_attr(test, test)]
pub(crate) fn every_test_says_what_it_shows() {
    undocumented_tests(&integration_files()).assert_none("tests without a doc");
}

#[cfg_attr(test, test)]
pub(crate) fn no_function_takes_a_bool() {
    flag_parameters(&integration_production_files()).assert_none("functions taking a bool");
}

#[cfg_attr(test, test)]
pub(crate) fn every_public_item_says_what_it_is() {
    undocumented_public_items(&integration_production_files())
        .assert_none("public items without a doc");
}

/// The checks this group adds to the adapters' style, each run over a file
/// that breaks it on purpose, finds the break.
#[cfg_attr(test, test)]
pub(crate) fn every_integration_check_finds_its_planted_break() {
    let files = [SourceFile::planted("planted.rs", PLANTED)];
    let checks: [(&str, Check); 1] = [("undocumented public item", undocumented_public_items)];
    let missed: Vec<&str> = checks
        .iter()
        .filter(|(_, check)| check(&files).is_empty())
        .map(|(name, _)| *name)
        .collect();
    assert!(
        missed.is_empty(),
        "checks that missed their planted break: {missed:?}"
    );
}

/// A file with a public item and a public field, neither documented.
const PLANTED: &str = "
/// A documented type.
pub struct Account {
    pub token: String,
}

pub fn reached() -> bool {
    true
}
";
