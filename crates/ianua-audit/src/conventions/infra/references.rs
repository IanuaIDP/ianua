//! Every kind of thing an audit record may point at, as the domain names
//! it, is one the audit store reads back.
//!
//! - **Named, then read.** The domain names a kind of reference with
//!   `RefKind::new("…")` beside the events that point at it, such as
//!   `RefKind::new("sandbox")`. The audit store keeps the kinds it reads in
//!   one list, `postgres/audit/payload.rs`, and refuses a stored record of
//!   any other kind as corrupt. A kind the domain names and the list
//!   leaves out is written into every record of its events, and then the
//!   audit log cannot be read: Ann's trail fails as soon as her first
//!   sandbox is made.

use std::collections::BTreeSet;

use crate::conventions::infra::source::{Findings, SourceFile, production_files, sibling_files};

/// The audit store's list of kinds it reads back.
const KINDS_FILE: &str = "postgres/audit/payload.rs";

/// What opens a kind written out by its word.
const NAMED: &str = "RefKind::new(\"";

/// The kinds `file` names by their word, before its tests, with the line
/// each is first named on.
fn kinds_named(file: &SourceFile) -> Vec<(String, usize)> {
    let mut named = Vec::new();
    for (index, line) in file.lines_before_tests().iter().enumerate() {
        let mut rest: &str = line;
        while let Some(start) = rest.find(NAMED) {
            rest = &rest[start + NAMED.len()..];
            let Some(end) = rest.find('"') else {
                break;
            };
            named.push((rest[..end].to_owned(), index + 1));
            rest = &rest[end..];
        }
    }
    named
}

/// Every kind the domain's files name that `read` does not hold.
pub(crate) fn kinds_the_trail_cannot_read(domain: &[SourceFile], read: &SourceFile) -> Findings {
    let readable: BTreeSet<String> = kinds_named(read)
        .into_iter()
        .map(|(kind, _)| kind)
        .collect();
    let mut findings = Findings::default();
    for file in domain {
        for (kind, line) in kinds_named(file) {
            if !readable.contains(&kind) {
                findings.flag_line(
                    file,
                    line,
                    format!(
                        "names the reference kind `{kind}`, which the audit store does not read back; add it to the list in {KINDS_FILE}"
                    ),
                );
            }
        }
    }
    findings
}

/// The domain's files.
fn domain_files() -> Vec<SourceFile> {
    sibling_files("ianua-domain", &["domains", "shared"])
}

/// The audit store's list of kinds.
fn kinds_file() -> SourceFile {
    production_files()
        .into_iter()
        .find(|file| file.path == KINDS_FILE)
        .unwrap_or_else(|| panic!("{KINDS_FILE} is not read"))
}

/// A domain file naming a kind the store's list leaves out.
const PLANTED_DOMAIN: &str = r#"
const SANDBOX: RefKind = RefKind::new("sandbox");
const RECIPE: RefKind = RefKind::new("recipe");
"#;

/// A store's list holding one of the two.
const PLANTED_LIST: &str = r#"
const REF_KINDS: &[RefKind] = &[RefKind::USER, RefKind::new("sandbox")];
"#;

/// Stops: the domain names a kind of reference the audit store does not
/// read back, so every record of its events would make the trail
/// unreadable.
#[cfg_attr(test, test)]
pub(crate) fn every_reference_kind_is_read_back() {
    kinds_the_trail_cannot_read(&domain_files(), &kinds_file())
        .assert_none("reference kinds the audit store does not read back");
}

/// The check reads the domain's kinds where they are named, such as the
/// workflows' and the sandboxes'.
#[cfg_attr(test, test)]
pub(crate) fn the_reference_kinds_are_read() {
    let named: BTreeSet<String> = domain_files()
        .iter()
        .flat_map(kinds_named)
        .map(|(kind, _)| kind)
        .collect();

    for expected in ["workflow", "sandbox", "sandbox_version"] {
        assert!(named.contains(expected), "{expected} is not read");
    }
}

/// The check finds the kind planted outside the list, and leaves a kind
/// the list holds alone.
#[cfg_attr(test, test)]
pub(crate) fn the_reference_kind_check_finds_its_planted_break() {
    let domain = [SourceFile::planted(
        "ianua-domain/planted.rs",
        PLANTED_DOMAIN,
    )];
    let held = [SourceFile::planted(
        "ianua-domain/held.rs",
        "const SANDBOX: RefKind = RefKind::new(\"sandbox\");\n",
    )];
    let list = SourceFile::planted(KINDS_FILE, PLANTED_LIST);

    assert!(!kinds_the_trail_cannot_read(&domain, &list).is_empty());
    assert!(kinds_the_trail_cannot_read(&held, &list).is_empty());
}
