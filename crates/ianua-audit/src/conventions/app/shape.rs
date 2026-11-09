//! The layout every use-case file keeps, and the plan limits they enforce.
//!
//! - Free functions sit below the use case's `impl Command` / `impl Query`,
//!   in the order: `ensure_*` checks, other helpers, `*_event` builders.
//! - A command saves first, then records: its `execute` dispatches no audit
//!   record before its first save or delete.
//! - Every `*Ports` struct derives `Fakes`, so its tests can take the ports
//!   they are not about from `..Ports::fakes()`.
//! - Every plan limit (`ResourceKind` variant) is checked by some use case:
//!   a limit nobody enforces fails silently.
//! - A use case that checks a plan limit has a test where the limit refuses
//!   (`RejectingLimitEnforcer`, or a refusing enforcer of its own).

use std::fs;
use std::path::{Path, PathBuf};

/// The use case files of the contexts switched on.
fn use_case_files() -> Vec<PathBuf> {
    let root = crate::conventions::crate_dir("ianua-app").join("src");
    crate::conventions::app::source::app_files()
        .into_iter()
        .filter(|file| file.path.starts_with("use_cases/"))
        .map(|file| root.join(file.path))
        .collect()
}

/// The file without its test module.
fn production_source(path: &Path) -> String {
    let source = fs::read_to_string(path).expect("a use case file is readable");
    match source.find("#[cfg(test)]") {
        Some(tests) => source[..tests].to_owned(),
        None => source,
    }
}

fn is_use_case_impl(line: &str) -> bool {
    line.starts_with("impl") && (line.contains(" Command for ") || line.contains(" Query for "))
}

/// The name of the free function a top-level line declares, if it does.
fn free_fn_name(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub(super) "))
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    rest.split(['(', '<']).next()
}

/// Where a free function belongs among the others below the use case.
fn rank(name: &str) -> u8 {
    if name.starts_with("ensure_") {
        return 0;
    }
    if name.ends_with("_event") || name.ends_with("_events") {
        return 2;
    }
    1
}

fn layout_findings(path: &Path, source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let Some(first_impl) = lines.iter().position(|line| is_use_case_impl(line)) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let mut last_rank = 0;
    for (index, line) in lines.iter().enumerate() {
        let Some(name) = free_fn_name(line) else {
            continue;
        };
        if index < first_impl {
            findings.push(format!(
                "{}:{}: `{name}` is above the use case impl",
                path.display(),
                index + 1
            ));
            continue;
        }
        let this_rank = rank(name);
        if this_rank < last_rank {
            findings.push(format!(
                "{}:{}: `{name}` is out of order (ensure_* checks, helpers, *_event builders)",
                path.display(),
                index + 1
            ));
        }
        last_rank = last_rank.max(this_rank);
    }
    findings
}

/// The body of the `execute` that follows the `impl Command` at `start`.
fn execute_body<'a>(lines: &'a [&'a str], start: usize) -> &'a [&'a str] {
    let Some(open) = lines[start..]
        .iter()
        .position(|line| line.contains("async fn execute"))
    else {
        return &[];
    };
    let open = start + open;
    let close = lines[open..]
        .iter()
        .position(|line| *line == "    }")
        .map_or(lines.len(), |end| open + end);
    &lines[open..close]
}

fn order_findings(path: &Path, source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut findings = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !(line.starts_with("impl") && line.contains(" Command for ")) {
            continue;
        }
        let body = execute_body(&lines, index);
        let dispatch = body.iter().position(|l| l.contains(".dispatch("));
        let write = body
            .iter()
            .position(|l| l.contains(".save(") || l.contains(".delete("));
        match (dispatch, write) {
            (Some(dispatch), Some(write)) if dispatch < write => findings.push(format!(
                "{}: `{}` records before it saves",
                path.display(),
                line.trim_end_matches(" {")
            )),
            _ => {}
        }
    }
    findings
}

fn fakes_findings(path: &Path, source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| is_ports_struct(line))
        .filter(|(index, _)| !derives_fakes(&lines[..*index]))
        .map(|(index, line)| {
            format!(
                "{}:{}: `{}` does not derive Fakes",
                path.display(),
                index + 1,
                line.trim_end_matches(" {")
            )
        })
        .collect()
}

fn is_ports_struct(line: &str) -> bool {
    line.strip_prefix("pub struct ")
        .and_then(|rest| rest.split([' ', '<']).next())
        .is_some_and(|name| name.ends_with("Ports"))
}

/// Whether the attributes right above a struct include `#[derive(...Fakes)]`.
fn derives_fakes(above: &[&str]) -> bool {
    above
        .iter()
        .rev()
        .take_while(|line| line.starts_with("#[") || line.starts_with("///"))
        .any(|line| line.starts_with("#[derive(") && line.contains("Fakes"))
}

/// The variants of the `ResourceKind` enum in `ports/limits.rs`.
fn resource_kinds() -> Vec<String> {
    let path = crate::conventions::crate_dir("ianua-app").join("src/ports/limits.rs");
    let source = fs::read_to_string(path).expect("the limits port is readable");
    let body = source
        .split("pub enum ResourceKind {")
        .nth(1)
        .and_then(|rest| rest.split("\n}").next())
        .expect("ports/limits.rs declares ResourceKind");
    body.lines()
        .map(str::trim)
        .filter_map(|line| line.strip_suffix(','))
        .filter(|name| name.chars().next().is_some_and(char::is_uppercase))
        .map(str::to_owned)
        .collect()
}

/// The plan limits no use case's production code names.
fn unenforced(kinds: &[String], sources: &[String]) -> Vec<String> {
    kinds
        .iter()
        .filter(|kind| {
            let named = format!("ResourceKind::{kind}");
            !sources.iter().any(|source| source.contains(&named))
        })
        .cloned()
        .collect()
}

/// Whether a use case's production code checks a plan limit.
fn checks_a_limit(production: &str) -> bool {
    [
        ".check_tenant_limit(",
        ".check_tenant_room(",
        ".check_org_limit(",
    ]
    .iter()
    .any(|call| production.contains(call))
}

/// Whether a use case's tests make the limit refuse.
fn tests_a_refusing_limit(tests: &str) -> bool {
    tests.contains("RejectingLimitEnforcer") || tests.contains("LimitEnforcer for ")
}

fn rejection_findings(path: &Path, source: &str) -> Vec<String> {
    let (production, tests) = source.split_once("#[cfg(test)]").unwrap_or((source, ""));
    if !checks_a_limit(production) || tests_a_refusing_limit(tests) {
        return Vec::new();
    }
    vec![format!(
        "{}: checks a plan limit but no test makes it refuse",
        path.display()
    )]
}

#[cfg_attr(test, test)]
pub(crate) fn free_functions_sit_below_the_use_case_in_order() {
    let findings: Vec<String> = use_case_files()
        .iter()
        .flat_map(|path| layout_findings(path, &production_source(path)))
        .collect();

    assert!(
        findings.is_empty(),
        "use-case layout:\n{}",
        findings.join("\n")
    );
}

#[cfg_attr(test, test)]
pub(crate) fn commands_save_before_they_record() {
    let findings: Vec<String> = use_case_files()
        .iter()
        .flat_map(|path| order_findings(path, &production_source(path)))
        .collect();

    assert!(
        findings.is_empty(),
        "save, then record:\n{}",
        findings.join("\n")
    );
}

#[cfg_attr(test, test)]
pub(crate) fn every_ports_struct_derives_fakes() {
    let findings: Vec<String> = use_case_files()
        .iter()
        .flat_map(|path| fakes_findings(path, &production_source(path)))
        .collect();

    assert!(
        findings.is_empty(),
        "ports without fakes():\n{}",
        findings.join("\n")
    );
}

#[cfg_attr(test, test)]
pub(crate) fn every_plan_limit_is_enforced_by_a_use_case() {
    if crate::conventions::app::source::some_use_cases_switched_off() {
        return;
    }
    let sources: Vec<String> = use_case_files()
        .iter()
        .map(|path| production_source(path))
        .collect();

    let missing = unenforced(&resource_kinds(), &sources);

    assert!(
        missing.is_empty(),
        "plan limits no use case checks: {}",
        missing.join(", ")
    );
}

#[cfg_attr(test, test)]
pub(crate) fn every_limit_check_has_a_rejection_test() {
    let findings: Vec<String> = use_case_files()
        .iter()
        .flat_map(|path| {
            let source = fs::read_to_string(path).expect("a use case file is readable");
            rejection_findings(path, &source)
        })
        .collect();

    assert!(
        findings.is_empty(),
        "limit checks without a rejection test:\n{}",
        findings.join("\n")
    );
}

#[cfg_attr(test, test)]
pub(crate) fn the_resource_kinds_are_read_from_the_limits_port() {
    let kinds = resource_kinds();

    assert!(kinds.contains(&"Users".to_owned()));
    assert!(kinds.contains(&"Groups".to_owned()));
}

#[cfg_attr(test, test)]
pub(crate) fn a_limit_no_use_case_names_is_found() {
    let kinds = vec!["Groups".to_owned(), "Widgets".to_owned()];
    let sources = vec!["check(ResourceKind::Groups)".to_owned()];

    assert_eq!(unenforced(&kinds, &sources), vec!["Widgets".to_owned()]);
}

#[cfg_attr(test, test)]
pub(crate) fn a_limit_check_without_a_refusing_test_is_found() {
    let source = "x.check_tenant_limit(a, b, ResourceKind::Groups);\n#[cfg(test)]\nmod tests {}\n";

    let findings = rejection_findings(Path::new("x.rs"), source);

    assert_eq!(findings.len(), 1);
}

#[cfg_attr(test, test)]
pub(crate) fn a_limit_check_with_a_refusing_test_passes() {
    let source =
        "x.check_tenant_limit(a, b, k);\n#[cfg(test)]\nmod tests { RejectingLimitEnforcer }\n";

    let findings = rejection_findings(Path::new("x.rs"), source);

    assert!(findings.is_empty());
}

#[cfg_attr(test, test)]
pub(crate) fn a_ports_struct_without_the_derive_is_found() {
    let source = "/// Ports.\n#[derive(Clone)]\npub struct XPorts {\n}\n";

    let findings = fakes_findings(Path::new("x.rs"), source);

    assert_eq!(findings.len(), 1);
}

#[cfg_attr(test, test)]
pub(crate) fn a_ports_struct_with_the_derive_passes() {
    let source =
        "/// Ports.\n#[derive(ianua_macros::Fakes)]\n#[derive(Clone)]\npub struct XPorts {\n}\n";

    let findings = fakes_findings(Path::new("x.rs"), source);

    assert!(findings.is_empty());
}

#[cfg_attr(test, test)]
pub(crate) fn a_free_function_above_the_use_case_is_found() {
    let source = "fn helper() {}\n\nimpl Command for X {\n}\n";

    let findings = layout_findings(Path::new("x.rs"), source);

    assert_eq!(findings.len(), 1);
}

#[cfg_attr(test, test)]
pub(crate) fn an_event_builder_before_a_check_is_found() {
    let source = "impl Query for X {\n}\n\nfn x_event() {}\n\nfn ensure_y() {}\n";

    let findings = layout_findings(Path::new("x.rs"), source);

    assert_eq!(findings.len(), 1);
}

#[cfg_attr(test, test)]
pub(crate) fn a_record_before_the_save_is_found() {
    let source = "impl Command for X {\n    async fn execute() {\n        auditor.dispatch(&[e]);\n        store.save(&x);\n    }\n}\n";

    let findings = order_findings(Path::new("x.rs"), source);

    assert_eq!(findings.len(), 1);
}
