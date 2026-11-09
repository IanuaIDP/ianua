//! Every name on the bus server and the cache server sits under the
//! deployment's namespace, so two deployments sharing both servers never
//! hear each other's events or count each other's keys.
//!
//! - **One place applies it.** Subjects, stream names and cache keys are
//!   written relative to the namespace, such as `tenant.<id>.<type>` or
//!   `rate:tenant:<id>`, and only `namespace.rs` puts them under it, through
//!   the bus server's and the cache server's adapters. A subject or key
//!   written with the platform's own prefix in it, such as
//!   `"ianua.tenant.>"`, `"ianua:rate"` or the `"ianua-events"` stream,
//!   would reach the server outside the namespace, or twice inside it, so
//!   none is written anywhere else: in the infra's bus, cache, outbox and
//!   inbox, the tenant database follower, the worker's consumers and the
//!   gateway's follower and fleet.

use crate::conventions::infra::source::{Findings, SourceFile, production_files, sibling_files};

/// The one file that puts a name under the namespace.
const NAMESPACE_FILE: &str = "namespace.rs";

/// The infra's folders and files that build bus subjects, stream names or
/// cache keys.
const INFRA_NAMERS: &[&str] = &[
    "bus/",
    "cache/",
    "outbox/",
    "inbox/",
    "postgres/tenant/databases/follower.rs",
];

/// The other crates' folders and files that name bus subjects.
const SIBLING_NAMERS: &[(&str, &[&str])] = &[
    ("ianua-server", &["worker", "worker.rs"]),
    ("ianua-zero", &["follow", "follow.rs", "fleet", "fleet.rs"]),
];

/// The literals that write the platform's own prefix into a name: a
/// subject, a key, or one of the streams.
const PREFIXED: &[&str] = &[
    "\"ianua.",
    "\"ianua:",
    "format!(\"ianua",
    "\"ianua-events",
    "\"ianua-messages",
    "\"ianua-dead-letters",
];

/// Lines outside the namespace's own file, before the tests, that write a
/// name with the platform's prefix in it.
pub(crate) fn names_outside_the_namespace(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files.iter().filter(|file| file.path != NAMESPACE_FILE) {
        for (index, line) in file.lines_before_tests().iter().enumerate() {
            if !is_comment(line) && PREFIXED.iter().any(|prefix| line.contains(prefix)) {
                findings.flag_line(
                    file,
                    index + 1,
                    "writes a bus subject, stream or cache key with the platform's prefix; write it relative to the namespace, which the bus and cache servers apply",
                );
            }
        }
    }
    findings
}

/// The files that build names: the infra's and its siblings'.
fn namers() -> Vec<SourceFile> {
    let infra = production_files().into_iter().filter(|file| {
        INFRA_NAMERS
            .iter()
            .any(|namer| file.path.starts_with(namer))
    });
    let siblings = SIBLING_NAMERS
        .iter()
        .flat_map(|(name, paths)| sibling_files(name, paths));
    infra.chain(siblings).collect()
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// A file writing the platform's prefix into a subject, a stream and a key.
const PLANTED: &str = r#"
const TENANT_EVENTS: &str = "ianua.tenant.>";
const STREAM: &str = "ianua-events";
fn key(parts: &[&str]) -> String {
    format!("ianua:{}", parts.join(":"))
}
"#;

/// Stops: a subject, a stream or a key written with the platform's
/// prefix, which a deployment under another namespace would still share
/// with every other on the same server.
#[cfg_attr(test, test)]
pub(crate) fn every_name_goes_through_the_namespace() {
    names_outside_the_namespace(&namers()).assert_none("names outside the namespace");
}

/// The check reads the files it is meant to: the infra's bus and cache,
/// the worker's consumers and the gateway's fleet.
#[cfg_attr(test, test)]
pub(crate) fn the_namers_are_read() {
    let paths: Vec<String> = namers().into_iter().map(|file| file.path).collect();

    for expected in [
        "bus/envelope.rs",
        "cache/state/mod.rs",
        "ianua-server/worker/consumers.rs",
        "ianua-zero/fleet.rs",
    ] {
        assert!(
            paths.iter().any(|path| path == expected),
            "{expected} is not read"
        );
    }
}

/// The check finds each break planted for it, and leaves the namespace's
/// own file alone.
#[cfg_attr(test, test)]
pub(crate) fn the_namespace_check_finds_its_planted_breaks() {
    let planted = [SourceFile::planted("bus/planted.rs", PLANTED)];
    let own = [SourceFile::planted(NAMESPACE_FILE, PLANTED)];

    let found = names_outside_the_namespace(&planted);

    assert!(!found.is_empty());
    assert!(names_outside_the_namespace(&own).is_empty());
}
