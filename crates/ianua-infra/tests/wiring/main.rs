//! The wiring graph: what each port is, what implements it, and what uses
//! it, read from the code and kept current by these tests.
//!
//! - **What is left to build may only shrink.** `unbuilt.snapshot` lists the
//!   ports nothing implements yet. A new port without an adapter fails, and
//!   so does a port that gained one but is still listed. During the infra
//!   rebuild the list is the progress report; at the end it is empty.
//! - **No port nobody uses.** A port no use case, service or API state
//!   holds is dead and is removed, unless it was built ahead of its user
//!   and is listed with the step that will use it.
//!
//! Current graph reports come from `ianua-audit graph <context>`.

mod graph;
mod sources;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use graph::Graph;

/// Ports built ahead of their first user, each with the step that will use
/// it. The list only shrinks.
const UNUSED_FOR_NOW: &[(&str, &str)] = &[];

/// Where a kept file of this test lives.
fn kept(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/wiring")
        .join(name)
}

fn writing() -> bool {
    std::env::var_os("IANUA_WRITE_GRAPH").is_some()
}

/// The ports listed as not built yet.
fn listed_unbuilt() -> BTreeSet<String> {
    fs::read_to_string(kept("unbuilt.snapshot"))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every port without an adapter is listed, and every listed port still
/// has none: the list of what is left to build only shrinks, and only on
/// purpose.
#[test]
fn what_is_left_to_build_is_the_list_kept() {
    let graph = Graph::read();
    let unbuilt: BTreeSet<String> = graph.unbuilt().into_iter().map(str::to_owned).collect();
    if writing() {
        let text: String = unbuilt.iter().map(|port| format!("{port}\n")).collect();
        fs::write(kept("unbuilt.snapshot"), text).expect("the snapshot is writable");
        return;
    }
    let listed = listed_unbuilt();
    let new_without_adapter: Vec<&String> = unbuilt.difference(&listed).collect();
    let built_but_listed: Vec<&String> = listed.difference(&unbuilt).collect();
    assert!(
        new_without_adapter.is_empty() && built_but_listed.is_empty(),
        "ports without an adapter that are not listed: {new_without_adapter:?}\n\
         ports built but still listed: {built_but_listed:?}\n\
         build the adapter, or run again with IANUA_WRITE_GRAPH=1 once the change is meant"
    );
}

/// Unused ports match the explicitly deferred list exactly; an unlisted unused
/// port or a listed port that has gained a caller fails the check.
#[test]
fn every_port_is_used() {
    let graph = Graph::read();
    let listed: BTreeSet<&str> = UNUSED_FOR_NOW.iter().map(|(port, _)| *port).collect();

    let unused = graph.unused();

    let unlisted: Vec<&&str> = unused.difference(&listed).collect();
    let used_but_listed: Vec<&&str> = listed.difference(&unused).collect();
    assert!(
        unlisted.is_empty() && used_but_listed.is_empty(),
        "ports nothing uses: {unlisted:?}\nports used but still listed as unused: {used_but_listed:?}"
    );
}
