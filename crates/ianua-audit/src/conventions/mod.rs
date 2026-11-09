//! The house rules each layer's code is written to, checked on its source:
//! the domain's, the application's, the adapters' and the API's, and the
//! integration crates', which keep the adapters' style.
//!
//! Each check reads files and stops on the first rule it finds broken,
//! naming the file and what is wrong. `ianua-audit check` runs every one,
//! catches a stop as a broken rule, and reports them all, failing when any
//! is broken. Each check is also a test of this tool, so `cargo test`
//! still runs them, together with the planted breaks that show each check
//! finds what it exists to find.

pub(crate) mod api;
pub(crate) mod app;
pub(crate) mod domain;
pub(crate) mod infra;
pub(crate) mod integrations;
pub(crate) mod plain;
mod registry;

use std::num::NonZeroUsize;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::thread;

/// The workspace the checks read, set once by `ianua-audit check`; tests
/// read the workspace this tool sits in.
static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// One check: the layer whose rules it holds, its name, and the code that
/// stops when its rule is broken.
pub(crate) struct Check {
    /// `domain`, `app`, `infra`, `api`, `integrations` or `plain`.
    pub(crate) layer: &'static str,
    /// What it holds, as its function is named.
    pub(crate) name: &'static str,
    /// Runs it; it stops with a message when its rule is broken.
    pub(crate) run: fn(),
}

/// A check whose rule is broken, with what it said.
pub(crate) struct Broken {
    /// The check.
    pub(crate) check: &'static Check,
    /// What it said, naming the files and what is wrong.
    pub(crate) said: String,
}

/// Reads the workspace at `root` from now on.
pub(crate) fn read_from(root: &Path) {
    let _ = ROOT.set(root.to_path_buf());
}

/// The folder of the workspace crate `name`.
pub(crate) fn crate_dir(name: &str) -> PathBuf {
    workspace().join("crates").join(name)
}

/// The folder holding the integration crates, beside `crates/`.
pub(crate) fn integrations_dir() -> PathBuf {
    workspace().join("integrations")
}

/// The file `rest` beside these checks, such as a snapshot they compare
/// against.
pub(crate) fn own_file(rest: &str) -> PathBuf {
    crate_dir("ianua-audit").join("src/conventions").join(rest)
}

/// The workspace root: the one set, or the one this tool was built in.
pub(crate) fn workspace() -> PathBuf {
    ROOT.get().cloned().unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .to_path_buf()
    })
}

/// Every check whose layer starts with one of `layers`, or all when none
/// is named.
pub(crate) fn chosen(layers: &[String]) -> Vec<&'static Check> {
    registry::CHECKS
        .iter()
        .filter(|check| {
            layers.is_empty()
                || layers
                    .iter()
                    .any(|layer| check.layer.starts_with(layer.as_str()))
        })
        .collect()
}

/// Runs `checks` side by side on every core, keeping quiet while they
/// run, and answers those whose rule is broken, in the order given.
pub(crate) fn broken(checks: &[&'static Check]) -> Vec<Broken> {
    let quiet = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let next = AtomicUsize::new(0);
    let outcomes: Mutex<Vec<(usize, Broken)>> = Mutex::new(Vec::new());
    let workers = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(check) = checks.get(index) else {
                        break;
                    };
                    let Some(found) = stopped(check) else {
                        continue;
                    };
                    outcomes
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((index, found));
                }
            });
        }
    });
    panic::set_hook(quiet);
    let mut found = outcomes
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    found.sort_by_key(|(index, _)| *index);
    found.into_iter().map(|(_, broken)| broken).collect()
}

/// `check` as broken, with what it said, when it stopped.
fn stopped(check: &'static Check) -> Option<Broken> {
    let outcome = panic::catch_unwind(AssertUnwindSafe(check.run));
    let stopped = outcome.err()?;
    Some(Broken {
        check,
        said: said(stopped.as_ref()),
    })
}

/// What a stopped check said.
fn said(stopped: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = stopped.downcast_ref::<String>() {
        return text.clone();
    }
    if let Some(text) = stopped.downcast_ref::<&str>() {
        return (*text).to_owned();
    }
    "the check stopped without saying why".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every check is listed once, under a layer it belongs to.
    #[test]
    fn every_check_is_listed_once() {
        let mut names: Vec<String> = registry::CHECKS
            .iter()
            .map(|check| format!("{}::{}", check.layer, check.name))
            .collect();
        let listed = names.len();
        names.sort();
        names.dedup();

        assert_eq!(names.len(), listed);
        assert!(registry::CHECKS.iter().all(|check| {
            ["domain", "app", "infra", "api", "integrations", "plain"].contains(&check.layer)
        }));
    }

    /// A check that stops is reported broken with what it said, and one
    /// that returns is not reported.
    #[test]
    fn a_stopped_check_is_reported_with_what_it_said() {
        static HOLDS: Check = Check {
            layer: "api",
            name: "holds",
            run: || {},
        };
        static BREAKS: Check = Check {
            layer: "api",
            name: "breaks",
            run: || panic!("files too long: planted.rs"),
        };

        let found = broken(&[&HOLDS, &BREAKS]);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].check.name, "breaks");
        assert_eq!(found[0].said, "files too long: planted.rs");
    }
}
