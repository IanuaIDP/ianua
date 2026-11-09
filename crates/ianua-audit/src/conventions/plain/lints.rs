//! The compiler's share of these rules.
//!
//! Function length, the number of inputs, `unwrap` outside tests, a
//! needless `pub`, an `else` after a return and the plain forms of borrowing
//! and closures are checked by the compiler's own lints, set once in the
//! workspace's `[workspace.lints]` with their limits in `clippy.toml`. Every
//! crate takes them with `[lints] workspace = true`; a crate without it
//! slips past all of them.

use std::fs;

use crate::conventions::infra::source::Findings;
use crate::conventions::workspace;

/// Crates whose code is generated or whose manifest a tool rewrites.
const LEFT_OUT: &[&str] = &["ianua-proto", "ianua-workspace-hack"];

/// A crate's manifest: where it is, and what it says.
pub(crate) struct Manifest {
    /// The manifest's path in the workspace, such as `crates/ianua-app/Cargo.toml`.
    pub path: String,
    /// The manifest's text.
    pub text: String,
}

/// Every crate manifest under `crates/` and `integrations/`, but those
/// left out.
pub(crate) fn manifests() -> Vec<Manifest> {
    let mut found = Vec::new();
    for folder in ["crates", "integrations"] {
        let Ok(entries) = fs::read_dir(workspace().join(folder)) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(text) = fs::read_to_string(entry.path().join("Cargo.toml")) else {
                continue;
            };
            if !LEFT_OUT.contains(&name.as_str()) {
                found.push(Manifest {
                    path: format!("{folder}/{name}/Cargo.toml"),
                    text,
                });
            }
        }
    }
    found.sort_by(|left, right| left.path.cmp(&right.path));
    found
}

/// Every manifest among `manifests` that does not take the workspace's
/// lints.
pub(crate) fn crates_without_shared_lints(manifests: &[Manifest]) -> Findings {
    let mut found = Findings::default();
    for manifest in manifests {
        if !manifest.text.contains("[lints]\nworkspace = true") {
            found.flag_at(
                &manifest.path,
                1,
                "takes no shared lints; add `[lints]` with `workspace = true`",
            );
        }
    }
    found
}
