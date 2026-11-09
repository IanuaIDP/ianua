//! The Rust source the wiring graph is read from: the app's ports and use
//! cases, the API's state, and every crate that implements a port.

use std::fs;
use std::path::{Path, PathBuf};

use syn::{Attribute, File, Item};

/// One parsed source file, with the crate and path it came from.
pub(crate) struct Source {
    /// The crate's folder name, such as `ianua-infra`.
    pub crate_name: &'static str,
    /// The path under the crate's `src/`.
    pub path: String,
    /// Its top-level items, with test-only modules left out.
    pub items: Vec<Item>,
}

/// The crates whose source the graph reads: every crate that implements a
/// port or holds one, the gateway, the servers and the worker included.
/// The end-to-end tests and the old infra in `legacy/` are left out.
pub(crate) const CRATES: &[&str] = &[
    "ianua-app",
    "ianua-api",
    "ianua-infra",
    "ianua-server",
    "ianua-zero",
    "ianua-ldap",
    "ianua-dns",
    "ianua-grpc",
    "ianua-audit",
];

/// Every non-test source file of `crate_name`.
pub(crate) fn sources_of(crate_name: &'static str) -> Vec<Source> {
    let root = crates_dir().join(crate_name).join("src");
    let mut found = Vec::new();
    collect(&root, &root, crate_name, &mut found);
    found
}

/// Locates the sibling crates this wiring test inspects.
// Cargo supplies the manifest path of this workspace member under crates/.
#[allow(clippy::expect_used)]
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the infra crate sits in the crates folder")
        .to_path_buf()
}

fn collect(root: &Path, dir: &Path, crate_name: &'static str, found: &mut Vec<Source>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .map(|part| part.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if relative.starts_with("test_support") {
            continue;
        }
        if path.is_dir() {
            collect(root, &path, crate_name, found);
            continue;
        }
        if let Some(source) = parsed(&path, crate_name, relative) {
            found.push(source);
        }
    }
}

fn parsed(path: &Path, crate_name: &'static str, relative: String) -> Option<Source> {
    if path.extension().is_none_or(|ext| ext != "rs") {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let file: File = syn::parse_file(&text).ok()?;
    let items = file
        .items
        .into_iter()
        .filter(|item| !only_for_tests(item))
        .collect();
    Some(Source {
        crate_name,
        path: relative,
        items,
    })
}

/// Whether `item` is built only for tests.
fn only_for_tests(item: &Item) -> bool {
    let attributes: &[Attribute] = match item {
        Item::Mod(inner) => &inner.attrs,
        Item::Impl(inner) => &inner.attrs,
        Item::Fn(inner) => &inner.attrs,
        Item::Struct(inner) => &inner.attrs,
        _ => &[],
    };
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string().starts_with("test"))
    })
}
