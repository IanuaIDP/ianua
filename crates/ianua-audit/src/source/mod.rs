//! The workspace's source files, read from disk and parsed where they parse.
//!
//! Only `src/` of each crate is read, as it builds outside tests: test
//! modules, `test_support` folders and modules switched off with
//! `#[cfg(any())]` are left out. A file that does not parse is kept as text
//! and reported, so a crate that does not build is still read as far as it
//! can be.

pub(crate) mod syntax;
pub(crate) mod usage;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use syn::{Attribute, File, ImplItem, Item};

use crate::source::syntax::line_of;
use crate::source::usage::Usage;

/// The crates read as adapters: everything that implements a port, wires
/// ports into use cases or drives a use case from outside.
const ADAPTER_CRATES: &[&str] = &[
    "ianua-api",
    "ianua-assembly",
    "ianua-infra",
    "ianua-server",
    "ianua-ldap",
    "ianua-zero",
    "ianua-grpc",
    "ianua-dns",
];

/// Where a crate sits in the hexagon.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Layer {
    /// `ianua-domain`.
    Domain,
    /// `ianua-app`.
    App,
    /// A crate that implements ports or drives use cases.
    Adapter,
}

impl Layer {
    /// The layer a crate folder belongs to, if it is read at all.
    fn of_crate(name: &str) -> Option<Self> {
        match name {
            "ianua-domain" => Some(Self::Domain),
            "ianua-app" => Some(Self::App),
            _ if ADAPTER_CRATES.contains(&name) => Some(Self::Adapter),
            _ => None,
        }
    }
}

/// Why a file could not be parsed as Rust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParseFailure {
    /// The 1-based line the parser stopped at.
    pub(crate) line: usize,
    /// What the parser said.
    pub(crate) message: String,
}

impl ParseFailure {
    /// Where `error` stopped the parser, and what it said.
    fn of(error: &syn::Error) -> Self {
        Self {
            line: error.span().start().line,
            message: error.to_string(),
        }
    }
}

/// One source file, as it builds outside tests.
pub(crate) struct SourceFile {
    /// The crate's folder name, such as `ianua-app`.
    pub(crate) crate_name: String,
    /// Where the crate sits.
    pub(crate) layer: Layer,
    /// The path below the crate's `src/`.
    pub(crate) path: String,
    syntax: Option<File>,
    failure: Option<ParseFailure>,
    usage: Usage,
    test_usage: Usage,
    tests: Option<File>,
    unbuilt: Vec<String>,
    for_tests: Vec<String>,
}

impl SourceFile {
    /// A file read from `text`, test items removed.
    pub(crate) fn new(crate_name: &str, layer: Layer, path: &str, text: &str) -> Self {
        let (syntax, failure, unbuilt, tests) = match syn::parse_file(text) {
            Ok(mut parsed) => {
                let unbuilt = unbuilt_modules(path, &parsed.items, never_built);
                let tests = test_items(&parsed);
                strip_tests(&mut parsed.items);
                (Some(parsed), None, unbuilt, Some(tests))
            }
            Err(error) => (None, Some(ParseFailure::of(&error)), Vec::new(), None),
        };
        let for_tests = tests
            .as_ref()
            .map(|tests| unbuilt_modules(path, &tests.items, compiled_only_for_tests))
            .unwrap_or_default();
        let test_usage = tests.as_ref().map(Usage::of_file).unwrap_or_default();
        let usage = syntax
            .as_ref()
            .map_or_else(|| Usage::of_text(text), Usage::of_file);
        Self {
            crate_name: crate_name.to_owned(),
            layer,
            path: path.to_owned(),
            syntax,
            failure,
            usage,
            test_usage,
            tests,
            unbuilt,
            for_tests,
        }
    }

    /// The file's own `#[cfg(test)]` items, as a file of their own, when it
    /// parses.
    pub(crate) fn test_syntax(&self) -> Option<&File> {
        self.tests.as_ref()
    }

    /// What the file's own `#[cfg(test)]` items name and call: its unit
    /// tests.
    pub(crate) fn test_usage(&self) -> &Usage {
        &self.test_usage
    }

    /// The module path of the file below its crate root, such as
    /// `["use_cases", "webhooks", "lookup"]` for `use_cases/webhooks/lookup.rs`.
    pub(crate) fn module_path(&self) -> Vec<String> {
        let trimmed = self.path.trim_end_matches(".rs");
        let mut parts: Vec<String> = trimmed.split('/').map(str::to_owned).collect();
        if matches!(
            parts.last().map(String::as_str),
            Some("mod" | "lib" | "main")
        ) {
            parts.pop();
        }
        parts
    }

    /// The path from the workspace root, such as
    /// `crates/ianua-app/src/lib.rs`.
    pub(crate) fn display_path(&self) -> String {
        format!("crates/{}/src/{}", self.crate_name, self.path)
    }

    /// The parsed file without its test items, when it parses.
    pub(crate) fn syntax(&self) -> Option<&File> {
        self.syntax.as_ref()
    }

    /// Why the file did not parse, when it did not.
    pub(crate) fn failure(&self) -> Option<&ParseFailure> {
        self.failure.as_ref()
    }

    /// What the file names and calls outside its tests.
    pub(crate) fn usage(&self) -> &Usage {
        &self.usage
    }
}

/// The top-level items of `parsed` built only for tests, as a file of
/// their own.
fn test_items(parsed: &File) -> File {
    File {
        shebang: None,
        attrs: Vec::new(),
        items: parsed
            .items
            .iter()
            .filter(|item| compiled_only_for_tests(item_attributes(item)))
            .cloned()
            .collect(),
    }
}

/// The modules declared in `items` of the file at `path` that `unbuilt`
/// says are not built, such as those switched off with `#[cfg(any())]` or
/// built only for tests. Each
/// is given as the path below `src/` its file or folder would have,
/// without `.rs`.
fn unbuilt_modules(path: &str, items: &[Item], unbuilt: fn(&[Attribute]) -> bool) -> Vec<String> {
    let parent = child_module_dir(path);
    items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.content.is_none() && unbuilt(&module.attrs) => {
                Some(format!("{parent}{}", module.ident))
            }
            _ => None,
        })
        .collect()
}

/// The folder (below `src/`, with a trailing `/` unless empty) that holds
/// the files of modules the file at `path` declares.
fn child_module_dir(path: &str) -> String {
    let (dir, file) = path.rsplit_once('/').unwrap_or(("", path));
    let prefix = match dir {
        "" => String::new(),
        dir => format!("{dir}/"),
    };
    match file {
        "mod.rs" | "lib.rs" | "main.rs" => prefix,
        _ => format!("{prefix}{}/", file.trim_end_matches(".rs")),
    }
}

/// Crates read only for their tests: they hold no production code.
const TEST_CRATES: &[&str] = &["ianua-scenarios"];

/// What a file built only for tests holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SupportKind {
    /// A `test_support` file: fakes and fixtures other tests use.
    Fake,
    /// A file under a crate's `tests/`.
    Test,
}

/// A file built only for tests, read whole: a `test_support` file of a
/// crate's `src/`, or a file under its `tests/`.
pub(crate) struct SupportFile {
    /// The crate's folder name.
    pub(crate) crate_name: String,
    /// The path below the crate's folder, such as
    /// `src/test_support/webhooks.rs` or `tests/api/webhooks.rs`.
    pub(crate) path: String,
    /// What it holds.
    pub(crate) kind: SupportKind,
    syntax: Option<File>,
    usage: Usage,
}

impl SupportFile {
    /// A support file read from `text`, tests kept.
    pub(crate) fn new(crate_name: &str, path: &str, kind: SupportKind, text: &str) -> Self {
        let syntax = syn::parse_file(text).ok();
        let usage = syntax
            .as_ref()
            .map_or_else(|| Usage::of_text(text), Usage::of_file);
        Self {
            crate_name: crate_name.to_owned(),
            path: path.to_owned(),
            kind,
            syntax,
            usage,
        }
    }

    /// The path from the workspace root.
    pub(crate) fn display_path(&self) -> String {
        format!("crates/{}/{}", self.crate_name, self.path)
    }

    /// The parsed file, when it parses.
    pub(crate) fn syntax(&self) -> Option<&File> {
        self.syntax.as_ref()
    }

    /// What the file names and calls.
    pub(crate) fn usage(&self) -> &Usage {
        &self.usage
    }
}

/// Every file the audit reads.
pub(crate) struct Workspace {
    /// The files, sorted by crate and path.
    pub(crate) files: Vec<SourceFile>,
    /// Files built only for tests, which the checks leave out and `impact`
    /// reads.
    pub(crate) support: Vec<SupportFile>,
    /// The files of `src/` modules built only for tests, such as a
    /// `#[cfg(test)] mod fixtures;`: test code throughout.
    pub(crate) for_tests: Vec<SourceFile>,
}

impl Workspace {
    /// Reads every crate under `root/crates` that sits in a layer, with the
    /// test files of those crates and of the test-only crates.
    ///
    /// # Errors
    ///
    /// Fails when `root/crates` or a file in it cannot be read.
    pub(crate) fn load(root: &Path) -> Result<Self> {
        let mut files = Vec::new();
        let mut support = Vec::new();
        let mut for_tests = Vec::new();
        for dir in crate_dirs(root)? {
            let name = (dir.file_name())
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
            if TEST_CRATES.contains(&name.as_str()) {
                support.extend(read_support(&name, &dir, SupportKind::Test, "tests")?);
                continue;
            }
            let Some(layer) = Layer::of_crate(&name) else {
                continue;
            };
            let (built, tests_only) = without_unbuilt(read_crate(&name, layer, &dir.join("src"))?);
            files.extend(built);
            for_tests.extend(tests_only);
            support.extend(read_support(&name, &dir, SupportKind::Fake, "src")?);
            support.extend(read_support(&name, &dir, SupportKind::Test, "tests")?);
        }
        Ok(Self {
            files,
            support,
            for_tests,
        })
    }

    /// Every test the workspace holds, as parsed files: the `#[cfg(test)]`
    /// items of each file, the files of modules built only for tests, and
    /// the parsed support files.
    pub(crate) fn tests(&self) -> impl Iterator<Item = &File> {
        let inline = self.files.iter().filter_map(SourceFile::test_syntax);
        let modules = self
            .for_tests
            .iter()
            .flat_map(|file| file.syntax().into_iter().chain(file.test_syntax()));
        let support = self.support.iter().filter_map(SupportFile::syntax);
        inline.chain(modules).chain(support)
    }

    /// The files of one layer.
    pub(crate) fn layer(&self, layer: Layer) -> impl Iterator<Item = &SourceFile> {
        self.files.iter().filter(move |file| file.layer == layer)
    }
}

/// Every built file of one crate.
/// The crate folders under `root/crates`, in order.
fn crate_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let crates_dir = root.join("crates");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&crates_dir)
        .with_context(|| format!("reading {}", crates_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    Ok(dirs)
}

fn read_crate(name: &str, layer: Layer, src: &Path) -> Result<Vec<SourceFile>> {
    let mut paths = Vec::new();
    collect_rust_files(src, &mut paths)?;
    paths.sort();
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let relative = path
            .strip_prefix(src)
            .map(|relative| relative.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if relative.split('/').any(|part| part == "test_support") {
            continue;
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        files.push(SourceFile::new(name, layer, &relative, &text));
    }
    Ok(files)
}

/// The files of `kind` below `dir/folder`: every file under `tests/`, and
/// under `src/` only those in a `test_support` folder.
fn read_support(
    name: &str,
    dir: &Path,
    kind: SupportKind,
    folder: &str,
) -> Result<Vec<SupportFile>> {
    let mut paths = Vec::new();
    collect_rust_files(&dir.join(folder), &mut paths)?;
    paths.sort();
    let mut found = Vec::new();
    for path in paths {
        let relative = path
            .strip_prefix(dir)
            .map(|relative| relative.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let wanted =
            kind == SupportKind::Test || relative.split('/').any(|part| part == "test_support");
        if !wanted {
            continue;
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        found.push(SupportFile::new(name, &relative, kind, &text));
    }
    Ok(found)
}

fn collect_rust_files(dir: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries {
        let path = entry
            .with_context(|| format!("listing {}", dir.display()))?
            .path();
        match path.extension() {
            _ if path.is_dir() => collect_rust_files(&path, found)?,
            Some(extension) if extension == "rs" => found.push(path),
            _ => {}
        }
    }
    Ok(())
}

/// `files` without those that belong to a module that is never built, and
/// apart from them those of a module built only for tests.
fn without_unbuilt(files: Vec<SourceFile>) -> (Vec<SourceFile>, Vec<SourceFile>) {
    let modules = |pick: fn(&SourceFile) -> &Vec<String>| -> Vec<(String, String)> {
        files
            .iter()
            .flat_map(|file| {
                pick(file)
                    .iter()
                    .map(|module| (file.crate_name.clone(), module.clone()))
            })
            .collect()
    };
    let unbuilt = modules(|file| &file.unbuilt);
    let for_tests = modules(|file| &file.for_tests);
    let (gone, built): (Vec<SourceFile>, Vec<SourceFile>) = files
        .into_iter()
        .partition(|file| belongs_to(file, &unbuilt));
    let tests_only = gone
        .into_iter()
        .filter(|file| belongs_to(file, &for_tests))
        .collect();
    (built, tests_only)
}

/// Whether `file` is the file or below the folder of one of `modules`, by
/// crate.
fn belongs_to(file: &SourceFile, modules: &[(String, String)]) -> bool {
    let module = file.path.trim_end_matches(".rs");
    modules.iter().any(|(crate_name, gone)| {
        *crate_name == file.crate_name
            && (module == gone || file.path.starts_with(&format!("{gone}/")))
    })
}

/// Whether a module declared with `attributes` is never part of the
/// production build.
fn never_built(attributes: &[Attribute]) -> bool {
    compiled_only_for_tests(attributes) || switched_off(attributes)
}

/// Whether the attributes hold `#[cfg(any())]`, which is never true.
fn switched_off(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string().replace(' ', "") == "any()")
    })
}

/// Whether an item is built only for tests: `#[cfg(test)]` or
/// `#[cfg(all(test, ..))]`.
fn compiled_only_for_tests(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        let Ok(list) = attribute.meta.require_list() else {
            return false;
        };
        let condition = list.tokens.to_string();
        attribute.path().is_ident("cfg")
            && (condition == "test" || condition.starts_with("all (test"))
    })
}

fn strip_tests(items: &mut Vec<Item>) {
    items.retain(|item| !never_built(item_attributes(item)));
    items.iter_mut().for_each(strip_tests_inside);
}

fn strip_tests_inside(item: &mut Item) {
    match item {
        Item::Mod(module) => {
            if let Some((_, inner)) = &mut module.content {
                strip_tests(inner);
            }
        }
        Item::Impl(block) => block
            .items
            .retain(|inner| !never_built(impl_item_attributes(inner))),
        _ => {}
    }
}

fn item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(inner) => &inner.attrs,
        Item::Enum(inner) => &inner.attrs,
        Item::Fn(inner) => &inner.attrs,
        Item::Impl(inner) => &inner.attrs,
        Item::Macro(inner) => &inner.attrs,
        Item::Mod(inner) => &inner.attrs,
        Item::Static(inner) => &inner.attrs,
        Item::Struct(inner) => &inner.attrs,
        Item::Trait(inner) => &inner.attrs,
        Item::Type(inner) => &inner.attrs,
        Item::Use(inner) => &inner.attrs,
        _ => &[],
    }
}

fn impl_item_attributes(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(inner) => &inner.attrs,
        ImplItem::Fn(inner) => &inner.attrs,
        ImplItem::Type(inner) => &inner.attrs,
        _ => &[],
    }
}

/// Where something sits: a file from the workspace root and a 1-based line,
/// or `0` for the whole file.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub(crate) struct Place {
    /// The path from the workspace root.
    pub(crate) file: String,
    /// The 1-based line, `0` for the whole file.
    pub(crate) line: usize,
}

impl Place {
    /// The line `node` starts on in `file`.
    pub(crate) fn of(file: &SourceFile, node: &impl syn::spanned::Spanned) -> Self {
        Self::at(file, line_of(node))
    }

    /// A 1-based line of `file`.
    pub(crate) fn at(file: &SourceFile, line: usize) -> Self {
        Self {
            file: file.display_path(),
            line,
        }
    }
}

#[cfg(test)]
pub(crate) mod planted {
    //! Files made up for tests.

    use super::{Layer, SourceFile, SupportFile, SupportKind, Workspace, without_unbuilt};

    /// A `test_support` file of `crate_name` at `path` below the crate.
    pub(crate) fn fake(crate_name: &str, path: &str, text: &str) -> SupportFile {
        SupportFile::new(crate_name, path, SupportKind::Fake, text)
    }

    /// A file under `tests/` of `crate_name` at `path` below the crate.
    pub(crate) fn test(crate_name: &str, path: &str, text: &str) -> SupportFile {
        SupportFile::new(crate_name, path, SupportKind::Test, text)
    }

    /// A workspace of `files` and the test files `support`.
    pub(crate) fn with_support(files: Vec<SourceFile>, support: Vec<SupportFile>) -> Workspace {
        let (files, for_tests) = without_unbuilt(files);
        Workspace {
            files,
            support,
            for_tests,
        }
    }

    /// A domain file at `path` below `src/`.
    pub(crate) fn domain(path: &str, text: &str) -> SourceFile {
        SourceFile::new("ianua-domain", Layer::Domain, path, text)
    }

    /// An app file at `path` below `src/`.
    pub(crate) fn app(path: &str, text: &str) -> SourceFile {
        SourceFile::new("ianua-app", Layer::App, path, text)
    }

    /// A file of the adapter crate `crate_name` at `path` below `src/`.
    pub(crate) fn adapter(crate_name: &str, path: &str, text: &str) -> SourceFile {
        SourceFile::new(crate_name, Layer::Adapter, path, text)
    }

    /// A workspace of `files`, without those of modules never built.
    pub(crate) fn workspace(files: Vec<SourceFile>) -> Workspace {
        with_support(files, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::planted::{app, workspace};

    #[test]
    fn test_modules_are_left_out_of_the_syntax() {
        let file = app(
            "lib.rs",
            "pub fn shipped() {}\n#[cfg(test)]\nmod tests { fn hidden() {} }\n",
        );

        let usage = file.usage();

        assert!(usage.idents.contains_key("shipped"));
        assert!(!usage.idents.contains_key("hidden"));
    }

    #[test]
    fn a_module_switched_off_drops_its_files() {
        let ws = workspace(vec![
            app(
                "use_cases/mod.rs",
                "#[cfg(any())]\npub mod old;\npub mod new;\n",
            ),
            app("use_cases/old/thing.rs", "pub fn old() {}"),
            app("use_cases/new.rs", "pub fn new() {}"),
        ]);

        let paths: Vec<&str> = ws.files.iter().map(|file| file.path.as_str()).collect();

        assert_eq!(paths, ["use_cases/mod.rs", "use_cases/new.rs"]);
    }

    #[test]
    fn a_files_unit_tests_are_read_apart() {
        let file = app(
            "lib.rs",
            "pub fn shipped() {}\n#[cfg(test)]\nmod tests { fn checks() { FakeStore::new(); } }\n",
        );

        let tests = file.test_usage();

        assert!(tests.idents.contains_key("FakeStore"));
        assert!(!tests.idents.contains_key("shipped"));
    }

    #[test]
    fn a_files_module_path_drops_mod_and_the_extension() {
        let leaf = app("use_cases/webhooks/lookup.rs", "");
        let folder = app("services/limits/mod.rs", "");

        assert_eq!(leaf.module_path(), ["use_cases", "webhooks", "lookup"]);
        assert_eq!(folder.module_path(), ["services", "limits"]);
    }

    #[test]
    fn a_file_that_does_not_parse_is_kept_with_its_failure() {
        let file = app("broken.rs", "pub fn broken( {}\nfn named_later() {}\n");

        assert!(file.syntax().is_none());
        assert!(file.failure().is_some());
        assert!(file.usage().idents.contains_key("named_later"));
    }
}
