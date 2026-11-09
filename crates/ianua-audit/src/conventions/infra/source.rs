//! The infra crate's source, read as text and parsed as Rust.

use std::collections::BTreeSet;
use std::fmt::Display;
use std::fs;
use std::path::{Path, PathBuf};

use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Block, ExprIf, File, Ident, ImplItem, ImplItemFn, Item, ItemFn, ItemMacro, ItemUse,
    Signature, TraitItemFn, UseTree,
};

/// One source file of the infra crate.
pub(crate) struct SourceFile {
    /// Its path under `src/`.
    pub path: String,
    text: String,
    syntax: Option<File>,
}

impl SourceFile {
    /// A file made up for a test, at `path`, holding `text`. A text that is
    /// not a whole Rust file is still read as text.
    pub(crate) fn planted(path: &str, text: &str) -> Self {
        Self {
            path: path.to_owned(),
            text: text.to_owned(),
            syntax: syn::parse_file(text).ok(),
        }
    }

    fn read(root: &Path, path: &Path) -> Self {
        let text = fs::read_to_string(path).expect("an infra file is readable");
        let syntax = syn::parse_file(&text)
            .unwrap_or_else(|error| panic!("{} does not parse: {error}", path.display()));
        Self {
            path: relative(root, path),
            text,
            syntax: Some(syntax),
        }
    }

    fn without_tests(mut self) -> Self {
        if let Some(syntax) = &mut self.syntax {
            strip_tests(&mut syntax.items);
        }
        self
    }

    /// The code before the file's test module.
    pub(crate) fn code(&self) -> &str {
        self.text
            .find("#[cfg(test)]")
            .map_or(self.text.as_str(), |at| &self.text[..at])
    }

    /// The file's test module and what follows it, or nothing when it has
    /// none.
    pub(crate) fn tests(&self) -> &str {
        self.text
            .find("#[cfg(test)]")
            .map_or("", |at| &self.text[at..])
    }

    /// The file's lines, the first at index 0.
    pub(crate) fn lines(&self) -> Vec<&str> {
        self.text.lines().collect()
    }

    /// The lines before the file's test module, the first at index 0: the
    /// part of the file that builds outside tests.
    pub(crate) fn lines_before_tests(&self) -> Vec<&str> {
        let lines = self.lines();
        let start = lines
            .windows(2)
            .position(|pair| {
                pair[0] == "#[cfg(test)]"
                    && (pair[1].starts_with("mod ") || pair[1].starts_with("pub(crate) mod "))
            })
            .unwrap_or(lines.len());
        lines[..start].to_vec()
    }

    /// The file's top-level items, as parsed.
    pub(crate) fn items(&self) -> &[Item] {
        self.syntax.as_ref().map_or(&[], |syntax| &syntax.items)
    }

    /// Every place in the file the conventions look at.
    pub(crate) fn inventory(&self) -> Inventory<'_> {
        let mut inventory = Inventory::default();
        if let Some(syntax) = &self.syntax {
            inventory.visit_file(syntax);
        }
        inventory
    }

    /// The `impl Trait for Type` blocks outside the tests, as the trait's
    /// last name and the type's last name.
    pub(crate) fn trait_impls(&self) -> Vec<(String, String, usize)> {
        let Ok(parsed) = syn::parse_file(self.code()) else {
            return Vec::new();
        };
        parsed
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Impl(block) => implemented(block),
                _ => None,
            })
            .collect()
    }
}

/// The trait and type an `impl Trait for Type` block names, with its line.
fn implemented(block: &syn::ItemImpl) -> Option<(String, String, usize)> {
    let (_, path, _) = block.trait_.as_ref()?;
    let trait_name = path.segments.last()?.ident.to_string();
    let type_name = last_segment(&block.self_ty)?;
    Some((trait_name, type_name, line_of(block)))
}

/// The last name of a path type, such as `UserId` for `types::UserId`.
fn last_segment(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

/// A function with a body.
pub(crate) struct Function<'ast> {
    /// Its signature.
    pub signature: &'ast Signature,
    /// Its body.
    pub body: &'ast Block,
}

/// Every place in a file the conventions look at.
#[derive(Default)]
pub(crate) struct Inventory<'ast> {
    /// Functions with bodies.
    pub functions: Vec<Function<'ast>>,
    /// Macro invocations at item level.
    pub item_macros: Vec<&'ast ItemMacro>,
    /// Attributes.
    pub attributes: Vec<&'ast Attribute>,
    /// `use` declarations.
    pub uses: Vec<&'ast ItemUse>,
    /// Paths written anywhere.
    pub paths: Vec<&'ast syn::Path>,
    /// `if` expressions.
    pub ifs: Vec<&'ast ExprIf>,
}

impl<'ast> Visit<'ast> for Inventory<'ast> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.functions.push(Function {
            signature: &item.sig,
            body: &item.block,
        });
        visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.functions.push(Function {
            signature: &item.sig,
            body: &item.block,
        });
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        if let Some(body) = &item.default {
            self.functions.push(Function {
                signature: &item.sig,
                body,
            });
        }
        visit::visit_trait_item_fn(self, item);
    }

    fn visit_item_macro(&mut self, item: &'ast ItemMacro) {
        self.item_macros.push(item);
        visit::visit_item_macro(self, item);
    }

    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        self.attributes.push(attribute);
        visit::visit_attribute(self, attribute);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.uses.push(item);
        visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.paths.push(path);
        visit::visit_path(self, path);
    }

    fn visit_expr_if(&mut self, expr: &'ast ExprIf) {
        self.ifs.push(expr);
        visit::visit_expr_if(self, expr);
    }
}

/// The lines (1-based) inside function bodies, braces excluded, and the
/// indented lines inside item macros, whose functions the parser does not
/// see.
pub(crate) fn body_lines(file: &SourceFile, inventory: &Inventory<'_>) -> BTreeSet<usize> {
    let lines = file.lines();
    let in_functions = inventory.functions.iter().flat_map(|function| {
        let span = function.body.span();
        span.start().line + 1..span.end().line
    });
    let in_macros = inventory.item_macros.iter().flat_map(|item| {
        let span = item.span();
        (span.start().line..=span.end().line).filter(|line| {
            let text = lines[line - 1];
            text.len() - text.trim_start().len() >= 8
        })
    });
    in_functions.chain(in_macros).collect()
}

/// The first names of a `use` tree, such as `crate` in `crate::ports::X`.
pub(crate) fn use_roots(tree: &UseTree) -> Vec<&Ident> {
    match tree {
        UseTree::Path(path) => vec![&path.ident],
        UseTree::Name(name) => vec![&name.ident],
        UseTree::Rename(rename) => vec![&rename.ident],
        UseTree::Group(group) => group.items.iter().flat_map(use_roots).collect(),
        UseTree::Glob(_) => Vec::new(),
    }
}

/// The 1-based line a node starts on.
pub(crate) fn line_of(node: &impl Spanned) -> usize {
    node.span().start().line
}

/// A convention, run over some files.
pub(crate) type Check = fn(&[SourceFile]) -> Findings;

/// What a convention found, one line per place.
#[derive(Default)]
pub(crate) struct Findings {
    found: Vec<String>,
}

impl Findings {
    /// Records a finding about a whole file.
    pub(crate) fn flag_file(&mut self, file: &SourceFile, message: impl Display) {
        self.found.push(format!("{}: {message}", file.path));
    }

    /// Records a finding at the line a node starts on.
    pub(crate) fn flag(&mut self, file: &SourceFile, at: &impl Spanned, message: impl Display) {
        self.flag_line(file, line_of(at), message);
    }

    /// Records a finding at a 1-based line.
    pub(crate) fn flag_line(&mut self, file: &SourceFile, line: usize, message: impl Display) {
        self.flag_at(&file.path, line, message);
    }

    /// Records a finding at a 1-based line of the file at `path` under
    /// `src/`.
    pub(crate) fn flag_at(&mut self, path: &str, line: usize, message: impl Display) {
        self.found.push(format!("{path}:{line}: {message}"));
    }

    /// Adds what `other` found.
    pub(crate) fn extend(&mut self, other: Findings) {
        self.found.extend(other.found);
    }

    /// Every finding, one line each, in the order found.
    pub(crate) fn lines(&self) -> &[String] {
        &self.found
    }

    /// Whether nothing was found.
    pub(crate) fn is_empty(&self) -> bool {
        self.found.is_empty()
    }

    /// Fails the test, listing every finding, unless there are none.
    pub(crate) fn assert_none(&self, rule: &str) {
        assert!(self.found.is_empty(), "{rule}:\n{}", self.found.join("\n"));
    }
}

fn source_root() -> PathBuf {
    crate::conventions::crate_dir("ianua-infra").join("src")
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default()
}

/// Every source file of the infra crate, test modules and test support
/// included.
pub(crate) fn infra_files() -> Vec<SourceFile> {
    let root = source_root();
    let mut files = Vec::new();
    collect(&root, &root, &mut files);
    files
}

/// The source files at `paths`, files or folders under the `src/` of the
/// sibling crate `name`, each path led by the crate's name, for a rule the
/// crates building on the infra's adapters keep with it.
pub(crate) fn sibling_files(name: &str, paths: &[&str]) -> Vec<SourceFile> {
    let root = crate::conventions::crate_dir("ianua-infra")
        .join("..")
        .join(name)
        .join("src");
    let mut files = Vec::new();
    for path in paths {
        let at = root.join(path);
        match at.is_dir() {
            true => collect(&root, &at, &mut files),
            false => files.push(SourceFile::read(&root, &at)),
        }
    }
    files
        .into_iter()
        .map(|mut file| {
            file.path = format!("{name}/{}", file.path);
            file
        })
        .collect()
}

/// Every source file of every crate under `crates/` and `integrations/`,
/// each path led by its crate's folder, such as `ianua-app/src/lib.rs`,
/// for the rules every crate keeps.
pub(crate) fn workspace_files() -> Vec<SourceFile> {
    let crates = crate::conventions::crate_dir("ianua-infra").join("..");
    let mut files = Vec::new();
    for root in [crates, crate::conventions::integrations_dir()] {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        let mut sources: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path().join("src"))
            .filter(|src| src.is_dir())
            .collect();
        sources.sort();
        for src in sources {
            collect(&root, &src, &mut files);
        }
    }
    files
}

/// Every source file of every crate's own test, bench and example targets,
/// each path led by its crate's folder, such as `ianua-app/tests/x.rs`,
/// and of the workspace's fuzz targets: the code that reaches a crate only
/// through what it makes public.
pub(crate) fn workspace_target_files() -> Vec<SourceFile> {
    let crates = crate::conventions::crate_dir("ianua-infra").join("..");
    let mut files = Vec::new();
    for root in [crates, crate::conventions::integrations_dir()] {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        let mut targets: Vec<PathBuf> = entries
            .flatten()
            .flat_map(|entry| ["tests", "benches", "examples"].map(|kind| entry.path().join(kind)))
            .filter(|target| target.is_dir())
            .collect();
        targets.sort();
        for target in targets {
            collect(&root, &target, &mut files);
        }
    }
    let workspace = crate::conventions::workspace();
    collect(&workspace, &workspace.join("fuzz"), &mut files);
    files
}

/// The workspace's code that ships: no test-support files, and no item
/// compiled only for tests.
pub(crate) fn workspace_production_files() -> Vec<SourceFile> {
    workspace_files()
        .into_iter()
        .filter(|file| !file.path.contains("/test_support"))
        .map(SourceFile::without_tests)
        .collect()
}

/// The infra as it builds outside tests: no test-support files, and no item
/// compiled only for tests.
pub(crate) fn production_files() -> Vec<SourceFile> {
    infra_files()
        .into_iter()
        .filter(|file| !file.path.starts_with("test_support"))
        .map(SourceFile::without_tests)
        .collect()
}

/// Every source file of every integration crate under `integrations/`,
/// test modules included, each path led by its crate's folder, such as
/// `github/src/lib.rs`.
pub(crate) fn integration_files() -> Vec<SourceFile> {
    let root = crate::conventions::integrations_dir();
    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut crates: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path().join("src"))
        .filter(|src| src.is_dir())
        .collect();
    crates.sort();
    let mut files = Vec::new();
    for src in crates {
        collect(&root, &src, &mut files);
    }
    files
}

/// The integration crates' code that ships: their test modules left out.
pub(crate) fn integration_production_files() -> Vec<SourceFile> {
    integration_files()
        .into_iter()
        .map(SourceFile::without_tests)
        .collect()
}

/// The folders under `src/`, each with the modules it holds: a file, or a
/// folder, with a file and the folder of its submodules counted as one.
pub(crate) fn folders() -> Vec<(String, usize)> {
    let root = source_root();
    let mut found = Vec::new();
    count_entries(&root, &root, &mut found);
    found
}

fn count_entries(root: &Path, dir: &Path, found: &mut Vec<(String, usize)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    let held = paths
        .iter()
        .filter(|path| path.is_dir() || path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| path.file_name().is_none_or(|name| name != "mod.rs"))
        .filter(|path| !(path.is_dir() && path.with_extension("rs").is_file()))
        .count();
    found.push((relative(root, dir), held));
    paths
        .iter()
        .filter(|path| path.is_dir())
        .for_each(|path| count_entries(root, path, found));
}

fn collect(root: &Path, dir: &Path, files: &mut Vec<SourceFile>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        let relative = relative(root, &path);
        if path.is_dir() {
            collect(root, &path, files);
            continue;
        }
        if relative.ends_with(".rs") {
            files.push(SourceFile::read(root, &path));
        }
    }
}

fn strip_tests(items: &mut Vec<Item>) {
    items.retain(|item| !compiled_only_for_tests(item_attributes(item)));
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
            .retain(|inner| !compiled_only_for_tests(impl_item_attributes(inner))),
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

/// Whether an item is built only for tests: `#[cfg(test)]` or
/// `#[cfg(all(test, ..))]`. An item also built for the `test-support`
/// feature ships to other crates, so it counts as production.
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
