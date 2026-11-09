//! The app's source, read as text and parsed as Rust, without the areas
//! still switched off.

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

/// One source file of the app crate.
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
        let text = fs::read_to_string(path).expect("an app file is readable");
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

    /// The `impl Command` and `impl Query` blocks outside the tests.
    pub(crate) fn use_case_impls(&self) -> Vec<syn::ItemImpl> {
        let Ok(parsed) = syn::parse_file(self.code()) else {
            return Vec::new();
        };
        parsed
            .items
            .into_iter()
            .filter_map(|item| match item {
                Item::Impl(block) if implements_a_use_case(&block) => Some(block),
                _ => None,
            })
            .collect()
    }

    /// The `type Caller` each use case in the file names.
    pub(crate) fn callers(&self) -> Vec<String> {
        self.use_case_impls()
            .iter()
            .flat_map(|block| block.items.iter())
            .filter_map(|item| match item {
                ImplItem::Type(alias) if alias.ident == "Caller" => last_segment(&alias.ty),
                _ => None,
            })
            .collect()
    }
}

/// Whether `block` implements `Command` or `Query`.
fn implements_a_use_case(block: &syn::ItemImpl) -> bool {
    block
        .trait_
        .as_ref()
        .and_then(|(_, path, _)| path.segments.last())
        .is_some_and(|segment| segment.ident == "Command" || segment.ident == "Query")
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
    crate::conventions::crate_dir("ianua-app").join("src")
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default()
}

/// Every source file of the app, test modules and test support included,
/// without the modules switched off with `#[cfg(any())]` while they are
/// moved to the new domain.
pub(crate) fn app_files() -> Vec<SourceFile> {
    let root = source_root();
    let skipped = switched_off(&root);
    let mut files = Vec::new();
    collect(&root, &root, &skipped, &mut files);
    files
}

/// The app as it builds outside tests: no test-support files, and no item
/// compiled only for tests.
pub(crate) fn production_files() -> Vec<SourceFile> {
    app_files()
        .into_iter()
        .filter(|file| !file.path.starts_with("test_support"))
        .map(SourceFile::without_tests)
        .collect()
}

/// Everything the app builds outside its tests, test support included: the
/// code a person reads and keeps, whoever compiles it.
pub(crate) fn built_files() -> Vec<SourceFile> {
    app_files()
        .into_iter()
        .map(SourceFile::without_tests)
        .collect()
}

/// The port files checked now: those of a use case context that is switched
/// on (a file, or every file in a folder, named after it), the planted ones,
/// and every port once no context is off.
pub(crate) fn checked_port_files(files: &[SourceFile]) -> Vec<String> {
    let all_on = !some_use_cases_switched_off();
    let contexts_on: Vec<String> = files
        .iter()
        .filter_map(|file| file.path.strip_prefix("use_cases/"))
        .filter_map(|rest| rest.split('/').next())
        .map(|context| context.trim_end_matches(".rs").to_owned())
        .collect();
    files
        .iter()
        .filter(|file| {
            let Some(stem) = file.path.strip_prefix("ports/") else {
                return false;
            };
            let stem = stem
                .split('/')
                .next()
                .unwrap_or(stem)
                .trim_end_matches(".rs");
            all_on || stem == "planted" || contexts_on.iter().any(|context| context == stem)
        })
        .map(|file| file.path.clone())
        .collect()
}

/// Whether some use case contexts are still switched off. A check over all
/// of them waits until none is.
pub(crate) fn some_use_cases_switched_off() -> bool {
    switched_off(&source_root())
        .iter()
        .any(|module| module.starts_with("use_cases/"))
}

/// The paths under `src/` of modules switched off in `lib.rs`,
/// `use_cases/mod.rs`, `test_support/mod.rs` and `services/mod.rs`.
fn switched_off(root: &Path) -> Vec<String> {
    [
        ("lib.rs", ""),
        ("use_cases/mod.rs", "use_cases/"),
        ("test_support/mod.rs", "test_support/"),
        ("services/mod.rs", "services/"),
    ]
    .iter()
    .flat_map(|(file, prefix)| {
        let text = fs::read_to_string(root.join(file)).unwrap_or_default();
        gated_modules(&text)
            .into_iter()
            .map(move |name| format!("{prefix}{name}"))
    })
    .collect()
}

/// The modules in `text` declared right under `#[cfg(any())]`.
fn gated_modules(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    lines
        .windows(2)
        .filter(|pair| pair[0] == "#[cfg(any())]")
        .filter_map(|pair| {
            pair[1]
                .strip_prefix("pub mod ")
                .or_else(|| pair[1].strip_prefix("pub(crate) mod "))
                .or_else(|| pair[1].strip_prefix("mod "))
                .map(|rest| rest.trim_end_matches(';').to_owned())
        })
        .collect()
}

fn collect(root: &Path, dir: &Path, skipped: &[String], files: &mut Vec<SourceFile>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        let relative = relative(root, &path);
        let module = relative.trim_end_matches(".rs");
        let gone = skipped
            .iter()
            .any(|gone| module == gone || relative.starts_with(&format!("{gone}/")));
        if gone {
            continue;
        }
        if path.is_dir() {
            collect(root, &path, skipped, files);
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
