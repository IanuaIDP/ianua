//! The domain's source, parsed as Rust, and the places in it the
//! conventions read.

use std::collections::BTreeSet;
use std::fmt::Display;
use std::fs;
use std::path::{Path, PathBuf};

use proc_macro2::TokenStream;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Block, Expr, ExprAssign, ExprIf, ExprMethodCall, Field, Fields, File, Ident,
    ImplItem, ImplItemFn, Item, ItemEnum, ItemFn, ItemImpl, ItemMacro, ItemStruct, ItemUse,
    Signature, TraitItemFn, Type, UseTree,
};

/// One domain source file, read and parsed.
pub(crate) struct SourceFile {
    /// The path below `src/`.
    pub path: String,
    text: String,
    syntax: File,
}

impl SourceFile {
    fn read(path: &Path) -> Self {
        let text = fs::read_to_string(path).expect("a domain file is readable");
        let syntax = syn::parse_file(&text)
            .unwrap_or_else(|error| panic!("{} does not parse: {error}", path.display()));
        Self {
            path: relative(path),
            text,
            syntax,
        }
    }

    fn without_tests(mut self) -> Self {
        strip_tests(&mut self.syntax.items);
        self
    }

    /// Every place in the file the conventions look at.
    pub(crate) fn inventory(&self) -> Inventory<'_> {
        let mut inventory = Inventory::default();
        inventory.visit_file(&self.syntax);
        inventory
    }

    /// The text a node was written as, with each line trimmed and the
    /// lines joined, so a chain split over lines reads as one.
    pub(crate) fn text_of(&self, node: &impl Spanned) -> String {
        node.span()
            .source_text()
            .expect("a parsed node has its source text")
            .lines()
            .map(str::trim)
            .collect()
    }

    /// The file's lines, the first at index 0.
    pub(crate) fn lines(&self) -> Vec<&str> {
        self.text.lines().collect()
    }

    /// The file's top-level items, as parsed.
    pub(crate) fn items(&self) -> &[Item] {
        &self.syntax.items
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
}

fn source_root() -> PathBuf {
    crate::conventions::crate_dir("ianua-domain").join("src")
}

fn relative(path: &Path) -> String {
    path.strip_prefix(source_root())
        .expect("a file under the source root")
        .display()
        .to_string()
}

fn rust_files() -> Vec<PathBuf> {
    let mut pending = vec![source_root()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("the source folder is readable") {
            let path = entry.expect("a directory entry").path();
            match path.extension() {
                _ if path.is_dir() => pending.push(path),
                Some(ext) if ext == "rs" => files.push(path),
                _ => {}
            }
        }
    }
    files.sort();
    files
}

/// Every domain file, test modules and test support included.
pub(crate) fn every_file() -> Vec<SourceFile> {
    rust_files()
        .iter()
        .map(|path| SourceFile::read(path))
        .collect()
}

/// The domain as it builds outside tests: no test-support files, and no
/// item compiled only for tests.
pub(crate) fn production_files() -> Vec<SourceFile> {
    rust_files()
        .iter()
        .map(|path| SourceFile::read(path))
        .filter(|file| !file.path.starts_with("test_support"))
        .map(SourceFile::without_tests)
        .collect()
}

/// The file written to break every convention once, read as if it were a
/// domain file at `domains/planted.rs`. It sits beside these checks as
/// text, so it is parsed here and never compiled, nor read as a crate's
/// source.
pub(crate) fn planted_file() -> SourceFile {
    let path = crate::conventions::own_file("domain/planted.rs.txt");
    let text = fs::read_to_string(&path).expect("the planted file is readable");
    let syntax = syn::parse_file(&text).expect("the planted file parses");
    SourceFile {
        path: "domains/planted.rs".to_owned(),
        text,
        syntax,
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

/// Whether a token stream names `name` anywhere, nested groups included.
pub(crate) fn tokens_name(tokens: &TokenStream, name: &str) -> bool {
    tokens.clone().into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(ident) => ident == name,
        proc_macro2::TokenTree::Group(group) => tokens_name(&group.stream(), name),
        _ => false,
    })
}

/// The 1-based line a node starts on.
pub(crate) fn line_of(node: &impl Spanned) -> usize {
    node.span().start().line
}

/// A path written as its segments joined by `::`, without generics.
pub(crate) fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// The last segment of a type written as a path, e.g. `Uuid` for
/// `uuid::Uuid`.
pub(crate) fn type_name(ty: &Type) -> Option<&Ident> {
    let Type::Path(path) = ty else {
        return None;
    };
    path.path.segments.last().map(|segment| &segment.ident)
}

/// The `T` of an `Option<T>`.
pub(crate) fn option_of(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let last = path.path.segments.last()?;
    let syn::PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return None;
    };
    let Some(syn::GenericArgument::Type(inner)) = arguments.args.first() else {
        return None;
    };
    (last.ident == "Option").then_some(inner)
}

/// Whether a type is `name`, or `Option<name>`.
pub(crate) fn is_or_maybe(ty: &Type, name: &str) -> bool {
    let inner = option_of(ty).unwrap_or(ty);
    type_name(inner).is_some_and(|ident| ident == name)
}

/// Whether a type names `name` anywhere in it, e.g. `String` in
/// `Vec<String>`.
pub(crate) fn type_mentions(ty: &Type, name: &str) -> bool {
    let mut paths = Paths::default();
    paths.visit_type(ty);
    paths
        .found
        .iter()
        .any(|path| path.segments.iter().any(|segment| segment.ident == name))
}

/// The first name each `use` brings in from, e.g. `tokio` for
/// `use tokio::sync::Mutex;`.
pub(crate) fn use_roots(tree: &UseTree) -> Vec<&Ident> {
    match tree {
        UseTree::Path(path) => vec![&path.ident],
        UseTree::Name(name) => vec![&name.ident],
        UseTree::Rename(rename) => vec![&rename.ident],
        UseTree::Group(group) => group.items.iter().flat_map(use_roots).collect(),
        UseTree::Glob(_) => Vec::new(),
    }
}

/// Every path written inside a node.
#[derive(Default)]
struct Paths<'ast> {
    found: Vec<&'ast syn::Path>,
}

impl<'ast> Visit<'ast> for Paths<'ast> {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.found.push(path);
        visit::visit_path(self, path);
    }
}

/// Every path written in a block, as text.
pub(crate) fn paths_in(block: &Block) -> Vec<String> {
    let mut paths = Paths::default();
    paths.visit_block(block);
    paths.found.into_iter().map(path_text).collect()
}

/// Whether code reports a validation failure: it names
/// `DomainError::Validation` or a `ValidationError`.
fn refuses<'ast>(visit_with: impl FnOnce(&mut Paths<'ast>)) -> bool {
    let mut paths = Paths::default();
    visit_with(&mut paths);
    paths.found.iter().any(|path| {
        path.segments
            .iter()
            .any(|segment| segment.ident == "Validation" || segment.ident == "ValidationError")
    })
}

/// A function with a body: free, in an impl, or a trait's default.
pub(crate) struct Function<'ast> {
    /// Its signature.
    pub signature: &'ast Signature,
    /// Its body.
    pub body: &'ast Block,
    /// Whether it is `pub` (any form).
    pub public: bool,
    /// Whether it is plain `pub`, reachable from outside the crate when
    /// its module is. A trait's default counts as such.
    pub exported: bool,
}

/// A field and the struct or enum that declares it.
pub(crate) struct DeclaredField<'ast> {
    /// The struct or enum.
    pub owner: &'ast Ident,
    /// The field's name; a tuple variant's field goes by its variant's
    /// name, with its position after a `.` when the variant has several.
    pub name: String,
    /// The field.
    pub field: &'ast Field,
}

/// What a tuple variant's field goes by: the variant's name, with the
/// field's position when there are several.
fn tuple_field_name(variant: &Ident, position: usize, count: usize) -> String {
    if count == 1 {
        return variant.to_string();
    }
    format!("{variant}.{position}")
}

/// A condition that decides whether input is refused, with whether the
/// code it guards refuses with a validation error.
pub(crate) struct Guard<'ast> {
    /// The condition.
    pub test: &'ast Expr,
    /// Whether the guarded code reports a validation failure.
    pub refuses: bool,
    /// Whether it sits in an `impl Rule for` block, where a format check
    /// particular to one type belongs.
    pub in_a_rule: bool,
}

/// Every place in a file the conventions look at.
#[derive(Default)]
pub(crate) struct Inventory<'ast> {
    /// Functions with bodies.
    pub functions: Vec<Function<'ast>>,
    /// Struct declarations.
    pub structs: Vec<&'ast ItemStruct>,
    /// Named fields of structs, and every field of enum variants.
    pub fields: Vec<DeclaredField<'ast>>,
    /// Impl blocks.
    pub impls: Vec<&'ast ItemImpl>,
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
    /// Assignments.
    pub assignments: Vec<&'ast ExprAssign>,
    /// Conditions that guard a refusal, or might.
    pub guards: Vec<Guard<'ast>>,
    in_a_rule: bool,
}

impl<'ast> Inventory<'ast> {
    fn add_named_fields(&mut self, owner: &'ast Ident, fields: &'ast Fields) {
        let Fields::Named(named) = fields else {
            return;
        };
        self.fields.extend(named.named.iter().map(|field| {
            DeclaredField {
                owner,
                name: field
                    .ident
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                field,
            }
        }));
    }

    fn add_variant_fields(&mut self, owner: &'ast Ident, variant: &'ast syn::Variant) {
        let Fields::Unnamed(unnamed) = &variant.fields else {
            return self.add_named_fields(owner, &variant.fields);
        };
        let count = unnamed.unnamed.len();
        self.fields
            .extend(
                unnamed
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(position, field)| DeclaredField {
                        owner,
                        name: tuple_field_name(&variant.ident, position, count),
                        field,
                    }),
            );
    }

    fn add_guard(&mut self, test: &'ast Expr, refuses: bool) {
        self.guards.push(Guard {
            test,
            refuses,
            in_a_rule: self.in_a_rule,
        });
    }
}

impl<'ast> Visit<'ast> for Inventory<'ast> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.functions.push(Function {
            signature: &item.sig,
            body: &item.block,
            public: !matches!(item.vis, syn::Visibility::Inherited),
            exported: matches!(item.vis, syn::Visibility::Public(_)),
        });
        visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.functions.push(Function {
            signature: &item.sig,
            body: &item.block,
            public: !matches!(item.vis, syn::Visibility::Inherited),
            exported: matches!(item.vis, syn::Visibility::Public(_)),
        });
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        if let Some(body) = &item.default {
            self.functions.push(Function {
                signature: &item.sig,
                body,
                public: true,
                exported: true,
            });
        }
        visit::visit_trait_item_fn(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        self.impls.push(item);
        let outer = self.in_a_rule;
        self.in_a_rule = item
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .is_some_and(|segment| segment.ident == "Rule");
        visit::visit_item_impl(self, item);
        self.in_a_rule = outer;
    }

    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        self.structs.push(item);
        self.add_named_fields(&item.ident, &item.fields);
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast ItemEnum) {
        for variant in &item.variants {
            self.add_variant_fields(&item.ident, variant);
        }
        visit::visit_item_enum(self, item);
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
        let refused = refuses(|paths| paths.visit_block(&expr.then_branch));
        self.add_guard(&expr.cond, refused);
        visit::visit_expr_if(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        if expr.method == "then" || expr.method == "then_some" {
            let refused = refuses(|paths| expr.args.iter().for_each(|arg| paths.visit_expr(arg)));
            self.add_guard(&expr.receiver, refused);
        }
        visit::visit_expr_method_call(self, expr);
    }

    fn visit_arm(&mut self, arm: &'ast Arm) {
        if let Some((_, guard)) = &arm.guard {
            let refused = refuses(|paths| paths.visit_expr(&arm.body));
            self.add_guard(guard, refused);
        }
        visit::visit_arm(self, arm);
    }

    fn visit_expr_assign(&mut self, expr: &'ast ExprAssign) {
        self.assignments.push(expr);
        visit::visit_expr_assign(self, expr);
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

/// What a convention found, one line per place.
#[derive(Default)]
pub(crate) struct Findings {
    found: Vec<String>,
}

impl Findings {
    /// Records a finding at the line a node starts on.
    pub(crate) fn flag(&mut self, file: &SourceFile, at: &impl Spanned, message: impl Display) {
        self.flag_line(file, line_of(at), message);
    }

    /// Records a finding at a 1-based line.
    pub(crate) fn flag_line(&mut self, file: &SourceFile, line: usize, message: impl Display) {
        self.found.push(format!("{}:{line}: {message}", file.path));
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
