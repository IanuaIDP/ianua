//! The code style infra shares with the domain and the app, checked the
//! same way they check their own.
//!
//! - No comment inside a function body: code that needs one is rewritten.
//! - No `if` directly inside another: flatten it or extract a function.
//! - Every `allow` or `expect` says why in a comment above it.
//! - A file keeps one test module, at its end, and no `// ──` dividers.
//! - No em dash anywhere: a sentence that needs one reads better split, or
//!   with a comma or a colon.
//! - A file holds at most [`MAX_CODE_LINES`] lines of code before its tests.
//! - Imports name their source from `crate::`, at the top of a module, and
//!   name what they take: no `super::` but a test module's `use super::*;`,
//!   no `super::super::`, no glob but a folder re-exporting its parts, no
//!   `use` inside a function, and no import the file does not use itself.
//! - No function takes a `bool`; a call `f(x, true)` says nothing about
//!   what `true` chose.
//! - Every test says in a doc comment, in plain words, what it shows: the
//!   behaviour, or for a refusal, what it stops (`Stops: ...`).

use std::collections::BTreeSet;

use syn::{Expr, Item, Stmt, UseTree, Visibility};

use crate::conventions::infra::source::{
    Check, Findings, SourceFile, body_lines, infra_files, line_of, production_files, use_roots,
};

/// Traits a file imports only to call their methods, so their name appears
/// nowhere else in it: the file (`*` for any), the trait, and why.
const TRAITS_IMPORTED_FOR_METHODS: &[(&str, &str, &str)] = &[];

/// The most lines of code a file holds before its tests, comments and
/// blank lines left out. A file past it holds more than one topic.
const MAX_CODE_LINES: usize = 550;

/// Whether a line is a comment of its own, not a doc comment.
fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("// ") || trimmed == "//"
}

/// Comments inside function bodies.
pub(crate) fn comments_in_function_bodies(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let inventory = file.inventory();
        let lines = file.lines();
        for line in body_lines(file, &inventory) {
            if is_comment(lines[line - 1]) {
                findings.flag_line(file, line, "comment inside a function body");
            }
        }
    }
    findings
}

/// Whether the lines directly above line `line` (1-based), through other
/// attributes and comments, include a comment that explains.
fn explained_above(lines: &[&str], line: usize) -> bool {
    lines[..line - 1]
        .iter()
        .rev()
        .map(|l| l.trim_start())
        .take_while(|l| l.starts_with("//") || l.starts_with("#["))
        .any(|l| l.starts_with("// ") || l.starts_with("/// "))
}

/// `allow` and `expect` attributes with no comment saying why.
pub(crate) fn unexplained_allows(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let lines = file.lines();
        for attribute in file.inventory().attributes {
            let silences =
                attribute.path().is_ident("allow") || attribute.path().is_ident("expect");
            if silences && !explained_above(&lines, line_of(attribute)) {
                findings.flag(file, attribute, "an `allow` without a comment saying why");
            }
        }
    }
    findings
}

/// Whether a condition opens with `let`, as `if let` and let chains do.
fn opens_with_let(condition: &Expr) -> bool {
    match condition {
        Expr::Let(_) => true,
        Expr::Binary(binary) => opens_with_let(&binary.left),
        _ => false,
    }
}

/// The blocks an `if` runs: its own, and a plain `else` block.
fn branches(expr: &syn::ExprIf) -> Vec<&syn::Block> {
    let otherwise = expr
        .else_branch
        .as_ref()
        .and_then(|(_, other)| match other.as_ref() {
            Expr::Block(block) => Some(&block.block),
            _ => None,
        });
    std::iter::once(&expr.then_branch)
        .chain(otherwise)
        .collect()
}

/// An `if` written directly inside another.
pub(crate) fn nested_ifs(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for outer in file.inventory().ifs {
            let nested = branches(outer)
                .into_iter()
                .flat_map(|block| &block.stmts)
                .filter_map(|stmt| match stmt {
                    Stmt::Expr(Expr::If(inner), _) => Some(inner),
                    _ => None,
                })
                .filter(|inner| !opens_with_let(&inner.cond));
            for inner in nested {
                findings.flag(
                    file,
                    inner,
                    "an `if` inside another; flatten it or extract a function",
                );
            }
        }
    }
    findings
}

/// Whether an item is the file's `#[cfg(test)]` module.
fn is_test_module(item: &Item) -> bool {
    let Item::Mod(module) = item else {
        return false;
    };
    module.attrs.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .parse_args::<syn::Ident>()
                .is_ok_and(|condition| condition == "test")
    })
}

/// A test module anywhere but last, or a second one.
pub(crate) fn misplaced_test_modules(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let items = file.items();
        let tests: Vec<usize> = (0..items.len())
            .filter(|index| is_test_module(&items[*index]))
            .collect();
        if tests.len() > 1 {
            findings.flag(
                file,
                &items[tests[1]],
                "a second test module; keep one, at the end",
            );
        }
        let Some(first) = tests.first() else {
            continue;
        };
        if *first + 1 != items.len() && tests.len() == 1 {
            findings.flag(
                file,
                &items[*first],
                "the test module is not the last item in the file",
            );
        }
    }
    findings
}

/// `// ──` dividers splitting a file into sections, in tests too: a file
/// that needs sections holds more than one thing.
pub(crate) fn divider_comments(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (index, line) in file.lines().iter().enumerate() {
            if line.trim_start().starts_with("// ──") {
                findings.flag_line(file, index + 1, "a section divider; split the file instead");
            }
        }
    }
    findings
}

/// Em dashes, in docs, comments or text alike.
pub(crate) fn em_dashes(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (index, line) in file.lines().iter().enumerate() {
            if line.contains('\u{2014}') {
                findings.flag_line(
                    file,
                    index + 1,
                    "an em dash; use a comma, a colon or two sentences",
                );
            }
        }
    }
    findings
}

/// Files with more than `cap` lines of code before their tests.
pub(crate) fn files_longer_than(files: &[SourceFile], cap: usize) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let code = file
            .lines_before_tests()
            .into_iter()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("//"))
            .count();
        if code > cap {
            findings.flag_line(
                file,
                1,
                format!("{code} lines of code, more than {cap}; split it by topic"),
            );
        }
    }
    findings
}

/// Whether a `use` tree is exactly `super::*`.
fn is_parent_glob(tree: &UseTree) -> bool {
    let UseTree::Path(path) = tree else {
        return false;
    };
    path.ident == "super" && matches!(*path.tree, UseTree::Glob(_))
}

/// Whether a `use` tree brings in a glob anywhere.
fn has_glob(tree: &UseTree) -> bool {
    match tree {
        UseTree::Glob(_) => true,
        UseTree::Path(path) => has_glob(&path.tree),
        UseTree::Group(group) => group.items.iter().any(has_glob),
        UseTree::Name(_) | UseTree::Rename(_) => false,
    }
}

/// The modules a file declares in files of their own, by name.
fn child_modules(file: &SourceFile) -> Vec<String> {
    file.items()
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.content.is_none() => Some(module.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// Imports that climb with `super::`, other than a test module's
/// `use super::*;`.
pub(crate) fn parent_imports(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for import in file.inventory().uses {
            let climbs = use_roots(&import.tree).iter().any(|root| *root == "super");
            if climbs && !is_parent_glob(&import.tree) {
                findings.flag(
                    file,
                    import,
                    "an import through `super::`; name it from `crate::`",
                );
            }
        }
    }
    findings
}

/// Paths through `super::super::`, imported or inline.
pub(crate) fn climbing_paths(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (index, line) in file.lines().iter().enumerate() {
            let code = line.trim_start();
            if !code.starts_with("//") && code.contains("super::super") {
                findings.flag_line(
                    file,
                    index + 1,
                    "a path through `super::super::`; name it from `crate::`",
                );
            }
        }
    }
    findings
}

/// Glob imports, other than a folder re-exporting its own parts.
pub(crate) fn glob_imports(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let children = child_modules(file);
        for import in file.inventory().uses {
            if !has_glob(&import.tree) {
                continue;
            }
            let re_exports_a_part = matches!(import.vis, Visibility::Public(_))
                && use_roots(&import.tree)
                    .iter()
                    .all(|root| children.contains(&root.to_string()));
            if !re_exports_a_part {
                findings.flag(file, import, "a glob import; name what it takes");
            }
        }
    }
    findings
}

/// `use` declarations inside a function body.
pub(crate) fn imports_inside_functions(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for function in file.inventory().functions {
            for statement in &function.body.stmts {
                if let Stmt::Item(Item::Use(import)) = statement {
                    findings.flag(
                        file,
                        import,
                        "an import inside a function; move it to the top of the module",
                    );
                }
            }
        }
    }
    findings
}

/// The words of a piece of source, for asking whether it names something.
fn words(text: &str) -> BTreeSet<&str> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .collect()
}

/// The names a `use` tree brings in, leaving out globs, `self` and `_`.
fn imported_names(tree: &UseTree, names: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => imported_names(&path.tree, names),
        UseTree::Name(name) if name.ident != "self" => names.push(name.ident.to_string()),
        UseTree::Rename(rename) if rename.rename != "_" => names.push(rename.rename.to_string()),
        UseTree::Group(group) => group
            .items
            .iter()
            .for_each(|item| imported_names(item, names)),
        UseTree::Name(_) | UseTree::Rename(_) | UseTree::Glob(_) => {}
    }
}

/// Whether `name` is a trait `file` imports for its methods alone.
fn imported_for_methods(file: &SourceFile, name: &str) -> bool {
    TRAITS_IMPORTED_FOR_METHODS
        .iter()
        .any(|(path, trait_name, _)| (*path == "*" || *path == file.path) && *trait_name == name)
}

/// The code a file builds outside tests, without its imports.
fn code_without_imports(file: &SourceFile) -> String {
    file.lines_before_tests()
        .into_iter()
        .filter(|line| {
            let line = line.trim_start();
            !line.starts_with("use ") && !line.starts_with("pub use ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Private imports the file never uses itself, kept only for a test
/// module's `use super::*;`.
pub(crate) fn imports_held_for_others(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let code = code_without_imports(file);
        let used = words(&code);
        for item in file.items() {
            let Item::Use(import) = item else {
                continue;
            };
            if !matches!(import.vis, Visibility::Inherited) {
                continue;
            }
            let mut names = Vec::new();
            imported_names(&import.tree, &mut names);
            for name in names
                .iter()
                .filter(|name| !used.contains(name.as_str()) && !imported_for_methods(file, name))
            {
                findings.flag(
                    file,
                    import,
                    format!("`{name}` is imported but not used here"),
                );
            }
        }
    }
    findings
}

/// Whether a type is `bool`.
fn is_flag(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    path.path.is_ident("bool")
}

/// Functions taking a `bool`. A `from` or `try_from` is exempt: turning a
/// stored or sent `bool` into a type that names its cases is the step this
/// check asks for.
pub(crate) fn flag_parameters(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for function in file.inventory().functions {
            let name = &function.signature.ident;
            if name == "from" || name == "try_from" {
                continue;
            }
            let flags = function
                .signature
                .inputs
                .iter()
                .filter_map(|argument| match argument {
                    syn::FnArg::Typed(typed) if is_flag(&typed.ty) => Some(typed),
                    _ => None,
                });
            for typed in flags {
                findings.flag(
                    file,
                    typed,
                    format!("`{name}` takes a `bool`; take a type that names each case"),
                );
            }
        }
    }
    findings
}

/// Whether the lines directly above line `index` (0-based), through other
/// attributes, include a doc comment.
fn documented_above(lines: &[&str], index: usize) -> bool {
    lines[..index]
        .iter()
        .rev()
        .map(|line| line.trim_start())
        .find(|line| !line.starts_with("#["))
        .is_some_and(|line| line.starts_with("///"))
}

/// Tests without a doc comment saying what they show.
pub(crate) fn undocumented_tests(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let lines = file.lines();
        for (index, line) in lines.iter().enumerate() {
            if line.trim() == "#[test]" && !documented_above(&lines, index) {
                findings.flag_line(file, index + 1, "a test without a doc saying what it shows");
            }
        }
    }
    findings
}

#[cfg_attr(test, test)]
pub(crate) fn function_bodies_carry_no_comments() {
    comments_in_function_bodies(&infra_files()).assert_none("comments inside function bodies");
}

#[cfg_attr(test, test)]
pub(crate) fn no_if_is_nested_in_another() {
    nested_ifs(&production_files()).assert_none("nested ifs");
}

#[cfg_attr(test, test)]
pub(crate) fn every_allow_says_why() {
    unexplained_allows(&production_files()).assert_none("unexplained allows");
}

#[cfg_attr(test, test)]
pub(crate) fn the_test_module_comes_last_and_alone() {
    misplaced_test_modules(&infra_files()).assert_none("misplaced test modules");
}

#[cfg_attr(test, test)]
pub(crate) fn no_file_is_split_by_dividers() {
    divider_comments(&infra_files()).assert_none("section dividers");
}

#[cfg_attr(test, test)]
pub(crate) fn no_file_holds_an_em_dash() {
    em_dashes(&infra_files()).assert_none("em dashes");
}

#[cfg_attr(test, test)]
pub(crate) fn no_file_holds_more_than_one_topic() {
    files_longer_than(&production_files(), MAX_CODE_LINES).assert_none("files too long");
}

#[cfg_attr(test, test)]
pub(crate) fn imports_name_their_source_from_the_crate() {
    parent_imports(&infra_files()).assert_none("imports through `super::`");
}

#[cfg_attr(test, test)]
pub(crate) fn no_path_climbs_two_levels() {
    climbing_paths(&infra_files()).assert_none("paths through `super::super::`");
}

#[cfg_attr(test, test)]
pub(crate) fn imports_name_what_they_take() {
    glob_imports(&production_files()).assert_none("glob imports");
}

#[cfg_attr(test, test)]
pub(crate) fn imports_sit_at_the_top_of_their_module() {
    imports_inside_functions(&infra_files()).assert_none("imports inside functions");
}

#[cfg_attr(test, test)]
pub(crate) fn each_file_imports_what_it_uses() {
    imports_held_for_others(&production_files()).assert_none("imports held for others");
}

#[cfg_attr(test, test)]
pub(crate) fn every_test_says_what_it_shows() {
    undocumented_tests(&infra_files()).assert_none("tests without a doc");
}

#[cfg_attr(test, test)]
pub(crate) fn no_function_takes_a_bool() {
    flag_parameters(&production_files()).assert_none("functions taking a bool");
}

/// Each style check, run over a file that breaks it on purpose, finds the
/// break. So a check that stops looking fails here instead of passing
/// everything.
#[cfg_attr(test, test)]
pub(crate) fn every_style_check_finds_its_planted_break() {
    let files = [SourceFile::planted("planted.rs", PLANTED)];
    let checks: [(&str, Check); 14] = [
        ("comment in a body", comments_in_function_bodies),
        ("nested if", nested_ifs),
        ("unexplained allow", unexplained_allows),
        ("misplaced test module", misplaced_test_modules),
        ("divider", divider_comments),
        ("em dash", em_dashes),
        ("long file", |files| files_longer_than(files, 5)),
        ("parent import", parent_imports),
        ("climbing path", climbing_paths),
        ("glob import", glob_imports),
        ("import in a function", imports_inside_functions),
        ("import held for others", imports_held_for_others),
        ("flag parameter", flag_parameters),
        ("undocumented test", undocumented_tests),
    ];
    let missed: Vec<&str> = checks
        .iter()
        .filter(|(_, check)| check(&files).is_empty())
        .map(|(name, _)| *name)
        .collect();
    assert!(
        missed.is_empty(),
        "style checks that missed their planted break: {missed:?}"
    );
}

/// A file breaking every style rule once.
const PLANTED: &str = r"
use super::sibling::Thing;
use super::super::cousin::Other;
use crate::ports::*;
use crate::unused::Held;
use tokio::time;

// ── a section

/// Says one thing — then another.

#[allow(dead_code)]
fn commented() {
    // says what the code should
    let x = 1;
}

fn nested(x: u8) {
    if x > 1 {
        if x > 2 {
            Thing::go();
        }
    }
}

fn importing(on: bool) {
    use std::fmt;
    Other::go(on, time::now());
}

#[cfg(test)]
mod tests {
    #[test]
    fn bare() {}
}

fn after() {}
";
