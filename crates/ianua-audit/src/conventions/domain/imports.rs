//! How a domain file imports: through `crate::` paths, at the top of a
//! module, naming what it takes. A path that climbs with `super::` has to
//! be counted to be read, and a glob or an import tucked inside a function
//! hides where a name comes from.

use syn::{Item, Stmt, UseTree, Visibility};

use crate::conventions::domain::source::{Findings, SourceFile, use_roots};

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

/// The modules a file declares in place of their own files, by name.
fn child_modules(file: &SourceFile) -> Vec<String> {
    file.items()
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.content.is_none() => Some(module.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// Where an import climbs with `super::`. A test module may open with
/// `use super::*;` to see the code it tests; anything else names its source
/// from `crate::`.
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

/// Where code names something through `super::super::`, in an import or
/// inline in a path. Two levels up has to be counted to be read; the full
/// `crate::` path says where it is.
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

/// Where production code imports a glob. A folder may re-export its own
/// parts with `pub use part::*;`; anything else names what it takes.
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

/// Where a `use` sits inside a function body instead of at the top of its
/// module.
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
