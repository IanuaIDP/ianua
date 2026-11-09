//! Names the message macro once per file: every production
//! `ianua_domain::message!` or `crate::message!` becomes `message!`, and the
//! file imports the macro at its top, so a keyed message fits the lines a
//! plain one did.

use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};
use syn::{Item, Macro};

use crate::collect::rust::cfg::{attributes, excluded};
use crate::rewrite::edit::{Offsets, Replacement};

/// The replacements naming the macro by its short name in `file`, and the
/// import to add when the file has none.
pub(crate) fn shortened(file: &syn::File, source: &str, import: &str) -> Vec<Replacement> {
    let mut finder = Finder {
        found: Vec::new(),
        in_test: false,
    };
    finder.visit_file(file);
    if finder.found.is_empty() {
        return Vec::new();
    }
    let mut replacements: Vec<Replacement> = finder
        .found
        .into_iter()
        .map(|path| Replacement {
            start: path.span().start(),
            end: path.span().end(),
            text: "message".to_owned(),
        })
        .collect();
    if !imports(source, import) {
        replacements.extend(import_line(file, source, import));
    }
    replacements
}

struct Finder {
    found: Vec<syn::Path>,
    in_test: bool,
}

impl<'ast> Visit<'ast> for Finder {
    fn visit_item(&mut self, item: &'ast Item) {
        if excluded(attributes(item)) {
            let was = std::mem::replace(&mut self.in_test, true);
            visit::visit_item(self, item);
            self.in_test = was;
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_macro(&mut self, invocation: &'ast Macro) {
        let names: Vec<String> = invocation
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let qualified = matches!(
            names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            ["ianua_domain" | "crate", "message"]
        );
        if qualified && !self.in_test {
            self.found.push(invocation.path.clone());
        }
        visit::visit_macro(self, invocation);
    }
}

/// Whether `source` already imports the macro with `import`.
fn imports(source: &str, import: &str) -> bool {
    source.lines().any(|line| line.trim() == import)
}

/// The import inserted before the file's first `use`, or before its first
/// item when it has none; rustfmt then sorts it into its group.
fn import_line(file: &syn::File, source: &str, import: &str) -> Option<Replacement> {
    let first_use = file.items.iter().find(|item| matches!(item, Item::Use(_)));
    let anchor = first_use.or(file.items.first())?;
    let start = anchor_start(anchor);
    let offsets = Offsets::new(source);
    offsets.of(start)?;
    Some(Replacement {
        start,
        end: start,
        text: format!("{import}\n"),
    })
}

/// Where an item starts, before any attribute or doc comment on it.
fn anchor_start(item: &Item) -> proc_macro2::LineColumn {
    let attribute = attributes(item)
        .first()
        .map(|attribute| attribute.span().start());
    attribute.unwrap_or_else(|| item.span().start())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::edit::applied;

    fn shorten(source: &str, import: &str) -> String {
        let file = syn::parse_file(source).unwrap();
        let (result, skipped) = applied(source, shortened(&file, source, import));
        assert!(skipped.is_empty());
        result
    }

    /// The macro is named short and imported once, before the first `use`.
    #[test]
    fn the_macro_is_named_short_and_imported() {
        let source = "use std::fmt;\n\nfn f() { ianua_domain::message!(\"k-a\", \"A\"); ianua_domain::message!(\"k-b\", \"B\"); }\n";

        let result = shorten(source, "use ianua_domain::message;");

        assert_eq!(
            result,
            "use ianua_domain::message;\nuse std::fmt;\n\nfn f() { message!(\"k-a\", \"A\"); message!(\"k-b\", \"B\"); }\n"
        );
    }

    /// A macro used only inside tests keeps its qualified path and adds no production import.
    #[test]
    fn macros_in_tests_keep_full_paths() {
        let source =
            "fn f() {}\n#[cfg(test)]\nmod tests { fn t() { crate::message!(\"k-a\", \"A\"); } }\n";

        assert_eq!(shorten(source, "use crate::message;"), source);
    }

    /// A file that already imports the macro gets no second import.
    #[test]
    fn an_existing_import_is_kept() {
        let source = "use crate::message;\nfn f() { crate::message!(\"k-a\", \"A\"); }\n";

        assert_eq!(
            shorten(source, "use crate::message;"),
            "use crate::message;\nfn f() { message!(\"k-a\", \"A\"); }\n"
        );
    }
}
