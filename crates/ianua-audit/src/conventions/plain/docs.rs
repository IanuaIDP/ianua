//! Comments that earn their place.
//!
//! - **A comment says what the name does not.** "Its id." on `id` and "The
//!   operation." on `operation` only say the name again; such a comment is
//!   rewritten to say something: where the id is shown, what the operation
//!   is for.
//! - **An error list stays short.** At most five lines under `# Errors`,
//!   alike cases grouped on one.
//! - **No filler.** No "This function…", "simply", "seamlessly",
//!   "leverage", "robust" or "it's worth noting".

use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, Field, ImplItemConst, ImplItemFn, ItemConst, ItemEnum, ItemFn, ItemStatic,
    ItemStruct, ItemTrait, ItemType, Lit, Meta, TraitItemFn, Variant,
};

use crate::conventions::infra::source::{Findings, SourceFile, line_of};
use crate::conventions::plain::words::{meaningful_words, name_words, only_restates};

/// The most lines an `# Errors` section holds.
pub(crate) const MOST_ERROR_LINES: usize = 5;

/// The most words a comment may have and still only restate its name; a
/// longer one says something, however plain.
const RESTATING_WORDS: usize = 4;

/// Phrases that pad a comment and say nothing, lower case.
pub(crate) const FILLER: &[&str] = &[
    "this function",
    "this struct",
    "this enum",
    "helper function",
    "utility function",
    "simply",
    "basically",
    "seamless",
    "leverage",
    "utilize",
    "robust",
    "comprehensive",
    "worth noting",
    "note that",
    "in order to",
    "elegant",
    "delve",
    "state-of-the-art",
    "cutting-edge",
];

/// Every doc comment among `files` that only says its item's name again.
pub(crate) fn comments_restating_names(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let mut documented = Documented {
            file,
            found: &mut found,
        };
        file.items()
            .iter()
            .for_each(|item| documented.visit_item(item));
    }
    found
}

/// Every `# Errors` section among `files` longer than [`MOST_ERROR_LINES`].
pub(crate) fn long_error_lists(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let lines = file.lines();
        let mut counting: Option<(usize, usize)> = None;
        for (at, line) in lines.iter().enumerate() {
            let said = line.trim_start();
            let Some(doc) = said.strip_prefix("///").map(str::trim) else {
                counting = flagged_when_over(&mut found, file, counting);
                continue;
            };
            if doc == "# Errors" {
                flagged_when_over(&mut found, file, counting);
                counting = Some((at.saturating_add(1), 0));
                continue;
            }
            if doc.starts_with("# ") {
                counting = flagged_when_over(&mut found, file, counting);
                continue;
            }
            if let Some((start, count)) = counting.filter(|_| doc.starts_with("- ")) {
                counting = Some((start, count.saturating_add(1)));
            }
        }
        flagged_when_over(&mut found, file, counting);
    }
    found
}

/// Flags the section `counting` describes when it holds too many lines,
/// and ends it.
fn flagged_when_over(
    found: &mut Findings,
    file: &SourceFile,
    counting: Option<(usize, usize)>,
) -> Option<(usize, usize)> {
    if let Some((start, count)) = counting.filter(|(_, count)| *count > MOST_ERROR_LINES) {
        found.flag_at(
            &file.path,
            start,
            format!(
                "`# Errors` lists {count} cases; group alike ones, at most {MOST_ERROR_LINES} lines"
            ),
        );
    }
    None
}

/// Every comment among `files` holding a filler phrase.
pub(crate) fn filler_phrases(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        for (at, line) in file.lines().iter().enumerate() {
            let Some((_, comment)) = line.split_once("//") else {
                continue;
            };
            let lower = comment.to_lowercase();
            if let Some(phrase) = FILLER.iter().find(|phrase| has_phrase(&lower, phrase)) {
                found.flag_at(
                    &file.path,
                    at.saturating_add(1),
                    format!("\"{phrase}\" pads the comment; say the thing itself"),
                );
            }
        }
    }
    found
}

/// Whether `text` holds `phrase` as whole words.
pub(crate) fn has_phrase(text: &str, phrase: &str) -> bool {
    text.match_indices(phrase).any(|(at, _)| {
        let before = text[..at].chars().last();
        let after = text[at.saturating_add(phrase.len())..].chars().next();
        before.is_none_or(|c| !c.is_alphanumeric()) && after.is_none_or(|c| !c.is_alphanumeric())
    })
}

/// Finds doc comments that only restate their item's name.
struct Documented<'a> {
    file: &'a SourceFile,
    found: &'a mut Findings,
}

impl Documented<'_> {
    fn check(&mut self, name: &syn::Ident, attributes: &[Attribute]) {
        let doc = doc_text(attributes);
        if doc.is_empty() {
            return;
        }
        let said = meaningful_words(&doc);
        let names = name_words(&name.to_string());
        if said.len() <= RESTATING_WORDS && only_restates(&said, &names) {
            self.found.flag_at(
                &self.file.path,
                line_of(name),
                format!(
                    "the comment on `{name}` only says its name again (\"{}\"); say what the name does not",
                    doc.trim()
                ),
            );
        }
    }
}

impl<'ast> Visit<'ast> for Documented<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.check(&item.sig.ident, &item.attrs);
        visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.check(&item.sig.ident, &item.attrs);
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        self.check(&item.sig.ident, &item.attrs);
        visit::visit_trait_item_fn(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        self.check(&item.ident, &item.attrs);
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast ItemEnum) {
        self.check(&item.ident, &item.attrs);
        visit::visit_item_enum(self, item);
    }

    fn visit_variant(&mut self, variant: &'ast Variant) {
        self.check(&variant.ident, &variant.attrs);
        visit::visit_variant(self, variant);
    }

    fn visit_field(&mut self, field: &'ast Field) {
        if let Some(name) = &field.ident {
            self.check(name, &field.attrs);
        }
        visit::visit_field(self, field);
    }

    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        self.check(&item.ident, &item.attrs);
    }

    fn visit_impl_item_const(&mut self, item: &'ast ImplItemConst) {
        self.check(&item.ident, &item.attrs);
    }

    fn visit_item_static(&mut self, item: &'ast ItemStatic) {
        self.check(&item.ident, &item.attrs);
    }

    fn visit_item_type(&mut self, item: &'ast ItemType) {
        self.check(&item.ident, &item.attrs);
    }

    fn visit_item_trait(&mut self, item: &'ast ItemTrait) {
        self.check(&item.ident, &item.attrs);
        visit::visit_item_trait(self, item);
    }
}

/// The doc comment `attributes` carry, its lines joined.
fn doc_text(attributes: &[Attribute]) -> String {
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("doc"))
        .filter_map(|attribute| {
            let Meta::NameValue(pair) = &attribute.meta else {
                return None;
            };
            let Expr::Lit(literal) = &pair.value else {
                return None;
            };
            let Lit::Str(text) = &literal.lit else {
                return None;
            };
            Some(text.value())
        })
        .collect::<Vec<_>>()
        .join(" ")
}
