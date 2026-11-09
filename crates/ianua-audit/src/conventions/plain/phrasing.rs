//! How comments are phrased.
//!
//! - **No stock openers.** A comment starts with what the thing is or does,
//!   never "Represents a…", "Provides a…", "Handles…", "Responsible
//!   for…", "Ensures that…" or "Allows you to…".
//! - **Straight quotes.** No curly quotes or apostrophes, which an editor
//!   types and a person writing code rarely does.
//! - **A comment no longer than it needs.** A function's doc comment is
//!   not more than twice as long as its body, past a dozen lines.
//! - **No code left in comments.** A comment line that is a statement is
//!   code someone meant to delete.

use syn::visit::{self, Visit};
use syn::{Attribute, ImplItemFn, ItemFn, Signature};

use crate::conventions::infra::source::{Findings, SourceFile, line_of};

/// How a comment must not start, lower case.
const STOCK_OPENERS: &[&str] = &[
    "represents ",
    "provides ",
    "handles ",
    "responsible for ",
    "is responsible for ",
    "ensures that ",
    "allows you to ",
    "this is a ",
    "a helper ",
    "a utility ",
];

/// Phrases that tell a comment's history instead of what the code is,
/// lower case.
pub(crate) const HISTORY: &[&str] = &[
    "previously",
    "formerly",
    "used to be",
    "the old code",
    "the new code",
    "before this change",
    "after this change",
    "this change",
];

/// The curly quotes and apostrophes.
const CURLY: &[char] = &['\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}'];

/// The fewest lines a doc comment has before its length is weighed.
const LONG_DOC_LINES: usize = 12;

/// Every doc comment among `files` starting with a stock opener.
pub(crate) fn stock_openers(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let lines = file.lines();
        for (at, line) in lines.iter().enumerate() {
            let Some(doc) = line.trim_start().strip_prefix("///").map(str::trim) else {
                continue;
            };
            let starts_comment =
                at == 0 || !lines[at.saturating_sub(1)].trim_start().starts_with("///");
            let lower = doc.to_lowercase();
            let opener = STOCK_OPENERS
                .iter()
                .find(|opener| lower.starts_with(*opener));
            if let Some(opener) = opener.filter(|_| starts_comment) {
                found.flag_at(
                    &file.path,
                    at.saturating_add(1),
                    format!(
                        "\"{}\" is a stock opener; start with what it is or does",
                        opener.trim()
                    ),
                );
            }
        }
    }
    found
}

/// Every comment among `files` telling its history: "previously", "no
/// longer used", "this change".
pub(crate) fn history_in_comments(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        for (at, line) in file.lines().iter().enumerate() {
            let Some((_, comment)) = line.split_once("//") else {
                continue;
            };
            if let Some(phrase) = history_phrase(comment) {
                found.flag_at(
                    &file.path,
                    at.saturating_add(1),
                    format!("\"{phrase}\" tells history; say what the code is now"),
                );
            }
        }
    }
    found
}

/// The history phrase `text` holds as whole words, if any.
pub(crate) fn history_phrase(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    HISTORY.iter().copied().find(|phrase| {
        lower.match_indices(phrase).any(|(at, _)| {
            let before = lower[..at].chars().last();
            let after = lower[at.saturating_add(phrase.len())..].chars().next();
            before.is_none_or(|c| !c.is_alphanumeric())
                && after.is_none_or(|c| !c.is_alphanumeric())
        })
    })
}

/// Every comment among `files` holding a curly quote or apostrophe.
pub(crate) fn curly_quotes(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        for (at, line) in file.lines().iter().enumerate() {
            let Some((_, comment)) = line.split_once("//") else {
                continue;
            };
            if comment.contains(CURLY) {
                found.flag_at(
                    &file.path,
                    at.saturating_add(1),
                    "a curly quote in a comment; use ' and \"",
                );
            }
        }
    }
    found
}

/// Every comment line among `files` that is a statement: code left behind.
pub(crate) fn commented_out_code(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        for (at, line) in file.lines().iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("///") || trimmed.starts_with("//!") {
                continue;
            }
            let Some(comment) = trimmed.strip_prefix("//").map(str::trim) else {
                continue;
            };
            if reads_as_code(comment) {
                found.flag_at(
                    &file.path,
                    at.saturating_add(1),
                    "code left in a comment; delete it",
                );
            }
        }
    }
    found
}

/// Whether a comment's text reads as a Rust statement.
fn reads_as_code(text: &str) -> bool {
    let starts = [
        "let ", "fn ", "use ", "pub fn ", "impl ", "match ", "return ", "if let ",
    ];
    starts.iter().any(|start| text.starts_with(start))
        && (text.ends_with(';') || text.ends_with('{'))
}

/// Every function among `files` whose doc comment is past a dozen lines and
/// more than twice as long as its body.
pub(crate) fn comments_longer_than_code(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let mut weighing = Weighing {
            file,
            found: &mut found,
        };
        file.items()
            .iter()
            .for_each(|item| weighing.visit_item(item));
    }
    found
}

/// Weighs each function's doc comment against its body.
struct Weighing<'a> {
    file: &'a SourceFile,
    found: &'a mut Findings,
}

impl Weighing<'_> {
    fn weigh(&mut self, signature: &Signature, attributes: &[Attribute], body: &syn::Block) {
        let doc_lines = attributes
            .iter()
            .filter(|attribute| attribute.path().is_ident("doc"))
            .count();
        let start = body.brace_token.span.open().start().line;
        let end = body.brace_token.span.close().start().line;
        let body_lines = end.saturating_sub(start).saturating_add(1);
        if doc_lines > LONG_DOC_LINES && doc_lines > body_lines.saturating_mul(2) {
            self.found.flag_at(
                &self.file.path,
                line_of(&signature.ident),
                format!(
                    "`{}` has {doc_lines} lines of comment for {body_lines} of code; say less",
                    signature.ident
                ),
            );
        }
    }
}

impl<'ast> Visit<'ast> for Weighing<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.weigh(&item.sig, &item.attrs, &item.block);
        visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.weigh(&item.sig, &item.attrs, &item.block);
        visit::visit_impl_item_fn(self, item);
    }
}
