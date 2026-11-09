//! What a draft leaves behind: placeholder macros, notes to come back to,
//! and emoji.
//!
//! - No `todo!`, `unimplemented!` or `dbg!` in code that ships.
//! - No `TODO`, `FIXME`, `XXX` or `HACK` note anywhere: the work is done
//!   or written down in the plan.
//! - No emoji in a comment.

use crate::conventions::infra::source::{Findings, SourceFile};

/// The placeholder macros code that ships never calls.
const PLACEHOLDERS: &[&str] = &["todo!(", "unimplemented!(", "dbg!("];

/// The notes left to come back to.
const NOTES: &[&str] = &["TODO", "FIXME", "XXX", "HACK"];

/// Every placeholder macro among `files`, read as they ship.
pub(crate) fn placeholder_macros(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        for (at, line) in file.lines_before_tests().iter().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            if let Some(macro_call) = PLACEHOLDERS.iter().find(|call| code.contains(*call)) {
                found.flag_at(
                    &file.path,
                    at.saturating_add(1),
                    format!("`{macro_call}` is left in code that ships; finish it"),
                );
            }
        }
    }
    found
}

/// Every note to come back to among `files`, in a comment.
pub(crate) fn notes_left_behind(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        for (at, line) in file.lines().iter().enumerate() {
            let Some((_, comment)) = line.split_once("//") else {
                continue;
            };
            let note = NOTES.iter().find(|note| {
                comment
                    .split(|c: char| !c.is_alphanumeric())
                    .any(|word| word == **note)
            });
            if let Some(note) = note {
                found.flag_at(
                    &file.path,
                    at.saturating_add(1),
                    format!("`{note}` is left behind; do it now or write it in the plan"),
                );
            }
        }
    }
    found
}

/// Every comment among `files` holding an emoji. A string may hold one: a
/// test checking that a name refuses emoji writes one there.
pub(crate) fn emoji(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        for (at, line) in file.lines().iter().enumerate() {
            let Some((_, comment)) = line.split_once("//") else {
                continue;
            };
            if comment.chars().any(is_emoji) {
                found.flag_at(&file.path, at.saturating_add(1), "an emoji in a comment");
            }
        }
    }
    found
}

/// Whether `c` is an emoji: the pictographs, the symbols and dingbats, and
/// the emoji modifiers.
fn is_emoji(c: char) -> bool {
    matches!(u32::from(c), 0x1F300..=0x1FAFF | 0x2600..=0x27BF | 0x1F000..=0x1F2FF)
}
