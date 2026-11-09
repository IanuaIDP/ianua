//! What a schema file says on purpose about a change the planner would
//! otherwise refuse, each on a comment line of its own:
//!
//! - `-- schema: drops sessions.legacy_flag because nothing reads it since 2.3`
//! - `-- schema: drops old_tokens because tokens moved to oauth_access_tokens`
//! - `-- schema: changes notes.body because widening varchar(200) to text`
//! - `-- schema: renamed notes.text to body`
//! - `-- schema: renamed drafts to notes`
//!
//! A drop or a change names its reason; a rename names both names, so a
//! renamed column is never guessed from one dropped and one added.

use std::collections::{BTreeMap, BTreeSet};

/// The marker a directive line starts with, after `--`.
const MARKER: &str = "schema:";

/// Everything the schema files say on purpose.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Directives {
    /// Tables and `table.column`s that may be dropped.
    pub(crate) drops: BTreeSet<String>,
    /// `table.column`s whose type or nullability may change.
    pub(crate) changes: BTreeSet<String>,
    /// Renamed tables and `table.column`s: the old name to the new.
    pub(crate) renamed: BTreeMap<String, String>,
}

impl Directives {
    /// Whether `target`, a table or `table.column`, may be dropped.
    pub(crate) fn drops(&self, target: &str) -> bool {
        self.drops.contains(target)
    }

    /// Whether `target`, a `table.column`, may change.
    pub(crate) fn changes(&self, target: &str) -> bool {
        self.changes.contains(target)
    }

    /// The new name of the old table `old`, when it was renamed.
    pub(crate) fn table_renamed(&self, old: &str) -> Option<&str> {
        self.renamed
            .get(old)
            .filter(|_| !old.contains('.'))
            .map(String::as_str)
    }

    /// The new name of column `column` of `table`, when it was renamed.
    pub(crate) fn column_renamed(&self, table: &str, column: &str) -> Option<&str> {
        self.renamed
            .get(&format!("{table}.{column}"))
            .map(String::as_str)
    }
}

/// A directive line that does not read, with why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unreadable {
    /// The line as written.
    pub(crate) line: String,
    /// Why it does not read.
    pub(crate) why: &'static str,
}

/// The directives of `texts`, the schema files' contents, or every line
/// that looks like one and does not read.
pub(crate) fn read<'a>(
    texts: impl IntoIterator<Item = &'a str>,
) -> Result<Directives, Vec<Unreadable>> {
    let mut found = Directives::default();
    let mut unreadable = Vec::new();
    for line in texts.into_iter().flat_map(str::lines) {
        let Some(said) = line.trim().strip_prefix("--").map(str::trim) else {
            continue;
        };
        let Some(said) = said.strip_prefix(MARKER).map(str::trim) else {
            continue;
        };
        if let Err(why) = take(&mut found, said) {
            unreadable.push(Unreadable {
                line: line.trim().to_owned(),
                why,
            });
        }
    }
    if unreadable.is_empty() {
        return Ok(found);
    }
    Err(unreadable)
}

/// Adds the directive `said` to `found`.
fn take(found: &mut Directives, said: &str) -> Result<(), &'static str> {
    let words: Vec<&str> = said.split_whitespace().collect();
    match words.as_slice() {
        ["drops", target, "because", reason @ ..] if !reason.is_empty() => {
            found.drops.insert((*target).to_owned());
            Ok(())
        }
        ["changes", target, "because", reason @ ..]
            if !reason.is_empty() && target.contains('.') =>
        {
            found.changes.insert((*target).to_owned());
            Ok(())
        }
        ["renamed", old, "to", new] => {
            found.renamed.insert((*old).to_owned(), (*new).to_owned());
            Ok(())
        }
        ["drops", ..] => Err("a drop names its table or table.column and `because` a reason"),
        ["changes", ..] => Err("a change names its table.column and `because` a reason"),
        ["renamed", ..] => Err("a rename reads `renamed <old> to <new>`"),
        _ => Err("a directive is `drops`, `changes` or `renamed`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each kind of directive is read, and an ordinary comment is not one.
    #[test]
    fn each_directive_is_read() {
        let text = "\
-- An ordinary comment about schema: nothing here.
-- schema: drops sessions.legacy_flag because nothing reads it since 2.3
-- schema: changes notes.body because widening to text
-- schema: renamed notes.text to body
-- schema: renamed drafts to notes
";

        let found = read([text]).unwrap();

        assert!(found.drops("sessions.legacy_flag"));
        assert!(found.changes("notes.body"));
        assert_eq!(found.column_renamed("notes", "text"), Some("body"));
        assert_eq!(found.table_renamed("drafts"), Some("notes"));
    }

    /// A drop without a reason and a change without a column each produce
    /// an error explaining the missing part of the directive.
    #[test]
    fn a_drop_without_its_reason_does_not_read() {
        let text =
            "-- schema: drops sessions.legacy_flag\n-- schema: changes notes because wider\n";

        let unreadable = read([text]).unwrap_err();

        assert_eq!(unreadable.len(), 2);
        assert!(unreadable[0].why.contains("because"));
        assert!(unreadable[1].why.contains("table.column"));
    }
}
