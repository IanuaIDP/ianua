//! The comments the schema writes above what it makes: a table, a column,
//! a named constraint, an index. A written migration carries each one
//! above its change, so the migration says why as the schema does.

use std::collections::BTreeMap;

/// The schema's comments, by what they sit above.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Notes {
    tables: BTreeMap<String, String>,
    columns: BTreeMap<(String, String), String>,
    constraints: BTreeMap<String, String>,
    indexes: BTreeMap<String, String>,
}

impl Notes {
    /// The comment above table `name`.
    pub(crate) fn table(&self, name: &str) -> Option<String> {
        self.tables.get(name).cloned()
    }

    /// The comment above column `column` of `table`.
    pub(crate) fn column(&self, table: &str, column: &str) -> Option<String> {
        self.columns
            .get(&(table.to_owned(), column.to_owned()))
            .cloned()
    }

    /// The comment above constraint `name`.
    pub(crate) fn constraint(&self, name: &str) -> Option<String> {
        self.constraints.get(name).cloned()
    }

    /// The comment above index `name`.
    pub(crate) fn index(&self, name: &str) -> Option<String> {
        self.indexes.get(name).cloned()
    }
}

/// What the line being read sits inside.
enum Inside {
    /// No table's definition.
    Nothing,
    /// The definition of this table.
    Table(String),
}

/// The comments of `texts`, the schema files' contents.
pub(crate) fn read<'a>(texts: impl IntoIterator<Item = &'a str>) -> Notes {
    let mut notes = Notes::default();
    for text in texts {
        read_one(&mut notes, text);
    }
    notes
}

/// Adds the comments of one file to `notes`.
fn read_one(notes: &mut Notes, text: &str) {
    let mut pending: Vec<&str> = Vec::new();
    let mut inside = Inside::Nothing;
    for line in text.lines().map(str::trim) {
        if let Some(comment) = line.strip_prefix("--") {
            pending.push(comment.trim());
            continue;
        }
        let note = taken(&mut pending);
        inside = placed(notes, inside, line, note);
    }
}

/// The pending comment lines as one note, the directives and the
/// foreign-key reasons left out, emptied for the next.
fn taken(pending: &mut Vec<&str>) -> Option<String> {
    let note = pending
        .iter()
        .filter(|line| !line.starts_with("schema:") && !line.starts_with("no foreign key"))
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    pending.clear();
    (!note.is_empty()).then_some(note)
}

/// Files `note` under what `line` makes, and what the next line sits in.
fn placed(notes: &mut Notes, inside: Inside, line: &str, note: Option<String>) -> Inside {
    let words: Vec<&str> = line.split_whitespace().collect();
    match (inside, words.as_slice()) {
        (_, ["CREATE", "TABLE", name, ..]) => {
            let name = name.trim_end_matches('(').to_owned();
            if let Some(note) = note {
                notes.tables.insert(name.clone(), note);
            }
            Inside::Table(name)
        }
        (_, ["CREATE", "INDEX" | "UNIQUE", ..]) => {
            if let (Some(name), Some(note)) = (index_name(&words), note) {
                notes.indexes.insert(name, note);
            }
            Inside::Nothing
        }
        (Inside::Table(table), _) => in_table(notes, table, &words, note),
        (Inside::Nothing, _) => Inside::Nothing,
    }
}

/// Files `note` under the constraint or column a line of `table` names,
/// and what the next line sits in.
fn in_table(notes: &mut Notes, table: String, words: &[&str], note: Option<String>) -> Inside {
    match words {
        [")" | ");", ..] => return Inside::Nothing,
        ["CONSTRAINT", name, ..] => {
            if let Some(note) = note {
                notes.constraints.insert((*name).to_owned(), note);
            }
        }
        [column, ..] => {
            if let Some(note) = note.filter(|_| is_column(column)) {
                notes
                    .columns
                    .insert((table.clone(), (*column).to_owned()), note);
            }
        }
        [] => {}
    }
    Inside::Table(table)
}

/// The index `CREATE [UNIQUE] INDEX name ON …` makes.
fn index_name(words: &[&str]) -> Option<String> {
    let at = words.iter().position(|word| *word == "INDEX")?;
    words
        .get(at.saturating_add(1))
        .filter(|name| **name != "CONCURRENTLY" && **name != "ON")
        .map(|name| (*name).to_owned())
}

/// Whether a table line's first word names a column, not a clause.
fn is_column(word: &str) -> bool {
    !matches!(
        word,
        "PRIMARY" | "FOREIGN" | "UNIQUE" | "CHECK" | "REFERENCES" | "ON" | "OR" | "AND" | "WHEN"
    ) && word
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table with a note above itself, a column, a constraint and an
    /// index, and a foreign-key reason that is not one.
    const API_KEYS: &str = "\
-- A tenant's API keys.
CREATE TABLE api_keys (
    id uuid PRIMARY KEY,
    -- When it was paused, or NULL while it works.
    paused_at timestamptz,
    -- no foreign key: kept after the account is gone
    created_by uuid,
    -- A paused key was paused after it was made.
    CONSTRAINT api_keys_paused_after_created
        CHECK (paused_at >= created_at)
);

-- A presented key is found by its digest alone.
CREATE INDEX api_keys_by_hash ON api_keys (key_hash);
";

    /// The comments above a table, a column, a constraint and an index are
    /// each filed under it; a foreign-key reason and a directive are not
    /// notes.
    #[test]
    fn each_comment_is_filed_under_what_it_sits_above() {
        let notes = read([API_KEYS]);

        assert_eq!(
            notes.table("api_keys").as_deref(),
            Some("A tenant's API keys.")
        );
        assert_eq!(
            notes.column("api_keys", "paused_at").as_deref(),
            Some("When it was paused, or NULL while it works.")
        );
        assert_eq!(notes.column("api_keys", "created_by"), None);
        assert_eq!(
            notes.constraint("api_keys_paused_after_created").as_deref(),
            Some("A paused key was paused after it was made.")
        );
        assert_eq!(
            notes.index("api_keys_by_hash").as_deref(),
            Some("A presented key is found by its digest alone.")
        );
    }
}
