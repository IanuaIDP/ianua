//! How every column of a table is kept: the field of the store's record
//! that holds it, and the queries that write and read it, read from the
//! migrations, the query files and the store's code.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::conventions::infra::fields::{Column, Usage, real_usage};
use crate::conventions::infra::source::{SourceFile, production_files};

/// One column, as the page shows it.
struct Shown {
    name: String,
    holds: String,
    written: String,
    read: String,
}

/// The page of every table whose name starts with `prefix`, in Markdown or
/// as text; `None` when no table does.
pub(crate) fn page(prefix: &str, markdown: bool) -> Option<String> {
    let (columns, usage) = real_usage();
    let files = production_files();
    let mut tables: BTreeMap<&str, Vec<&Column>> = BTreeMap::new();
    for column in columns
        .iter()
        .filter(|column| column.table.starts_with(prefix))
    {
        tables
            .entry(column.table.as_str())
            .or_default()
            .push(column);
    }
    if tables.is_empty() {
        return None;
    }
    let mut out = String::new();
    for (table, columns) in tables {
        let held = held_by(table, &files);
        let shown: Vec<Shown> = columns
            .iter()
            .map(|column| shown(column, &usage, &held))
            .collect();
        let file = columns.first().map_or("", |column| column.file.as_str());
        match markdown {
            true => markdown_table(&mut out, table, file, &shown),
            false => text_table(&mut out, table, file, &shown),
        }
    }
    Some(out)
}

/// What the page says of `column`.
fn shown(column: &Column, usage: &Usage, held: &BTreeMap<String, BTreeSet<String>>) -> Shown {
    let key = (column.table.clone(), column.name.clone());
    let queries = |found: Option<&BTreeSet<String>>| {
        found.map_or_else(
            || "-".to_owned(),
            |paths| {
                paths
                    .iter()
                    .map(|path| short(path, &column.table))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        )
    };
    Shown {
        name: column.name.clone(),
        holds: held.get(&column.name).map_or_else(
            || "-".to_owned(),
            |fields| fields.iter().cloned().collect::<Vec<_>>().join(", "),
        ),
        written: written_note(column, queries(usage.written.get(&key))),
        read: read_note(column, queries(usage.read.get(&key))),
    }
}

/// Who writes `column`, saying when the database fills it.
fn written_note(column: &Column, queries: String) -> String {
    match (queries.as_str(), column.defaulted) {
        ("-", true) => "its default".to_owned(),
        _ => queries,
    }
}

/// Who reads `column`, saying when only its key or a person does.
fn read_note(column: &Column, queries: String) -> String {
    match (queries.as_str(), column.keyed, column.unread) {
        ("-", true, _) => "its key".to_owned(),
        ("-", false, true) => "a person, on purpose".to_owned(),
        _ => queries,
    }
}

/// `path` without its table's folder, as the page lists it.
fn short(path: &str, table: &str) -> String {
    path.strip_prefix(&format!("queries/{table}/"))
        .unwrap_or(path)
        .to_owned()
}

/// The fields of the store's records each column of `table` is read into:
/// a column read as `self.column` into `field:`, or into `let name =`.
fn held_by(table: &str, files: &[SourceFile]) -> BTreeMap<String, BTreeSet<String>> {
    let named = format!("queries/{table}/");
    let stores: Vec<String> = files
        .iter()
        .filter(|file| file.lines_before_tests().join("\n").contains(&named))
        .map(|file| file.path.trim_end_matches(".rs").to_owned())
        .collect();
    let mut held: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for file in files.iter().filter(|file| {
        stores.iter().any(|store| {
            file.path.trim_end_matches(".rs") == store
                || file.path.starts_with(&format!("{store}/"))
        })
    }) {
        let mut reader = Reader::default();
        for line in file.lines_before_tests() {
            reader.read(line, &mut held);
        }
    }
    held
}

/// Reads lines in order, following each `field:` or `let name =` across
/// the lines its expression spans.
#[derive(Default)]
struct Reader {
    /// The fields and names being read into, each with the bracket depth
    /// it began at.
    targets: Vec<(String, usize)>,
    /// How deep in brackets the reading is.
    depth: usize,
    /// Whether the last line ended on `self`, so a line opening with `.`
    /// goes on reading it, as rustfmt breaks `self` and `.column`.
    after_self: bool,
}

impl Reader {
    /// What `line` reads `self.column` into, added to `held`.
    fn read(&mut self, line: &str, held: &mut BTreeMap<String, BTreeSet<String>>) {
        let continued = match (self.after_self, line.trim().starts_with('.')) {
            (true, true) => format!("self{}", line.trim()),
            _ => line.trim().to_owned(),
        };
        let trimmed = continued.as_str();
        self.after_self = trimmed.ends_with("self");
        if let Some(target) = target_of(trimmed) {
            self.targets.push((target.to_owned(), self.depth));
        }
        if let Some((target, _)) = self.targets.last() {
            for column in columns_read(trimmed) {
                held.entry(column).or_default().insert(target.clone());
            }
        }
        let opens = trimmed.matches(['(', '[', '{']).count();
        let closes = trimmed.matches([')', ']', '}']).count();
        self.depth = self.depth.saturating_add(opens).saturating_sub(closes);
        let ended = trimmed.ends_with([',', ';']);
        while self
            .targets
            .last()
            .is_some_and(|(_, began)| *began > self.depth || (*began == self.depth && ended))
        {
            self.targets.pop();
        }
    }
}

/// The field or name `line` starts reading into, if it starts one.
fn target_of(line: &str) -> Option<&str> {
    line.strip_prefix("let ")
        .and_then(|rest| rest.split_once(" ="))
        .map(|(name, _)| name)
        .or_else(|| line.split_once(": ").map(|(field, _)| field))
        .filter(|name| name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// The columns `line` reads as `self.column`.
fn columns_read(line: &str) -> Vec<String> {
    line.match_indices("self.")
        .map(|(at, found)| {
            line[at.saturating_add(found.len())..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .filter(|column| !column.is_empty())
        .collect()
}

/// `shown` as text under `table`'s name.
fn text_table(out: &mut String, table: &str, file: &str, shown: &[Shown]) {
    let _ = writeln!(out, "{table}  ({file})");
    for column in shown {
        let _ = writeln!(
            out,
            "  {}\n    holds:      {}\n    written by: {}\n    read by:    {}",
            column.name, column.holds, column.written, column.read
        );
    }
    out.push('\n');
}

/// `shown` as a Markdown table under `table`'s name.
fn markdown_table(out: &mut String, table: &str, file: &str, shown: &[Shown]) {
    let _ = writeln!(out, "### `{table}`\n\nMade in `{file}`.\n");
    out.push_str("| Column | Held in | Written by | Read by |\n| --- | --- | --- | --- |\n");
    for column in shown {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            column.name,
            code(&column.holds),
            code(&column.written),
            code(&column.read)
        );
    }
    out.push('\n');
}

/// `list` with each name in code, leaving words as they are.
fn code(list: &str) -> String {
    if list == "-" || list.contains(' ') && !list.contains(", ") && !list.contains('.') {
        return list.to_owned();
    }
    list.split(", ")
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A column read as `self.column` into a field, or through a `let`,
    /// is shown in the field it reaches, even across lines.
    #[test]
    fn a_column_is_shown_in_the_field_it_is_read_into() {
        let mut held = BTreeMap::new();
        let mut reader = Reader::default();
        let lines = [
            "        let stage = stage_from(",
            "            CONNECTION.choice(&self.stage)?,",
            "            self.code_hash,",
            "        )?;",
            "        PendingConnection::reconstitute(PendingConnectionRow {",
            "            name: CONNECTION.value(\"name\", Label::new(\"name\", self.name))?,",
            "        })",
        ];

        for line in lines {
            reader.read(line, &mut held);
        }

        assert_eq!(held["name"], BTreeSet::from(["name".to_owned()]));
        assert_eq!(held["code_hash"], BTreeSet::from(["stage".to_owned()]));
        assert_eq!(held["stage"], BTreeSet::from(["stage".to_owned()]));
    }

    /// The pending connections page shows each column with its field and
    /// the queries that write and read it.
    #[test]
    fn the_pending_connections_page_shows_where_each_column_goes() {
        let page = page("workflow_pending_connections", false).unwrap();

        assert!(page.contains("workflow_pending_connections"));
        assert!(page.contains("  place\n    holds:      place"));
    }
}
