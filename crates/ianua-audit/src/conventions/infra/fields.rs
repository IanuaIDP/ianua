//! Every column a migration defines is written by a query and read back by
//! one, read from the migrations and the query files, so a value the
//! platform saves and never reads, or reads and never saves, fails the
//! build instead of hiding until someone needs it.
//!
//! The compiler already holds the rest of the way: a store's record must
//! fill every field of the domain's row, and a field of a record or of the
//! columns it writes that nothing uses is dead code. What it cannot see is
//! SQL: a column the save query writes and no query selects, a column
//! queries read that nothing ever writes, or one no query names at all.
//!
//! - **Written, then read.** A column some query writes is read by some
//!   query too: selected, returned, or used to find or order rows.
//! - **Read, then written.** A column queries read is written by a query,
//!   or filled by its default.
//! - **Named.** A column no query names is refused, unless its definition
//!   says why: `-- not read by the app: <why>`.
//!
//! A query is counted for every table it names, so a column read through
//! a join in another table's folder counts as read.

use std::collections::{BTreeMap, BTreeSet};

use crate::conventions::infra::schema::{Migration, planted, schema};
use crate::conventions::infra::source::{Findings, SourceFile, production_files};
use crate::conventions::infra::sql::{QueryFile, query_files};

/// What a column's definition says to be left unread.
const UNREAD: &str = "not read by the app:";

/// The words that open a table constraint rather than a column.
const CONSTRAINTS: &[&str] = &[
    "constraint",
    "primary",
    "unique",
    "check",
    "foreign",
    "exclude",
    "like",
];

/// The words that end a `SET` list.
const SET_ENDS: &[&str] = &["where", "returning", "from"];

/// One column, as the migrations leave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Column {
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// Whether the database fills it when an insert leaves it out.
    pub defaulted: bool,
    /// Whether its definition says why no query reads it.
    pub unread: bool,
    /// Whether it is part of a primary key or a unique key, so the
    /// database reads it on every write it refuses as a repeat.
    pub keyed: bool,
    /// The migration that defines it.
    pub file: String,
    /// The line it is defined on.
    pub line: usize,
}

/// Which queries write and read each column, by table and name.
#[derive(Debug, Default)]
pub(crate) struct Usage {
    /// The query files writing each column.
    pub written: BTreeMap<(String, String), BTreeSet<String>>,
    /// The query files reading each column.
    pub read: BTreeMap<(String, String), BTreeSet<String>>,
}

/// Every column `migrations` leave, in table and definition order.
pub(crate) fn columns(migrations: &[Migration]) -> Vec<Column> {
    let mut kept: Vec<Column> = Vec::new();
    for migration in migrations {
        for (offset, statement) in statements(&migration.sql) {
            let at = Place {
                migration,
                offset,
                statement,
            };
            apply(&mut kept, &at);
        }
    }
    kept
}

/// Where a statement is: its migration, its offset in the SQL, its text.
struct Place<'a> {
    migration: &'a Migration,
    offset: usize,
    statement: &'a str,
}

impl Place<'_> {
    /// The place `by` further into the same statement.
    fn shifted(&self, by: usize) -> Self {
        Place {
            migration: self.migration,
            offset: self.offset.saturating_add(by),
            statement: self.statement,
        }
    }

    /// The column `name` of `table`, defined here by `definition`.
    fn column(&self, table: &str, name: &str, definition: &str) -> Column {
        let lead = definition
            .len()
            .saturating_sub(definition.trim_start().len());
        let at = self.offset.saturating_add(lead);
        let line = self.migration.sql[..at]
            .matches('\n')
            .count()
            .saturating_add(1);
        let upper = definition.to_uppercase();
        Column {
            table: table.to_owned(),
            name: name.to_owned(),
            defaulted: upper.contains(" DEFAULT ")
                || upper.contains("GENERATED ")
                || upper.contains("SERIAL"),
            unread: self
                .migration
                .text
                .lines()
                .nth(line.saturating_sub(1))
                .is_some_and(|written| written.contains(UNREAD)),
            keyed: upper.contains("PRIMARY KEY") || upper.contains(" UNIQUE"),
            file: self.migration.name.clone(),
            line,
        }
    }
}

/// The statements of `sql`, each with its offset.
fn statements(sql: &str) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut start = 0;
    for (at, _) in sql.match_indices(';') {
        found.push((start, &sql[start..at]));
        start = at.saturating_add(1);
    }
    found.push((start, &sql[start..]));
    found
}

/// `kept` after the statement at `at`.
fn apply(kept: &mut Vec<Column>, at: &Place<'_>) {
    let lower = at.statement.to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    match words.as_slice() {
        ["create", "table", ..] => created(kept, at, &lower),
        ["alter", "table", ..] => altered(kept, at, &lower),
        ["create", "unique", "index", ..] => {
            let Some((_, rest)) = lower.split_once(" on ") else {
                return;
            };
            let Some(table) = rest
                .split(|c: char| c.is_whitespace() || c == '(')
                .find(|part| !matches!(*part, "" | "only"))
            else {
                return;
            };
            if let Some(names) = rest.split_once('(').map(|(_, inside)| key_names(inside)) {
                mark_keyed(kept, table, &names);
            }
        }
        ["drop", "table", rest @ ..] => {
            let gone: Vec<String> = rest
                .iter()
                .filter(|word| !matches!(**word, "if" | "exists" | "cascade"))
                .map(|word| word.trim_matches(',').to_owned())
                .collect();
            kept.retain(|column| !gone.contains(&column.table));
        }
        _ => {}
    }
}

/// The columns a `CREATE TABLE` at `at` adds to `kept`.
fn created(kept: &mut Vec<Column>, at: &Place<'_>, lower: &str) {
    let Some(open) = lower.find('(') else {
        return;
    };
    let Some(table) = lower[..open]
        .split_whitespace()
        .rfind(|word| !matches!(*word, "if" | "not" | "exists"))
    else {
        return;
    };
    let table = table.trim_matches('"');
    let body_start = open.saturating_add(1);
    let mut keys = Vec::new();
    for (within, item) in split_top(&lower[body_start..], ',') {
        let Some(name) = item.split_whitespace().next() else {
            continue;
        };
        if CONSTRAINTS.contains(&name) {
            if let Some(names) = constraint_key(item) {
                keys.push(names);
            }
            continue;
        }
        let name = name.trim_matches('"');
        let offset = body_start.saturating_add(within);
        kept.push(at.shifted(offset).column(table, name, item));
    }
    for names in keys {
        mark_keyed(kept, table, &names);
    }
}

/// The columns a primary key or unique constraint `clause` names, if it is
/// one.
fn constraint_key(clause: &str) -> Option<Vec<String>> {
    let at = clause
        .find("primary key")
        .or_else(|| clause.find("unique"))?;
    let (_, inside) = clause[at..].split_once('(')?;
    Some(key_names(inside))
}

/// The column names in a key's list, up to its closing bracket.
fn key_names(inside: &str) -> Vec<String> {
    split_top(inside, ',')
        .into_iter()
        .filter_map(|(_, part)| part.split_whitespace().next())
        .map(|name| name.trim_matches('"').to_owned())
        .collect()
}

/// Marks the columns `names` of `table` as keyed.
fn mark_keyed(kept: &mut [Column], table: &str, names: &[String]) {
    for column in kept.iter_mut() {
        if column.table == table && names.contains(&column.name) {
            column.keyed = true;
        }
    }
}

/// `kept` after an `ALTER TABLE` at `at`.
fn altered(kept: &mut Vec<Column>, at: &Place<'_>, lower: &str) {
    let mut words = lower.split_whitespace().skip(2);
    let Some(table) = words.find(|word| !matches!(*word, "if" | "exists" | "only")) else {
        return;
    };
    let Some(clauses_at) = lower.find(table).map(|at| at.saturating_add(table.len())) else {
        return;
    };
    for (within, clause) in split_top(&lower[clauses_at..], ',') {
        let offset = clauses_at.saturating_add(within);
        changed(kept, &at.shifted(offset), table, clause);
    }
}

/// `kept` after one clause of an `ALTER TABLE` of `table`.
fn changed(kept: &mut Vec<Column>, at: &Place<'_>, table: &str, clause: &str) {
    let words: Vec<&str> = clause
        .split_whitespace()
        .filter(|word| !matches!(*word, "if" | "not" | "exists"))
        .collect();
    match words.as_slice() {
        ["add", "column", name, ..] => kept.push(at.column(table, name, clause)),
        ["add", "constraint", ..] | ["add", "primary", ..] | ["add", "unique", ..] => {
            if let Some(names) = constraint_key(clause) {
                mark_keyed(kept, table, &names);
            }
        }
        ["drop", "column", name, ..] => {
            kept.retain(|column| !(column.table == table && column.name == *name));
        }
        ["rename", "column", from, "to", to, ..] => {
            for column in kept.iter_mut() {
                if column.table == table && column.name == *from {
                    column.name = (*to).to_owned();
                }
            }
        }
        ["alter", "column", name, change, "default", ..] => {
            for column in kept.iter_mut() {
                if column.table == table && column.name == *name {
                    column.defaulted = *change == "set";
                }
            }
        }
        _ => {}
    }
}

/// The parts of `text` split at `separator` outside brackets and quoted
/// text, each with its offset, stopping at the bracket that closes the one
/// `text` is in. A default such as `'{"v": 1, "value": []}'` is one part.
fn split_top(text: &str, separator: char) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut depth = 0_usize;
    let mut start = 0;
    let mut quoted = false;
    for (at, c) in text.char_indices() {
        if c == '\'' {
            quoted = !quoted;
            continue;
        }
        if quoted {
            continue;
        }
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' if depth == 0 => {
                found.push((start, &text[start..at]));
                return found;
            }
            ')' => depth = depth.saturating_sub(1),
            c if c == separator && depth == 0 => {
                found.push((start, &text[start..at]));
                start = at.saturating_add(c.len_utf8());
            }
            _ => {}
        }
    }
    found.push((start, &text[start..]));
    found
}

/// Which of `columns` each of `queries` writes and reads.
pub(crate) fn usage(columns: &[Column], queries: &[QueryFile]) -> Usage {
    let mut by_table: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for column in columns {
        by_table
            .entry(column.table.as_str())
            .or_default()
            .insert(column.name.as_str());
    }
    let mut found = Usage::default();
    for query in queries {
        let touched = Touched::of(&query.sql().to_lowercase());
        found.add(query.path(), &touched, &by_table);
    }
    found
}

impl Usage {
    /// What `touched`, from the query at `path`, says of `tables`.
    fn add(&mut self, path: &str, touched: &Touched, tables: &BTreeMap<&str, BTreeSet<&str>>) {
        for (table, names) in tables {
            if !touched.named.contains(*table) {
                continue;
            }
            let written = touched.targets.contains(*table);
            for name in names {
                let key = ((*table).to_owned(), (*name).to_owned());
                if written && touched.written.contains(*name) {
                    self.written
                        .entry(key.clone())
                        .or_default()
                        .insert(path.to_owned());
                }
                if touched.read.contains(*name) {
                    self.read.entry(key).or_default().insert(path.to_owned());
                }
            }
        }
    }
}

/// What one query names, writes and reads, by word.
struct Touched {
    named: BTreeSet<String>,
    targets: BTreeSet<String>,
    written: BTreeSet<String>,
    read: BTreeSet<String>,
}

impl Touched {
    /// What the lower-case SQL `sql` touches.
    fn of(sql: &str) -> Self {
        let mut text = sql.to_owned();
        let mut targets = BTreeSet::new();
        let mut written = BTreeSet::new();
        inserted(&mut text, &mut targets, &mut written);
        updated(&text, &mut targets);
        blank_conflicts(&mut text);
        set_lists(&mut text, &mut written);
        let named: BTreeSet<String> = words(sql).map(|(_, word)| word.to_owned()).collect();
        let read = words(&text).map(|(_, word)| word.to_owned()).collect();
        Self {
            named,
            targets,
            written,
            read,
        }
    }
}

/// The identifiers of `text`, each with its offset.
fn words(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut found = Vec::new();
    let mut start: Option<usize> = None;
    for (at, c) in text.char_indices() {
        let part = c.is_ascii_alphanumeric() || c == '_';
        match (part, start) {
            (true, None) => start = Some(at),
            (false, Some(from)) => {
                found.push((from, &text[from..at]));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        found.push((from, &text[from..]));
    }
    found.into_iter()
}

/// `text` with `from..to` blanked out, so its words are no longer read.
fn blank(text: &mut String, from: usize, to: usize) {
    text.replace_range(from..to, &" ".repeat(to.saturating_sub(from)));
}

/// The tables `INSERT INTO` names, and the columns its lists write, each
/// list blanked out of `text`.
fn inserted(text: &mut String, targets: &mut BTreeSet<String>, written: &mut BTreeSet<String>) {
    let (mut from, opener) = (0, "insert into ");
    while let Some(found) = text[from..].find(opener) {
        let after = from.saturating_add(found).saturating_add(opener.len());
        from = after;
        let rest = &text[after..];
        let Some(written_as) = rest
            .split(|c: char| c.is_whitespace() || c == '(')
            .find(|part| !part.is_empty())
        else {
            continue;
        };
        let table = written_as
            .rsplit('.')
            .next()
            .unwrap_or(written_as)
            .to_owned();
        let Some(open) = rest.find('(') else {
            targets.insert(table);
            continue;
        };
        let before: Vec<&str> = rest[..open].split_whitespace().collect();
        let names_columns =
            matches!(before.as_slice(), [name] | [name, "as", _] if *name == written_as);
        targets.insert(table);
        if !names_columns {
            continue;
        }
        let list_start = after.saturating_add(open).saturating_add(1);
        written.extend(take_column_list(text, list_start));
    }
}

/// The column names of the list that starts at `list_start` in `text`,
/// the list blanked out.
fn take_column_list(text: &mut String, list_start: usize) -> Vec<String> {
    let list: Vec<(usize, String)> = split_top(&text[list_start..], ',')
        .into_iter()
        .map(|(at, item)| (at, item.trim().to_owned()))
        .collect();
    let end = list
        .last()
        .map_or(list_start, |(at, _)| list_start.saturating_add(*at));
    let close = text[end..]
        .find(')')
        .map_or(end, |at| end.saturating_add(at));
    blank(text, list_start, close);
    list.into_iter().map(|(_, name)| name).collect()
}

/// The tables `UPDATE` names.
fn updated(text: &str, targets: &mut BTreeSet<String>) {
    let mut words = words(text).map(|(_, word)| word).peekable();
    while let Some(word) = words.next() {
        if word != "update" {
            continue;
        }
        if let Some(table) = words.find(|next| !matches!(*next, "only" | "public")) {
            targets.insert(table.to_owned());
        }
    }
}

/// `text` with every `ON CONFLICT (...)` target and `excluded.` value
/// blanked out: they say which row an insert meets and what it brings,
/// not what is read back.
fn blank_conflicts(text: &mut String) {
    while let Some(at) = text.find("excluded.") {
        let end = words(&text[at..])
            .nth(1)
            .map_or(text.len(), |(offset, word)| {
                at.saturating_add(offset).saturating_add(word.len())
            });
        blank(text, at, end);
    }
    let mut from = 0;
    while let Some(found) = text[from..].find("on conflict") {
        let at = from.saturating_add(found);
        from = at.saturating_add(1);
        let rest = &text[at..];
        let Some(open) = rest.find('(') else {
            continue;
        };
        if rest[..open].split_whitespace().count() > 2 {
            continue;
        }
        let start = at.saturating_add(open);
        let close = text[start..].find(')').map_or(text.len(), |end| {
            start.saturating_add(end).saturating_add(1)
        });
        blank(text, start, close);
    }
}

/// The columns every `SET` list writes, each `column =` blanked out of
/// `text` so only the values it is set to are read.
fn set_lists(text: &mut String, written: &mut BTreeSet<String>) {
    let sets: Vec<usize> = words(text)
        .filter(|(_, word)| *word == "set")
        .map(|(at, _)| at.saturating_add(3))
        .collect();
    for start in sets {
        let list = list_end(&text[start..]);
        let items: Vec<(usize, usize, String)> =
            split_top(&text[start..start.saturating_add(list)], ',')
                .into_iter()
                .filter_map(|(at, item)| {
                    let equals = item.find('=')?;
                    let name = item[..equals].trim().to_owned();
                    Some((
                        start.saturating_add(at),
                        start
                            .saturating_add(at)
                            .saturating_add(equals)
                            .saturating_add(1),
                        name,
                    ))
                })
                .collect();
        for (from, to, name) in items {
            written.insert(name);
            blank(text, from, to);
        }
    }
}

/// How far a `SET` list at the start of `text` runs: to a word that ends
/// it outside brackets, the bracket that closes the one it is in, or the
/// end.
fn list_end(text: &str) -> usize {
    let mut depth = 0_usize;
    for (at, c) in text.char_indices() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' if depth == 0 => return at,
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        let starts_word =
            at == 0 || !text[..at].ends_with(|p: char| p.is_ascii_alphanumeric() || p == '_');
        if depth == 0 && starts_word && SET_ENDS.iter().any(|end| ends_here(&text[at..], end)) {
            return at;
        }
    }
    text.len()
}

/// Whether `text` opens with the whole word `word`.
fn ends_here(text: &str, word: &str) -> bool {
    text.starts_with(word)
        && !text[word.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

/// Columns of `columns` that `usage` shows written and never read, read
/// and never written, or never named.
pub(crate) fn columns_out_of_use(columns: &[Column], usage: &Usage) -> Findings {
    let mut findings = Findings::default();
    for column in columns {
        let key = (column.table.clone(), column.name.clone());
        let written = usage.written.contains_key(&key);
        let read = column.keyed || usage.read.contains_key(&key);
        let name = format!("`{}.{}`", column.table, column.name);
        let problem = match (written, read) {
            (true, true) => None,
            (false, true) if column.defaulted => None,
            (false, true) => Some(format!("{name} is read by queries but no query writes it")),
            (_, false) if column.unread => None,
            (true, false) => Some(format!(
                "{name} is written by {} but no query reads it back",
                listed(&usage.written[&key])
            )),
            (false, false) => Some(format!(
                "{name} is named by no query; read it, drop it, or say `-- {UNREAD} <why>`"
            )),
        };
        if let Some(problem) = problem {
            findings.flag_at(&column.file, column.line, problem);
        }
    }
    findings
}

/// `paths` as a short list.
fn listed(paths: &BTreeSet<String>) -> String {
    paths
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The SQL written in the store's code rather than in a file: each source
/// file's string literals, as one query, such as a search's filters.
pub(crate) fn queries_in_code(files: &[SourceFile]) -> Vec<QueryFile> {
    files
        .iter()
        .map(|file| {
            let code = file.lines_before_tests().join("\n");
            QueryFile::planted(&file.path, &string_literals(&code).join("\n"))
        })
        .collect()
}

/// The contents of every plain string literal in `code`.
fn string_literals(code: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut chars = code.chars().peekable();
    let mut previous = ' ';
    while let Some(c) = chars.next() {
        if c == '\'' && previous != '\\' {
            skip_char_literal(&mut chars);
        }
        if c == '"' && previous != '\\' {
            found.push(literal(&mut chars));
        }
        previous = c;
    }
    found
}

/// Skips a character literal, so `'"'` opens no string; a lifetime is
/// left as it is.
fn skip_char_literal(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let mut ahead = chars.clone();
    let closes = match ahead.next() {
        Some('\\') => ahead.nth(1) == Some('\''),
        Some(_) => ahead.next() == Some('\''),
        None => false,
    };
    if closes {
        while let Some(c) = chars.next() {
            if c == '\\' {
                chars.next();
                continue;
            }
            if c == '\'' {
                return;
            }
        }
    }
}

/// The rest of a string literal whose opening quote was read.
fn literal(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut text = String::new();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
                text.push(' ');
            }
            '"' => return text,
            c => text.push(c),
        }
    }
    text
}

/// Columns no query of the platform reads, each with why it is kept: they
/// are there for a person reading the table, not for the platform.
const KEPT_FOR_PEOPLE: &[(&str, &str, &str)] = &[
    (
        "audit_chain_anchors",
        "purged_before",
        "the cutoff of the purge that left an anchor, for an operator tracing a chain",
    ),
    (
        "wasm_modules",
        "uploaded_at",
        "when a tenant uploaded a module, for an operator",
    ),
    (
        "tenant_databases",
        "registered_at",
        "when a tenant's database was registered, for an operator",
    ),
    (
        "acme_accounts",
        "created_at",
        "when the certificate authority's account was made, for an operator",
    ),
    (
        "payment_events",
        "created_at",
        "when the payment provider made an event, for an operator matching it with the provider",
    ),
    (
        "resource_grants",
        "granted_by_kind",
        "who granted a resource, for an operator; the audit trail records each grant too",
    ),
    (
        "resource_grants",
        "granted_by_id",
        "who granted a resource, for an operator; the audit trail records each grant too",
    ),
];

/// `columns` with those [`KEPT_FOR_PEOPLE`] names counted as unread on
/// purpose.
fn with_kept_for_people(columns: Vec<Column>) -> Vec<Column> {
    columns
        .into_iter()
        .map(|mut column| {
            column.unread |= KEPT_FOR_PEOPLE
                .iter()
                .any(|(table, name, _)| column.table == *table && column.name == *name);
            column
        })
        .collect()
}

/// Every column of the real migrations, with what the queries in files
/// and in the store's code do with it.
pub(crate) fn real_usage() -> (Vec<Column>, Usage) {
    let columns = with_kept_for_people(columns(&schema()));
    let mut queries = query_files();
    queries.extend(queries_in_code(&production_files()));
    let usage = usage(&columns, &queries);
    (columns, usage)
}

/// Stops: a value the platform saves and never reads back, reads and
/// never saves, or a column nothing names at all.
#[cfg_attr(test, test)]
pub(crate) fn every_column_is_written_and_read() {
    let (columns, usage) = real_usage();
    columns_out_of_use(&columns, &usage).assert_none("columns out of use");
}

/// Pat adds "remind at" to pending connections and writes it in the save
/// query but forgets the select; a column is read and never written; a
/// column nothing names. The check names each.
#[cfg_attr(test, test)]
pub(crate) fn the_column_check_finds_its_planted_break() {
    let schema = [planted(
        "0001_reminders.sql",
        "CREATE TABLE reminders (\n    id uuid PRIMARY KEY,\n    remind_at timestamptz NOT NULL,\n    \
         note text,\n    forgotten text,\n    kept text, -- not read by the app: kept for operators\n    \
         created_at timestamptz NOT NULL DEFAULT now()\n);",
    )];
    let queries = [
        QueryFile::planted(
            "queries/reminders/save.sql",
            "INSERT INTO reminders (id, remind_at) VALUES ($1, $2)\n\
             ON CONFLICT (id) DO UPDATE SET remind_at = EXCLUDED.remind_at",
        ),
        QueryFile::planted(
            "queries/reminders/find.sql",
            "SELECT id, note, created_at FROM reminders WHERE id = $1",
        ),
    ];
    let columns = columns(&schema);

    let found = columns_out_of_use(&columns, &usage(&columns, &queries));

    let lines = found.lines();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[0].contains("`reminders.remind_at` is written by queries/reminders/save.sql"));
    assert!(lines[1].contains("`reminders.note` is read by queries but no query writes it"));
    assert!(lines[2].contains("`reminders.forgotten` is named by no query"));
    assert!(lines[0].starts_with("0001_reminders.sql:3:"));
}

/// The migrations' columns follow their changes: an added column, a
/// renamed one, a dropped one and a dropped table.
#[cfg_attr(test, test)]
pub(crate) fn columns_follow_the_migrations_changes() {
    let schema = [
        planted(
            "0001_notes.sql",
            "CREATE TABLE notes (id uuid PRIMARY KEY, body text, CONSTRAINT notes_body CHECK (body <> ''));\n\
             CREATE TABLE drafts (id uuid PRIMARY KEY);",
        ),
        planted(
            "0002_notes_more.sql",
            "ALTER TABLE notes ADD COLUMN pinned boolean NOT NULL DEFAULT false,\n    \
             ADD COLUMN title text;\nALTER TABLE notes RENAME COLUMN body TO text;\n\
             ALTER TABLE notes DROP COLUMN title;\nDROP TABLE drafts;",
        ),
    ];

    let found: Vec<(String, String, bool)> = columns(&schema)
        .into_iter()
        .map(|column| (column.table, column.name, column.defaulted))
        .collect();

    assert_eq!(
        found,
        [
            ("notes".to_owned(), "id".to_owned(), false),
            ("notes".to_owned(), "text".to_owned(), false),
            ("notes".to_owned(), "pinned".to_owned(), true),
        ]
    );
}

/// A default written as quoted text holding commas, such as a JSON value,
/// is part of its one column: `layout` is read as one column, not as
/// `layout` and a column called `"value":`.
#[cfg_attr(test, test)]
pub(crate) fn a_quoted_default_with_commas_is_one_column() {
    let schema = [planted(
        "0001_versions.sql",
        "CREATE TABLE versions (\n    id uuid PRIMARY KEY,\n    \
         layout jsonb NOT NULL DEFAULT '{\"v\": 1, \"value\": []}',\n    name text\n);",
    )];

    let found: Vec<String> = columns(&schema)
        .into_iter()
        .map(|column| column.name)
        .collect();

    assert_eq!(found, ["id", "layout", "name"]);
}
