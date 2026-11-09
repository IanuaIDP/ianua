//! How tables point at each other, read from the schema, so a link the
//! database cannot keep honest fails the build.
//!
//! - **A link never crosses tenants.** A foreign key from one tenant table
//!   to another includes `tenant_id`, so a row can only ever point at a row
//!   of its own tenant, whatever the code does.
//! - **Every link says what a delete does.** Each foreign key states
//!   `ON DELETE CASCADE`, `RESTRICT` or `SET NULL`, chosen from the
//!   domain's rules, never left to the default.
//! - **Every link is indexed.** Its columns lead an index, the primary key
//!   or a unique constraint; Postgres does not add one itself, and without
//!   it every delete of a parent reads the whole child table.
//! - **Every id column is a link or says why not.** A `uuid` column named
//!   `…_id` is a foreign key, or the comment above it starts
//!   `-- no foreign key:` and gives the reason, such as a table in another
//!   database. An id that quietly points somewhere is how orphans pile up.

use crate::conventions::infra::schema::{
    Migration, Table, flat, planted, schema, tables, tenant_tables_in,
};
use crate::conventions::infra::source::Findings;

/// A foreign key: the table and columns it starts from, the table it
/// points at, and what follows `REFERENCES`.
struct Link {
    table: String,
    columns: Vec<String>,
    target: String,
    clause: String,
    file: String,
}

/// The columns of a primary key, a unique constraint or an index of a table.
struct Key {
    table: String,
    columns: Vec<String>,
}

/// A column of a table, with its type.
struct Column {
    name: String,
    kind: String,
}

/// The parts of a table's definition, split at the commas between them.
fn entries(body: &str) -> Vec<String> {
    let inner = body.split_once('(').map_or("", |(_, inner)| inner);
    let mut parts = Vec::new();
    let mut depth = 0_i32;
    let mut current = String::new();
    for c in inner.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(flat(&current));
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    parts.push(flat(&current));
    parts
        .into_iter()
        .map(|part| match part.strip_prefix("CONSTRAINT ") {
            Some(named) => named
                .split_once(' ')
                .map_or(String::new(), |(_, rest)| rest.to_owned()),
            None => part,
        })
        .filter(|part| !part.is_empty())
        .collect()
}

/// The names in the first bracketed list of `text`, such as `(a, b)`.
fn bracketed(text: &str) -> Vec<String> {
    let Some((_, rest)) = text.split_once('(') else {
        return Vec::new();
    };
    let inside = rest.split_once(')').map_or(rest, |(inside, _)| inside);
    inside
        .split(',')
        .filter_map(|name| name.split_whitespace().next())
        .map(|name| name.trim_matches('"').to_owned())
        .collect()
}

/// The table a `REFERENCES …` clause points at, and the clause itself.
fn target_of(text: &str) -> Option<(String, String)> {
    let (_, clause) = text.split_once("REFERENCES ")?;
    let target = clause
        .split_whitespace()
        .next()?
        .trim_matches('(')
        .to_owned();
    Some((target, clause.to_owned()))
}

/// The columns of `table`.
fn columns_of(table: &Table) -> Vec<Column> {
    entries(&table.body)
        .iter()
        .filter(|entry| {
            !["PRIMARY KEY", "UNIQUE", "FOREIGN KEY", "CHECK", "EXCLUDE"]
                .iter()
                .any(|start| entry.starts_with(start))
        })
        .filter_map(|entry| {
            let mut words = entry.split_whitespace();
            Some(Column {
                name: words.next()?.trim_matches('"').to_owned(),
                kind: words.next()?.to_lowercase(),
            })
        })
        .collect()
}

/// Every foreign key `migrations` make: in a table's columns, in its
/// constraints, and added later with `ALTER TABLE`.
fn links(migrations: &[Migration]) -> Vec<Link> {
    let mut found = table_links(migrations);
    found.extend(altered_links(migrations));
    found
}

/// The foreign keys `migrations` declare inside a table's definition.
fn table_links(migrations: &[Migration]) -> Vec<Link> {
    let mut found = Vec::new();
    for table in tables(migrations) {
        for entry in entries(&table.body) {
            let columns = match entry.strip_prefix("FOREIGN KEY") {
                Some(rest) => bracketed(rest),
                None => entry
                    .split_whitespace()
                    .next()
                    .map(|name| vec![name.to_owned()])
                    .unwrap_or_default(),
            };
            if let Some((target, clause)) = target_of(&entry) {
                found.push(Link {
                    table: table.name.clone(),
                    columns,
                    target,
                    clause,
                    file: table.file.clone(),
                });
            }
        }
    }
    found
}

/// The foreign keys `migrations` add to a table later with `ALTER TABLE`.
fn altered_links(migrations: &[Migration]) -> Vec<Link> {
    let mut found = Vec::new();
    for migration in migrations {
        for statement in flat(&migration.sql).split(';') {
            let Some(altered) = statement.trim().strip_prefix("ALTER TABLE ") else {
                continue;
            };
            let Some((_, added)) = altered.split_once("FOREIGN KEY") else {
                continue;
            };
            let Some((target, clause)) = target_of(added) else {
                continue;
            };
            found.push(Link {
                table: altered
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
                columns: bracketed(added),
                target,
                clause,
                file: migration.name.clone(),
            });
        }
    }
    found
}

/// Every primary key, unique constraint and whole-table index
/// `migrations` make. A partial index is left out: it holds only some rows,
/// so a delete of a parent cannot rely on it.
fn keys(migrations: &[Migration]) -> Vec<Key> {
    let mut found = table_keys(migrations);
    found.extend(index_keys(migrations));
    found
}

/// The primary keys and unique constraints `migrations` declare inside a
/// table's definition.
fn table_keys(migrations: &[Migration]) -> Vec<Key> {
    let mut found = Vec::new();
    for table in tables(migrations) {
        for entry in entries(&table.body) {
            let columns = if entry.starts_with("PRIMARY KEY") || entry.starts_with("UNIQUE") {
                bracketed(&entry)
            } else if entry.contains(" PRIMARY KEY") || entry.contains(" UNIQUE") {
                entry
                    .split_whitespace()
                    .next()
                    .map(|name| vec![name.to_owned()])
                    .unwrap_or_default()
            } else {
                continue;
            };
            found.push(Key {
                table: table.name.clone(),
                columns,
            });
        }
    }
    found
}

/// The whole-table indexes `migrations` make; a partial index is left out.
fn index_keys(migrations: &[Migration]) -> Vec<Key> {
    let mut found = Vec::new();
    for migration in migrations {
        for statement in flat(&migration.sql).split(';') {
            let Some((_, rest)) = statement.split_once(" INDEX ") else {
                continue;
            };
            let Some((_, on)) = rest.split_once(" ON ") else {
                continue;
            };
            if on.contains(" WHERE ") {
                continue;
            }
            found.push(Key {
                table: on.split_whitespace().next().unwrap_or_default().to_owned(),
                columns: bracketed(on),
            });
        }
    }
    found
}

/// Whether `columns` are, in any order, the leading columns of `key`.
fn leads(key: &Key, columns: &[String]) -> bool {
    key.columns.len() >= columns.len()
        && columns.iter().all(|column| {
            key.columns
                .iter()
                .take(columns.len())
                .any(|held| held == column)
        })
}

/// Foreign keys between tenant tables that leave out `tenant_id`.
pub(crate) fn links_across_tenants(migrations: &[Migration]) -> Findings {
    let tenant_tables = tenant_tables_in(migrations);
    let mut findings = Findings::default();
    for link in links(migrations).iter().filter(|link| {
        tenant_tables.contains(&link.table)
            && tenant_tables.contains(&link.target)
            && !link.columns.iter().any(|column| column == "tenant_id")
    }) {
        findings.flag_at(
            &link.file,
            1,
            format!(
                "`{}` points at `{}` without `tenant_id`; link `(tenant_id, …)` so a row cannot reach another tenant's",
                link.table, link.target
            ),
        );
    }
    findings
}

/// Foreign keys that leave what a delete does to the default.
pub(crate) fn links_without_a_delete_rule(migrations: &[Migration]) -> Findings {
    let mut findings = Findings::default();
    for link in links(migrations)
        .iter()
        .filter(|link| !link.clause.contains("ON DELETE"))
    {
        findings.flag_at(
            &link.file,
            1,
            format!(
                "`{}` points at `{}` without `ON DELETE`; say whether a delete cascades, is refused or empties the link",
                link.table, link.target
            ),
        );
    }
    findings
}

/// Foreign keys whose columns lead no index.
pub(crate) fn links_without_an_index(migrations: &[Migration]) -> Findings {
    let keys = keys(migrations);
    let mut findings = Findings::default();
    for link in links(migrations).iter().filter(|link| {
        !keys
            .iter()
            .any(|key| key.table == link.table && leads(key, &link.columns))
    }) {
        findings.flag_at(
            &link.file,
            1,
            format!(
                "`{}` ({}) points at `{}` but no index leads with those columns",
                link.table,
                link.columns.join(", "),
                link.target
            ),
        );
    }
    findings
}

/// Whether the comment block right above the definition of `column` in
/// `text` gives a reason for having no foreign key.
fn explained(text: &str, column: &str) -> bool {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    lines.iter().enumerate().any(|(at, line)| {
        line.starts_with(&format!("{column} uuid"))
            && lines
                .iter()
                .take(at)
                .rev()
                .take_while(|above| above.starts_with("--"))
                .any(|above| above.starts_with("-- no foreign key:"))
    })
}

/// `uuid` columns named `…_id` that are no foreign key and say not why.
pub(crate) fn id_columns_without_a_link(migrations: &[Migration]) -> Findings {
    let links = links(migrations);
    let mut findings = Findings::default();
    for table in tables(migrations) {
        let text = migrations
            .iter()
            .find(|migration| migration.name == table.file)
            .map_or("", |migration| migration.text.as_str());
        for column in columns_of(&table).iter().filter(|column| {
            column.kind == "uuid"
                && column.name.ends_with("_id")
                && column.name != "tenant_id"
                && !links
                    .iter()
                    .any(|link| link.table == table.name && link.columns.contains(&column.name))
                && !explained(text, &column.name)
        }) {
            findings.flag_at(
                &table.file,
                1,
                format!(
                    "`{}.{}` is no foreign key; make it one, or say why above it with `-- no foreign key: …`",
                    table.name, column.name
                ),
            );
        }
    }
    findings
}

/// Stops: a row of one tenant points at another tenant's row, and the
/// database lets it.
#[cfg_attr(test, test)]
pub(crate) fn no_link_crosses_tenants() {
    links_across_tenants(&schema()).assert_none("links that can cross tenants");
}

/// Stops: a delete quietly takes rows with it, or quietly fails, because
/// nobody chose.
#[cfg_attr(test, test)]
pub(crate) fn every_link_says_what_a_delete_does() {
    links_without_a_delete_rule(&schema()).assert_none("links without a delete rule");
}

/// Stops: deleting one parent reads every row of the child table.
#[cfg_attr(test, test)]
pub(crate) fn every_link_is_indexed() {
    links_without_an_index(&schema()).assert_none("links without an index");
}

/// Stops: an id points at a row nobody keeps, and orphans pile up.
#[cfg_attr(test, test)]
pub(crate) fn every_id_column_is_a_link_or_says_why_not() {
    id_columns_without_a_link(&schema()).assert_none("id columns without a link");
}

/// Notes in folders linked by the folder's id alone, with no delete rule,
/// no index, and an author id with no link and no reason.
const LINKED_WRONG: &str = "CREATE TABLE folders (tenant_id uuid NOT NULL, id uuid PRIMARY KEY);\n\
         CREATE TABLE notes (\n\
             tenant_id uuid NOT NULL,\n\
             id uuid PRIMARY KEY,\n\
             folder_id uuid NOT NULL REFERENCES folders (id),\n\
             author_id uuid NOT NULL\n\
         );";

/// The same notes linked within the tenant, deleted with their folder,
/// indexed, and the author id's missing link explained.
const LINKED_RIGHT: &str = "CREATE TABLE folders (tenant_id uuid NOT NULL, id uuid PRIMARY KEY, UNIQUE (tenant_id, id));\n\
         CREATE TABLE notes (\n\
             tenant_id uuid NOT NULL,\n\
             id uuid PRIMARY KEY,\n\
             folder_id uuid NOT NULL,\n\
             -- no foreign key: authors live in another database.\n\
             author_id uuid NOT NULL,\n\
             FOREIGN KEY (tenant_id, folder_id) REFERENCES folders (tenant_id, id) ON DELETE CASCADE\n\
         );\n\
         CREATE INDEX notes_in_folder ON notes (tenant_id, folder_id);";

/// Each relationship check finds the break planted for it, and passes the
/// same schema written right, so a check that matches nothing or too much
/// fails here.
#[cfg_attr(test, test)]
pub(crate) fn every_relationship_check_finds_its_planted_break() {
    let wrong = [planted("0001_notes.sql", LINKED_WRONG)];
    let right = [planted("0001_notes.sql", LINKED_RIGHT)];

    assert!(!links_across_tenants(&wrong).is_empty());
    assert!(!links_without_a_delete_rule(&wrong).is_empty());
    assert!(!links_without_an_index(&wrong).is_empty());
    assert!(!id_columns_without_a_link(&wrong).is_empty());
    assert!(links_across_tenants(&right).is_empty());
    assert!(links_without_a_delete_rule(&right).is_empty());
    assert!(links_without_an_index(&right).is_empty());
    assert!(id_columns_without_a_link(&right).is_empty());
}
