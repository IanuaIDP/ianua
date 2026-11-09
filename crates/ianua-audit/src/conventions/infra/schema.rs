//! The schema, read from `schema/`, the database as it should be, so a
//! table that would leak or drift fails the build before it reaches a
//! database. The migrations are generated from it and may write a table's
//! keys and policies as separate statements, so the shape rules read the
//! schema; the sequence and the ban on logic are checked on the migrations
//! themselves, since those are what run.
//!
//! - **Every tenant table is under row-level security.** A table with a
//!   `tenant_id` column has it switched on, forced, so its owner is held to
//!   it too, and a policy that asks [`TENANT_POLICY`] of its `tenant_id`.
//! - **No logic in the database.** No migration makes a function, a
//!   procedure, a trigger or an anonymous `DO` block: every rule lives in
//!   Rust, where it is read, tested and changed with the code that relies
//!   on it.
//! - **Every table has a primary key.** A row a store cannot name is a row
//!   it cannot update or delete exactly.
//! - **Migrations run in one plain sequence.** Each file is
//!   `NNNN_name.sql`, the numbers run 1, 2, 3 with no gap and no repeat,
//!   and the name is lower case words joined by `_`.

use std::fs;

use crate::conventions::infra::source::Findings;

/// One migration file: its name, its text as written, and its SQL with the
/// comments left out.
pub(crate) struct Migration {
    /// The file's name, such as `0003_platform_tenants.sql`.
    pub name: String,
    /// The file as written, comments included.
    pub text: String,
    /// The file's SQL, its comments left out.
    pub sql: String,
}

/// A table a migration creates, with the text of its definition.
pub(crate) struct Table {
    /// The table's name.
    pub name: String,
    /// The definition between `CREATE TABLE name (` and its closing `);`.
    pub body: String,
    /// The migration that creates it.
    pub file: String,
}

/// Every migration, in the order of its file name.
pub(crate) fn migrations() -> Vec<Migration> {
    sql_files("migrations")
}

/// Every file of the schema, the database as it should be, in the order of
/// its file name.
pub(crate) fn schema() -> Vec<Migration> {
    sql_files("schema")
}

/// Every `.sql` file in the infrastructure crate's folder `folder`, in the
/// order of its file name.
fn sql_files(folder: &str) -> Vec<Migration> {
    let dir = crate::conventions::crate_dir("ianua-infra").join(folder);
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<Migration> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .map(|path| {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            planted(
                &name,
                &fs::read_to_string(&path).expect("a migration is readable"),
            )
        })
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// A migration named `name` holding `text`, as read or made up for a test.
pub(crate) fn planted(name: &str, text: &str) -> Migration {
    Migration {
        name: name.to_owned(),
        text: text.to_owned(),
        sql: without_comments(text),
    }
}

/// `sql` without its `--` comments, so a word in a comment is never read
/// as part of the SQL.
pub(crate) fn without_comments(sql: &str) -> String {
    sql.lines()
        .map(|line| line.split_once("--").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `sql` on one line, single spaced, so words are found wherever they wrap.
pub(crate) fn flat(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The tables `migrations` create.
pub(crate) fn tables(migrations: &[Migration]) -> Vec<Table> {
    migrations
        .iter()
        .flat_map(|migration| {
            migration
                .sql
                .split("CREATE TABLE")
                .skip(1)
                .filter_map(|rest| {
                    let name = rest.split_whitespace().find(|word| {
                        !matches!(word.to_uppercase().as_str(), "IF" | "NOT" | "EXISTS")
                    })?;
                    Some(Table {
                        name: name.trim_matches(|c: char| c == '(' || c == '"').to_owned(),
                        body: rest.split(");").next()?.to_owned(),
                        file: migration.name.clone(),
                    })
                })
        })
        .collect()
}

/// The names of the tables `migrations` create.
pub(crate) fn table_names(migrations: &[Migration]) -> Vec<String> {
    tables(migrations)
        .into_iter()
        .map(|table| table.name)
        .collect()
}

/// The names of the tables `migrations` create with a `tenant_id` column.
pub(crate) fn tenant_tables_in(migrations: &[Migration]) -> Vec<String> {
    tables(migrations)
        .into_iter()
        .filter(|table| table.body.contains("tenant_id"))
        .map(|table| table.name)
        .collect()
}

/// The names of the tenant tables of the real migrations.
pub(crate) fn tenant_tables() -> Vec<String> {
    tenant_tables_in(&schema())
}

/// What a tenant table's policy asks of its `tenant_id`: the row is the
/// tenant's the transaction was given, or the transaction spans tenants.
pub(crate) const TENANT_POLICY: &str = "(tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR current_setting('app.platform_scope', true) = 'on')";

/// What a migration may never make: logic kept in the database.
const DATABASE_LOGIC: &[&str] = &[
    "CREATE FUNCTION",
    "CREATE OR REPLACE FUNCTION",
    "CREATE PROCEDURE",
    "CREATE OR REPLACE PROCEDURE",
    "CREATE TRIGGER",
    "CREATE OR REPLACE TRIGGER",
    "CREATE RULE",
    "DO $$",
];

/// Migrations that keep logic in the database.
pub(crate) fn logic_in_the_database(migrations: &[Migration]) -> Findings {
    let mut findings = Findings::default();
    for migration in migrations {
        let sql = flat(&migration.sql).to_uppercase();
        for made in DATABASE_LOGIC {
            if sql.contains(made) {
                findings.flag_at(
                    &migration.name,
                    1,
                    format!("makes `{made}`; write the logic in Rust"),
                );
            }
        }
    }
    findings
}

/// Tenant tables missing row-level security: not switched on, not forced,
/// or with no policy asking [`TENANT_POLICY`].
pub(crate) fn tenant_tables_without_row_security(migrations: &[Migration]) -> Findings {
    let written: Vec<&str> = migrations
        .iter()
        .map(|migration| migration.sql.as_str())
        .collect();
    let every = flat(&written.join("\n"));
    let mut findings = Findings::default();
    for table in tables(migrations)
        .into_iter()
        .filter(|table| table.body.contains("tenant_id"))
    {
        let name = &table.name;
        let enabled = every.contains(&format!("ALTER TABLE {name} ENABLE ROW LEVEL SECURITY"));
        let forced = every.contains(&format!("ALTER TABLE {name} FORCE ROW LEVEL SECURITY"));
        let policy = every.split("CREATE POLICY").skip(1).any(|policy| {
            let policy = policy.split(';').next().unwrap_or_default();
            policy.contains(&format!(" ON {name} ")) && policy.contains(TENANT_POLICY)
        });
        if !(enabled && forced && policy) {
            findings.flag_at(
                &table.file,
                1,
                format!(
                    "`{name}` has a `tenant_id` but no row-level security switched on, forced, \
                     and a policy asking {TENANT_POLICY}"
                ),
            );
        }
    }
    findings
}

/// Tables created without a primary key.
pub(crate) fn tables_without_a_primary_key(migrations: &[Migration]) -> Findings {
    let mut findings = Findings::default();
    for table in tables(migrations)
        .into_iter()
        .filter(|table| !table.body.contains("PRIMARY KEY"))
    {
        findings.flag_at(
            &table.file,
            1,
            format!("`{}` has no primary key", table.name),
        );
    }
    findings
}

/// Migrations not named `NNNN_name.sql`, or numbered out of sequence.
pub(crate) fn migrations_out_of_sequence(migrations: &[Migration]) -> Findings {
    let mut findings = Findings::default();
    for (expected, migration) in (1_u32..).zip(migrations) {
        let Some((number, name)) = migration
            .name
            .strip_suffix(".sql")
            .and_then(|stem| stem.split_once('_'))
        else {
            findings.flag_at(&migration.name, 1, "is not named `NNNN_name.sql`");
            continue;
        };
        let words = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if number.len() != 4 || number.parse::<u32>().ok() != Some(expected) || !words {
            findings.flag_at(
                &migration.name,
                1,
                format!("should be `{expected:04}_` followed by lower case words joined by `_`"),
            );
        }
    }
    findings
}

/// Stops: a tenant's rows are read by another tenant because the table
/// was made without its row-level security.
#[cfg_attr(test, test)]
pub(crate) fn every_tenant_table_is_under_row_security() {
    tenant_tables_without_row_security(&schema())
        .assert_none("tenant tables without row-level security");
}

/// Stops: a row no store can name exactly.
#[cfg_attr(test, test)]
pub(crate) fn every_table_has_a_primary_key() {
    tables_without_a_primary_key(&schema()).assert_none("tables without a primary key");
}

/// Stops: two migrations share a number, or one is skipped, and the
/// schema depends on the order they happened to be read in.
#[cfg_attr(test, test)]
pub(crate) fn migrations_run_in_one_plain_sequence() {
    migrations_out_of_sequence(&migrations()).assert_none("migrations out of sequence");
}

/// Stops: a rule kept in a database function, where no Rust test reads it
/// and nobody changing the code sees it.
#[cfg_attr(test, test)]
pub(crate) fn no_migration_keeps_logic_in_the_database() {
    logic_in_the_database(&migrations()).assert_none("logic kept in the database");
}

/// Each schema check finds the break planted for it, so a check that
/// silently matches nothing fails here.
#[cfg_attr(test, test)]
pub(crate) fn every_schema_check_finds_its_planted_break() {
    let leaking = [planted(
        "0001_notes.sql",
        "CREATE TABLE notes (id uuid PRIMARY KEY, tenant_id uuid NOT NULL);\n\
         ALTER TABLE notes ENABLE ROW LEVEL SECURITY;",
    )];
    let keyless = [planted(
        "0001_notes.sql",
        "CREATE TABLE notes (body text NOT NULL);",
    )];
    let skipped = [
        planted("0001_notes.sql", ""),
        planted("0003_more_notes.sql", ""),
        planted("0004_Notes.sql", ""),
    ];

    assert_eq!(tenant_tables_in(&leaking), ["notes"]);
    assert!(!tenant_tables_without_row_security(&leaking).is_empty());
    assert!(!tables_without_a_primary_key(&keyless).is_empty());
    assert!(!migrations_out_of_sequence(&skipped).is_empty());
    let logic = [planted(
        "0001_notes.sql",
        "CREATE FUNCTION purge(t uuid) RETURNS void LANGUAGE sql AS $$ SELECT 1 $$;",
    )];
    assert!(!logic_in_the_database(&logic).is_empty());
}
