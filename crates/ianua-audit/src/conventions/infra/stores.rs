//! The one shape every Postgres store has, so a store written later reads
//! like the ones before it.
//!
//! - **The mapping lives in `record.rs`.** A store `postgres/<context>/<store>.rs`
//!   keeps its row types in `<store>/record.rs`, which rebuilds an
//!   aggregate through its `reconstitute`, or a port's value through that
//!   value's own constructors, so a stored row passes the domain's checks
//!   and is never repaired. Only a store that reads nothing back has none.
//! - **Every JSON column has its shape pinned.** Each `Kept` column a
//!   mapper declares is sealed in that file's tests, against the shape it
//!   writes today.
//! - **Every store has tests**, and they arrange rows through the real
//!   stores. Raw SQL in a store's tests is the one way a test could write a
//!   row no store would, so it goes through `TestDb::tamper`, which says so.

use crate::conventions::infra::source::{Findings, SourceFile, infra_files};

/// The folder of the crate's own machinery.
const FOUNDATION: &str = "postgres/foundation/";

/// The plain SQL calls a store's tests must not make.
const RAW_SQL: &[&str] = &[
    "sqlx::query(",
    "sqlx::query_as(",
    "sqlx::query_scalar(",
    "sqlx::raw_sql(",
];

/// Whether `file` is a Postgres store: a file of a context folder holding a
/// `Pg…` adapter.
fn is_store(file: &SourceFile) -> bool {
    file.path.starts_with("postgres/")
        && !file.path.starts_with(FOUNDATION)
        && !file.path.ends_with("/mod.rs")
        && file
            .trait_impls()
            .iter()
            .any(|(_, adapter, _)| adapter.starts_with("Pg"))
}

/// The path of the mapper `store` keeps its rows in.
fn mapper_of(store: &SourceFile) -> String {
    format!(
        "{}/record.rs",
        store.path.strip_suffix(".rs").unwrap_or(&store.path)
    )
}

/// Stores that read no row back, so there is nothing to map, with the
/// reason. A store that reads anything back keeps a `record.rs`.
const READING_NOTHING_BACK: &[(&str, &str)] = &[
    (
        "postgres/runtime.rs",
        "pings the database for the readiness check and reads no row",
    ),
    (
        "postgres/agents/identity/assertions.rs",
        "a ledger of spent agent assertion ids that answers only whether an id was new; it reads no row back",
    ),
    (
        "postgres/organization/billing/events.rs",
        "a ledger of payment provider events that answers only whether an event was new and whether it is the newest of its kind; it reads no row back",
    ),
    (
        "postgres/shared/reactions.rs",
        "a ledger of the events the monitors acted on that answers only whether a note was new; it reads no row back",
    ),
    (
        "postgres/federation/saml_messages/taken_logouts.rs",
        "a ledger of taken logout request ids that answers only whether one was new; it reads no row back",
    ),
    (
        "postgres/routing/decisions.rs",
        "holds no SQL of its own; it reads through PgUserStore and PgRoleStore, whose mappers rebuild the rows, and answers a decision",
    ),
    (
        "postgres/limits/tenant.rs",
        "answers only how many rows a tenant holds of a kind, straight from one count; it rebuilds no row",
    ),
    (
        "postgres/limits/organization.rs",
        "answers only how many tenants or channels an organization holds, straight from one count; it rebuilds no row",
    ),
    (
        "postgres/tenant/copies.rs",
        "copies the parts of a clone through the stores of each context, whose own mappers read the rows back; it reads no row itself",
    ),
    (
        "postgres/organization/identity_providers/saml_assertions.rs",
        "a ledger of spent assertion ids that answers only whether an id was new; it reads no row back",
    ),
    (
        "postgres/oauth/proofs/assertions.rs",
        "a ledger of spent client assertion ids that answers only whether an id was new; it reads no row back",
    ),
    (
        "postgres/oauth/proofs/dpop.rs",
        "a ledger of spent DPoP proof ids that answers only whether a proof was new; it reads no row back",
    ),
    (
        "postgres/federation/saml/assertions.rs",
        "a ledger of spent assertion ids that answers only whether an id was new; it reads no row back",
    ),
    (
        "postgres/shared/existence/users.rs",
        "answers only yes or no, straight from one query; it reads no row back",
    ),
    (
        "postgres/shared/existence/principals.rs",
        "answers only yes or no, straight from one query per kind; it reads no row back",
    ),
    (
        "postgres/signals/suspended.rs",
        "reads back only the ids of the agents a stop suspended; it rebuilds no row",
    ),
    (
        "postgres/scheduling/sweeps.rs",
        "answers only whether a round's claim was the first; it reads no row back",
    ),
    (
        "postgres/agents/run/lease.rs",
        "answers only whether this worker holds a run's lease; it reads no row back",
    ),
    (
        "postgres/workflows/leases/execution.rs",
        "answers only whether this worker holds an execution's lease; it reads no row back",
    ),
    (
        "postgres/workflows/leases/grant.rs",
        "answers only whether a caller got an account's turn; it reads no row back",
    ),
    (
        "postgres/audit/retention.rs",
        "reads only the last expired link it purges up to, and answers a count; it rebuilds no row",
    ),
    (
        "postgres/audit/moves.rs",
        "reads back only the name of the schema a tenant lives in, and copies rows between tables; it rebuilds no row",
    ),
    (
        "postgres/tenant/databases.rs",
        "reads back only the names of the schemas tenants live in, checked as names, to route by; it rebuilds no row",
    ),
    (
        "postgres/scheduling/stalled.rs",
        "reads back only the ids of the work left half-done, for the sweep to hand out again; it rebuilds no row",
    ),
    (
        "postgres/tenant/purger.rs",
        "reads back only the name of the schema a tenant lives in, and removes rows; it rebuilds no row",
    ),
    (
        "postgres/routing/stream_records.rs",
        "the gateway writes stream records and its role may read none back; its `record.rs` holds only the columns it writes",
    ),
];

/// Stores that read their rows through another store's mapper, with that
/// mapper: a view of the same records, kept in step by sharing it.
const MAPPED_ELSEWHERE: &[(&str, &str)] = &[
    (
        "postgres/shared/labels/control_plane.rs",
        "postgres/shared/labels/record.rs",
    ),
    (
        "postgres/agents/oversight/activity.rs",
        "postgres/audit/logs/record.rs",
    ),
    (
        "postgres/notifications/inbox/operators.rs",
        "postgres/notifications/inbox/record.rs",
    ),
    (
        "postgres/notifications/inbox/members.rs",
        "postgres/notifications/inbox/record.rs",
    ),
    (
        "postgres/notifications/inbox/users.rs",
        "postgres/notifications/inbox/record.rs",
    ),
];

/// Whether `mapper` rebuilds what its rows hold: an aggregate through its
/// `reconstitute`, a port's value through that value's own constructors in
/// an `into_…` function, or the rows of another store's table through that
/// store's mapper (its `record` module), so each table keeps one mapping.
fn rebuilds(mapper: &SourceFile) -> bool {
    let code = mapper.code();
    code.contains("::reconstitute(") || code.contains("fn into_") || code.contains("::record::")
}

/// Stores without a `record.rs` rebuilding what they read back.
pub(crate) fn stores_without_a_mapper(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for store in files.iter().filter(|file| {
        is_store(file)
            && !READING_NOTHING_BACK
                .iter()
                .any(|(path, _)| *path == file.path)
    }) {
        let mapper = MAPPED_ELSEWHERE
            .iter()
            .find(|(path, _)| *path == store.path)
            .map_or_else(|| mapper_of(store), |(_, shared)| (*shared).to_owned());
        let mapped = files
            .iter()
            .find(|file| file.path == mapper)
            .is_some_and(rebuilds);
        if !mapped {
            findings.flag_file(
                store,
                format!(
                    "keeps no `{mapper}` rebuilding what it reads, through `reconstitute` or an `into_…` of the port's value"
                ),
            );
        }
    }
    findings
}

/// Stores without a test module.
pub(crate) fn stores_without_tests(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for store in files
        .iter()
        .filter(|file| is_store(file) && file.tests().is_empty())
    {
        findings.flag_file(store, "has no tests against Postgres");
    }
    findings
}

/// The names of the `Kept` columns `file` declares.
fn kept_columns(file: &SourceFile) -> Vec<String> {
    file.code()
        .lines()
        .filter_map(|line| {
            let declared = line.trim_start().split_once("const ")?.1;
            let (name, kind) = declared.split_once(':')?;
            kind.trim_start()
                .starts_with("Kept")
                .then(|| name.trim().to_owned())
        })
        .collect()
}

/// JSON columns whose stored shape no test pins.
pub(crate) fn kept_columns_without_a_pinned_shape(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let tests: String = file
            .tests()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        for column in kept_columns(file)
            .into_iter()
            .filter(|column| !tests.contains(&format!("{column}.seal(")))
        {
            findings.flag_file(
                file,
                format!("declares `{column}` but no test pins the shape it is sealed in"),
            );
        }
    }
    findings
}

/// Store tests that run plain SQL instead of going through the stores, or
/// through `TestDb::tamper` for a row no store would write.
pub(crate) fn raw_sql_in_store_tests(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files
        .iter()
        .filter(|file| file.path.starts_with("postgres/") && !file.path.starts_with(FOUNDATION))
    {
        if RAW_SQL.iter().any(|call| file.tests().contains(call)) {
            findings.flag_file(
                file,
                "runs plain SQL in its tests; arrange rows through the stores, and corrupt one with `TestDb::tamper`",
            );
        }
    }
    findings
}

/// A store breaking every shape rule once: no mapper, no tests, an
/// unpinned JSON column, and plain SQL in a test.
const PLANTED_STORE: &str = r#"
pub struct PgNoteStore;
impl NoteStore for PgNoteStore {}
"#;

const PLANTED_MAPPER: &str = r#"
const BODY: Kept = Kept { entity: "note", column: "body", shape: 1 };
fn note_from() {}
#[cfg(test)]
mod tests {
    fn arrange() { sqlx::query("INSERT INTO notes VALUES (1)"); }
}
"#;

/// Stops: a store maps rows in a way of its own, or skips the domain's
/// checks on the way in.
#[cfg_attr(test, test)]
pub(crate) fn every_store_keeps_its_mapping_in_a_record_file() {
    stores_without_a_mapper(&infra_files()).assert_none("stores without a mapper");
}

/// Stops: a store reaches production without running once against
/// Postgres.
#[cfg_attr(test, test)]
pub(crate) fn every_store_has_tests() {
    stores_without_tests(&infra_files()).assert_none("stores without tests");
}

/// Stops: the domain changes how it writes a value, and rows written
/// before can no longer be read.
#[cfg_attr(test, test)]
pub(crate) fn every_json_column_has_its_shape_pinned() {
    kept_columns_without_a_pinned_shape(&infra_files())
        .assert_none("JSON columns without a pinned shape");
}

/// Stops: a test writes rows past the stores without saying it means to.
#[cfg_attr(test, test)]
pub(crate) fn store_tests_go_through_the_stores() {
    raw_sql_in_store_tests(&infra_files()).assert_none("plain SQL in store tests");
}

/// Each store check finds the break planted for it, so a check that
/// silently matches nothing fails here.
#[cfg_attr(test, test)]
pub(crate) fn every_store_check_finds_its_planted_break() {
    let files = [
        SourceFile::planted("postgres/notes/notes.rs", PLANTED_STORE),
        SourceFile::planted("postgres/notes/notes/record.rs", PLANTED_MAPPER),
    ];

    assert!(!stores_without_a_mapper(&files).is_empty());
    assert!(!stores_without_tests(&files).is_empty());
    assert!(!kept_columns_without_a_pinned_shape(&files).is_empty());
    assert!(!raw_sql_in_store_tests(&files).is_empty());
}
