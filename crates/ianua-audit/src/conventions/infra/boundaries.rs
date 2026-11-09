//! What keeps an adapter an adapter: the outside world stays outside the
//! ports, and every call out is bounded.
//!
//! - **Errors keep their cause.** An infra error becomes a `DomainError`
//!   through the crate's own mapping, never through `to_string()`, which
//!   throws the cause away.
//! - **No panics in adapters.** No `unwrap()` or `expect(..)` outside tests,
//!   unless the line above says why it cannot fail.
//! - **Stores never hold a connection of their own.** Only the Postgres
//!   foundation takes connections from the pool or opens transactions; a
//!   store asks the unit of work, so its writes join the running unit and
//!   run under row-level security for its tenant.
//! - **SQL is checked when it compiles.** Stores use `sqlx::query!` and its
//!   siblings. The plain functions, which take any string, are left to the
//!   paging helper, which binds every value. No SQL is built with
//!   `format!`.
//! - **Everything is bounded.** No unbounded channel, and no HTTP client
//!   without a timeout.

use crate::conventions::infra::source::{Findings, SourceFile, production_files};

/// The Postgres foundation: the only folder whose files touch the pool,
/// open transactions or run plain SQL strings.
const POSTGRES_FOUNDATION: &str = "postgres/foundation/";

/// Files that build SQL with `format!`, with the reason.
const SQL_BUILT_ALLOWED: &[(&str, &str)] = &[
    (
        "postgres/foundation/roles.rs",
        "a role's name cannot be bound as a value; it is checked against the names the platform makes and quoted",
    ),
    (
        "postgres/foundation/tenant_databases/schemas.rs",
        "a schema's name cannot be bound as a value; it is made from the tenant's id, checked against that shape and quoted",
    ),
    (
        "postgres/foundation/tenant_databases/purge.rs",
        "a table's name cannot be bound as a value; it comes from the database's catalog and is quoted",
    ),
    (
        "postgres/foundation/tenant_databases/trail.rs",
        "a schema's name cannot be bound as a value; it comes checked and quoted from `TenantSchema`",
    ),
];

/// Calls that take a connection or open a transaction.
const CONNECTION_CALLS: &[&str] = &[".acquire(", ".begin(", ".begin_with("];

/// What a file that reaches the database names: its pool, its connections
/// or its queries.
const DATABASE_NAMES: &[&str] = &["sqlx", "PgPool", "PgConnection", "Databases"];

/// The plain SQL functions, which take any string.
const PLAIN_SQL: &[&str] = &[
    "sqlx::query(",
    "sqlx::query_as(",
    "sqlx::query_scalar(",
    "sqlx::query_with(",
    "sqlx::raw_sql(",
];

/// Words that mark a string as SQL.
const SQL_WORDS: &[&str] = &["SELECT ", "INSERT ", "UPDATE ", "DELETE ", " WHERE "];

/// Constructors of outbound clients without a timeout.
const UNBOUNDED_CLIENTS: &[&str] = &["reqwest::Client::new(", "Client::new()", "reqwest::get("];

/// Readers of certificate PEM that never end on a cut-off certificate: the
/// streaming reader `der` puts behind `from_pem`, which the chain reader
/// calls too. Every certificate is read through `crypto::certificates::pem`.
const LOOPING_PEM_READERS: &[&str] = &["Certificate::from_pem(", "load_pem_chain(", "DecodePem"];

/// Unbounded queues.
const UNBOUNDED_QUEUES: &[&str] = &["unbounded_channel", "mpsc::unbounded", "unbounded()"];

/// Errors turned into text, losing their cause.
pub(crate) fn errors_turned_into_text(files: &[SourceFile]) -> Findings {
    lines_matching(
        &every(files),
        |line| line.contains("map_err(") && line.contains("to_string()"),
        "turns an error into text; map it through the crate's error mapping to keep its cause",
    )
}

/// `unwrap()` and `expect(..)` with no reason given above them.
pub(crate) fn unexplained_panics(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let lines = file.lines_before_tests();
        for (index, line) in lines.iter().enumerate() {
            let panics = line.contains(".unwrap()") || line.contains(".expect(");
            if panics && !reasoned_above(&lines, index) {
                findings.flag_line(
                    file,
                    index + 1,
                    "may panic; return an error, or say above why it cannot fail",
                );
            }
        }
    }
    findings
}

/// Connections and transactions taken outside the Postgres foundation, in
/// files that reach the database. A file that names no pool, connection
/// or query, such as a sandbox runner waiting on its run slots, takes no
/// database connection, whatever it acquires.
pub(crate) fn connections_outside_the_foundation(files: &[SourceFile]) -> Findings {
    let outside: Vec<&SourceFile> = outside_foundation(files)
        .into_iter()
        .filter(|file| {
            file.lines()
                .iter()
                .any(|line| DATABASE_NAMES.iter().any(|name| line.contains(name)))
        })
        .collect();
    lines_matching(
        &outside,
        |line| CONNECTION_CALLS.iter().any(|call| line.contains(call)),
        "takes a connection of its own; ask the unit of work",
    )
}

/// SQL that is not checked when it compiles, outside the paging helper.
pub(crate) fn unchecked_sql(files: &[SourceFile]) -> Findings {
    let outside = outside_foundation(files);
    let mut findings = lines_matching(
        &outside,
        |line| PLAIN_SQL.iter().any(|call| line.contains(call)),
        "runs a plain SQL string; use `sqlx::query!` or the paging helper",
    );
    let building: Vec<&SourceFile> = files
        .iter()
        .filter(|file| !SQL_BUILT_ALLOWED.iter().any(|(path, _)| *path == file.path))
        .collect();
    let built = lines_matching(
        &building,
        |line| {
            line.contains("format!(")
                && SQL_WORDS
                    .iter()
                    .any(|word| line.to_uppercase().contains(word))
        },
        "builds SQL with `format!`; bind the values instead",
    );
    findings.extend(built);
    findings
}

/// Unbounded queues, outbound clients without a timeout, and certificate
/// readers that can run for ever.
pub(crate) fn unbounded_resources(files: &[SourceFile]) -> Findings {
    let all = every(files);
    let mut findings = lines_matching(
        &all,
        |line| UNBOUNDED_QUEUES.iter().any(|queue| line.contains(queue)),
        "an unbounded queue; give it a capacity",
    );
    let clients = lines_matching(
        &all,
        |line| UNBOUNDED_CLIENTS.iter().any(|client| line.contains(client)),
        "an outbound client without a timeout; build it with one",
    );
    findings.extend(clients);
    let readers = lines_matching(
        &all,
        |line| {
            LOOPING_PEM_READERS
                .iter()
                .any(|reader| line.contains(reader))
        },
        "a PEM reader that never ends on a cut-off certificate; read it through crypto::certificates::pem",
    );
    findings.extend(readers);
    findings
}

fn every(files: &[SourceFile]) -> Vec<&SourceFile> {
    files.iter().collect()
}

fn outside_foundation(files: &[SourceFile]) -> Vec<&SourceFile> {
    files
        .iter()
        .filter(|file| !file.path.starts_with(POSTGRES_FOUNDATION))
        .collect()
}

/// Every line before the tests of `files` that `matches`, flagged with
/// `message`.
fn lines_matching(
    files: &[&SourceFile],
    matches: impl Fn(&str) -> bool,
    message: &str,
) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for (index, line) in file.lines_before_tests().iter().enumerate() {
            if matches(line) && !is_doc(line) {
                findings.flag_line(file, index + 1, message);
            }
        }
    }
    findings
}

fn is_doc(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("///") || trimmed.starts_with("//!")
}

/// Whether the line above `index` is a comment saying why it cannot fail.
fn reasoned_above(lines: &[&str], index: usize) -> bool {
    index
        .checked_sub(1)
        .and_then(|above| lines.get(above))
        .is_some_and(|line| line.trim_start().starts_with("// "))
}

/// A file breaking every boundary once.
const PLANTED: &str = r#"
fn load(pool: &PgPool) -> Result<User, DomainError> {
    let mut connection = pool.acquire().await.map_err(|error| DomainError::infra_msg(error.to_string()))?;
    let row = sqlx::query("SELECT * FROM users").fetch_one(&mut *connection).await.unwrap();
    let sql = format!("SELECT * FROM users WHERE id = {id}");
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let client = reqwest::Client::new();
    let anchor = Certificate::from_pem(pem.as_bytes());
}
"#;

/// An error turned into text loses its cause.
#[cfg_attr(test, test)]
pub(crate) fn no_error_is_turned_into_text() {
    errors_turned_into_text(&production_files()).assert_none("errors turned into text");
}

/// Stops: an adapter panics on a database hiccup and takes the request
/// down with it.
#[cfg_attr(test, test)]
pub(crate) fn no_adapter_panics_without_a_reason() {
    unexplained_panics(&production_files()).assert_none("unexplained panics");
}

/// Stops: a store writes on a connection of its own, outside the running
/// unit, so its write is kept when the unit rolls back, and runs without
/// the tenant's row-level security.
#[cfg_attr(test, test)]
pub(crate) fn no_store_takes_a_connection_of_its_own() {
    connections_outside_the_foundation(&production_files())
        .assert_none("connections outside the foundation");
}

/// Stops: a value pasted into SQL becomes an injection, and a typo in a
/// query is only found when it runs.
#[cfg_attr(test, test)]
pub(crate) fn every_query_is_checked_when_it_compiles() {
    unchecked_sql(&production_files()).assert_none("unchecked SQL");
}

/// Stops: a hung upstream or a flood fills memory or holds a task forever.
#[cfg_attr(test, test)]
pub(crate) fn every_queue_and_client_is_bounded() {
    unbounded_resources(&production_files()).assert_none("unbounded queues and clients");
}

/// Each boundary check finds the break planted for it, so a check that
/// silently matches nothing fails here.
#[cfg_attr(test, test)]
pub(crate) fn every_boundary_check_finds_its_planted_break() {
    let files = [SourceFile::planted("postgres/identity/users.rs", PLANTED)];

    assert!(!errors_turned_into_text(&files).is_empty());
    assert!(!unexplained_panics(&files).is_empty());
    assert!(!connections_outside_the_foundation(&files).is_empty());
    assert!(
        connections_outside_the_foundation(&[SourceFile::planted(
            "sandbox/planted.rs",
            "async fn run(slots: &Semaphore) {\n    let _slot = slots.acquire().await;\n}\n",
        )])
        .is_empty()
    );
    assert!(!unchecked_sql(&files).is_empty());
    assert!(!unbounded_resources(&files).is_empty());
}
