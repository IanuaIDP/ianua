//! The SQL itself: every query is read as written, so a slow or loose one
//! fails the build before it reaches a database.
//!
//! - **Name the columns.** No `SELECT *` and no `table.*`: a column added
//!   later is never read by accident, and the query reads only what the
//!   row needs.
//! - **Page by key, never by offset.** `OFFSET` reads and throws away every
//!   row before the page, so page 1,000 costs a thousand pages.
//! - **No leading wildcard.** `LIKE '%…'` can never use an index.
//! - **Every query on a tenant's table names the tenant.** A table with a
//!   `tenant_id` column is filtered by it, besides row-level security, so
//!   a missing filter is a bug here and not a scan of every tenant.
//! - **No read of a whole table.** A `SELECT` with neither `WHERE` nor
//!   `LIMIT` reads every row there is.
//! - **No query in a loop.** One query per item is a thousand round trips
//!   for a thousand items; read them in one query.
//!
//! And every store's SQL lives in files of its own:
//!
//! - **No SQL inside a store.** A store names a file under `queries/`; only
//!   the foundation writes SQL in Rust.
//! - **Every query file is used**, and says what it does in a comment on
//!   its first line.
//! - **Query files are grouped by table**: each folder under `queries/` is
//!   named after a table the migrations make.
//!
//! Whether each query can use an index is asked of Postgres itself, with
//! its plan, in the plan tests.

use std::fs;
use std::path::Path;

use syn::visit::{self, Visit};
use syn::{ExprForLoop, ExprMacro, ExprWhile, Macro, StmtMacro};

use crate::conventions::infra::schema::{
    self, Migration, planted, tenant_tables, tenant_tables_in, without_comments,
};
use crate::conventions::infra::source::{Findings, SourceFile, line_of, production_files};

/// The macros whose first string is checked SQL.
const QUERY_MACROS: &[&str] = &["query!(", "query_as!(", "query_scalar!("];

/// The macros that name a query file, by its path from the crate's root.
const QUERY_FILE_MACROS: &[&str] = &["query_file!(", "query_file_as!(", "query_file_scalar!("];

/// The folder of the crate's own machinery, whose SQL is written in Rust.
const FOUNDATION: &str = "postgres/foundation/";

/// A query file under `queries/`: its path from the crate's root, and its
/// text as written.
pub(crate) struct QueryFile {
    path: String,
    text: String,
}

/// A query as written: the file it is in, the line it starts on, and its
/// SQL.
pub(crate) struct Query {
    path: String,
    line: usize,
    sql: String,
}

/// Every query of `files`, and every query kept in a file of its own under
/// `queries/`.
pub(crate) fn every_query(files: &[SourceFile]) -> Vec<Query> {
    let mut found = written_inline(files);
    found.extend(query_files().iter().map(QueryFile::query));
    found
}

impl QueryFile {
    /// A query file at `path` holding `text`, as read or made up for a
    /// test.
    pub(crate) fn planted(path: &str, text: &str) -> Self {
        Self {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    /// Its path from the crate's root, such as `queries/users/find.sql`.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// Its SQL, its comments left out.
    pub(crate) fn sql(&self) -> String {
        without_comments(&self.text)
    }

    /// The query the file holds, its comments left out.
    fn query(&self) -> Query {
        Query {
            path: self.path.clone(),
            line: 1,
            sql: without_comments(&self.text),
        }
    }

    /// The folder under `queries/` the file sits in.
    fn table(&self) -> &str {
        self.path
            .strip_prefix("queries/")
            .and_then(|rest| rest.split_once('/'))
            .map_or("", |(table, _)| table)
    }
}

/// The queries written inside `files`, as the first string of a query
/// macro.
fn written_inline(files: &[SourceFile]) -> Vec<Query> {
    files.iter().flat_map(inline_queries).collect()
}

/// The SQL of every checked query written in `file`.
fn inline_queries(file: &SourceFile) -> Vec<Query> {
    let code = file.lines_before_tests().join("\n");
    let mut found = Vec::new();
    for marker in QUERY_MACROS {
        let mut from = 0;
        while let Some(at) = code[from..].find(marker) {
            let start = from + at + marker.len();
            if let Some(sql) = first_string(&code[start..]) {
                found.push(Query {
                    path: file.path.clone(),
                    line: code[..start].lines().count(),
                    sql,
                });
            }
            from = start;
        }
    }
    found
}

/// Every file under `queries/`.
pub(crate) fn query_files() -> Vec<QueryFile> {
    let root = crate::conventions::crate_dir("ianua-infra");
    let mut found = Vec::new();
    collect_sql(&root, &root.join("queries"), &mut found);
    found
}

fn collect_sql(root: &Path, dir: &Path, found: &mut Vec<QueryFile>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for path in entries.flatten().map(|entry| entry.path()) {
        if path.is_dir() {
            collect_sql(root, &path, found);
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "sql") {
            continue;
        }
        found.push(QueryFile {
            path: path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/"),
            text: fs::read_to_string(&path).expect("a query file is readable"),
        });
    }
}

/// SQL written inside a store instead of a file of its own.
pub(crate) fn sql_inside_stores(files: &[SourceFile]) -> Findings {
    let stores: Vec<SourceFile> = files
        .iter()
        .filter(|file| !file.path.starts_with(FOUNDATION))
        .map(|file| SourceFile::planted(&file.path, &file.lines().join("\n")))
        .collect();
    let mut findings = Findings::default();
    for query in written_inline(&stores) {
        findings.flag_at(
            &query.path,
            query.line,
            "writes its SQL inline; keep it in a file under `queries/` and name it with `query_file!`",
        );
    }
    findings
}

/// The query files `files` name, by their path from the crate's root.
fn named_query_files(files: &[SourceFile]) -> Vec<String> {
    let mut named = Vec::new();
    for file in files {
        let code = file.code();
        for marker in QUERY_FILE_MACROS {
            let mut from = 0;
            while let Some(at) = code[from..].find(marker) {
                let start = from + at + marker.len();
                named.extend(first_string(&code[start..]));
                from = start;
            }
        }
    }
    named
}

/// Query files nothing names.
pub(crate) fn unused_query_files(query_files: &[QueryFile], files: &[SourceFile]) -> Findings {
    let named = named_query_files(files);
    let mut findings = Findings::default();
    for file in query_files
        .iter()
        .filter(|file| !named.contains(&file.path))
    {
        findings.flag_at(&file.path, 1, "is named by no store; remove it or use it");
    }
    findings
}

/// Query files that do not open with a comment saying what they do.
pub(crate) fn unexplained_query_files(query_files: &[QueryFile]) -> Findings {
    let mut findings = Findings::default();
    for file in query_files
        .iter()
        .filter(|file| !file.text.trim_start().starts_with("--"))
    {
        findings.flag_at(&file.path, 1, "opens without a comment saying what it does");
    }
    findings
}

/// Query files in a folder not named after a table of `migrations`.
pub(crate) fn query_files_outside_their_table(
    query_files: &[QueryFile],
    migrations: &[Migration],
) -> Findings {
    let tables = schema::table_names(migrations);
    let mut findings = Findings::default();
    for file in query_files
        .iter()
        .filter(|file| !tables.iter().any(|table| table == file.table()))
    {
        findings.flag_at(
            &file.path,
            1,
            "sits in a folder no table is named after; group queries by the table they read",
        );
    }
    findings
}

/// Stores that take a transaction-level lock from a query file without
/// `scoped_holding`, so the unit could commit the lock before the writes it
/// guards in another database.
pub(crate) fn locks_outside_scoped_holding(
    query_files: &[QueryFile],
    files: &[SourceFile],
) -> Findings {
    let locking: Vec<&str> = query_files
        .iter()
        .filter(|file| file.text.contains("pg_advisory_xact_lock"))
        .map(|file| file.path.as_str())
        .collect();
    let mut findings = Findings::default();
    for file in files.iter().filter(|file| {
        let named = named_query_files(std::slice::from_ref(*file));
        named.iter().any(|path| locking.contains(&path.as_str()))
            && !file.code().contains("scoped_holding")
    }) {
        findings.flag_file(
            file,
            "takes an advisory lock outside `scoped_holding`; the lock may commit before the writes it guards",
        );
    }
    findings
}

/// The first string literal in `text`, plain or raw.
fn first_string(text: &str) -> Option<String> {
    let quote = text.find('"')?;
    let hashes = text[..quote]
        .chars()
        .rev()
        .take_while(|c| *c == '#')
        .count();
    let closing = format!("\"{}", "#".repeat(hashes));
    let body = &text[quote + 1..];
    let end = body.find(&closing)?;
    Some(body[..end].to_owned())
}

/// `sql` in upper case on one line, so words are found wherever they wrap.
fn flat(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
}

/// Queries that break a rule `breaks` describes.
fn queries_breaking(queries: &[Query], breaks: impl Fn(&str) -> Option<&'static str>) -> Findings {
    let mut findings = Findings::default();
    for query in queries {
        if let Some(message) = breaks(&flat(&query.sql)) {
            findings.flag_at(&query.path, query.line, message);
        }
    }
    findings
}

/// Queries reading every column, with `*` or `table.*`.
pub(crate) fn queries_reading_every_column(queries: &[Query]) -> Findings {
    queries_breaking(queries, |sql| {
        (sql.contains("SELECT *") || sql.contains(".*") || sql.contains("RETURNING *"))
            .then_some("reads `*`; name the columns the row needs")
    })
}

/// Queries paging by offset.
pub(crate) fn queries_paging_by_offset(queries: &[Query]) -> Findings {
    let held_to_it: Vec<&Query> = queries
        .iter()
        .filter(|query| {
            !OFFSET_ALLOWED
                .iter()
                .any(|(allowed, _)| allowed_by(&query.path, allowed))
        })
        .collect();
    let mut findings = Findings::default();
    for query in held_to_it {
        if flat(&query.sql).contains(" OFFSET ") {
            findings.flag_at(
                &query.path,
                query.line,
                "pages by `OFFSET`; page by key with the paging helper",
            );
        }
    }
    findings
}

/// Folders whose queries may page by `OFFSET`, with the reason.
const OFFSET_ALLOWED: &[(&str, &str)] = &[
    (
        "postgres/federation/scim/",
        "SCIM lists answer `startIndex` and `totalResults`, as RFC 7644 requires; `startIndex` is capped",
    ),
    (
        "queries/*/scim_",
        "the queries of the SCIM stores, filed under the table they read and named `scim_…`, for the same reason",
    ),
];

/// Where the one `OFFSET` builder, `WindowQuery`, may be used: the
/// foundation that defines it and the SCIM stores it exists for.
const WINDOW_QUERY_ALLOWED: &[&str] = &["postgres/foundation/", "postgres/federation/scim/"];

/// Files outside SCIM that page through the `OFFSET` builder.
pub(crate) fn windows_outside_scim(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files.iter().filter(|file| {
        file.code().contains("WindowQuery")
            && !WINDOW_QUERY_ALLOWED
                .iter()
                .any(|allowed| file.path.starts_with(allowed))
    }) {
        findings.flag_file(
            file,
            "pages by `OFFSET` through `WindowQuery`, which only SCIM may; page by key with `PageQuery`",
        );
    }
    findings
}

/// Whether `path` matches `allowed`, where a `*` in it stands for one
/// folder: `queries/*/scim_` matches `queries/users/scim_page.sql`.
fn allowed_by(path: &str, allowed: &str) -> bool {
    let Some((before, after)) = allowed.split_once('*') else {
        return path.starts_with(allowed);
    };
    path.strip_prefix(before)
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(_, file)| file.starts_with(after.trim_start_matches('/')))
}

/// Queries with a leading wildcard.
pub(crate) fn queries_with_a_leading_wildcard(queries: &[Query]) -> Findings {
    queries_breaking(queries, |sql| {
        (sql.contains("LIKE '%") || sql.contains("LIKE '%' ||"))
            .then_some("matches with a leading `%`, which no index serves")
    })
}

/// Queries reading a whole table: a `SELECT` with neither `WHERE` nor
/// `LIMIT`.
pub(crate) fn queries_reading_a_whole_table(queries: &[Query]) -> Findings {
    queries_breaking(queries, |sql| {
        let reads = sql.trim_start().starts_with("SELECT") || sql.trim_start().starts_with("WITH");
        (reads && sql.contains(" FROM ") && !sql.contains(" WHERE ") && !sql.contains(" LIMIT "))
            .then_some("reads a whole table; filter it or bound it")
    })
}

/// Queries on a tenant's table that never name the tenant.
pub(crate) fn queries_missing_the_tenant(queries: &[Query], tenant_tables: &[String]) -> Findings {
    let mut findings = Findings::default();
    for query in queries {
        let sql = flat(&query.sql);
        let touched = tenant_tables
            .iter()
            .find(|table| names_table(&sql, &table.to_uppercase()));
        if let Some(table) = touched.filter(|_| !sql.contains("TENANT_ID")) {
            findings.flag_at(
                &query.path,
                query.line,
                format!("touches `{table}` without its `tenant_id`; filter by the tenant"),
            );
        }
    }
    findings
}

/// Whether `sql` reads or writes `table`.
fn names_table(sql: &str, table: &str) -> bool {
    ["FROM ", "JOIN ", "UPDATE ", "INTO ", "DELETE FROM "]
        .iter()
        .any(|keyword| {
            sql.match_indices(&format!("{keyword}{table}"))
                .any(|(at, found)| {
                    sql[at + found.len()..]
                        .chars()
                        .next()
                        .is_none_or(|next| !(next.is_alphanumeric() || next == '_'))
                })
        })
}

/// Query macros run inside a loop.
pub(crate) fn queries_in_loops(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let Ok(parsed) = syn::parse_file(file.code()) else {
            continue;
        };
        let mut loops = LoopedQueries::default();
        loops.visit_file(&parsed);
        for line in loops.lines {
            findings.flag_line(file, line, "queries once per item; read them in one query");
        }
    }
    findings
}

/// The lines of query macros found inside loop bodies.
#[derive(Default)]
struct LoopedQueries {
    depth: usize,
    lines: Vec<usize>,
}

impl<'ast> Visit<'ast> for LoopedQueries {
    fn visit_expr_for_loop(&mut self, expr: &'ast ExprForLoop) {
        self.depth += 1;
        visit::visit_expr_for_loop(self, expr);
        self.depth -= 1;
    }

    fn visit_expr_while(&mut self, expr: &'ast ExprWhile) {
        self.depth += 1;
        visit::visit_expr_while(self, expr);
        self.depth -= 1;
    }

    fn visit_expr_macro(&mut self, expr: &'ast ExprMacro) {
        self.note(&expr.mac);
        visit::visit_expr_macro(self, expr);
    }

    fn visit_stmt_macro(&mut self, stmt: &'ast StmtMacro) {
        self.note(&stmt.mac);
        visit::visit_stmt_macro(self, stmt);
    }
}

impl LoopedQueries {
    /// Notes `mac` when it is a query macro inside a loop.
    fn note(&mut self, mac: &Macro) {
        let is_query = mac.path.segments.last().is_some_and(|name| {
            matches!(
                name.ident.to_string().as_str(),
                "query"
                    | "query_as"
                    | "query_scalar"
                    | "query_file"
                    | "query_file_as"
                    | "query_file_scalar"
            )
        });
        if is_query && self.depth > 0 {
            self.lines.push(line_of(mac));
        }
    }
}

/// A store breaking every SQL rule once.
const PLANTED: &str = r#"
async fn planted(tenant: TenantId, ids: Vec<UserId>) {
    sqlx::query!("SELECT * FROM users WHERE tenant_id = $1", tenant);
    sqlx::query!("SELECT id FROM users WHERE tenant_id = $1 ORDER BY id LIMIT 20 OFFSET 40", tenant);
    sqlx::query!("SELECT id FROM users WHERE tenant_id = $1 AND email LIKE '%' || $2", tenant);
    sqlx::query!("SELECT id FROM users");
    sqlx::query!("UPDATE users SET name = $1 WHERE id = $2");
    for id in ids {
        sqlx::query!("SELECT id FROM users WHERE tenant_id = $1 AND id = $2", tenant, id);
    }
}
"#;

/// Stops: a column added later is read by accident, and a query reads more
/// than the row needs.
#[cfg_attr(test, test)]
pub(crate) fn every_query_names_its_columns() {
    queries_reading_every_column(&every_query(&production_files()))
        .assert_none("queries reading every column");
}

/// Stops: a deep page reads and throws away every row before it.
#[cfg_attr(test, test)]
pub(crate) fn no_query_pages_by_offset() {
    queries_paging_by_offset(&every_query(&production_files()))
        .assert_none("queries paging by offset");
}

/// Stops: a search no index can serve scans the whole table.
#[cfg_attr(test, test)]
pub(crate) fn no_query_matches_with_a_leading_wildcard() {
    queries_with_a_leading_wildcard(&every_query(&production_files()))
        .assert_none("queries with a leading wildcard");
}

/// Stops: a query reads every row of a table.
#[cfg_attr(test, test)]
pub(crate) fn no_query_reads_a_whole_table() {
    queries_reading_a_whole_table(&every_query(&production_files()))
        .assert_none("queries reading a whole table");
}

/// Stops: a query on a tenant's table forgets the tenant and leans on
/// row-level security alone, or reads every tenant's rows.
#[cfg_attr(test, test)]
pub(crate) fn every_query_on_a_tenant_table_names_the_tenant() {
    queries_missing_the_tenant(&every_query(&production_files()), &tenant_tables())
        .assert_none("queries missing the tenant");
}

/// Stops: a thousand items cost a thousand round trips.
#[cfg_attr(test, test)]
pub(crate) fn no_query_runs_in_a_loop() {
    queries_in_loops(&production_files()).assert_none("queries in loops");
}

/// Each SQL check finds the break planted for it, so a check that silently
/// matches nothing fails here.
#[cfg_attr(test, test)]
pub(crate) fn every_sql_check_finds_its_planted_break() {
    let files = [SourceFile::planted("postgres/identity/users.rs", PLANTED)];
    let queries = written_inline(&files);
    let migrations = [planted(
        "0001_users.sql",
        "CREATE TABLE users (id uuid PRIMARY KEY, tenant_id uuid NOT NULL);",
    )];
    let tables = tenant_tables_in(&migrations);
    let stray = [QueryFile {
        path: "queries/people/by_id.sql".to_owned(),
        text: "SELECT id FROM users WHERE id = $1".to_owned(),
    }];

    assert_eq!(tables, ["users"]);
    assert!(!queries_reading_every_column(&queries).is_empty());
    assert!(!queries_paging_by_offset(&queries).is_empty());
    assert!(!queries_with_a_leading_wildcard(&queries).is_empty());
    assert!(!queries_reading_a_whole_table(&queries).is_empty());
    assert!(!queries_missing_the_tenant(&queries, &tables).is_empty());
    assert!(!queries_in_loops(&files).is_empty());
    assert!(!sql_inside_stores(&files).is_empty());
    assert!(!unused_query_files(&stray, &files).is_empty());
    assert!(!unexplained_query_files(&stray).is_empty());
    assert!(!query_files_outside_their_table(&stray, &migrations).is_empty());
    assert_lock_planted_break_found();
}

/// A lock query run through `scoped` rather than the scoped holder is
/// found.
fn assert_lock_planted_break_found() {
    let lock = [QueryFile {
        path: "queries/users/hold.sql".to_owned(),
        text: "-- Holds the users.\nSELECT pg_advisory_xact_lock($1)::text AS \"held!\"".to_owned(),
    }];
    let holder = [SourceFile::planted(
        "postgres/identity/users.rs",
        "fn hold() { scoped(d, s, async |c| sqlx::query_file!(\"queries/users/hold.sql\", 1)); }",
    )];
    assert!(!locks_outside_scoped_holding(&lock, &holder).is_empty());
}

/// Stops: a lock taken in one database commits before the writes it guards
/// in another, and a racing request passes the check it was meant to wait
/// for.
#[cfg_attr(test, test)]
pub(crate) fn every_advisory_lock_is_taken_through_scoped_holding() {
    locks_outside_scoped_holding(&query_files(), &production_files())
        .assert_none("advisory locks outside scoped_holding");
}

/// Stops: a store's SQL hides in Rust, where it is read by no one who looks
/// for the queries of a table.
#[cfg_attr(test, test)]
pub(crate) fn no_store_writes_its_sql_inline() {
    sql_inside_stores(&production_files()).assert_none("SQL inside stores");
}

/// Stops: a query file stays behind after its store stopped using it.
#[cfg_attr(test, test)]
pub(crate) fn every_query_file_is_used() {
    unused_query_files(&query_files(), &production_files()).assert_none("unused query files");
}

/// Stops: a query file nobody can tell the purpose of without reading it.
#[cfg_attr(test, test)]
pub(crate) fn every_query_file_says_what_it_does() {
    unexplained_query_files(&query_files()).assert_none("query files without a comment");
}

/// Stops: a table's queries scattered over folders named for other things.
#[cfg_attr(test, test)]
pub(crate) fn query_files_are_grouped_by_table() {
    query_files_outside_their_table(&query_files(), &schema::schema())
        .assert_none("query files outside their table's folder");
}

/// Stops: a list outside SCIM pages by `OFFSET` through the builder made
/// for SCIM alone.
#[cfg_attr(test, test)]
pub(crate) fn only_scim_pages_through_the_offset_builder() {
    windows_outside_scim(&production_files()).assert_none("OFFSET builder outside SCIM");
    let planted = [SourceFile::planted(
        "postgres/identity/users.rs",
        "fn list() { WindowQuery::ids(\"id\", \"users\"); }",
    )];
    assert!(!windows_outside_scim(&planted).is_empty());
}

/// The SCIM allowance reaches the SCIM stores and their `scim_` query files
/// under any table, and nothing else.
#[cfg_attr(test, test)]
pub(crate) fn only_the_scim_queries_may_page_by_offset() {
    let allowed = |path: &str| {
        OFFSET_ALLOWED
            .iter()
            .any(|(allowed, _)| allowed_by(path, allowed))
    };

    assert!(allowed("postgres/federation/scim/users.rs"));
    assert!(allowed("queries/users/scim_page.sql"));
    assert!(!allowed("queries/users/page.sql"));
    assert!(!allowed("queries/users/nested/scim_page.sql"));
    assert!(!allowed("postgres/identity/users.rs"));
}

/// A query in a file of its own is read without its comments, so the
/// checks see it as they see one written inline.
#[cfg_attr(test, test)]
pub(crate) fn a_query_file_is_read_without_its_comments() {
    let sql = "-- reads every WHERE they ask\nSELECT id FROM users -- all of them\n";

    assert_eq!(flat(&without_comments(sql)), "SELECT ID FROM USERS");
}
