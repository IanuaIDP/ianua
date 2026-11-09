---
name: add-store
description: Add or change a Postgres store in ianua-infra, including the schema change, migration, checked queries, tenant scoping and real-database tests. Use when a port needs storage or a table changes, e.g. "/add-store oauth api_keys add paused_at".
argument-hint: <context> <table> [what changes]
---

# Add a store

Copy `crates/ianua-infra/src/postgres/oauth/api_keys.rs` and its
`api_keys/record.rs`, with the files in `crates/ianua-infra/queries/api_keys/`.

## The schema

1. Change the database as it should be, in `crates/ianua-infra/schema/`.
   Never write a migration by hand.
2. Run `cargo run -p ianua-schema -- diff <name>`. It writes the next
   migration and proves the migrations reach the schema. Name it by what it
   holds, such as `key_pausing`, never `new` or `final`. The tool needs
   Docker, or a server named by `SCHEMA_DATABASE_URL`.
3. It refuses what would hurt stored data. A new required column needs a
   default, and goes last in its table. A drop, a change or a rename says so
   on purpose with a `-- schema:` line, for example
   `-- schema: renamed notes.text to body`.
4. **Migrations run on data that already exists.** A released migration is
   never edited. Every change is a new file. To set values on existing rows,
   use `SET LOCAL app.platform_scope = 'on';` before the `UPDATE`, or row
   security hides every row.

Table rules:

- A tenant table has `tenant_id`, row security forced, and the `tenant_rows`
  policy. See `schema/0021_messaging.sql`.
- Every id column is a foreign key or carries `-- no foreign key: why`. A
  link says what a delete does, and is indexed.
- No functions, procedures, triggers or `DO` blocks. Logic lives in Rust.

## The port and the adapter

The port is a trait in `crates/ianua-app/src/ports/<context>`. It returns
domain types or `DomainError`, never a `sqlx` type. A tenant store implements
`TenantScoped` and takes a `ScopedTenant`.

The store is `Pg<Port>` in `src/postgres/<context>/`:

- `record.rs` holds what a row looks like. It rebuilds the aggregate through
  `reconstitute`, so stored data is checked on the way out.
- Run every query through `foundation::unit::scoped`. It joins the current
  unit of work and sets the tenant.
- Report a duplicate through `foundation::errors::unique_on` and name the
  constraint. Other errors never become text.
- An update writes only its own columns, with `WHERE id`, so it cannot bring
  back a row deleted meanwhile.

## Queries

One file per statement: `queries/<table>/<what>.sql`, used with
`sqlx::query_file_as!`. No SQL inline in Rust. Each file starts with a
comment saying what it does. Name the columns, no `SELECT *`. A query on a
tenant table names the tenant. Page by cursor through `foundation::paging`,
never by offset. Never run a query in a loop: send arrays with `UNNEST`.
Every read that can grow has a limit, and a bounded delete runs in rounds.

## The gateway's database role

The gateway connects as a role with almost no rights. It can insert its
records but not read them, as `foundation/roles.rs` lists. So its writes use
`ON CONFLICT DO NOTHING`. `ON CONFLICT (id)` needs `SELECT` on that column and
fails at run time. See `queries/stream_records/write.sql`. A new table the
gateway reads must be added to `GATEWAY_READS`.

## Tests

Hit a real database, in `#[cfg(test)] mod tests` of the store. Docker must be
running. Start with `TestDb::fresh().await` from `crate::test_support`.

Cover the round trip of every column, a second tenant seeing nothing, each
unique conflict, and a corrupt row refused, using `db.tamper(sql)`. Run a new
query that can grow through `db.plan(sql)` or a test in `tests/plans`.

## Check

```sh
sqlx migrate run --source crates/ianua-infra/migrations
cargo sqlx prepare --workspace -- -p ianua-infra --all-targets --all-features
cargo run -p ianua-schema -- check
cargo +nightly fmt -p ianua-infra
SQLX_OFFLINE=true cargo nextest run -p ianua-infra --lib -E 'test(/<store>/)'
SQLX_OFFLINE=true cargo clippy -p ianua-infra --all-targets --all-features -- -D warnings
cargo run --release -p ianua-audit -- check infra
```

`DATABASE_URL` must name a development database for the first two commands.
Commit the `.sqlx` files they change.
