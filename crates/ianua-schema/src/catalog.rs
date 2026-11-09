//! What a database holds, read from its own catalog: its tables with their
//! columns in order, constraints, indexes, row security and policies, and
//! the extensions it loaded. Two databases built from the same SQL read
//! back equal, whatever order their constraints and indexes were written in.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;

/// Whether a column takes NULL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Nullability {
    /// It may be NULL.
    Null,
    /// It never is.
    NotNull,
}

/// How a column gets a value it is not given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Filled {
    /// It is not filled: NULL, or refused when it may not be.
    Not,
    /// From this default expression.
    Default(String),
    /// Always from this expression over the row, stored.
    Generated(String),
}

/// One column of a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Column {
    /// Identifier read from the catalog and used to match planned changes.
    pub(crate) name: String,
    /// Its type as Postgres writes it, with a collation it was given.
    pub(crate) data_type: String,
    /// Whether it takes NULL.
    pub(crate) nullability: Nullability,
    /// How it is filled when not given.
    pub(crate) filled: Filled,
}

/// What kind of constraint it is, in the order a new table adds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ConstraintKind {
    /// Uniquely identifies each row with non-null columns.
    PrimaryKey,
    /// A unique key.
    Unique,
    /// A check over the row.
    Check,
    /// Requires referenced values to exist in the target relation.
    ForeignKey,
    /// An exclusion constraint.
    Exclusion,
}

impl ConstraintKind {
    /// The kind Postgres records as `code`, if it is one of these.
    fn from_code(code: &str) -> Option<Self> {
        match code {
            "p" => Some(Self::PrimaryKey),
            "u" => Some(Self::Unique),
            "c" => Some(Self::Check),
            "f" => Some(Self::ForeignKey),
            "x" => Some(Self::Exclusion),
            _ => None,
        }
    }
}

/// One named constraint of a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Constraint {
    /// What kind it is.
    pub(crate) kind: ConstraintKind,
    /// Its definition as Postgres writes it back.
    pub(crate) definition: String,
}

/// Whether a table holds its rows to its policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowSecurity {
    /// Not at all.
    Off,
    /// For every role but the table's owner.
    On,
    /// For its owner too.
    Forced,
}

/// Catalog structure compared across databases to plan schema changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Table {
    /// Its columns, in order.
    pub(crate) columns: Vec<Column>,
    /// Its constraints, by name.
    pub(crate) constraints: BTreeMap<String, Constraint>,
    /// Its indexes that back no constraint, by name, each with its
    /// definition.
    pub(crate) indexes: BTreeMap<String, String>,
    /// Whether it holds its rows to its policies.
    pub(crate) row_security: RowSecurity,
    /// Its policies, by name, each written as the clauses after
    /// `CREATE POLICY name ON table`.
    pub(crate) policies: BTreeMap<String, String>,
}

impl Table {
    /// The column called `name`, if the table has one.
    pub(crate) fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|column| column.name == name)
    }
}

/// Everything a database holds that the migrations make.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Catalog {
    /// The extensions it loaded.
    pub(crate) extensions: BTreeSet<String>,
    /// Its tables, by name.
    pub(crate) tables: BTreeMap<String, Table>,
}

/// A table's row as the catalog lists it.
type TableRow = (String, bool, bool);
/// A column's row: table, name, type, not null, default, generated.
type ColumnRow = (String, String, String, bool, Option<String>, String);
/// A constraint's row: table, name, kind, definition.
type ConstraintRow = (String, String, String, String);
/// An index's row: table, name, definition.
type IndexRow = (String, String, String);
/// A policy's row: table, name, permissive, roles, command, using, check.
type PolicyRow = (
    String,
    String,
    String,
    Vec<String>,
    String,
    Option<String>,
    Option<String>,
);

/// Reads the catalog of the database `pool` reaches, its public schema.
///
/// # Errors
///
/// Returns the database's error when a catalog cannot be read.
pub(crate) async fn read(pool: &PgPool) -> Result<Catalog, sqlx::Error> {
    let mut tables: BTreeMap<String, Table> = sqlx::query_as::<_, TableRow>(TABLES)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|(name, on, forced)| (name, empty_table(on, forced)))
        .collect();
    fill_columns(pool, &mut tables).await?;
    fill_constraints(pool, &mut tables).await?;
    fill_indexes(pool, &mut tables).await?;
    fill_policies(pool, &mut tables).await?;
    let extensions = sqlx::query_scalar::<_, String>(EXTENSIONS)
        .fetch_all(pool)
        .await?
        .into_iter()
        .collect();
    Ok(Catalog { extensions, tables })
}

/// Adds each column to the table it belongs to.
async fn fill_columns(
    pool: &PgPool,
    tables: &mut BTreeMap<String, Table>,
) -> Result<(), sqlx::Error> {
    for row in sqlx::query_as::<_, ColumnRow>(COLUMNS)
        .fetch_all(pool)
        .await?
    {
        let (table, column) = column_of(row);
        if let Some(table) = tables.get_mut(&table) {
            table.columns.push(column);
        }
    }
    Ok(())
}

/// Adds each constraint of a kind the schema keeps to its table.
async fn fill_constraints(
    pool: &PgPool,
    tables: &mut BTreeMap<String, Table>,
) -> Result<(), sqlx::Error> {
    for (table, name, code, definition) in sqlx::query_as::<_, ConstraintRow>(CONSTRAINTS)
        .fetch_all(pool)
        .await?
    {
        let (Some(table), Some(kind)) = (tables.get_mut(&table), ConstraintKind::from_code(&code))
        else {
            continue;
        };
        table
            .constraints
            .insert(name, Constraint { kind, definition });
    }
    Ok(())
}

/// Adds each index to its table.
async fn fill_indexes(
    pool: &PgPool,
    tables: &mut BTreeMap<String, Table>,
) -> Result<(), sqlx::Error> {
    for (table, name, definition) in sqlx::query_as::<_, IndexRow>(INDEXES)
        .fetch_all(pool)
        .await?
    {
        if let Some(table) = tables.get_mut(&table) {
            table.indexes.insert(name, definition);
        }
    }
    Ok(())
}

/// Adds each row security policy to its table.
async fn fill_policies(
    pool: &PgPool,
    tables: &mut BTreeMap<String, Table>,
) -> Result<(), sqlx::Error> {
    for row in sqlx::query_as::<_, PolicyRow>(POLICIES)
        .fetch_all(pool)
        .await?
    {
        let (table, name, clauses) = policy_of(row);
        if let Some(table) = tables.get_mut(&table) {
            table.policies.insert(name, clauses);
        }
    }
    Ok(())
}

/// A table with nothing read into it yet.
fn empty_table(on: bool, forced: bool) -> Table {
    let row_security = match (on, forced) {
        (false, _) => RowSecurity::Off,
        (true, false) => RowSecurity::On,
        (true, true) => RowSecurity::Forced,
    };
    Table {
        columns: Vec::new(),
        constraints: BTreeMap::new(),
        indexes: BTreeMap::new(),
        row_security,
        policies: BTreeMap::new(),
    }
}

/// The table and column a column's row describes.
fn column_of(row: ColumnRow) -> (String, Column) {
    let (table, name, data_type, not_null, expression, generated) = row;
    let filled = match (expression, generated.as_str()) {
        (Some(expression), "s") => Filled::Generated(expression),
        (Some(expression), _) => Filled::Default(expression),
        (None, _) => Filled::Not,
    };
    let nullability = if not_null {
        Nullability::NotNull
    } else {
        Nullability::Null
    };
    let column = Column {
        name,
        data_type,
        nullability,
        filled,
    };
    (table, column)
}

/// The table, name and clauses a policy's row describes.
fn policy_of(row: PolicyRow) -> (String, String, String) {
    let (table, name, permissive, roles, command, using, check) = row;
    let mut clauses = format!("AS {permissive} FOR {command} TO {}", roles.join(", "));
    if let Some(using) = using {
        clauses.push_str(&format!(" USING ({using})"));
    }
    if let Some(check) = check {
        clauses.push_str(&format!(" WITH CHECK ({check})"));
    }
    (table, name, clauses)
}

/// The tables of the public schema, the migrations' own record left out.
const TABLES: &str = "
    SELECT c.relname::text, c.relrowsecurity, c.relforcerowsecurity
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
      AND c.relname <> '_sqlx_migrations'";

/// Every column of those tables, in order, a collation other than its
/// type's written into its type.
const COLUMNS: &str = "
    SELECT c.relname::text, a.attname::text,
           format_type(a.atttypid, a.atttypmod)
               || CASE WHEN a.attcollation <> t.typcollation
                       THEN ' COLLATE \"' || co.collname || '\"' ELSE '' END,
           a.attnotnull, pg_get_expr(d.adbin, d.adrelid), a.attgenerated::text
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_type t ON t.oid = a.atttypid
    LEFT JOIN pg_collation co ON co.oid = a.attcollation
    LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
      AND a.attnum > 0 AND NOT a.attisdropped
    ORDER BY c.relname, a.attnum";

/// Every constraint of those tables, with its definition.
const CONSTRAINTS: &str = "
    SELECT c.relname::text, con.conname::text, con.contype::text,
           pg_get_constraintdef(con.oid)
    FROM pg_constraint con
    JOIN pg_class c ON c.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'";

/// Every index that backs no constraint, with its definition.
const INDEXES: &str = "
    SELECT i.tablename::text, i.indexname::text, i.indexdef
    FROM pg_indexes i
    WHERE i.schemaname = 'public'
      AND NOT EXISTS (
          SELECT 1 FROM pg_constraint con
          JOIN pg_class ci ON ci.oid = con.conindid
          WHERE ci.relname = i.indexname)";

/// Every policy, with its clauses.
const POLICIES: &str = "
    SELECT tablename::text, policyname::text, permissive, roles::text[], cmd, qual, with_check
    FROM pg_policies WHERE schemaname = 'public'";

/// The extensions loaded, the one every database has left out.
const EXTENSIONS: &str = "SELECT extname::text FROM pg_extension WHERE extname <> 'plpgsql'";

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored generated column reads as generated, a default as a
    /// default, and a column with neither as not filled.
    #[test]
    fn a_columns_expression_reads_as_what_fills_it() {
        let row = |expression: Option<&str>, generated: &str| -> ColumnRow {
            (
                "users".to_owned(),
                "name_search".to_owned(),
                "text".to_owned(),
                false,
                expression.map(str::to_owned),
                generated.to_owned(),
            )
        };

        let (_, generated) = column_of(row(Some("lower(name)"), "s"));
        let (_, defaulted) = column_of(row(Some("false"), ""));
        let (_, plain) = column_of(row(None, ""));

        assert_eq!(
            generated.filled,
            Filled::Generated("lower(name)".to_owned())
        );
        assert_eq!(defaulted.filled, Filled::Default("false".to_owned()));
        assert_eq!(plain.filled, Filled::Not);
    }

    /// A policy reads back as the clauses that would make it again.
    #[test]
    fn a_policy_reads_as_its_clauses() {
        let row: PolicyRow = (
            "notes".to_owned(),
            "tenant_rows".to_owned(),
            "PERMISSIVE".to_owned(),
            vec!["public".to_owned()],
            "ALL".to_owned(),
            Some("(tenant_id = x)".to_owned()),
            None,
        );

        let (_, _, clauses) = policy_of(row);

        assert_eq!(
            clauses,
            "AS PERMISSIVE FOR ALL TO public USING ((tenant_id = x))"
        );
    }
}
