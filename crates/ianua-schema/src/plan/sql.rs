//! The SQL each planned change is written as.

use crate::catalog::{Column, Filled, Nullability, RowSecurity, Table};

/// A column as `CREATE TABLE` or `ADD COLUMN` writes it.
pub(super) fn column_definition(column: &Column) -> String {
    let mut written = format!("{} {}", column.name, column.data_type);
    match &column.filled {
        Filled::Not => {}
        Filled::Default(expression) => written.push_str(&format!(" DEFAULT {expression}")),
        Filled::Generated(expression) => {
            written.push_str(&format!(" GENERATED ALWAYS AS ({expression}) STORED"));
        }
    }
    if column.nullability == Nullability::NotNull {
        written.push_str(" NOT NULL");
    }
    written
}

/// `CREATE TABLE` with the table's columns; its constraints, indexes and
/// policies are written apart, once every new table exists.
pub(super) fn create_table(name: &str, table: &Table) -> String {
    let columns: Vec<String> = table
        .columns
        .iter()
        .map(|column| format!("    {}", column_definition(column)))
        .collect();
    format!("CREATE TABLE {name} (\n{}\n);", columns.join(",\n"))
}

/// The statements switching a table's row security from `from` to `to`.
pub(super) fn row_security(name: &str, from: RowSecurity, to: RowSecurity) -> Vec<String> {
    let enabled = |security: RowSecurity| security != RowSecurity::Off;
    let forced = |security: RowSecurity| security == RowSecurity::Forced;
    let mut statements = Vec::new();
    match (enabled(from), enabled(to)) {
        (false, true) => statements.push(format!("ALTER TABLE {name} ENABLE ROW LEVEL SECURITY;")),
        (true, false) => statements.push(format!("ALTER TABLE {name} DISABLE ROW LEVEL SECURITY;")),
        _ => {}
    }
    match (forced(from), forced(to)) {
        (false, true) => statements.push(format!("ALTER TABLE {name} FORCE ROW LEVEL SECURITY;")),
        (true, false) => {
            statements.push(format!("ALTER TABLE {name} NO FORCE ROW LEVEL SECURITY;"))
        }
        _ => {}
    }
    statements
}

/// An index's definition as the catalog wrote it, the public schema left
/// out, made as `concurrency` says.
pub(super) fn create_index(definition: &str, concurrency: Concurrency) -> String {
    let plain = definition.replacen(" ON public.", " ON ", 1);
    let written = match concurrency {
        Concurrency::Plain => plain,
        Concurrency::Concurrent => plain.replacen(" INDEX ", " INDEX CONCURRENTLY ", 1),
    };
    format!("{written};")
}

/// Whether an index is made while the table goes on taking writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Concurrency {
    /// In the migration's transaction, for a table made in it.
    Plain,
    /// Concurrently, for a table that already has rows.
    Concurrent,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A column is written with its type, what fills it and whether it is
    /// required.
    #[test]
    fn a_column_is_written_whole() {
        let column = Column {
            name: "readable".to_owned(),
            data_type: "boolean".to_owned(),
            nullability: Nullability::NotNull,
            filled: Filled::Default("false".to_owned()),
        };

        assert_eq!(
            column_definition(&column),
            "readable boolean DEFAULT false NOT NULL"
        );
    }

    /// An index on a table with rows is made concurrently, a unique one
    /// included, and never names the public schema.
    #[test]
    fn an_index_on_a_table_with_rows_is_made_concurrently() {
        let definition = "CREATE UNIQUE INDEX notes_one ON public.notes USING btree (tenant_id)";

        let written = create_index(definition, Concurrency::Concurrent);

        assert_eq!(
            written,
            "CREATE UNIQUE INDEX CONCURRENTLY notes_one ON notes USING btree (tenant_id);"
        );
    }

    /// Forcing row security on a table that had it off switches it on and
    /// forces it.
    #[test]
    fn row_security_is_switched_on_and_forced() {
        let statements = row_security("notes", RowSecurity::Off, RowSecurity::Forced);

        assert_eq!(
            statements,
            [
                "ALTER TABLE notes ENABLE ROW LEVEL SECURITY;",
                "ALTER TABLE notes FORCE ROW LEVEL SECURITY;"
            ]
        );
    }
}
