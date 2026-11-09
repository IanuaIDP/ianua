//! Every way two catalogs differ, as lines a person reads: what the
//! migrations build against what the schema says.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use crate::catalog::{Catalog, Table};

/// How `built` differs from `wanted`, one line each; empty when they agree.
pub(crate) fn differences(built: &Catalog, wanted: &Catalog) -> Vec<String> {
    let mut lines = Vec::new();
    for extension in wanted.extensions.difference(&built.extensions) {
        lines.push(format!("extension {extension} is not loaded"));
    }
    for extension in built.extensions.difference(&wanted.extensions) {
        lines.push(format!(
            "extension {extension} is loaded but not in the schema"
        ));
    }
    for name in names(&built.tables, &wanted.tables) {
        match (built.tables.get(name), wanted.tables.get(name)) {
            (None, Some(_)) => lines.push(format!("table {name} is missing")),
            (Some(_), None) => lines.push(format!("table {name} is not in the schema")),
            (Some(built), Some(wanted)) => lines.extend(table_differences(name, built, wanted)),
            (None, None) => {}
        }
    }
    lines
}

/// How one table differs.
fn table_differences(name: &str, built: &Table, wanted: &Table) -> Vec<String> {
    let mut lines = column_differences(name, built, wanted);
    lines.extend(keyed(
        "constraint",
        name,
        &built.constraints,
        &wanted.constraints,
    ));
    lines.extend(keyed("index", name, &built.indexes, &wanted.indexes));
    lines.extend(keyed("policy", name, &built.policies, &wanted.policies));
    if built.row_security != wanted.row_security {
        lines.push(format!(
            "{name}: row security is {:?}, the schema has {:?}",
            built.row_security, wanted.row_security
        ));
    }
    lines
}

/// How one table's columns differ: their order, then each column the
/// schema names that was built otherwise.
fn column_differences(name: &str, built: &Table, wanted: &Table) -> Vec<String> {
    let mut lines = Vec::new();
    let built_order = column_names(built);
    let wanted_order = column_names(wanted);
    if built_order != wanted_order {
        lines.push(format!(
            "{name}: columns are ({}), the schema has ({})",
            built_order.join(", "),
            wanted_order.join(", ")
        ));
    }
    for column in &wanted.columns {
        let Some(found) = built.column(&column.name) else {
            continue;
        };
        if found != column {
            lines.push(format!(
                "{name}.{}: built as {found:?}, the schema has {column:?}",
                column.name
            ));
        }
    }
    lines
}

/// The names of `table`'s columns, in order.
fn column_names(table: &Table) -> Vec<&str> {
    table
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect()
}

/// How two maps of named things of one table differ.
fn keyed<T: PartialEq + Debug>(
    what: &str,
    table: &str,
    built: &BTreeMap<String, T>,
    wanted: &BTreeMap<String, T>,
) -> Vec<String> {
    names(built, wanted)
        .into_iter()
        .filter_map(|name| match (built.get(name), wanted.get(name)) {
            (None, Some(_)) => Some(format!("{table}: {what} {name} is missing")),
            (Some(_), None) => Some(format!("{table}: {what} {name} is not in the schema")),
            (Some(built), Some(wanted)) if built != wanted => Some(format!(
                "{table}: {what} {name} is {built:?}, the schema has {wanted:?}"
            )),
            _ => None,
        })
        .collect()
}

/// Every key of either map, in order.
fn names<'a, T>(
    left: &'a BTreeMap<String, T>,
    right: &'a BTreeMap<String, T>,
) -> BTreeSet<&'a str> {
    left.keys()
        .chain(right.keys())
        .map(String::as_str)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Column, Filled, Nullability, RowSecurity};

    /// A table of the given columns, each a nullable text.
    fn table(columns: &[&str]) -> Table {
        Table {
            columns: columns
                .iter()
                .map(|name| Column {
                    name: (*name).to_owned(),
                    data_type: "text".to_owned(),
                    nullability: Nullability::Null,
                    filled: Filled::Not,
                })
                .collect(),
            constraints: BTreeMap::new(),
            indexes: BTreeMap::new(),
            row_security: RowSecurity::Forced,
            policies: BTreeMap::new(),
        }
    }

    /// A catalog of one table called `notes`.
    fn catalog(table: Table) -> Catalog {
        Catalog {
            extensions: BTreeSet::new(),
            tables: BTreeMap::from([("notes".to_owned(), table)]),
        }
    }

    /// Equal catalogs differ in nothing.
    #[test]
    fn equal_catalogs_have_no_differences() {
        let notes = catalog(table(&["id", "body"]));

        assert!(differences(&notes, &notes.clone()).is_empty());
    }

    /// A column the schema has that was not built, a column in another
    /// place, and an index nobody wrote are each named.
    #[test]
    fn each_difference_is_named() {
        let mut built = table(&["body", "id"]);
        built
            .indexes
            .insert("notes_by_body".to_owned(), "CREATE INDEX".to_owned());
        let wanted = table(&["id", "body", "title"]);

        let lines = differences(&catalog(built), &catalog(wanted));

        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("columns are (body, id), the schema has (id, body, title)"));
        assert!(lines[1].contains("index notes_by_body is not in the schema"));
    }
}
