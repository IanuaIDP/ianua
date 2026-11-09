//! The planner's rules, each with a planted case: what it writes, and what
//! it refuses until the schema says so on purpose.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::catalog::{Column, Constraint, Filled, Nullability, RowSecurity};
use crate::directives::{self, Directives};
use crate::notes::{self, Notes};

/// A nullable text column.
fn text(name: &str) -> Column {
    Column {
        name: name.to_owned(),
        data_type: "text".to_owned(),
        nullability: Nullability::Null,
        filled: Filled::Not,
    }
}

/// A table of `columns`, under forced row security.
fn table(columns: Vec<Column>) -> Table {
    Table {
        columns,
        constraints: BTreeMap::new(),
        indexes: BTreeMap::new(),
        row_security: RowSecurity::Forced,
        policies: BTreeMap::new(),
    }
}

/// A catalog of the named tables.
fn catalog(tables: Vec<(&str, Table)>) -> Catalog {
    Catalog {
        extensions: BTreeSet::new(),
        tables: tables
            .into_iter()
            .map(|(name, table)| (name.to_owned(), table))
            .collect(),
    }
}

/// The plan from `released` to `wanted`, with `said` as the schema's
/// directives and comments.
fn planned(released: &Catalog, wanted: &Catalog, said: &str) -> Plan {
    let directives: Directives = directives::read([said]).unwrap();
    let notes: Notes = notes::read([said]);
    let parts = BTreeMap::from([("tenants".to_owned(), Part::Platform)]);
    let inputs = Inputs {
        directives: &directives,
        notes: &notes,
        parts: &parts,
    };
    plan(released, wanted, &inputs)
}

/// The plan's SQL, statement by statement.
fn sql(plan: &Plan) -> Vec<&str> {
    plan.statements
        .iter()
        .map(|statement| statement.sql.as_str())
        .collect()
}

/// Ann adds a nullable `paused_at` at the end of `api_keys`: one column is
/// added, with the schema's comment as its note.
#[test]
fn nullable_columns_can_be_appended() {
    let released = catalog(vec![("api_keys", table(vec![text("id")]))]);
    let wanted = catalog(vec![(
        "api_keys",
        table(vec![text("id"), text("paused_at")]),
    )]);
    let said =
        "CREATE TABLE api_keys (\n    id text,\n    -- When it was paused.\n    paused_at text\n);";

    let plan = planned(&released, &wanted, said);

    assert!(plan.refusals.is_empty(), "{:?}", plan.refusals);
    assert_eq!(
        sql(&plan),
        ["ALTER TABLE api_keys ADD COLUMN paused_at text;"]
    );
    assert_eq!(
        plan.statements[0].note.as_deref(),
        Some("When it was paused.")
    );
}

/// Adding a required column without a default or inserting a column
/// between existing ones produces a refusal explaining the unsafe addition.
#[test]
fn unsafe_column_additions_are_refused() {
    let required = Column {
        nullability: Nullability::NotNull,
        ..text("owner")
    };
    let released = catalog(vec![("notes", table(vec![text("id"), text("body")]))]);
    let wanted_required = catalog(vec![(
        "notes",
        table(vec![text("id"), text("body"), required]),
    )]);
    let wanted_between = catalog(vec![(
        "notes",
        table(vec![text("id"), text("title"), text("body")]),
    )]);

    let required_plan = planned(&released, &wanted_required, "");
    let between_plan = planned(&released, &wanted_between, "");

    assert!(required_plan.refusals[0].contains("fails on every row already there"));
    assert!(between_plan.refusals[0].contains("move it to the end of notes"));
}

/// Removing a column from the schema is refused for data loss until a
/// directive gives the reason, after which the plan contains its drop.
#[test]
fn dropping_columns_requires_a_reason() {
    let released = catalog(vec![("sessions", table(vec![text("id"), text("legacy")]))]);
    let wanted = catalog(vec![("sessions", table(vec![text("id")]))]);

    let refused = planned(&released, &wanted, "");
    let allowed = planned(
        &released,
        &wanted,
        "-- schema: drops sessions.legacy because nothing reads it since 2.3",
    );

    assert!(refused.refusals[0].contains("dropping it loses its data"));
    assert!(allowed.refusals.is_empty());
    assert_eq!(sql(&allowed), ["ALTER TABLE sessions DROP COLUMN legacy;"]);
}

/// A renamed column is renamed, never dropped and added again.
#[test]
fn a_renamed_column_is_renamed() {
    let released = catalog(vec![("notes", table(vec![text("id"), text("text")]))]);
    let wanted = catalog(vec![("notes", table(vec![text("id"), text("body")]))]);

    let plan = planned(&released, &wanted, "-- schema: renamed notes.text to body");

    assert!(plan.refusals.is_empty(), "{:?}", plan.refusals);
    assert_eq!(
        sql(&plan),
        ["ALTER TABLE notes RENAME COLUMN text TO body;"]
    );
}

/// A check added to a table with rows is added `NOT VALID` and validated
/// after; a new index on it is made concurrently, alone.
#[test]
fn checks_and_indexes_limit_table_locking() {
    let released = catalog(vec![("notes", table(vec![text("id"), text("body")]))]);
    let mut changed = table(vec![text("id"), text("body")]);
    changed.constraints.insert(
        "notes_body_named".to_owned(),
        Constraint {
            kind: ConstraintKind::Check,
            definition: "CHECK ((body <> ''::text))".to_owned(),
        },
    );
    changed.indexes.insert(
        "notes_by_body".to_owned(),
        "CREATE INDEX notes_by_body ON public.notes USING btree (body)".to_owned(),
    );
    let wanted = catalog(vec![("notes", changed)]);

    let plan = planned(&released, &wanted, "");

    assert_eq!(
        sql(&plan),
        [
            "ALTER TABLE notes ADD CONSTRAINT notes_body_named CHECK ((body <> ''::text)) NOT VALID;\n\
             ALTER TABLE notes VALIDATE CONSTRAINT notes_body_named;",
            "CREATE INDEX CONCURRENTLY notes_by_body ON notes USING btree (body);"
        ]
    );
    assert_eq!(plan.statements[1].running, Running::Alone);
}

/// Two new tables, one pointing at the other: both are made before any
/// key, and their policies after.
#[test]
fn tables_are_created_before_their_keys() {
    let plan = planned(&Catalog::default(), &tenants_and_notes(), "");

    let steps: Vec<Step> = plan.statements.iter().map(|each| each.step).collect();
    assert_eq!(
        steps,
        [
            Step::CreateTable,
            Step::CreateTable,
            Step::AddKey,
            Step::AddConstraint,
            Step::RowSecurity,
            Step::RowSecurity,
            Step::RowSecurity,
            Step::RowSecurity,
            Step::CreatePolicy
        ]
    );
}

/// A new platform table is made in the platform part.
#[test]
fn platform_tables_go_to_the_platform() {
    let plan = planned(&Catalog::default(), &tenants_and_notes(), "");

    let tenants_made = plan
        .statements
        .iter()
        .find(|statement| statement.sql.starts_with("CREATE TABLE tenants"))
        .unwrap();
    assert_eq!(tenants_made.part, Part::Platform);
}

/// The platform's tenants with their key, and the tenants' notes pointing
/// at them under a policy.
fn tenants_and_notes() -> Catalog {
    let mut tenants = table(vec![text("id")]);
    tenants.constraints.insert(
        "tenants_pkey".to_owned(),
        Constraint {
            kind: ConstraintKind::PrimaryKey,
            definition: "PRIMARY KEY (id)".to_owned(),
        },
    );
    let mut notes = table(vec![text("id"), text("tenant_id")]);
    notes.constraints.insert(
        "notes_tenant_fkey".to_owned(),
        Constraint {
            kind: ConstraintKind::ForeignKey,
            definition: "FOREIGN KEY (tenant_id) REFERENCES tenants(id)".to_owned(),
        },
    );
    notes.policies.insert(
        "tenant_rows".to_owned(),
        "AS PERMISSIVE FOR ALL TO public USING (true)".to_owned(),
    );
    catalog(vec![("tenants", tenants), ("notes", notes)])
}

/// Omitting a table is refused for row loss; a reasoned directive produces
/// the requested table drop.
#[test]
fn dropping_tables_requires_a_reason() {
    let released = catalog(vec![("old_tokens", table(vec![text("id")]))]);

    let refused = planned(&released, &Catalog::default(), "");
    let allowed = planned(
        &released,
        &Catalog::default(),
        "-- schema: drops old_tokens because tokens moved to oauth_access_tokens",
    );

    assert!(refused.refusals[0].contains("dropping it loses its rows"));
    assert_eq!(sql(&allowed), ["DROP TABLE old_tokens;"]);
}

/// Changing a column's type and making it required produces two refusals
/// without a reason; a directive permits both alterations.
#[test]
fn type_and_requirement_changes_need_reasons() {
    let released = catalog(vec![("notes", table(vec![text("id"), text("size")]))]);
    let changed = Column {
        data_type: "integer".to_owned(),
        nullability: Nullability::NotNull,
        ..text("size")
    };
    let wanted = catalog(vec![("notes", table(vec![text("id"), changed]))]);

    let refused = planned(&released, &wanted, "");
    let allowed = planned(
        &released,
        &wanted,
        "-- schema: changes notes.size because sizes are counts",
    );

    assert_eq!(refused.refusals.len(), 2, "{:?}", refused.refusals);
    assert_eq!(
        sql(&allowed),
        [
            "ALTER TABLE notes ALTER COLUMN size TYPE integer USING size::integer;",
            "ALTER TABLE notes ALTER COLUMN size SET NOT NULL;"
        ]
    );
}
