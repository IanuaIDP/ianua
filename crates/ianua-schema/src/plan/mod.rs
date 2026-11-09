//! The changes that take a database from what the released migrations
//! build to what the schema says, in an order that applies, with every
//! change that could lose data or hold a long lock refused or written the
//! safe way.
//!
//! Ann adds `paused_at` to `api_keys` in the schema. The planner writes
//! `ALTER TABLE api_keys ADD COLUMN paused_at timestamptz` and its check,
//! the check added `NOT VALID` and validated after, so the table is locked
//! only briefly. Had she removed `last_used_ip` instead, it would refuse:
//! dropping a column loses its data, so the schema must say so on purpose.

mod sql;
mod table;

use std::collections::BTreeMap;

use crate::catalog::{Catalog, ConstraintKind, Table};
use crate::directives::Directives;
use crate::notes::Notes;
use crate::plan::table::Planning;

/// Which database a table lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Part {
    /// Every database: a tenant's own and the platform's.
    Tenant,
    /// The platform database alone.
    Platform,
}

/// How a statement is run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Running {
    /// Inside the migration's transaction, with the others.
    InTransaction,
    /// Alone and outside any transaction, so it holds no long lock: a new
    /// index on a table that already has rows.
    Alone,
}

/// When a statement runs, relative to the others: each step needs what
/// the ones before it made or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Step {
    /// An extension a table needs.
    Extension,
    /// A policy dropped or about to be written again.
    DropPolicy,
    /// An index dropped or about to be written again.
    DropIndex,
    /// A constraint dropped or about to be written again.
    DropConstraint,
    /// A table renamed.
    RenameTable,
    /// A column renamed.
    RenameColumn,
    /// A table made.
    CreateTable,
    /// A column added.
    AddColumn,
    /// A column's type, nullability or default changed.
    ChangeColumn,
    /// A column dropped.
    DropColumn,
    /// A table dropped.
    DropTable,
    /// A primary or unique key added, which foreign keys may point at.
    AddKey,
    /// A check, foreign key or exclusion added.
    AddConstraint,
    /// An index made.
    CreateIndex,
    /// Row security switched.
    RowSecurity,
    /// A policy written.
    CreatePolicy,
}

/// One statement of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Statement {
    /// The database its table lives in.
    pub(crate) part: Part,
    /// How it is run.
    pub(crate) running: Running,
    /// When it runs.
    pub(crate) step: Step,
    /// Why, taken from the schema's comment on what it makes.
    pub(crate) note: Option<String>,
    /// The SQL, ending in `;`.
    pub(crate) sql: String,
}

/// The plan: its statements in order, or what it refuses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The statements, in the order they run.
    pub(crate) statements: Vec<Statement>,
    /// Each change refused, with what to do instead.
    pub(crate) refusals: Vec<String>,
}

/// What the planner reads beside the two catalogs.
pub(crate) struct Inputs<'a> {
    /// What the schema says on purpose.
    pub(crate) directives: &'a Directives,
    /// The schema's comments, for each statement's note.
    pub(crate) notes: &'a Notes,
    /// The database each table lives in, by name; a table not named lives
    /// in every database.
    pub(crate) parts: &'a BTreeMap<String, Part>,
}

impl Inputs<'_> {
    /// The database `table` lives in.
    pub(crate) fn part_of(&self, table: &str) -> Part {
        self.parts.get(table).copied().unwrap_or(Part::Tenant)
    }
}

/// The plan from `released` to `wanted`.
pub(crate) fn plan(released: &Catalog, wanted: &Catalog, inputs: &Inputs<'_>) -> Plan {
    let mut plan = Plan::default();
    extensions(released, wanted, &mut plan);
    let renamed = renamed_tables(released, wanted, inputs, &mut plan);
    for (name, table) in &wanted.tables {
        let mut planning = Planning::new(name, inputs, &mut plan);
        match renamed.get(name) {
            Some(before) => table::change(&mut planning, before, table),
            None => table::create(&mut planning, table),
        }
    }
    for name in renamed.keys() {
        if !wanted.tables.contains_key(name) {
            table::drop_table(&mut Planning::new(name, inputs, &mut plan));
        }
    }
    plan.statements
        .sort_by_key(|statement| (statement.step, statement.running));
    plan
}

/// Plans the extensions the schema adds, refusing any it removes.
fn extensions(released: &Catalog, wanted: &Catalog, plan: &mut Plan) {
    for extension in wanted.extensions.difference(&released.extensions) {
        plan.statements.push(Statement {
            part: Part::Tenant,
            running: Running::InTransaction,
            step: Step::Extension,
            note: None,
            sql: format!("CREATE EXTENSION IF NOT EXISTS {extension};"),
        });
    }
    for extension in released.extensions.difference(&wanted.extensions) {
        plan.refusals.push(format!(
            "extension {extension} is no longer in the schema; removing one is written by hand"
        ));
    }
}

/// The released tables under the names the schema gives them, each
/// renamed table's rename planned.
fn renamed_tables(
    released: &Catalog,
    wanted: &Catalog,
    inputs: &Inputs<'_>,
    plan: &mut Plan,
) -> BTreeMap<String, Table> {
    let mut tables = BTreeMap::new();
    for (name, table) in &released.tables {
        let Some(new) = inputs
            .directives
            .table_renamed(name)
            .filter(|new| wanted.tables.contains_key(*new))
        else {
            tables.insert(name.clone(), table.clone());
            continue;
        };
        plan.statements.push(Statement {
            part: inputs.part_of(new),
            running: Running::InTransaction,
            step: Step::RenameTable,
            note: None,
            sql: format!("ALTER TABLE {name} RENAME TO {new};"),
        });
        tables.insert(new.to_owned(), table.clone());
    }
    tables
}

/// The step a constraint of `kind` is added at.
fn adding_step(kind: ConstraintKind) -> Step {
    match kind {
        ConstraintKind::PrimaryKey | ConstraintKind::Unique => Step::AddKey,
        ConstraintKind::Check | ConstraintKind::ForeignKey | ConstraintKind::Exclusion => {
            Step::AddConstraint
        }
    }
}

#[cfg(test)]
mod tests;
