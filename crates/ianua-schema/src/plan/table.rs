//! The changes to one table: made whole, dropped on purpose, or changed
//! column by column, constraint by constraint.

use crate::catalog::{Column, Constraint, ConstraintKind, Filled, Nullability, RowSecurity, Table};
use crate::plan::sql::{self, Concurrency};
use crate::plan::{Inputs, Plan, Running, Statement, Step, adding_step};

/// One table's changes being planned.
pub(super) struct Planning<'a, 'b> {
    name: &'a str,
    inputs: &'a Inputs<'b>,
    plan: &'a mut Plan,
}

impl<'a, 'b> Planning<'a, 'b> {
    /// Planning the table called `name` into `plan`.
    pub(super) fn new(name: &'a str, inputs: &'a Inputs<'b>, plan: &'a mut Plan) -> Self {
        Self { name, inputs, plan }
    }
}

impl Planning<'_, '_> {
    /// Adds a statement run in the migration's transaction.
    fn push(&mut self, step: Step, note: Option<String>, sql: String) {
        let statement = self.statement(step, note, sql);
        self.plan.statements.push(statement);
    }

    /// Adds a statement run on its own, outside the migration's
    /// transaction.
    fn push_alone(&mut self, step: Step, note: Option<String>, sql: String) {
        let statement = Statement {
            running: Running::Alone,
            ..self.statement(step, note, sql)
        };
        self.plan.statements.push(statement);
    }

    /// A statement of this table, run in the migration's transaction.
    fn statement(&self, step: Step, note: Option<String>, sql: String) -> Statement {
        Statement {
            part: self.inputs.part_of(self.name),
            running: Running::InTransaction,
            step,
            note,
            sql,
        }
    }

    /// Refuses a change, saying what to do instead.
    fn refuse(&mut self, why: String) {
        self.plan.refusals.push(why);
    }
}

/// Plans `table`, made whole: its columns, then its constraints, indexes,
/// row security and policies once every new table exists.
pub(super) fn create(planning: &mut Planning<'_, '_>, table: &Table) {
    let name = planning.name;
    let note = planning.inputs.notes.table(name);
    planning.push(Step::CreateTable, note, sql::create_table(name, table));
    for (constraint_name, constraint) in &table.constraints {
        add_constraint(planning, constraint_name, constraint, Validation::AtOnce);
    }
    for (index, definition) in &table.indexes {
        let note = planning.inputs.notes.index(index);
        let written = sql::create_index(definition, Concurrency::Plain);
        planning.push(Step::CreateIndex, note, written);
    }
    for statement in sql::row_security(name, RowSecurity::Off, table.row_security) {
        planning.push(Step::RowSecurity, None, statement);
    }
    for (policy, clauses) in &table.policies {
        planning.push(
            Step::CreatePolicy,
            None,
            format!("CREATE POLICY {policy} ON {name} {clauses};"),
        );
    }
}

/// Plans dropping `table`, which only a `drops` directive allows.
pub(super) fn drop_table(planning: &mut Planning<'_, '_>) {
    let name = planning.name;
    if !planning.inputs.directives.drops(name) {
        planning.refuse(format!(
            "table {name} is not in the schema: dropping it loses its rows; say \
             `-- schema: drops {name} because <reason>` once nothing uses it, or \
             `-- schema: renamed {name} to <new>`"
        ));
        return;
    }
    planning.push(Step::DropTable, None, format!("DROP TABLE {name};"));
}

/// Plans the changes from `before` to `after`, both called `name` now.
pub(super) fn change(planning: &mut Planning<'_, '_>, before: &Table, after: &Table) {
    let before = renamed_columns(planning, before, after);
    columns(planning, &before, after);
    constraints(planning, &before, after);
    indexes(planning, &before, after);
    for statement in sql::row_security(planning.name, before.row_security, after.row_security) {
        planning.push(Step::RowSecurity, None, statement);
    }
    policies(planning, &before, after);
}

/// `before` with the columns the schema renamed under their new names,
/// each rename planned.
fn renamed_columns(planning: &mut Planning<'_, '_>, before: &Table, after: &Table) -> Table {
    let mut renamed = before.clone();
    for column in &mut renamed.columns {
        let Some(new) = planning
            .inputs
            .directives
            .column_renamed(planning.name, &column.name)
            .filter(|new| after.column(new).is_some())
        else {
            continue;
        };
        let sql = format!(
            "ALTER TABLE {} RENAME COLUMN {} TO {new};",
            planning.name, column.name
        );
        planning.push(Step::RenameColumn, None, sql);
        new.clone_into(&mut column.name);
    }
    renamed
}

/// Plans the columns added, dropped and changed.
fn columns(planning: &mut Planning<'_, '_>, before: &Table, after: &Table) {
    let kept = names_also_in(after, before);
    let was = names_also_in(before, after);
    if kept != was {
        planning.refuse(format!(
            "{}: the schema puts kept columns in another order ({}); a table's columns \
             keep their order, so write them as they were ({})",
            planning.name,
            kept.join(", "),
            was.join(", ")
        ));
    }
    for (position, column) in after.columns.iter().enumerate() {
        match before.column(&column.name) {
            None => add_column(planning, column, position, kept.len()),
            Some(old) => column_changed(planning, old, column),
        }
    }
    for column in &before.columns {
        if after.column(&column.name).is_none() {
            column_dropped(planning, column);
        }
    }
}

/// The names of `table`'s columns that `other` has too, in `table`'s
/// order.
fn names_also_in<'a>(table: &'a Table, other: &Table) -> Vec<&'a str> {
    table
        .columns
        .iter()
        .filter(|column| other.column(&column.name).is_some())
        .map(|column| column.name.as_str())
        .collect()
}

/// Plans `column`, new at `position`, after the table's `kept` columns.
fn add_column(planning: &mut Planning<'_, '_>, column: &Column, position: usize, kept: usize) {
    let name = planning.name;
    if position < kept {
        planning.refuse(format!(
            "{name}.{}: a new column goes after every column the table has; move it to \
             the end of {name}",
            column.name
        ));
        return;
    }
    if column.nullability == Nullability::NotNull && column.filled == Filled::Not {
        planning.refuse(format!(
            "{name}.{}: a new required column with no default fails on every row already \
             there; give it a default, or add it nullable, fill it, and require it in a \
             later release",
            column.name
        ));
        return;
    }
    let note = planning.inputs.notes.column(name, &column.name);
    let sql = format!(
        "ALTER TABLE {name} ADD COLUMN {};",
        sql::column_definition(column)
    );
    planning.push(Step::AddColumn, note, sql);
}

/// Plans dropping `column`, which only a `drops` directive allows.
fn column_dropped(planning: &mut Planning<'_, '_>, column: &Column) {
    let target = format!("{}.{}", planning.name, column.name);
    if !planning.inputs.directives.drops(&target) {
        planning.refuse(format!(
            "{target} is not in the schema: dropping it loses its data; say \
             `-- schema: drops {target} because <reason>` in a release after the code \
             stopped using it, or `-- schema: renamed {target} to <new>`"
        ));
        return;
    }
    let sql = format!("ALTER TABLE {} DROP COLUMN {};", planning.name, column.name);
    planning.push(Step::DropColumn, None, sql);
}

/// Plans the change of a kept column from `old` to `new`.
fn column_changed(planning: &mut Planning<'_, '_>, old: &Column, new: &Column) {
    let target = format!("{}.{}", planning.name, new.name);
    type_changed(planning, &target, old, new);
    nullability_changed(planning, &target, old, new);
    change_default(planning, &target, old, new);
}

/// Plans a kept column's type changing, which only a `changes` directive
/// allows.
fn type_changed(planning: &mut Planning<'_, '_>, target: &str, old: &Column, new: &Column) {
    if old.data_type == new.data_type {
        return;
    }
    if !planning.inputs.directives.changes(target) {
        planning.refuse(format!(
            "{target}: its type changes from {} to {}, which may not fit every value; \
             say `-- schema: changes {target} because <reason>`",
            old.data_type, new.data_type
        ));
        return;
    }
    let sql = format!(
        "ALTER TABLE {} ALTER COLUMN {} TYPE {} USING {}::{};",
        planning.name, new.name, new.data_type, new.name, new.data_type
    );
    planning.push(Step::ChangeColumn, None, sql);
}

/// Plans a kept column's nullability changing.
fn nullability_changed(planning: &mut Planning<'_, '_>, target: &str, old: &Column, new: &Column) {
    let name = planning.name;
    let alter = |change: &str| format!("ALTER TABLE {name} ALTER COLUMN {} {change};", new.name);
    match (old.nullability, new.nullability) {
        (Nullability::NotNull, Nullability::Null) => {
            planning.push(Step::ChangeColumn, None, alter("DROP NOT NULL"));
        }
        (Nullability::Null, Nullability::NotNull) if planning.inputs.directives.changes(target) => {
            planning.push(Step::ChangeColumn, None, alter("SET NOT NULL"));
        }
        (Nullability::Null, Nullability::NotNull) => planning.refuse(format!(
            "{target}: requiring it fails on any row where it is NULL; fill it first, then \
             say `-- schema: changes {target} because <reason>`"
        )),
        _ => {}
    }
}

/// Plans a kept column's default changing; a generated column changing is
/// written by hand.
fn change_default(planning: &mut Planning<'_, '_>, target: &str, old: &Column, new: &Column) {
    let name = planning.name;
    let alter = |change: String| format!("ALTER TABLE {name} ALTER COLUMN {} {change};", new.name);
    match (&old.filled, &new.filled) {
        (before, after) if before == after => {}
        (Filled::Not | Filled::Default(_), Filled::Default(expression)) => {
            planning.push(
                Step::ChangeColumn,
                None,
                alter(format!("SET DEFAULT {expression}")),
            );
        }
        (Filled::Default(_), Filled::Not) => {
            planning.push(Step::ChangeColumn, None, alter("DROP DEFAULT".to_owned()));
        }
        _ => planning.refuse(format!(
            "{target}: what generates it changes; write this migration by hand"
        )),
    }
}

/// How a constraint added to a table is checked against its rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Validation {
    /// At once: the table is new and empty.
    AtOnce,
    /// Added `NOT VALID` and validated after, so the table is locked only
    /// briefly.
    Later,
}

/// Plans adding `constraint` called `name`.
fn add_constraint(
    planning: &mut Planning<'_, '_>,
    name: &str,
    constraint: &Constraint,
    validation: Validation,
) {
    let table = planning.name;
    let note = planning.inputs.notes.constraint(name);
    let step = adding_step(constraint.kind);
    let deferred = validation == Validation::Later
        && matches!(
            constraint.kind,
            ConstraintKind::Check | ConstraintKind::ForeignKey
        );
    if !deferred {
        let sql = format!(
            "ALTER TABLE {table} ADD CONSTRAINT {name} {};",
            constraint.definition
        );
        planning.push(step, note, sql);
        return;
    }
    let sql = format!(
        "ALTER TABLE {table} ADD CONSTRAINT {name} {} NOT VALID;\n\
         ALTER TABLE {table} VALIDATE CONSTRAINT {name};",
        constraint.definition
    );
    planning.push(step, note, sql);
}

/// Plans the constraints dropped, added and changed.
fn constraints(planning: &mut Planning<'_, '_>, before: &Table, after: &Table) {
    let table = planning.name;
    for (name, old) in &before.constraints {
        if after.constraints.get(name) != Some(old) {
            let sql = format!("ALTER TABLE {table} DROP CONSTRAINT {name};");
            planning.push(Step::DropConstraint, None, sql);
        }
    }
    for (name, new) in &after.constraints {
        if before.constraints.get(name) != Some(new) {
            add_constraint(planning, name, new, Validation::Later);
        }
    }
}

/// Plans the indexes dropped, added and changed: a new one is made
/// concurrently, alone, so the table goes on taking writes.
fn indexes(planning: &mut Planning<'_, '_>, before: &Table, after: &Table) {
    for (name, old) in &before.indexes {
        if after.indexes.get(name) != Some(old) {
            planning.push(Step::DropIndex, None, format!("DROP INDEX {name};"));
        }
    }
    for (name, new) in &after.indexes {
        if before.indexes.get(name) != Some(new) {
            let note = planning.inputs.notes.index(name);
            let sql = sql::create_index(new, Concurrency::Concurrent);
            planning.push_alone(Step::CreateIndex, note, sql);
        }
    }
}

/// Plans the policies dropped, written and written again.
fn policies(planning: &mut Planning<'_, '_>, before: &Table, after: &Table) {
    let table = planning.name;
    for (name, old) in &before.policies {
        if after.policies.get(name) != Some(old) {
            planning.push(
                Step::DropPolicy,
                None,
                format!("DROP POLICY {name} ON {table};"),
            );
        }
    }
    for (name, clauses) in &after.policies {
        if before.policies.get(name) != Some(clauses) {
            let sql = format!("CREATE POLICY {name} ON {table} {clauses};");
            planning.push(Step::CreatePolicy, None, sql);
        }
    }
}
