//! Keyset paging: one page of a list, read straight from an index.
//!
//! A list never pages by `OFFSET`, which reads and throws away every row
//! before the page. It seeks past the last row of the page before, from the
//! cursor, and reads one row more than the page holds to learn whether
//! another page follows. The app's `Keyset` then seals the page and its
//! cursor from the rows read.
//!
//! The seek is built as a [`Condition`] first, plain data a test can read,
//! and only then written out as SQL. The query is made of `&'static str`
//! pieces and bound values alone, so nothing a caller sends can become SQL
//! text.
//!
//! An empty value sorts where Postgres puts `NULL`: last in an ascending
//! order, first in a descending one, which is where the app's cursor puts
//! a missing value too.
//!
//! Filters shaped as trees are in [`picks`], and SCIM's one stretch by
//! position, the only read that does not page by key, in [`window`].

pub(crate) mod picks;
pub(crate) mod window;

use std::collections::HashMap;
use std::marker::PhantomData;

use ianua_app::listing::{KeyOrder, Keyset, SortDirection, SortField, SortKey, SortOrder};
use sqlx::{PgConnection, Postgres, QueryBuilder};
use uuid::Uuid;

use crate::postgres::foundation::paging::picks::Picks;

/// Whether a sort column can hold `NULL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Nullable {
    /// A `NOT NULL` column.
    Never,
    /// A column that may be empty.
    Maybe,
}

/// How a store's sort fields are its table's columns.
pub(crate) trait SortColumns: SortField {
    /// The column `self` sorts by, as the store's query names it.
    fn column(self) -> &'static str;

    /// Whether that column can hold `NULL`.
    fn nullable(self) -> Nullable;
}

/// The query for the ids of one page of a list: the table, its filters,
/// the seek past the cursor, the order and the limit.
///
/// It reads ids alone. The store then reads the rows of those ids with one
/// query checked when it compiles, so every row is read and mapped the
/// same way however it was found.
///
/// The same filters can instead count the rows they keep, for a rule that
/// needs how many there are and never the rows themselves: such a query is
/// a `PageQuery<Count>`, which has no way to be read as a page.
pub(crate) struct PageQuery<'q, Read = Ids> {
    builder: QueryBuilder<'q, Postgres>,
    id: &'static str,
    clause: Clause,
    read: PhantomData<Read>,
}

/// A [`PageQuery`] that reads the ids of one page.
pub(crate) struct Ids;

/// A [`PageQuery`] that counts the rows its filters keep.
pub(crate) struct Count;

/// Whether the query has its `WHERE` yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Clause {
    /// No condition is written yet; the next opens `WHERE`.
    Open,
    /// A condition is written; the next joins it with `AND`.
    Narrowed,
}

impl<'q, Read> PageQuery<'q, Read> {
    /// `SELECT list FROM from`, before any condition.
    fn select(list: &'static str, from: &'static str) -> Self {
        let mut builder = QueryBuilder::new("SELECT ");
        builder.push(list);
        builder.push(" FROM ");
        builder.push(from);
        Self {
            builder,
            id: list,
            clause: Clause::Open,
            read: PhantomData,
        }
    }

    /// Keeps the rows where `condition` holds, with `value` bound where it
    /// marks `?`, such as `o.status = ?`.
    pub(crate) fn filter<T>(mut self, condition: &'static str, value: T) -> Self
    where
        T: 'q + sqlx::Encode<'q, Postgres> + sqlx::Type<Postgres> + Send,
    {
        self.narrow();
        self.push_bound(condition, value);
        self
    }

    /// Keeps the rows where the fixed `condition`, such as
    /// `status <> 'deleted'`, holds.
    pub(crate) fn keep(mut self, condition: &'static str) -> Self {
        self.narrow();
        self.builder.push(condition);
        self
    }

    /// Keeps the rows `picks` keeps, a tree of fixed conditions each with
    /// its text bound.
    pub(crate) fn picking(mut self, picks: &Picks) -> Self {
        self.narrow();
        picks.write(&mut self.builder);
        self
    }

    /// The query as written so far, for a sibling builder that ends it in
    /// a way of its own.
    pub(super) fn into_builder(self) -> QueryBuilder<'q, Postgres> {
        self.builder
    }

    /// Writes `text` with `value` bound where it marks `?`.
    fn push_bound<T>(&mut self, text: &'static str, value: T)
    where
        T: 'q + sqlx::Encode<'q, Postgres> + sqlx::Type<Postgres> + Send,
    {
        let (before, after) = text.split_once('?').unwrap_or((text, ""));
        self.builder.push(before);
        self.builder.push_bind(value);
        self.builder.push(after);
    }

    fn narrow(&mut self) {
        let joint = match self.clause {
            Clause::Open => " WHERE ",
            Clause::Narrowed => " AND ",
        };
        self.builder.push(joint);
        self.clause = Clause::Narrowed;
    }
}

impl<'q> PageQuery<'q, Count> {
    /// How many rows of `from`, such as `users`, the filters keep.
    pub(crate) fn counted(from: &'static str) -> Self {
        Self::select("count(*)", from)
    }

    /// The number of rows the filters keep.
    pub(crate) async fn count(mut self, connection: &mut PgConnection) -> Result<i64, sqlx::Error> {
        self.builder
            .build_query_scalar::<i64>()
            .fetch_one(connection)
            .await
    }
}

impl<'q> PageQuery<'q, Ids> {
    /// The ids of the rows of `from`, such as `organizations o`, read from
    /// the column `id`, such as `o.id`.
    pub(crate) fn ids(id: &'static str, from: &'static str) -> Self {
        Self::select(id, from)
    }

    /// The ids of the rows of `from`, read from the column `id`, beside the
    /// rows `join` brings in, such as `LEFT JOIN user_metadata m ON
    /// m.user_id = users.id AND m.key = ?`, with `value` bound where it
    /// marks `?`.
    ///
    /// The join is written before any condition, so it can never follow a
    /// `WHERE`.
    pub(crate) fn joined<T>(
        id: &'static str,
        from: &'static str,
        join: &'static str,
        value: T,
    ) -> Self
    where
        T: 'q + sqlx::Encode<'q, Postgres> + sqlx::Type<Postgres> + Send,
    {
        let mut query = Self::ids(id, from);
        query.builder.push(" ");
        query.push_bound(join, value);
        query
    }

    /// The ids of the page `keyset` asks for, in its order, ties broken by
    /// the id.
    pub(crate) async fn fetch<F: SortColumns>(
        self,
        keyset: &Keyset<'_, SortOrder<F>>,
        connection: &mut PgConnection,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        let columns = columns_of(keyset.order(), self.id);
        self.fetch_in(&columns, keyset, connection).await
    }

    /// Reads bounded integer positions using the same validated cursor seek
    /// as UUID-backed lists, for immutable ordered child snapshots.
    pub(crate) async fn fetch_positions<F: SortColumns>(
        self,
        keyset: &Keyset<'_, SortOrder<F>>,
        connection: &mut PgConnection,
    ) -> Result<Vec<i64>, sqlx::Error> {
        let columns = columns_of(keyset.order(), self.id);
        self.fetch_in(&columns, keyset, connection).await
    }

    /// The ids of the page `keyset` asks for, for an order that is not a
    /// sort of named fields: each of `sorted_by`, a column or an expression
    /// such as `num_nulls(m.value_text)`, in the keyset's direction for it,
    /// ties broken by the id.
    pub(crate) async fn fetch_by<O: KeyOrder>(
        self,
        keyset: &Keyset<'_, O>,
        sorted_by: &[(&'static str, Nullable)],
        connection: &mut PgConnection,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        let columns = listed_columns(keyset.directions(), sorted_by, self.id);
        self.fetch_in(&columns, keyset, connection).await
    }

    /// The rows ordered by `columns`, bounded and positioned by the keyset.
    async fn fetch_in<T, O: KeyOrder>(
        mut self,
        columns: &[Column],
        keyset: &Keyset<'_, O>,
        connection: &mut PgConnection,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        T: for<'r> sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres> + Send + Unpin,
    {
        if let Some(after) = keyset.after() {
            self.narrow();
            seek(columns, after).write(&mut self.builder);
        }
        write_order(&mut self.builder, columns);
        self.builder.push(" LIMIT ");
        self.builder
            .push_bind(i64::try_from(keyset.fetch()).unwrap_or(i64::MAX));
        self.builder
            .build_query_scalar::<T>()
            .fetch_all(connection)
            .await
    }
}

/// `rows` in the order of `ids`, the order the page was read in. A row
/// removed between the two reads is absent from the page.
pub(crate) fn in_page_order<R>(ids: &[Uuid], rows: Vec<R>, id_of: impl Fn(&R) -> Uuid) -> Vec<R> {
    let mut by_id: HashMap<Uuid, R> = rows.into_iter().map(|row| (id_of(&row), row)).collect();
    ids.iter().filter_map(|id| by_id.remove(id)).collect()
}

/// A column a page is ordered by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Column {
    name: &'static str,
    direction: SortDirection,
    nullable: Nullable,
}

/// A condition on a row, before it is written as SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Condition {
    /// The column holds exactly the value, or is empty for a missing one.
    Level(Column, SortKey),
    /// The column sorts past the value, in its direction.
    Past(Column, SortKey),
    /// Every condition holds.
    All(Vec<Condition>),
    /// At least one condition holds; none at all is false.
    Any(Vec<Condition>),
    /// The columns, read as one row, sort past the values as one row.
    RowPast(Vec<Column>, Vec<SortKey>),
}

/// The columns `order` sorts by, then `id` in the direction of its last
/// term.
fn columns_of<F: SortColumns>(order: &SortOrder<F>, id: &'static str) -> Vec<Column> {
    let tiebreak = order
        .terms()
        .last()
        .map(|term| term.direction())
        .unwrap_or_default();
    order
        .terms()
        .iter()
        .map(|term| Column {
            name: term.field().column(),
            direction: term.direction(),
            nullable: term.field().nullable(),
        })
        .chain(std::iter::once(Column {
            name: id,
            direction: tiebreak,
            nullable: Nullable::Never,
        }))
        .collect()
}

/// The columns `sorted_by` names, each in its place in `directions`, then
/// `id` in the last direction, which is the tiebreak's.
fn listed_columns(
    directions: &[SortDirection],
    sorted_by: &[(&'static str, Nullable)],
    id: &'static str,
) -> Vec<Column> {
    let tiebreak = directions.last().copied().unwrap_or_default();
    sorted_by
        .iter()
        .zip(directions)
        .map(|(&(name, nullable), &direction)| Column {
            name,
            direction,
            nullable,
        })
        .chain(std::iter::once(Column {
            name: id,
            direction: tiebreak,
            nullable: Nullable::Never,
        }))
        .collect()
}

/// The rows past the cursor `after`.
///
/// When every column goes the same way and none can be empty, that is one
/// row comparison, which an index answers directly. Otherwise it is written
/// out: past the cursor on the first column, or level with it and past it
/// on the second, and so on.
fn seek(columns: &[Column], after: &[SortKey]) -> Condition {
    if compares_as_one_row(columns, after) {
        return Condition::RowPast(columns.to_vec(), after.to_vec());
    }
    let branches = (0..columns.len().min(after.len()))
        .filter_map(|depth| branch(columns, after, depth))
        .collect();
    Condition::Any(branches)
}

/// Whether the seek is one row comparison: one direction throughout, no
/// column that can be empty, no missing value in the cursor.
fn compares_as_one_row(columns: &[Column], after: &[SortKey]) -> bool {
    let direction = columns.first().map(|column| column.direction);
    columns
        .iter()
        .all(|column| Some(column.direction) == direction && column.nullable == Nullable::Never)
        && !after.contains(&SortKey::Missing)
}

/// Level with the cursor on the first `depth` columns and past it on the
/// next, or nothing when no row can sort past the cursor there.
fn branch(columns: &[Column], after: &[SortKey], depth: usize) -> Option<Condition> {
    let pairs = || columns.iter().copied().zip(after.iter().cloned());
    let (column, key) = pairs().nth(depth)?;
    let past = column.past(key)?;
    let levels = pairs()
        .take(depth)
        .map(|(column, key)| Condition::Level(column, key));
    Some(Condition::All(
        levels.chain(std::iter::once(past)).collect(),
    ))
}

impl Column {
    /// The condition of sorting past `key` on this column, or `None` when
    /// nothing can: an ascending column whose cursor is already at the
    /// empty end, where `NULL` comes last.
    fn past(self, key: SortKey) -> Option<Condition> {
        match (self.direction, &key) {
            (SortDirection::Asc, SortKey::Missing) => None,
            (SortDirection::Asc | SortDirection::Desc, _) => Some(Condition::Past(self, key)),
        }
    }

    /// The comparison that goes on past a value in this column's direction.
    fn beyond(self) -> &'static str {
        match self.direction {
            SortDirection::Asc => " > ",
            SortDirection::Desc => " < ",
        }
    }
}

impl Condition {
    /// Writes the condition into `query`, every value bound.
    fn write(&self, query: &mut QueryBuilder<'_, Postgres>) {
        match self {
            Self::Level(column, key) => write_level(query, *column, key),
            Self::Past(column, key) => write_past(query, *column, key),
            Self::All(conditions) => write_joined(query, conditions, " AND ", "TRUE"),
            Self::Any(conditions) => write_joined(query, conditions, " OR ", "FALSE"),
            Self::RowPast(columns, keys) => write_row_past(query, columns, keys),
        }
    }
}

/// `column = $n`, or `column IS NULL` for a missing value.
fn write_level(query: &mut QueryBuilder<'_, Postgres>, column: Column, key: &SortKey) {
    query.push(column.name);
    if *key == SortKey::Missing {
        query.push(" IS NULL");
        return;
    }
    query.push(" = ");
    bind_key(query, key);
}

/// `column > $n` or `column < $n`, with the empty rows that sort past a
/// value: after it when ascending, none when descending. Past a missing
/// value in a descending column is every row that has one.
fn write_past(query: &mut QueryBuilder<'_, Postgres>, column: Column, key: &SortKey) {
    if *key == SortKey::Missing {
        query.push(column.name);
        query.push(" IS NOT NULL");
        return;
    }
    let empty_follows =
        column.direction == SortDirection::Asc && column.nullable == Nullable::Maybe;
    query.push("(");
    query.push(column.name);
    query.push(column.beyond());
    bind_key(query, key);
    if empty_follows {
        query.push(" OR ");
        query.push(column.name);
        query.push(" IS NULL");
    }
    query.push(")");
}

/// `(a, b, id) > ($1, $2, $3)`.
fn write_row_past(query: &mut QueryBuilder<'_, Postgres>, columns: &[Column], keys: &[SortKey]) {
    let Some(first) = columns.first() else {
        query.push("FALSE");
        return;
    };
    query.push("(");
    let mut names = query.separated(", ");
    columns.iter().for_each(|column| {
        names.push(column.name);
    });
    query.push(")");
    query.push(first.beyond());
    query.push("(");
    for (index, key) in keys.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        bind_key(query, key);
    }
    query.push(")");
}

/// The conditions joined by `between` in brackets, or `empty` for none.
fn write_joined(
    query: &mut QueryBuilder<'_, Postgres>,
    conditions: &[Condition],
    between: &str,
    empty: &str,
) {
    match conditions {
        [] => {
            query.push(empty);
            return;
        }
        [only] => {
            only.write(query);
            return;
        }
        [_, _, ..] => {}
    }
    query.push("(");
    for (index, condition) in conditions.iter().enumerate() {
        if index > 0 {
            query.push(between);
        }
        condition.write(query);
    }
    query.push(")");
}

/// ` ORDER BY a ASC, b DESC, id DESC`.
fn write_order(query: &mut QueryBuilder<'_, Postgres>, columns: &[Column]) {
    query.push(" ORDER BY ");
    let mut terms = query.separated(", ");
    columns.iter().for_each(|column| {
        terms.push(column.name);
        terms.push_unseparated(match column.direction {
            SortDirection::Asc => " ASC",
            SortDirection::Desc => " DESC",
        });
    });
}

/// Binds `key` as the type it holds. A missing value is never bound: it is
/// written as `IS NULL` or `IS NOT NULL` before a value would be needed.
fn bind_key(query: &mut QueryBuilder<'_, Postgres>, key: &SortKey) {
    match key {
        SortKey::Integer(number) => query.push_bind(*number),
        SortKey::Text(text) => query.push_bind(text.clone()),
        SortKey::Time(at) => query.push_bind(*at),
        SortKey::Id(id) => query.push_bind(*id),
        SortKey::Missing => query.push("NULL"),
    };
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn column(name: &'static str, direction: SortDirection, nullable: Nullable) -> Column {
        Column {
            name,
            direction,
            nullable,
        }
    }

    fn id(direction: SortDirection) -> Column {
        column("id", direction, Nullable::Never)
    }

    fn text(value: &str) -> SortKey {
        SortKey::Text(value.to_owned())
    }

    fn written(condition: &Condition) -> String {
        let mut query = QueryBuilder::<Postgres>::new("");
        condition.write(&mut query);
        query.sql().to_owned()
    }

    /// Names sorted one way on a column never empty: one row comparison,
    /// which the index on `(name, id)` answers directly.
    #[test]
    fn one_direction_on_full_columns_seeks_as_one_row() {
        let columns = [
            column("name", SortDirection::Asc, Nullable::Never),
            id(SortDirection::Asc),
        ];
        let after = [text("bob"), SortKey::Id(Uuid::nil())];

        let condition = seek(&columns, &after);

        assert_eq!(
            condition,
            Condition::RowPast(columns.to_vec(), after.to_vec())
        );
        assert_eq!(written(&condition), "(name, id) > ($1, $2)");
    }

    /// Newest first, then by name: the directions differ, so the seek is
    /// written out, past on the first column, or level on it and past on
    /// the next.
    #[test]
    fn mixed_directions_are_written_out() {
        let columns = [
            column("created_at", SortDirection::Desc, Nullable::Never),
            column("name", SortDirection::Asc, Nullable::Never),
            id(SortDirection::Asc),
        ];
        let after = [SortKey::Integer(7), text("bob"), SortKey::Id(Uuid::nil())];

        let sql = written(&seek(&columns, &after));

        assert_eq!(
            sql,
            "((created_at < $1) OR (created_at = $2 AND (name > $3)) \
             OR (created_at = $4 AND name = $5 AND (id > $6)))"
        );
    }

    /// An ascending column that may be empty: rows with no value sort after
    /// every value, so they are past it too.
    #[test]
    fn an_empty_value_follows_every_value_when_ascending() {
        let maybe = column("ends_at", SortDirection::Asc, Nullable::Maybe);

        let condition = maybe.past(SortKey::Integer(3));

        assert_eq!(
            condition.as_ref().map(written).as_deref(),
            Some("(ends_at > $1 OR ends_at IS NULL)")
        );
    }

    /// The cursor already stands among the empty rows of an ascending
    /// column: nothing sorts past it there, so that branch is left out.
    #[test]
    fn nothing_follows_the_empty_end_of_an_ascending_column() {
        let maybe = column("ends_at", SortDirection::Asc, Nullable::Maybe);

        assert_eq!(maybe.past(SortKey::Missing), None);
    }

    /// Descending, empty rows come first: past an empty value is every row
    /// that has one.
    #[test]
    fn every_value_follows_an_empty_one_when_descending() {
        let maybe = column("ends_at", SortDirection::Desc, Nullable::Maybe);

        let condition = maybe.past(SortKey::Missing);

        assert_eq!(
            condition.as_ref().map(written).as_deref(),
            Some("ends_at IS NOT NULL")
        );
    }

    /// A row level with an empty cursor value is one with no value, written
    /// `IS NULL`, never compared with a bound `NULL`, which matches nothing.
    #[test]
    fn level_with_an_empty_value_is_null() {
        let maybe = column("ends_at", SortDirection::Desc, Nullable::Maybe);

        assert_eq!(
            written(&Condition::Level(maybe, SortKey::Missing)),
            "ends_at IS NULL"
        );
    }

    /// A joined list writes its join, with the value bound, before the first
    /// condition, which then opens the `WHERE`.
    #[test]
    fn a_join_comes_before_every_condition() {
        let query = PageQuery::joined(
            "u.id",
            "users u",
            "LEFT JOIN notes n ON n.user_id = u.id AND n.kind = ?",
            "memo",
        )
        .filter("u.tenant_id = ?", Uuid::nil());

        assert_eq!(
            query.builder.sql(),
            "SELECT u.id FROM users u LEFT JOIN notes n ON n.user_id = u.id AND n.kind = $1 \
             WHERE u.tenant_id = $2"
        );
    }

    /// An order of expressions takes the keyset's direction for each, and
    /// the id last in the direction of the last.
    #[test]
    fn listed_columns_follow_the_directions_and_end_with_the_id() {
        let directions = [SortDirection::Asc, SortDirection::Desc, SortDirection::Desc];
        let sorted_by = [
            ("num_nulls(n.body)", Nullable::Never),
            ("n.body", Nullable::Maybe),
        ];

        let columns = listed_columns(&directions, &sorted_by, "u.id");

        assert_eq!(
            columns,
            [
                column("num_nulls(n.body)", SortDirection::Asc, Nullable::Never),
                column("n.body", SortDirection::Desc, Nullable::Maybe),
                id_named("u.id", SortDirection::Desc),
            ]
        );
    }

    /// A count keeps the filters a page would, and reads no id.
    #[test]
    fn a_count_reads_how_many_rows_its_filters_keep() {
        let query = PageQuery::counted("users").filter("tenant_id = ?", Uuid::nil());

        assert_eq!(
            query.builder.sql(),
            "SELECT count(*) FROM users WHERE tenant_id = $1"
        );
    }

    fn id_named(name: &'static str, direction: SortDirection) -> Column {
        column(name, direction, Nullable::Never)
    }
}
