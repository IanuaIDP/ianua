//! A filter that is a tree: fixed conditions joined by `and` and `or`.
//!
//! A filter a caller builds, such as a SCIM directory's
//! `userName sw "ann" or externalId eq "42"`, has a shape known only when
//! it arrives. It is built as [`Picks`] first, plain data a test can read,
//! and only then written out as SQL, each branch in brackets. Every
//! condition is a `&'static str` the store chose by matching a closed enum,
//! and every value is bound, so nothing a caller sends becomes SQL text.

use sqlx::{Postgres, QueryBuilder};

/// Which rows a filter keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Picks {
    /// Every row.
    All,
    /// The rows where the fixed condition holds, with the text bound where
    /// it marks `?`, such as `users.external_id = ?`.
    Holds(&'static str, String),
    /// The rows both filters keep.
    And(Box<Picks>, Box<Picks>),
    /// The rows either filter keeps.
    Or(Box<Picks>, Box<Picks>),
}

impl Picks {
    /// Writes the filter into `query`, every value bound, every branch in
    /// brackets.
    pub(crate) fn write(&self, query: &mut QueryBuilder<'_, Postgres>) {
        match self {
            Self::All => {
                query.push("TRUE");
            }
            Self::Holds(condition, value) => write_holds(query, condition, value),
            Self::And(left, right) => write_joined(query, left, " AND ", right),
            Self::Or(left, right) => write_joined(query, left, " OR ", right),
        }
    }
}

/// `(condition)` with `value` bound where it marks `?`.
fn write_holds(query: &mut QueryBuilder<'_, Postgres>, condition: &'static str, value: &str) {
    let (before, after) = condition.split_once('?').unwrap_or((condition, ""));
    query.push("(");
    query.push(before);
    query.push_bind(value.to_owned());
    query.push(after);
    query.push(")");
}

/// `(left between right)`.
fn write_joined(
    query: &mut QueryBuilder<'_, Postgres>,
    left: &Picks,
    between: &'static str,
    right: &Picks,
) {
    query.push("(");
    left.write(query);
    query.push(between);
    right.write(query);
    query.push(")");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(picks: &Picks) -> String {
        let mut query = QueryBuilder::<Postgres>::new("");
        picks.write(&mut query);
        query.sql().to_owned()
    }

    fn holds(condition: &'static str, value: &str) -> Box<Picks> {
        Box::new(Picks::Holds(condition, value.to_owned()))
    }

    /// No filter keeps every row.
    #[test]
    fn everything_is_true() {
        assert_eq!(written(&Picks::All), "TRUE");
    }

    /// One condition is written in brackets, its value bound and never
    /// written into the text.
    #[test]
    fn a_condition_binds_its_value() {
        let sql = written(&Picks::Holds(
            "users.email = lower(?)",
            "x' OR '1'='1".to_owned(),
        ));

        assert_eq!(sql, "(users.email = lower($1))");
    }

    /// `a and (b or c)`: each join is bracketed, so the `or` binds inside
    /// the `and` as the tree says, never as SQL's precedence would.
    #[test]
    fn nested_joins_keep_the_shape_of_the_tree() {
        let picks = Picks::And(
            holds("a = ?", "1"),
            Box::new(Picks::Or(holds("b = ?", "2"), holds("c = ?", "3"))),
        );

        assert_eq!(written(&picks), "((a = $1) AND ((b = $2) OR (c = $3)))");
    }

    /// `(a or b) and c` reads apart from `a or (b and c)`.
    #[test]
    fn an_or_under_an_and_is_bracketed_on_the_left_too() {
        let picks = Picks::And(
            Box::new(Picks::Or(holds("a = ?", "1"), holds("b = ?", "2"))),
            holds("c = ?", "3"),
        );

        assert_eq!(written(&picks), "(((a = $1) OR (b = $2)) AND (c = $3))");
    }
}
