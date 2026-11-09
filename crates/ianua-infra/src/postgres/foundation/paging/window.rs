//! A stretch of a list by position, for SCIM alone.
//!
//! Every other list is paged by key with [`PageQuery`]. SCIM cannot be:
//! RFC 7644, section 3.4.2.4, has a directory ask for entries from its
//! 1-based `startIndex` and read `totalResults`, so its stores read a
//! stretch by `OFFSET` and count the rows their filter keeps. The start is
//! capped by [`ScimWindow`] before it reaches this builder, so no request
//! makes Postgres read and throw away more than that many rows, and the
//! cap is why `OFFSET` is allowed here and nowhere else.
//!
//! The query is made of `&'static str` pieces and bound values alone, as
//! [`PageQuery`] is, whose filters it shares.

use ianua_app::listing::SortDirection;
use ianua_app::ports::federation::ScimWindow;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::postgres::foundation::paging::picks::Picks;
use crate::postgres::foundation::paging::{Count, Ids, PageQuery};

/// The query for the ids of one SCIM stretch, or for how many rows its
/// filters keep.
pub(crate) struct WindowQuery<'q, Read = Ids> {
    query: PageQuery<'q, Read>,
}

impl<'q, Read> WindowQuery<'q, Read> {
    /// Keeps the rows where `condition` holds, with `value` bound where it
    /// marks `?`.
    pub(crate) fn filter<T>(self, condition: &'static str, value: T) -> Self
    where
        T: 'q + sqlx::Encode<'q, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send,
    {
        Self {
            query: self.query.filter(condition, value),
        }
    }

    /// Keeps the rows where the fixed `condition` holds.
    pub(crate) fn keep(self, condition: &'static str) -> Self {
        Self {
            query: self.query.keep(condition),
        }
    }

    /// Keeps the rows `picks` keeps.
    pub(crate) fn picking(self, picks: &Picks) -> Self {
        Self {
            query: self.query.picking(picks),
        }
    }
}

impl<'q> WindowQuery<'q, Ids> {
    /// The ids of the rows of `from`, such as `users`, read from the column
    /// `id`, such as `users.id`.
    pub(crate) fn ids(id: &'static str, from: &'static str) -> Self {
        Self {
            query: PageQuery::ids(id, from),
        }
    }

    /// The ids of the stretch `window` asks for, ordered by `order`, each
    /// column with its empty values last whichever way it runs. The last
    /// column should be the id, so the order holds from one stretch to the
    /// next.
    pub(crate) async fn fetch(
        self,
        order: &[(&'static str, SortDirection)],
        window: ScimWindow,
        connection: &mut PgConnection,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        let mut builder = self.query.into_builder();
        builder.push(" ORDER BY ");
        let mut terms = builder.separated(", ");
        for (column, direction) in order {
            terms.push(*column);
            terms.push_unseparated(match direction {
                SortDirection::Asc => " ASC NULLS LAST",
                SortDirection::Desc => " DESC NULLS LAST",
            });
        }
        builder.push(" OFFSET ");
        builder.push_bind(i64::try_from(window.skip()).unwrap_or(i64::MAX));
        builder.push(" LIMIT ");
        builder.push_bind(i64::try_from(window.count()).unwrap_or(i64::MAX));
        builder
            .build_query_scalar::<Uuid>()
            .fetch_all(connection)
            .await
    }
}

impl<'q> WindowQuery<'q, Count> {
    /// How many rows of `from` the filters keep.
    pub(crate) fn counted(from: &'static str) -> Self {
        Self {
            query: PageQuery::counted(from),
        }
    }

    /// The number of rows the filters keep.
    pub(crate) async fn count(self, connection: &mut PgConnection) -> Result<i64, sqlx::Error> {
        self.query.count(connection).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sql_of(query: WindowQuery<'_, Ids>) -> String {
        query.query.into_builder().sql().to_owned()
    }

    /// A stretch's filters, its tree among them, read as a page's would.
    #[test]
    fn a_stretch_is_filtered_as_a_page_is() {
        let query = WindowQuery::ids("users.id", "users")
            .filter("users.tenant_id = ?", Uuid::nil())
            .picking(&Picks::Holds(
                "users.email = lower(?)",
                "ann@acme.example".to_owned(),
            ));

        assert_eq!(
            sql_of(query),
            "SELECT users.id FROM users WHERE users.tenant_id = $1 AND (users.email = lower($2))"
        );
    }
}
