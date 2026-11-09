//! The platform's operators, kept in the platform database.
//!
//! An address names one operator, since an operator signs in by it. A list
//! first reads the ids of its page, then reads those rows by id, as every
//! read of an operator does.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::operator::{OperatorFilter, OperatorSortField, OperatorStore};
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OperatorId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{OperatorColumns, OperatorRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps an address to one operator.
const EMAIL_KEY: &str = "operators_email_key";

/// The Postgres operator store.
pub struct PgOperatorStore {
    databases: Arc<Databases>,
}

impl PgOperatorStore {
    /// A store keeping operators in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The records of the operators `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<OperatorRecord>, sqlx::Error> {
    sqlx::query_file_as!(OperatorRecord, "queries/operators/by_ids.sql", ids)
        .fetch_all(connection)
        .await
}

fn rebuilt_all(records: Vec<OperatorRecord>) -> Result<Vec<Operator>, DomainError> {
    records
        .into_iter()
        .map(OperatorRecord::into_operator)
        .collect()
}

/// The ids of the operators `filter` keeps.
fn listed(filter: &OperatorFilter) -> PageQuery<'static> {
    let every = PageQuery::ids("id", "operators");
    let Some(status) = filter.status else {
        return every;
    };
    every.filter("status = ?", status.word())
}

impl SortColumns for OperatorSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Email => "email",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

#[async_trait]
impl OperatorStore for PgOperatorStore {
    async fn find_by_id(&self, id: &OperatorId) -> Result<Option<Operator>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            records_of(connection, &ids).await
        })
        .await?;
        records
            .into_iter()
            .next()
            .map(OperatorRecord::into_operator)
            .transpose()
    }

    async fn find_by_email(&self, email: &Email) -> Result<Option<Operator>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                OperatorRecord,
                "queries/operators/by_email.sql",
                email.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(OperatorRecord::into_operator).transpose()
    }

    async fn list(
        &self,
        filter: &OperatorFilter,
        sort: &SortOrder<OperatorSortField>,
        page: &PageRequest,
    ) -> Result<Page<Operator>, DomainError> {
        let keyset = page.keyset(sort)?;
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids = listed(filter).fetch(&keyset, &mut *connection).await?;
            let records = records_of(connection, &ids).await?;
            Ok(in_page_order(&ids, records, |record| record.id))
        })
        .await?;
        Ok(keyset.seal(rebuilt_all(records)?))
    }

    async fn any_exists(&self) -> Result<bool, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!("queries/operators/any.sql")
                .fetch_one(connection)
                .await
        })
        .await
    }

    async fn save(&self, operator: &Operator) -> Result<(), DomainError> {
        let columns = OperatorColumns::of(operator);
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let attempt = sqlx::query_file!(
                "queries/operators/save.sql",
                columns.id,
                columns.email,
                columns.password_hash,
                columns.status,
                columns.created_at,
            )
            .execute(connection)
            .await;
            unique_on(attempt, EMAIL_KEY)
        })
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-operator-signs-in-with-this",
                "another operator signs in with this address"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_domain::domains::operator::identity::OperatorRow;
    use ianua_domain::domains::operator::status::OperatorStatus;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::operator::{active_operator, operator_row};

    struct Fixture {
        db: TestDb,
        store: PgOperatorStore,
    }

    /// A fresh database and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgOperatorStore::new(Arc::clone(&db.databases)),
            db,
        }
    }

    fn by(field: OperatorSortField) -> SortOrder<OperatorSortField> {
        SortOrder::single(Sort::ascending(field))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn emails(page: &Page<Operator>) -> Vec<&str> {
        page.items
            .iter()
            .map(|operator| operator.email().as_str())
            .collect()
    }

    impl Fixture {
        async fn save_all(&self, operators: &[&Operator]) {
            for operator in operators {
                self.store.save(operator).await.unwrap();
            }
        }

        async fn listed(
            &self,
            filter: &OperatorFilter,
            sort: &SortOrder<OperatorSortField>,
            page: &PageRequest,
        ) -> Page<Operator> {
            self.store.list(filter, sort, page).await.unwrap()
        }
    }

    /// Olga is found by her id and by her address, as she was saved.
    #[tokio::test]
    async fn a_saved_operator_is_found_by_id_and_by_address() {
        let fx = fixture().await;
        let olga = active_operator("olga@ianua.dev");
        fx.save_all(&[&olga]).await;

        let by_id = fx.store.find_by_id(olga.id()).await.unwrap().unwrap();
        let by_email = fx.store.find_by_email(olga.email()).await.unwrap().unwrap();

        for found in [&by_id, &by_email] {
            assert_eq!(found.id(), olga.id());
            assert_eq!(found.password_hash(), olga.password_hash());
            assert_eq!(found.status(), OperatorStatus::Active);
            assert_eq!(found.created_at(), olga.created_at());
        }
    }

    /// An id or address no operator has finds nothing, and a platform
    /// with no operator says none exists.
    #[tokio::test]
    async fn an_unknown_operator_is_not_found() {
        let fx = fixture().await;
        let nobody = Email::new("nobody@ianua.dev").unwrap();

        assert!(
            fx.store
                .find_by_id(&OperatorId::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(fx.store.find_by_email(&nobody).await.unwrap().is_none());
        assert!(!fx.store.any_exists().await.unwrap());
    }

    /// Once one operator exists, the platform says one does, whatever its
    /// status.
    #[tokio::test]
    async fn a_disabled_operator_still_counts_as_one() {
        let fx = fixture().await;
        let row = operator_row("off@ianua.dev", OperatorStatus::Disabled);
        fx.save_all(&[&Operator::reconstitute(row).unwrap()]).await;

        assert!(fx.store.any_exists().await.unwrap());
    }

    /// Saving a second operator with Olga's address returns a conflict.
    #[tokio::test]
    async fn an_address_another_operator_has_is_refused() {
        let fx = fixture().await;
        fx.save_all(&[&active_operator("olga@ianua.dev")]).await;

        let second = fx.store.save(&active_operator("olga@ianua.dev")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// The operators list by address page by page, each page after the
    /// last, and the last says nothing follows.
    #[tokio::test]
    async fn operators_are_listed_page_by_page() {
        let fx = fixture().await;
        let operators = ["c@ianua.dev", "a@ianua.dev", "b@ianua.dev"].map(active_operator);
        fx.save_all(&operators.iter().collect::<Vec<_>>()).await;
        let order = by(OperatorSortField::Email);

        let page_one = fx.listed(&OperatorFilter::all(), &order, &first(2)).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.listed(&OperatorFilter::all(), &order, &after).await;

        assert_eq!(emails(&page_one), ["a@ianua.dev", "b@ianua.dev"]);
        assert_eq!(emails(&page_two), ["c@ianua.dev"]);
        assert!(!page_two.has_next());
    }

    /// A list narrows to one status, and sorts by status and by creation
    /// with every operator once.
    #[tokio::test]
    async fn a_list_narrows_by_status_and_sorts_by_each_field() {
        let fx = fixture().await;
        let off = Operator::reconstitute(OperatorRow {
            created_at: at(5),
            ..operator_row("off@ianua.dev", OperatorStatus::Disabled)
        })
        .unwrap();
        fx.save_all(&[&active_operator("on@ianua.dev"), &off]).await;
        let disabled = OperatorFilter {
            status: Some(OperatorStatus::Disabled),
        };

        let every = OperatorFilter::all();

        let only_off = fx
            .listed(&disabled, &by(OperatorSortField::Email), &first(10))
            .await;
        let by_status = fx
            .listed(&every, &by(OperatorSortField::Status), &first(10))
            .await;
        let by_created = fx
            .listed(&every, &by(OperatorSortField::CreatedAt), &first(10))
            .await;

        assert_eq!(emails(&only_off), ["off@ianua.dev"]);
        assert_eq!(emails(&by_status), ["on@ianua.dev", "off@ianua.dev"]);
        assert_eq!(emails(&by_created), ["on@ianua.dev", "off@ianua.dev"]);
    }

    /// Olga is disabled: saving her again keeps the new status and the time
    /// she was made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let olga = active_operator("olga@ianua.dev");
        fx.save_all(&[&olga]).await;
        let disabled = Operator::reconstitute(OperatorRow {
            id: *olga.id(),
            created_at: at(9),
            ..operator_row("olga@ianua.dev", OperatorStatus::Disabled)
        })
        .unwrap();

        fx.save_all(&[&disabled]).await;

        let found = fx.store.find_by_id(olga.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), OperatorStatus::Disabled);
        assert_eq!(found.created_at(), olga.created_at());
    }

    /// Reading Olga's row after its email is replaced with invalid text
    /// reports corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_operator_is_refused() {
        let fx = fixture().await;
        let olga = active_operator("olga@ianua.dev");
        fx.save_all(&[&olga]).await;
        fx.db
            .tamper("UPDATE operators SET email = 'not an address'")
            .await;

        let read = fx.store.find_by_id(olga.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
