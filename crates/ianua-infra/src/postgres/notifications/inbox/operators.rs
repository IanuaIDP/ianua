//! An operator's inbox, in the platform database.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::notifications::{
    Kept, NotificationSortField, PlatformNotificationStore, ReadFilter,
};
use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{NotificationId, OperatorId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::paging::{PageQuery, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::notifications::inbox::listing::in_reads;
use crate::postgres::notifications::inbox::record::{
    NotificationColumns, NotificationRecord, kept, rebuilt,
};

/// The Postgres store of operators' notifications.
pub struct PgPlatformNotificationStore {
    databases: Arc<Databases>,
}

impl PgPlatformNotificationStore {
    /// A store keeping operators' notifications in `databases`' platform
    /// database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// The records of `operator`'s notifications that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    operator: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<NotificationRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        NotificationRecord,
        "queries/platform_notifications/by_ids.sql",
        operator,
        ids
    )
    .fetch_all(connection)
    .await
}

#[async_trait]
impl PlatformNotificationStore for PgPlatformNotificationStore {
    async fn list_for_operator(
        &self,
        operator_id: &OperatorId,
        reads: ReadFilter,
        sort: &SortOrder<NotificationSortField>,
        page: &PageRequest,
    ) -> Result<Page<Notification>, DomainError> {
        let keyset = page.keyset(sort)?;
        let operator = *operator_id.as_uuid();
        let listed = in_reads(
            PageQuery::ids("id", "platform_notifications").filter("operator_id = ?", operator),
            reads,
        );
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids = listed.fetch(&keyset, &mut *connection).await?;
            let records = records_of(connection, &operator, &ids).await?;
            Ok(in_page_order(&ids, records, |record| record.id))
        })
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn unread_count(&self, operator_id: &OperatorId) -> Result<u64, DomainError> {
        let count = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/platform_notifications/unread_count.sql",
                operator_id.as_uuid()
            )
            .fetch_one(connection)
            .await
        })
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }

    async fn mark_read(
        &self,
        operator_id: &OperatorId,
        notification_id: &NotificationId,
    ) -> Result<bool, DomainError> {
        let marked = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/platform_notifications/mark_read.sql",
                operator_id.as_uuid(),
                notification_id.as_uuid()
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(marked.rows_affected() == 1)
    }

    async fn mark_all_read(&self, operator_id: &OperatorId) -> Result<u64, DomainError> {
        let marked = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/platform_notifications/mark_all_read.sql",
                operator_id.as_uuid()
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(marked.rows_affected())
    }

    async fn save(
        &self,
        operator_id: &OperatorId,
        notification: &Notification,
    ) -> Result<Kept, DomainError> {
        let columns = NotificationColumns::of(notification);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let done = sqlx::query_file!(
                "queries/platform_notifications/save.sql",
                columns.id,
                operator_id.as_uuid(),
                columns.event_type,
                columns.category,
                columns.severity,
                columns.title,
                columns.body,
                columns.resource_id,
                columns.reach,
                columns.read,
                columns.created_at,
            )
            .execute(connection)
            .await?;
            Ok(kept(done.rows_affected()))
        })
        .await
    }

    async fn purge_before(&self, cutoff: OffsetDateTime) -> Result<u64, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let done = sqlx::query_file!("queries/platform_notifications/purge_before.sql", cutoff)
                .execute(connection)
                .await?;
            Ok(done.rows_affected())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::operator::OperatorStore;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::types::Text;

    use super::*;
    use crate::postgres::operator::PgOperatorStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::notifications::{
        key_rotated, notice, notification_row, own_account_notice, user_registered,
    };
    use crate::test_support::rows::operator::active_operator;

    struct Fixture {
        db: TestDb,
        store: PgPlatformNotificationStore,
        ann: OperatorId,
        bob: OperatorId,
    }

    /// A fresh database with two operators, Ann and Bob, and the store.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let ann = an_operator(&db, "ann@ianua.example").await;
        let bob = an_operator(&db, "bob@ianua.example").await;
        let store = PgPlatformNotificationStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            ann,
            bob,
        }
    }

    /// Saves an operator at `email` through the operator store.
    async fn an_operator(db: &TestDb, email: &str) -> OperatorId {
        let operator = active_operator(email);
        PgOperatorStore::new(Arc::clone(&db.databases))
            .save(&operator)
            .await
            .unwrap();
        *operator.id()
    }

    fn newest_first() -> SortOrder<NotificationSortField> {
        SortOrder::default()
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn ids(page: &Page<Notification>) -> Vec<NotificationId> {
        page.items.iter().map(Notification::id).collect()
    }

    /// A saved notice reads back whole in Ann's inbox, and Bob's stays
    /// empty.
    #[tokio::test]
    async fn a_saved_notice_reads_back_in_its_inbox_only() {
        let fx = fixture().await;
        let saved = own_account_notice(0);

        fx.store.save(&fx.ann, &saved).await.unwrap();

        let page = fx
            .store
            .list_for_operator(&fx.ann, ReadFilter::All, &newest_first(), &first(10))
            .await
            .unwrap();
        let found = &page.items[0];
        assert_eq!(found.id(), saved.id());
        assert_eq!(found.event_type(), saved.event_type());
        assert_eq!(found.category(), saved.category());
        assert_eq!(found.severity(), saved.severity());
        assert_eq!(found.title().as_str(), saved.title().as_str());
        assert_eq!(
            found.body().map(Text::as_str),
            saved.body().map(Text::as_str)
        );
        assert_eq!(found.resource_id(), saved.resource_id());
        assert_eq!(found.reach(), saved.reach());
        assert_eq!(found.created_at(), saved.created_at());
        assert!(!found.is_read());
        let theirs = fx
            .store
            .list_for_operator(&fx.bob, ReadFilter::All, &newest_first(), &first(10))
            .await
            .unwrap();
        assert!(theirs.items.is_empty());
    }

    /// A retried fan-out saves the same notice twice: it is kept once, the
    /// second save says it was there already, and a read made in between is
    /// not undone.
    #[tokio::test]
    async fn saving_a_notice_again_changes_nothing() {
        let fx = fixture().await;
        let saved = notice(user_registered(), 0);
        let once = fx.store.save(&fx.ann, &saved).await.unwrap();
        fx.store.mark_read(&fx.ann, &saved.id()).await.unwrap();

        let again = fx.store.save(&fx.ann, &saved).await.unwrap();

        assert_eq!((once, again), (Kept::New, Kept::AlreadyKept));

        let page = fx
            .store
            .list_for_operator(&fx.ann, ReadFilter::All, &newest_first(), &first(10))
            .await
            .unwrap();
        assert_eq!(ids(&page), [saved.id()]);
        assert!(page.items[0].is_read());
    }

    /// Purging removes Ann's notice before the cutoff and keeps Bob's
    /// notice made exactly at it.
    #[tokio::test]
    async fn a_notice_made_before_the_cutoff_is_purged() {
        let fx = fixture().await;
        let (old, recent) = (notice(user_registered(), 0), notice(user_registered(), 10));
        fx.store.save(&fx.ann, &old).await.unwrap();
        fx.store.save(&fx.bob, &recent).await.unwrap();

        let removed = fx.store.purge_before(recent.created_at()).await.unwrap();

        let left = fx
            .store
            .list_for_operator(&fx.bob, ReadFilter::All, &newest_first(), &first(10))
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert_eq!(ids(&left), [recent.id()]);
        assert_eq!(fx.store.unread_count(&fx.ann).await.unwrap(), 0);
    }

    /// Ann's inbox lists newest first, page by page.
    #[tokio::test]
    async fn an_inbox_lists_newest_first_across_pages() {
        let fx = fixture().await;
        let notices = [
            notice(user_registered(), 0),
            notice(user_registered(), 10),
            notice(key_rotated(), 20),
        ];
        for each in &notices {
            fx.store.save(&fx.ann, each).await.unwrap();
        }

        let page_one = fx
            .store
            .list_for_operator(&fx.ann, ReadFilter::All, &newest_first(), &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx
            .store
            .list_for_operator(&fx.ann, ReadFilter::All, &newest_first(), &after)
            .await
            .unwrap();

        assert_eq!(ids(&page_one), [notices[2].id(), notices[1].id()]);
        assert_eq!(ids(&page_two), [notices[0].id()]);
        assert!(!page_two.has_next());
    }

    /// Ascending severity lists info, warning and critical across two
    /// pages, following urgency rather than the words' alphabetical order.
    #[tokio::test]
    async fn an_inbox_lists_by_severity_across_pages() {
        let fx = fixture().await;
        let at_severity = |severity, seconds| {
            Notification::reconstitute(notification_row(user_registered(), severity, seconds))
                .unwrap()
        };
        let warning = at_severity(NotificationSeverity::Warning, 0);
        let critical = at_severity(NotificationSeverity::Critical, 10);
        let info = at_severity(NotificationSeverity::Info, 20);
        for each in [&warning, &critical, &info] {
            fx.store.save(&fx.ann, each).await.unwrap();
        }
        let by_severity = SortOrder::single(Sort::ascending(NotificationSortField::Severity));

        let page_one = fx
            .store
            .list_for_operator(&fx.ann, ReadFilter::All, &by_severity, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx
            .store
            .list_for_operator(&fx.ann, ReadFilter::All, &by_severity, &after)
            .await
            .unwrap();

        assert_eq!(ids(&page_one), [info.id(), warning.id()]);
        assert_eq!(ids(&page_two), [critical.id()]);
    }

    /// The unread list and count leave out what Ann read; marking all
    /// read marks the rest and counts them.
    #[tokio::test]
    async fn reads_are_counted_listed_and_marked() {
        let fx = fixture().await;
        let notices = [
            notice(user_registered(), 0),
            notice(user_registered(), 10),
            notice(key_rotated(), 20),
        ];
        for each in &notices {
            fx.store.save(&fx.ann, each).await.unwrap();
        }
        fx.store
            .save(&fx.bob, &notice(key_rotated(), 30))
            .await
            .unwrap();

        let found = fx.store.mark_read(&fx.ann, &notices[0].id()).await.unwrap();

        assert!(found);
        assert_eq!(fx.store.unread_count(&fx.ann).await.unwrap(), 2);
        let unread = fx
            .store
            .list_for_operator(&fx.ann, ReadFilter::UnreadOnly, &newest_first(), &first(10))
            .await
            .unwrap();
        assert_eq!(ids(&unread), [notices[2].id(), notices[1].id()]);
        assert_eq!(fx.store.mark_all_read(&fx.ann).await.unwrap(), 2);
        assert_eq!(fx.store.unread_count(&fx.ann).await.unwrap(), 0);
        assert_eq!(fx.store.unread_count(&fx.bob).await.unwrap(), 1);
    }

    /// Marking Ann's notice through Bob's inbox reports it missing and
    /// leaves Ann's unread count unchanged.
    #[tokio::test]
    async fn a_notice_in_another_inbox_is_not_marked() {
        let fx = fixture().await;
        let hers = notice(user_registered(), 0);
        fx.store.save(&fx.ann, &hers).await.unwrap();

        let found = fx.store.mark_read(&fx.bob, &hers.id()).await.unwrap();

        assert!(!found);
        assert_eq!(fx.store.unread_count(&fx.ann).await.unwrap(), 1);
    }

    /// Listing a stored key-rotation notice filed under identity fails
    /// as corrupt storage.
    #[tokio::test]
    async fn a_notice_filed_under_another_category_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.ann, &notice(key_rotated(), 0))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE platform_notifications SET category = 'identity'")
            .await;

        let read = fx
            .store
            .list_for_operator(&fx.ann, ReadFilter::All, &newest_first(), &first(10))
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
