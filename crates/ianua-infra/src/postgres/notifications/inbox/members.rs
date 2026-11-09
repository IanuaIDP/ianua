//! An organization member's inbox, in the platform database. Every read
//! and write names the organization beside the member, so a member is only
//! ever reached within their own organization.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Listing, Page};
use ianua_app::ports::notifications::{
    Kept, NotificationSortField, OrgNotificationStore, ReadFilter,
};
use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{NotificationId, OrgUserId, OrganizationId};
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

/// The Postgres store of organization members' notifications.
pub struct PgOrgNotificationStore {
    databases: Arc<Databases>,
}

impl PgOrgNotificationStore {
    /// A store keeping members' notifications in `databases`' platform
    /// database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// One member's inbox, as its queries name it.
#[derive(Clone, Copy)]
struct MemberInbox {
    organization: Uuid,
    member: Uuid,
}

impl MemberInbox {
    /// The inbox of `org_user_id` within `organization_id`.
    fn of(organization_id: &OrganizationId, org_user_id: &OrgUserId) -> Self {
        Self {
            organization: *organization_id.as_uuid(),
            member: *org_user_id.as_uuid(),
        }
    }
}

/// The records of `inbox`'s notifications that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    inbox: MemberInbox,
    ids: &[Uuid],
) -> Result<Vec<NotificationRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        NotificationRecord,
        "queries/org_notifications/by_ids.sql",
        inbox.organization,
        inbox.member,
        ids
    )
    .fetch_all(connection)
    .await
}

#[async_trait]
impl OrgNotificationStore for PgOrgNotificationStore {
    async fn list_for_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        listing: Listing<'_, ReadFilter, NotificationSortField>,
    ) -> Result<Page<Notification>, DomainError> {
        let keyset = listing.keyset()?;
        let inbox = MemberInbox::of(organization_id, org_user_id);
        let listed = in_reads(
            PageQuery::ids("id", "org_notifications")
                .filter("organization_id = ?", inbox.organization)
                .filter("org_user_id = ?", inbox.member),
            listing.filter,
        );
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids = listed.fetch(&keyset, &mut *connection).await?;
            let records = records_of(connection, inbox, &ids).await?;
            Ok(in_page_order(&ids, records, |record| record.id))
        })
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn unread_count(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<u64, DomainError> {
        let count = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/org_notifications/unread_count.sql",
                organization_id.as_uuid(),
                org_user_id.as_uuid()
            )
            .fetch_one(connection)
            .await
        })
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }

    async fn mark_read(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        notification_id: &NotificationId,
    ) -> Result<bool, DomainError> {
        let marked = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_notifications/mark_read.sql",
                organization_id.as_uuid(),
                org_user_id.as_uuid(),
                notification_id.as_uuid()
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(marked.rows_affected() == 1)
    }

    async fn mark_all_read(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<u64, DomainError> {
        let marked = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_notifications/mark_all_read.sql",
                organization_id.as_uuid(),
                org_user_id.as_uuid()
            )
            .execute(connection)
            .await
        })
        .await?;
        Ok(marked.rows_affected())
    }

    async fn save(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        notification: &Notification,
    ) -> Result<Kept, DomainError> {
        let columns = NotificationColumns::of(notification);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let done = sqlx::query_file!(
                "queries/org_notifications/save.sql",
                columns.id,
                organization_id.as_uuid(),
                org_user_id.as_uuid(),
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
            let done = sqlx::query_file!("queries/org_notifications/purge_before.sql", cutoff)
                .execute(connection)
                .await?;
            Ok(done.rows_affected())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, PageRequest, Sort, SortOrder};
    use ianua_app::ports::organization::OrgUserStore;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::organization::PgOrgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::saved_organization;
    use crate::test_support::rows::notifications::{key_rotated, notice, user_registered};
    use crate::test_support::rows::organization::org_user_row;

    struct Fixture {
        db: TestDb,
        store: PgOrgNotificationStore,
        acme: OrganizationId,
        ann: OrgUserId,
        sam: OrgUserId,
    }

    impl Fixture {
        /// Reads Ann's inbox within Acme using the supplied filter and page cursor.
        async fn ann_page(
            &self,
            listing: Listing<'_, ReadFilter, NotificationSortField>,
        ) -> Page<Notification> {
            self.store
                .list_for_user(&self.acme, &self.ann, listing)
                .await
                .unwrap()
        }
    }

    /// A fresh database with Acme and two of its members, Ann and Sam, and
    /// the store.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let ann = a_member(&db, acme, "ann@acme.example").await;
        let sam = a_member(&db, acme, "sam@acme.example").await;
        let store = PgOrgNotificationStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            acme,
            ann,
            sam,
        }
    }

    /// Saves a member of `organization` at `email` through the member
    /// store.
    async fn a_member(db: &TestDb, organization: OrganizationId, email: &str) -> OrgUserId {
        let member = OrgUser::reconstitute(org_user_row(organization, email)).unwrap();
        PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&member)
            .await
            .unwrap();
        *member.id()
    }

    fn listing<'a>(
        reads: ReadFilter,
        sort: &'a SortOrder<NotificationSortField>,
        page: &'a PageRequest,
    ) -> Listing<'a, ReadFilter, NotificationSortField> {
        Listing {
            filter: reads,
            sort,
            page,
        }
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn ids(page: &Page<Notification>) -> Vec<NotificationId> {
        page.items.iter().map(Notification::id).collect()
    }

    /// Purging removes Ann's notice before the cutoff and keeps Sam's
    /// notice made exactly at it.
    #[tokio::test]
    async fn a_notice_made_before_the_cutoff_is_purged() {
        let fx = fixture().await;
        let (old, recent) = (notice(user_registered(), 0), notice(user_registered(), 10));
        fx.store.save(&fx.acme, &fx.ann, &old).await.unwrap();
        fx.store.save(&fx.acme, &fx.sam, &recent).await.unwrap();

        let removed = fx.store.purge_before(recent.created_at()).await.unwrap();

        let newest = SortOrder::default();
        let left = fx
            .store
            .list_for_user(
                &fx.acme,
                &fx.sam,
                listing(ReadFilter::All, &newest, &first(10)),
            )
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert_eq!(ids(&left), [recent.id()]);
        assert_eq!(fx.store.unread_count(&fx.acme, &fx.ann).await.unwrap(), 0);
    }

    /// Ann's inbox lists her notices newest first, page by page, and
    /// none of Sam's.
    #[tokio::test]
    async fn a_member_lists_their_own_notices_across_pages() {
        let fx = fixture().await;
        let notices = [
            notice(user_registered(), 0),
            notice(key_rotated(), 10),
            notice(user_registered(), 20),
        ];
        for each in &notices {
            fx.store.save(&fx.acme, &fx.ann, each).await.unwrap();
        }
        fx.store
            .save(&fx.acme, &fx.sam, &notice(key_rotated(), 30))
            .await
            .unwrap();
        let newest = SortOrder::default();

        let page_one = fx
            .ann_page(listing(ReadFilter::All, &newest, &first(2)))
            .await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.ann_page(listing(ReadFilter::All, &newest, &after)).await;

        assert_eq!(ids(&page_one), [notices[2].id(), notices[1].id()]);
        assert_eq!(ids(&page_two), [notices[0].id()]);
    }

    /// Sorted by category, Ann's notices come alphabetically by the word
    /// each is filed under.
    #[tokio::test]
    async fn a_member_lists_by_category() {
        let fx = fixture().await;
        let identity = notice(user_registered(), 0);
        let crypto = notice(key_rotated(), 10);
        for each in [&identity, &crypto] {
            fx.store.save(&fx.acme, &fx.ann, each).await.unwrap();
        }
        let by_category = SortOrder::single(Sort::ascending(NotificationSortField::Category));

        let page = fx
            .store
            .list_for_user(
                &fx.acme,
                &fx.ann,
                listing(ReadFilter::All, &by_category, &first(10)),
            )
            .await
            .unwrap();

        assert_eq!(ids(&page), [crypto.id(), identity.id()]);
    }

    /// Ann marks one notice read, then the rest: the unread list and
    /// count follow, and Sam's stay as they were.
    #[tokio::test]
    async fn reads_are_counted_listed_and_marked() {
        let fx = fixture().await;
        let notices = [notice(user_registered(), 0), notice(key_rotated(), 10)];
        for each in &notices {
            fx.store.save(&fx.acme, &fx.ann, each).await.unwrap();
        }
        fx.store
            .save(&fx.acme, &fx.sam, &notice(key_rotated(), 20))
            .await
            .unwrap();
        let newest = SortOrder::default();

        let found = fx
            .store
            .mark_read(&fx.acme, &fx.ann, &notices[1].id())
            .await
            .unwrap();

        assert!(found);
        let unread = fx
            .store
            .list_for_user(
                &fx.acme,
                &fx.ann,
                listing(ReadFilter::UnreadOnly, &newest, &first(10)),
            )
            .await
            .unwrap();
        assert_eq!(ids(&unread), [notices[0].id()]);
        assert_eq!(fx.store.unread_count(&fx.acme, &fx.ann).await.unwrap(), 1);
        assert_eq!(fx.store.mark_all_read(&fx.acme, &fx.ann).await.unwrap(), 1);
        assert_eq!(fx.store.unread_count(&fx.acme, &fx.ann).await.unwrap(), 0);
        assert_eq!(fx.store.unread_count(&fx.acme, &fx.sam).await.unwrap(), 1);
    }

    /// Another organization's id cannot list or mark Ann's notice;
    /// her unread count in Acme remains unchanged.
    #[tokio::test]
    async fn an_inbox_is_reached_only_within_its_organization() {
        let fx = fixture().await;
        let hers = notice(user_registered(), 0);
        fx.store.save(&fx.acme, &fx.ann, &hers).await.unwrap();
        let other = saved_organization(&fx.db.databases).await;
        let newest = SortOrder::default();

        let listed = fx
            .store
            .list_for_user(
                &other,
                &fx.ann,
                listing(ReadFilter::All, &newest, &first(10)),
            )
            .await
            .unwrap();
        let found = fx
            .store
            .mark_read(&other, &fx.ann, &hers.id())
            .await
            .unwrap();

        assert!(listed.items.is_empty());
        assert!(!found);
        assert_eq!(fx.store.unread_count(&fx.acme, &fx.ann).await.unwrap(), 1);
    }

    /// An unknown event type in a stored notice makes the member's inbox
    /// listing fail as corrupt storage.
    #[tokio::test]
    async fn a_notice_of_an_unknown_event_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&fx.acme, &fx.ann, &notice(user_registered(), 0))
            .await
            .unwrap();
        fx.db
            .tamper("UPDATE org_notifications SET event_type = 'wizard.cast'")
            .await;
        let newest = SortOrder::default();

        let read = fx
            .store
            .list_for_user(
                &fx.acme,
                &fx.ann,
                listing(ReadFilter::All, &newest, &first(10)),
            )
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
