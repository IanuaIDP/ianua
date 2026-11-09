//! A tenant user's inbox, with the tenant, in its own database when it has
//! one, under row-level security.
//!
//! A list and a count show only what [`Notification::shows_to`] shows: a
//! notice on the reader's own account, or one in a category whose right
//! they hold. The categories they may see are worked out here from what
//! they hold, so the database filters by them from an index; no category
//! means only their own account's notices show.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Listing, Page};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::notifications::{
    Kept, NotificationSortField, TenantNotificationFilter, TenantNotificationStore,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{NotificationId, UserId};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::paging::{PageQuery, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::notifications::inbox::listing::in_reads;
use crate::postgres::notifications::inbox::record::{
    NotificationColumns, NotificationRecord, kept, rebuilt,
};

/// The Postgres store of tenant users' notifications.
pub struct PgTenantNotificationStore {
    databases: Arc<Databases>,
}

impl PgTenantNotificationStore {
    /// A store keeping tenant users' notifications in `databases`, each in
    /// its tenant's database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgTenantNotificationStore {}

/// One tenant user's inbox, as its queries name it.
#[derive(Clone, Copy)]
struct UserInbox {
    tenant: Uuid,
    user: Uuid,
}

impl UserInbox {
    /// The inbox of `user_id` within `tenant_id`.
    fn of(tenant_id: &ScopedTenant, user_id: &UserId) -> Self {
        Self {
            tenant: *tenant_id.as_uuid(),
            user: *user_id.as_uuid(),
        }
    }
}

/// The words of the categories someone holding `held` may see.
fn seen_categories(held: &[SystemPermission]) -> Vec<String> {
    NotificationCategory::all()
        .iter()
        .filter(|category| held.contains(&category.required_permission()))
        .map(|category| category.word().to_owned())
        .collect()
}

/// The records of `inbox`'s notifications that `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    inbox: UserInbox,
    ids: &[Uuid],
) -> Result<Vec<NotificationRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        NotificationRecord,
        "queries/tenant_notifications/by_ids.sql",
        inbox.tenant,
        inbox.user,
        ids
    )
    .fetch_all(connection)
    .await
}

#[async_trait]
impl TenantNotificationStore for PgTenantNotificationStore {
    async fn list_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        listing: Listing<'_, &TenantNotificationFilter<'_>, NotificationSortField>,
    ) -> Result<Page<Notification>, DomainError> {
        let keyset = listing.keyset()?;
        let inbox = UserInbox::of(tenant_id, user_id);
        let listed = in_reads(
            PageQuery::ids("id", "tenant_notifications")
                .filter("tenant_id = ?", inbox.tenant)
                .filter("user_id = ?", inbox.user)
                .filter(
                    "(reach IN ('own_account', 'addressed') OR category = ANY(?))",
                    seen_categories(listing.filter.permissions),
                ),
            listing.filter.reads,
        );
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                let records = records_of(connection, inbox, &ids).await?;
                Ok(in_page_order(&ids, records, |record| record.id))
            },
        )
        .await?;
        Ok(keyset.seal(rebuilt(records)?))
    }

    async fn unread_count(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        permissions: &[SystemPermission],
    ) -> Result<u64, DomainError> {
        let seen = seen_categories(permissions);
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/tenant_notifications/unread_count.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    &seen
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }

    async fn mark_read(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        notification_id: &NotificationId,
    ) -> Result<bool, DomainError> {
        let marked = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/tenant_notifications/mark_read.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    notification_id.as_uuid()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(marked.rows_affected() == 1)
    }

    async fn mark_all_read(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<u64, DomainError> {
        let marked = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/tenant_notifications/mark_all_read.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(marked.rows_affected())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        notification: &Notification,
    ) -> Result<Kept, DomainError> {
        let columns = NotificationColumns::of(notification);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let done = sqlx::query_file!(
                    "queries/tenant_notifications/save.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
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
            },
        )
        .await
    }

    async fn purge_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let done = sqlx::query_file!(
                    "queries/tenant_notifications/purge_before.sql",
                    tenant_id.as_uuid(),
                    cutoff
                )
                .execute(connection)
                .await?;
                Ok(done.rows_affected())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, PageRequest, SortOrder};
    use ianua_app::ports::notifications::ReadFilter;
    use ianua_domain::domains::authorization::permission::{CryptoAction, UserAction};
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::notifications::{
        addressed_notice, key_rotated, notice, own_account_notice, user_registered,
    };
    use crate::test_support::rows::oauth::a_person;

    struct Fixture {
        db: TestDb,
        store: PgTenantNotificationStore,
        acme: ScopedTenant,
        carol: UserId,
    }

    /// A fresh database with one tenant user, Carol, and the store.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = ScopedTenant::for_background(TenantId::new());
        let carol = a_person(&db, &acme, "carol@acme.example").await;
        let store = PgTenantNotificationStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            acme,
            carol,
        }
    }

    fn sees_users() -> Vec<SystemPermission> {
        vec![SystemPermission::Users(UserAction::View)]
    }

    fn sees_keys_and_users() -> Vec<SystemPermission> {
        vec![
            SystemPermission::Users(UserAction::View),
            SystemPermission::Crypto(CryptoAction::View),
        ]
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    impl Fixture {
        /// Carol's inbox as someone holding `held` sees it, filtered by
        /// `reads`, newest first.
        async fn listed(
            &self,
            held: &[SystemPermission],
            reads: ReadFilter,
            page: &PageRequest,
        ) -> Page<Notification> {
            let filter = TenantNotificationFilter {
                permissions: held,
                reads,
            };
            let sort = SortOrder::default();
            self.store
                .list_for_user(
                    &self.acme,
                    &self.carol,
                    Listing {
                        filter: &filter,
                        sort: &sort,
                        page,
                    },
                )
                .await
                .unwrap()
        }

        /// Puts `notices` in Carol's inbox.
        async fn saved(&self, notices: &[&Notification]) {
            for each in notices {
                self.store
                    .save(&self.acme, &self.carol, each)
                    .await
                    .unwrap();
            }
        }
    }

    fn ids(page: &Page<Notification>) -> Vec<NotificationId> {
        page.items.iter().map(Notification::id).collect()
    }

    /// Acme's purge removes Carol's notice before the cutoff and keeps
    /// the notice at it; Dave's old notice in Globex remains unread.
    #[tokio::test]
    async fn a_notice_made_before_the_cutoff_is_purged_in_its_tenant_only() {
        let fx = fixture().await;
        let (old, recent) = (notice(user_registered(), 0), notice(user_registered(), 10));
        fx.saved(&[&old, &recent]).await;
        let globex = ScopedTenant::for_background(TenantId::new());
        let dave = a_person(&fx.db, &globex, "dave@globex.example").await;
        let elsewhere = notice(user_registered(), 0);
        fx.store.save(&globex, &dave, &elsewhere).await.unwrap();

        let removed = fx
            .store
            .purge_before(&fx.acme, recent.created_at())
            .await
            .unwrap();

        let left = fx.listed(&sees_users(), ReadFilter::All, &first(10)).await;
        let theirs = fx
            .store
            .unread_count(&globex, &dave, &sees_users())
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert_eq!(ids(&left), [recent.id()]);
        assert_eq!(theirs, 1);
    }

    /// Carol may see users but not keys: the key rotation in her inbox is
    /// left out of her list and her count, and shows once she may see keys.
    #[tokio::test]
    async fn a_notice_shows_only_to_who_holds_its_categorys_right() {
        let fx = fixture().await;
        let registered = notice(user_registered(), 0);
        let rotated = notice(key_rotated(), 10);
        fx.saved(&[&registered, &rotated]).await;

        let as_user_viewer = fx.listed(&sees_users(), ReadFilter::All, &first(10)).await;
        let as_key_viewer = fx
            .listed(&sees_keys_and_users(), ReadFilter::All, &first(10))
            .await;

        assert_eq!(ids(&as_user_viewer), [registered.id()]);
        assert_eq!(ids(&as_key_viewer), [rotated.id(), registered.id()]);
        let counted = fx
            .store
            .unread_count(&fx.acme, &fx.carol, &sees_users())
            .await
            .unwrap();
        assert_eq!(counted, 1);
    }

    /// With no category permissions, Carol still sees and counts her own
    /// account's notice, while a user-registration notice stays hidden.
    #[tokio::test]
    async fn a_notice_on_the_readers_own_account_shows_whatever_they_hold() {
        let fx = fixture().await;
        let locked = own_account_notice(0);
        fx.saved(&[&locked, &notice(user_registered(), 10)]).await;

        let page = fx.listed(&[], ReadFilter::All, &first(10)).await;

        assert_eq!(ids(&page), [locked.id()]);
        let counted = fx
            .store
            .unread_count(&fx.acme, &fx.carol, &[])
            .await
            .unwrap();
        assert_eq!(counted, 1);
    }

    /// With no category permissions, Carol still sees and counts a notice
    /// addressed to her, while a user-registration notice stays hidden.
    #[tokio::test]
    async fn a_notice_sent_to_the_reader_shows_whatever_they_hold() {
        let fx = fixture().await;
        let sent = addressed_notice(0);
        fx.saved(&[&sent, &notice(user_registered(), 10)]).await;

        let page = fx.listed(&[], ReadFilter::All, &first(10)).await;

        assert_eq!(ids(&page), [sent.id()]);
        let counted = fx
            .store
            .unread_count(&fx.acme, &fx.carol, &[])
            .await
            .unwrap();
        assert_eq!(counted, 1);
    }

    /// Carol's inbox lists newest first, page by page.
    #[tokio::test]
    async fn an_inbox_lists_across_pages() {
        let fx = fixture().await;
        let notices = [
            notice(user_registered(), 0),
            notice(user_registered(), 10),
            notice(user_registered(), 20),
        ];
        fx.saved(&notices.iter().collect::<Vec<_>>()).await;

        let page_one = fx.listed(&sees_users(), ReadFilter::All, &first(2)).await;
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx.listed(&sees_users(), ReadFilter::All, &after).await;

        assert_eq!(ids(&page_one), [notices[2].id(), notices[1].id()]);
        assert_eq!(ids(&page_two), [notices[0].id()]);
        assert!(!page_two.has_next());
    }

    /// Marking all read marks even a notice Carol may not see now, so it
    /// does not come back unread when she is given the right.
    #[tokio::test]
    async fn marking_all_read_marks_whatever_it_needs_to_be_seen() {
        let fx = fixture().await;
        let registered = notice(user_registered(), 0);
        let rotated = notice(key_rotated(), 10);
        fx.saved(&[&registered, &rotated]).await;

        let found = fx
            .store
            .mark_read(&fx.acme, &fx.carol, &registered.id())
            .await
            .unwrap();
        let marked = fx.store.mark_all_read(&fx.acme, &fx.carol).await.unwrap();

        assert!(found);
        assert_eq!(marked, 1);
        let unread = fx
            .listed(&sees_keys_and_users(), ReadFilter::UnreadOnly, &first(10))
            .await;
        assert!(unread.items.is_empty());
    }

    /// Another tenant counts none of Carol's notices and cannot mark one
    /// read; it remains in her unread list in Acme.
    #[tokio::test]
    async fn another_tenant_never_reaches_the_inbox() {
        let fx = fixture().await;
        let hers = notice(user_registered(), 0);
        fx.saved(&[&hers]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let counted = fx
            .store
            .unread_count(&other, &fx.carol, &sees_users())
            .await
            .unwrap();
        let found = fx
            .store
            .mark_read(&other, &fx.carol, &hers.id())
            .await
            .unwrap();

        assert_eq!(counted, 0);
        assert!(!found);
        let still = fx
            .listed(&sees_users(), ReadFilter::UnreadOnly, &first(10))
            .await;
        assert_eq!(ids(&still), [hers.id()]);
    }

    /// A user-registration notice tampered to claim own-account reach
    /// makes the inbox read fail as corrupt storage.
    #[tokio::test]
    async fn a_row_reaching_an_own_account_for_another_event_is_refused() {
        let fx = fixture().await;
        fx.saved(&[&notice(user_registered(), 0)]).await;
        fx.db
            .tamper("UPDATE tenant_notifications SET reach = 'own_account'")
            .await;
        let filter = TenantNotificationFilter {
            permissions: &[],
            reads: ReadFilter::All,
        };
        let sort = SortOrder::default();
        let page = first(10);

        let read = fx
            .store
            .list_for_user(
                &fx.acme,
                &fx.carol,
                Listing {
                    filter: &filter,
                    sort: &sort,
                    page: &page,
                },
            )
            .await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
