//! The places outside the app an organization's notifications go to, in
//! the platform database. Every read, write and delete names the
//! organization beside the destination, so one organization never reaches
//! another's.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::notifications::NotificationDestinationStore;
use ianua_domain::domains::notifications::destination::NotificationDestination;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{NotificationDestinationId, OrganizationId};

use self::record::{DestinationColumns, DestinationRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of organizations' notification destinations.
pub struct PgNotificationDestinationStore {
    databases: Arc<Databases>,
}

impl PgNotificationDestinationStore {
    /// A store keeping destinations in `databases`' platform database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl NotificationDestinationStore for PgNotificationDestinationStore {
    async fn find(
        &self,
        organization_id: &OrganizationId,
        id: &NotificationDestinationId,
    ) -> Result<Option<NotificationDestination>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                DestinationRecord,
                "queries/org_notification_destinations/by_id.sql",
                organization_id.as_uuid(),
                id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(DestinationRecord::into_destination).transpose()
    }

    async fn list(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<NotificationDestination>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                DestinationRecord,
                "queries/org_notification_destinations/of_organization.sql",
                organization_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        records
            .into_iter()
            .map(DestinationRecord::into_destination)
            .collect()
    }

    async fn save(&self, destination: &NotificationDestination) -> Result<(), DomainError> {
        let columns = DestinationColumns::of(destination);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_notification_destinations/save.sql",
                columns.id,
                columns.organization_id,
                columns.name,
                columns.kind,
                columns.hook,
                columns.url,
                columns.signing_secret,
                &columns.categories,
                columns.minimum_severity,
                columns.state,
                columns.created_at,
                columns.updated_at,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    async fn delete(
        &self,
        organization_id: &OrganizationId,
        id: &NotificationDestinationId,
    ) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_notification_destinations/delete.sql",
                organization_id.as_uuid(),
                id.as_uuid()
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::destination::{
        DestinationKind, DestinationState, NotificationDestinationRow,
    };
    use ianua_domain::domains::notifications::severity::NotificationSeverity;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::audit::saved_organization;
    use crate::test_support::rows::notifications::{
        destination, slack_destination_row, webhook_destination_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgNotificationDestinationStore,
        acme: OrganizationId,
    }

    /// A fresh database with one organization, Acme, and the store.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let store = PgNotificationDestinationStore::new(Arc::clone(&db.databases));
        Fixture { db, store, acme }
    }

    /// Acme's Slack destination reads back whole, its sealed address kept
    /// as it came.
    #[tokio::test]
    async fn a_saved_destination_reads_back() {
        let fx = fixture().await;
        let saved = destination(slack_destination_row(fx.acme));

        fx.store.save(&saved).await.unwrap();

        let found = fx.store.find(&fx.acme, saved.id()).await.unwrap().unwrap();
        assert_eq!(found.id(), saved.id());
        assert_eq!(found.organization_id(), &fx.acme);
        assert_eq!(found.name().as_str(), saved.name().as_str());
        assert_eq!(found.endpoint(), saved.endpoint());
        assert_eq!(found.filter(), saved.filter());
        assert_eq!(found.state(), DestinationState::Active);
        assert_eq!(found.created_at(), saved.created_at());
        assert_eq!(found.updated_at(), saved.updated_at());
    }

    /// Acme's destinations list oldest first, each kind with its own
    /// endpoint.
    #[tokio::test]
    async fn an_organizations_destinations_list_oldest_first() {
        let fx = fixture().await;
        let later = destination(webhook_destination_row(fx.acme, 10));
        let earlier = destination(slack_destination_row(fx.acme));
        let elsewhere = saved_organization(&fx.db.databases).await;
        for each in [
            &later,
            &earlier,
            &destination(slack_destination_row(elsewhere)),
        ] {
            fx.store.save(each).await.unwrap();
        }

        let listed = fx.store.list(&fx.acme).await.unwrap();

        let kinds: Vec<DestinationKind> = listed
            .iter()
            .map(|listed| listed.endpoint().kind())
            .collect();
        assert_eq!(kinds, [DestinationKind::Slack, DestinationKind::Webhook]);
        assert_eq!(listed[1].endpoint(), later.endpoint());
    }

    /// Saving again keeps the change: a paused destination with a new
    /// filter stays paused, and keeps when it was added.
    #[tokio::test]
    async fn saving_again_keeps_the_change() {
        let fx = fixture().await;
        let row = slack_destination_row(fx.acme);
        let id = row.id;
        fx.store.save(&destination(row)).await.unwrap();
        let changed = destination(NotificationDestinationRow {
            id,
            categories: vec![NotificationCategory::Crypto],
            minimum_severity: NotificationSeverity::Warning,
            state: DestinationState::Paused,
            updated_at: at(30),
            ..slack_destination_row(fx.acme)
        });

        fx.store.save(&changed).await.unwrap();

        let found = fx.store.find(&fx.acme, &id).await.unwrap().unwrap();
        assert_eq!(found.state(), DestinationState::Paused);
        assert_eq!(found.filter().categories(), [NotificationCategory::Crypto]);
        assert_eq!(found.filter().minimum(), NotificationSeverity::Warning);
        assert_eq!(found.created_at(), at(0));
        assert_eq!(found.updated_at(), at(30));
    }

    /// A deleted destination is gone; deleting it again does nothing.
    #[tokio::test]
    async fn a_deleted_destination_is_gone() {
        let fx = fixture().await;
        let saved = destination(slack_destination_row(fx.acme));
        fx.store.save(&saved).await.unwrap();

        fx.store.delete(&fx.acme, saved.id()).await.unwrap();
        fx.store.delete(&fx.acme, saved.id()).await.unwrap();

        assert!(fx.store.find(&fx.acme, saved.id()).await.unwrap().is_none());
        assert!(fx.store.list(&fx.acme).await.unwrap().is_empty());
    }

    /// Another organization cannot find, delete or take over Acme's
    /// destination; Acme keeps its endpoint and the other's list stays empty.
    #[tokio::test]
    async fn another_organization_never_reaches_a_destination() {
        let fx = fixture().await;
        let saved = destination(slack_destination_row(fx.acme));
        fx.store.save(&saved).await.unwrap();
        let other = saved_organization(&fx.db.databases).await;
        let taken = destination(NotificationDestinationRow {
            id: *saved.id(),
            ..webhook_destination_row(other, 0)
        });

        let found = fx.store.find(&other, saved.id()).await.unwrap();
        fx.store.delete(&other, saved.id()).await.unwrap();
        fx.store.save(&taken).await.unwrap();

        assert!(found.is_none());
        let kept = fx.store.find(&fx.acme, saved.id()).await.unwrap().unwrap();
        assert_eq!(kept.endpoint(), saved.endpoint());
        assert!(fx.store.list(&other).await.unwrap().is_empty());
    }

    /// A stored Slack destination with an extra webhook URL makes the
    /// destination list fail as corrupt storage.
    #[tokio::test]
    async fn an_endpoint_whose_columns_do_not_fit_its_kind_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&destination(slack_destination_row(fx.acme)))
            .await
            .unwrap();
        fx.db
            .tamper(
                "ALTER TABLE org_notification_destinations \
                 DROP CONSTRAINT org_notification_destinations_endpoint_fits_kind; \
                 UPDATE org_notification_destinations SET url = 'https://evil.example/hook'",
            )
            .await;

        let read = fx.store.list(&fx.acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
