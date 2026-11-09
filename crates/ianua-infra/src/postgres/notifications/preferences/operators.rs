//! An operator's choices, in the platform database.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::notifications::OperatorPreferenceStore;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::personal::OperatorNotificationPreferences;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OperatorId;

use self::record::into_operator_preferences;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::notifications::preferences::choice::{
    ChoiceColumns, ChoiceRecord, HolderRecord, choices_of,
};

/// The Postgres store of operators' notification choices.
pub struct PgOperatorPreferenceStore {
    databases: Arc<Databases>,
}

impl PgOperatorPreferenceStore {
    /// A store keeping operators' choices in `databases`' platform
    /// database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OperatorPreferenceStore for PgOperatorPreferenceStore {
    async fn find(
        &self,
        operator_id: &OperatorId,
    ) -> Result<Option<OperatorNotificationPreferences>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ChoiceRecord,
                "queries/operator_notification_preferences/of_operator.sql",
                operator_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        into_operator_preferences(*operator_id, records)
    }

    async fn save(&self, preferences: &OperatorNotificationPreferences) -> Result<(), DomainError> {
        let columns = ChoiceColumns::of(&preferences.preferences());
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/operator_notification_preferences/save.sql",
                preferences.operator_id().as_uuid(),
                &columns.categories,
                &columns.channels,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    async fn chosen_channels(
        &self,
        category: NotificationCategory,
    ) -> Result<Vec<(OperatorId, NotificationChannel)>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                HolderRecord,
                "queries/operator_notification_preferences/chosen_channels.sql",
                category.word()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        choices_of(records, OperatorId::from_uuid)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::operator::OperatorStore;
    use ianua_domain::domains::notifications::personal::OperatorNotificationPreferencesRow;
    use ianua_domain::domains::notifications::preference::NotificationPreferenceRow;

    use super::*;
    use crate::postgres::operator::PgOperatorStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::operator::active_operator;

    struct Fixture {
        db: TestDb,
        store: PgOperatorPreferenceStore,
        ann: OperatorId,
        bob: OperatorId,
    }

    /// A fresh database with two operators, Ann and Bob, and the store.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let ann = an_operator(&db, "ann@ianua.example").await;
        let bob = an_operator(&db, "bob@ianua.example").await;
        let store = PgOperatorPreferenceStore::new(Arc::clone(&db.databases));
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

    /// `operator`'s choices: `channel` for tenants, in the app for every
    /// other category.
    fn choosing(
        operator: OperatorId,
        channel: NotificationChannel,
    ) -> OperatorNotificationPreferences {
        OperatorNotificationPreferences::reconstitute(OperatorNotificationPreferencesRow {
            operator_id: operator,
            preferences: vec![NotificationPreferenceRow {
                category: NotificationCategory::Tenant,
                channel,
            }],
        })
        .unwrap()
    }

    /// An operator who never chose anything has no choices kept.
    #[tokio::test]
    async fn an_operator_who_never_chose_has_none() {
        let fx = fixture().await;

        assert!(fx.store.find(&fx.ann).await.unwrap().is_none());
    }

    /// Ann's choices read back as saved, and saving again keeps the new
    /// channel; Bob's stay his own.
    #[tokio::test]
    async fn saved_choices_read_back_and_are_replaced() {
        let fx = fixture().await;
        fx.store
            .save(&choosing(fx.ann, NotificationChannel::Disabled))
            .await
            .unwrap();
        fx.store
            .save(&choosing(fx.bob, NotificationChannel::Disabled))
            .await
            .unwrap();

        fx.store
            .save(&choosing(fx.ann, NotificationChannel::InAppAndEmail))
            .await
            .unwrap();

        let hers = fx.store.find(&fx.ann).await.unwrap().unwrap();
        let his = fx.store.find(&fx.bob).await.unwrap().unwrap();
        assert_eq!(
            hers.channel_for(NotificationCategory::Tenant),
            NotificationChannel::InAppAndEmail
        );
        assert_eq!(
            his.channel_for(NotificationCategory::Tenant),
            NotificationChannel::Disabled
        );
    }

    /// The fan-out reads every operator's channel for tenants at once.
    #[tokio::test]
    async fn every_operators_channel_for_a_category_is_read_at_once() {
        let fx = fixture().await;
        fx.store
            .save(&choosing(fx.ann, NotificationChannel::InAppAndEmail))
            .await
            .unwrap();
        fx.store
            .save(&choosing(fx.bob, NotificationChannel::Disabled))
            .await
            .unwrap();

        let mut chosen = fx
            .store
            .chosen_channels(NotificationCategory::Tenant)
            .await
            .unwrap();
        chosen.sort_by_key(|(operator, _)| *operator.as_uuid());

        let mut expected = vec![
            (fx.ann, NotificationChannel::InAppAndEmail),
            (fx.bob, NotificationChannel::Disabled),
        ];
        expected.sort_by_key(|(operator, _)| *operator.as_uuid());
        assert_eq!(chosen, expected);
    }

    /// An unknown channel in an operator's stored preferences makes the
    /// read fail as corrupt storage.
    #[tokio::test]
    async fn a_choice_of_an_unknown_channel_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&choosing(fx.ann, NotificationChannel::Disabled))
            .await
            .unwrap();
        fx.db
            .tamper(
                "ALTER TABLE operator_notification_preferences \
                 DROP CONSTRAINT operator_notification_preferences_channel_known; \
                 UPDATE operator_notification_preferences SET channel = 'pager'",
            )
            .await;

        let read = fx.store.find(&fx.ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
