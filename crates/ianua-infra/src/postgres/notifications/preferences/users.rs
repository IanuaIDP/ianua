//! A tenant user's choices, with the tenant, under row-level security.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::notifications::NotificationPreferenceStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::preference::NotificationPreference;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UserId;

use self::record::into_preferences;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::notifications::preferences::choice::{
    ChoiceColumns, ChoiceRecord, HolderRecord, choices_of,
};

/// The Postgres store of tenant users' notification choices.
pub struct PgNotificationPreferenceStore {
    databases: Arc<Databases>,
}

impl PgNotificationPreferenceStore {
    /// A store keeping tenant users' choices in `databases`, each in its
    /// tenant's database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgNotificationPreferenceStore {}

#[async_trait]
impl NotificationPreferenceStore for PgNotificationPreferenceStore {
    async fn get(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<NotificationPreference>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChoiceRecord,
                    "queries/notification_preferences/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        into_preferences(records)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        preferences: &[NotificationPreference],
    ) -> Result<(), DomainError> {
        let columns = ChoiceColumns::of(preferences);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/notification_preferences/save.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    &columns.categories,
                    &columns.channels,
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }

    async fn chosen_channels(
        &self,
        tenant_id: &ScopedTenant,
        category: NotificationCategory,
    ) -> Result<Vec<(UserId, NotificationChannel)>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    HolderRecord,
                    "queries/notification_preferences/chosen_channels.sql",
                    tenant_id.as_uuid(),
                    category.word()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        choices_of(records, UserId::from_uuid)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::oauth::a_person;

    struct Fixture {
        db: TestDb,
        store: PgNotificationPreferenceStore,
        acme: ScopedTenant,
        carol: UserId,
        dave: UserId,
    }

    impl Fixture {
        /// Persists one member of the fixture tenant's complete preference selection.
        async fn save_choices(&self, user: &UserId, choices: &[NotificationPreference]) {
            self.store.save(&self.acme, user, choices).await.unwrap();
        }

        /// Reads every saved channel for one category in the fixture tenant.
        async fn chosen_channels(
            &self,
            category: NotificationCategory,
        ) -> Vec<(UserId, NotificationChannel)> {
            self.store
                .chosen_channels(&self.acme, category)
                .await
                .unwrap()
        }
    }

    /// A fresh database with two users of one tenant, Carol and Dave, and
    /// the store.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = ScopedTenant::for_background(TenantId::new());
        let carol = a_person(&db, &acme, "carol@acme.example").await;
        let dave = a_person(&db, &acme, "dave@acme.example").await;
        let store = PgNotificationPreferenceStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            acme,
            carol,
            dave,
        }
    }

    fn chose(
        category: NotificationCategory,
        channel: NotificationChannel,
    ) -> NotificationPreference {
        NotificationPreference::new(category, channel)
    }

    fn channels(
        preferences: &[NotificationPreference],
    ) -> Vec<(NotificationCategory, NotificationChannel)> {
        preferences
            .iter()
            .map(|preference| (preference.category(), preference.channel()))
            .collect()
    }

    /// Carol's choices read back as saved; Dave, who chose nothing, has
    /// none.
    #[tokio::test]
    async fn saved_choices_read_back_for_their_user_only() {
        let fx = fixture().await;
        let saved = [
            chose(
                NotificationCategory::Identity,
                NotificationChannel::InAppAndEmail,
            ),
            chose(NotificationCategory::Crypto, NotificationChannel::Disabled),
        ];

        fx.store.save(&fx.acme, &fx.carol, &saved).await.unwrap();

        let found = fx.store.get(&fx.acme, &fx.carol).await.unwrap();
        assert_eq!(
            channels(&found),
            [
                (NotificationCategory::Crypto, NotificationChannel::Disabled),
                (
                    NotificationCategory::Identity,
                    NotificationChannel::InAppAndEmail
                ),
            ]
        );
        assert!(fx.store.get(&fx.acme, &fx.dave).await.unwrap().is_empty());
    }

    /// Saving again replaces the choices: a category left out is dropped,
    /// one kept takes its new channel.
    #[tokio::test]
    async fn saving_again_replaces_the_choices() {
        let fx = fixture().await;
        let before = [
            chose(
                NotificationCategory::Identity,
                NotificationChannel::InAppAndEmail,
            ),
            chose(NotificationCategory::Crypto, NotificationChannel::Disabled),
        ];
        fx.store.save(&fx.acme, &fx.carol, &before).await.unwrap();

        fx.store
            .save(
                &fx.acme,
                &fx.carol,
                &[chose(
                    NotificationCategory::Identity,
                    NotificationChannel::Disabled,
                )],
            )
            .await
            .unwrap();

        let found = fx.store.get(&fx.acme, &fx.carol).await.unwrap();
        assert_eq!(
            channels(&found),
            [(
                NotificationCategory::Identity,
                NotificationChannel::Disabled
            )]
        );
    }

    /// The fan-out reads every user's channel for one category at once:
    /// Carol's and Dave's for identity, and only theirs.
    #[tokio::test]
    async fn every_users_channel_for_a_category_is_read_at_once() {
        let fx = fixture().await;
        fx.save_choices(
            &fx.carol,
            &[
                chose(
                    NotificationCategory::Identity,
                    NotificationChannel::InAppAndEmail,
                ),
                chose(NotificationCategory::Crypto, NotificationChannel::Disabled),
            ],
        )
        .await;
        fx.save_choices(
            &fx.dave,
            &[chose(
                NotificationCategory::Identity,
                NotificationChannel::Disabled,
            )],
        )
        .await;

        let mut chosen = fx.chosen_channels(NotificationCategory::Identity).await;
        chosen.sort_by_key(|(user, _)| *user.as_uuid());

        let mut expected = vec![
            (fx.carol, NotificationChannel::InAppAndEmail),
            (fx.dave, NotificationChannel::Disabled),
        ];
        expected.sort_by_key(|(user, _)| *user.as_uuid());
        assert_eq!(chosen, expected);
    }

    /// Another tenant finds neither Carol's preferences nor Acme's
    /// chosen channels for identity notices.
    #[tokio::test]
    async fn another_tenant_never_reads_the_choices() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.acme,
                &fx.carol,
                &[chose(
                    NotificationCategory::Identity,
                    NotificationChannel::Disabled,
                )],
            )
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let hers = fx.store.get(&other, &fx.carol).await.unwrap();
        let chosen = fx
            .store
            .chosen_channels(&other, NotificationCategory::Identity)
            .await
            .unwrap();

        assert!(hers.is_empty());
        assert!(chosen.is_empty());
    }

    /// An unknown channel in Carol's stored preferences makes the read
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_choice_of_an_unknown_channel_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(
                &fx.acme,
                &fx.carol,
                &[chose(
                    NotificationCategory::Identity,
                    NotificationChannel::Disabled,
                )],
            )
            .await
            .unwrap();
        fx.db
            .tamper(
                "ALTER TABLE notification_preferences DROP CONSTRAINT notification_preferences_channel_known; \
                 UPDATE notification_preferences SET channel = 'pager'",
            )
            .await;

        let read = fx.store.get(&fx.acme, &fx.carol).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
