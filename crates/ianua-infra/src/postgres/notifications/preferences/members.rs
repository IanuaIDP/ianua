//! An organization member's choices, in the platform database. Every read
//! and write names the organization beside the member.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::notifications::MemberPreferenceStore;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::personal::MemberNotificationPreferences;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId};

use self::record::into_member_preferences;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::notifications::preferences::choice::{
    ChoiceColumns, ChoiceRecord, HolderRecord, choices_of,
};

/// The Postgres store of organization members' notification choices.
pub struct PgMemberPreferenceStore {
    databases: Arc<Databases>,
}

impl PgMemberPreferenceStore {
    /// A store keeping members' choices in `databases`' platform database.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl MemberPreferenceStore for PgMemberPreferenceStore {
    async fn find(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<MemberNotificationPreferences>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ChoiceRecord,
                "queries/org_notification_preferences/of_member.sql",
                organization_id.as_uuid(),
                org_user_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        into_member_preferences(*organization_id, *org_user_id, records)
    }

    async fn save(&self, preferences: &MemberNotificationPreferences) -> Result<(), DomainError> {
        let columns = ChoiceColumns::of(&preferences.preferences());
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_notification_preferences/save.sql",
                preferences.organization_id().as_uuid(),
                preferences.org_user_id().as_uuid(),
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
        organization_id: &OrganizationId,
        category: NotificationCategory,
    ) -> Result<Vec<(OrgUserId, NotificationChannel)>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                HolderRecord,
                "queries/org_notification_preferences/chosen_channels.sql",
                organization_id.as_uuid(),
                category.word()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        choices_of(records, OrgUserId::from_uuid)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::OrgUserStore;
    use ianua_domain::domains::notifications::personal::MemberNotificationPreferencesRow;
    use ianua_domain::domains::notifications::preference::NotificationPreferenceRow;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::organization::PgOrgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::saved_organization;
    use crate::test_support::rows::organization::org_user_row;

    struct Fixture {
        db: TestDb,
        store: PgMemberPreferenceStore,
        acme: OrganizationId,
        ann: OrgUserId,
        sam: OrgUserId,
    }

    /// A fresh database with Acme and two of its members, Ann and Sam, and
    /// the store.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = saved_organization(&db.databases).await;
        let ann = a_member(&db, acme, "ann@acme.example").await;
        let sam = a_member(&db, acme, "sam@acme.example").await;
        let store = PgMemberPreferenceStore::new(Arc::clone(&db.databases));
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

    /// `member`'s choices of Acme: `channel` for crypto, in the app for
    /// every other category.
    fn choosing(
        organization: OrganizationId,
        member: OrgUserId,
        channel: NotificationChannel,
    ) -> MemberNotificationPreferences {
        MemberNotificationPreferences::reconstitute(MemberNotificationPreferencesRow {
            organization_id: organization,
            org_user_id: member,
            preferences: vec![NotificationPreferenceRow {
                category: NotificationCategory::Crypto,
                channel,
            }],
        })
        .unwrap()
    }

    /// A member who never chose anything has no choices kept.
    #[tokio::test]
    async fn a_member_who_never_chose_has_none() {
        let fx = fixture().await;

        let found = fx.store.find(&fx.acme, &fx.ann).await.unwrap();

        assert!(found.is_none());
    }

    /// Ann's choices read back as saved, every category she left alone in
    /// the app, and saving again keeps the new channel.
    #[tokio::test]
    async fn saved_choices_read_back_and_are_replaced() {
        let fx = fixture().await;
        fx.store
            .save(&choosing(fx.acme, fx.ann, NotificationChannel::Disabled))
            .await
            .unwrap();

        fx.store
            .save(&choosing(
                fx.acme,
                fx.ann,
                NotificationChannel::InAppAndEmail,
            ))
            .await
            .unwrap();

        let found = fx.store.find(&fx.acme, &fx.ann).await.unwrap().unwrap();
        assert_eq!(
            found.channel_for(NotificationCategory::Crypto),
            NotificationChannel::InAppAndEmail
        );
        assert_eq!(
            found.channel_for(NotificationCategory::Identity),
            NotificationChannel::InApp
        );
        assert_eq!(found.org_user_id(), &fx.ann);
    }

    /// The fan-out reads every member's channel for crypto at once.
    #[tokio::test]
    async fn every_members_channel_for_a_category_is_read_at_once() {
        let fx = fixture().await;
        fx.store
            .save(&choosing(fx.acme, fx.ann, NotificationChannel::Disabled))
            .await
            .unwrap();
        fx.store
            .save(&choosing(
                fx.acme,
                fx.sam,
                NotificationChannel::InAppAndEmail,
            ))
            .await
            .unwrap();

        let mut chosen = fx
            .store
            .chosen_channels(&fx.acme, NotificationCategory::Crypto)
            .await
            .unwrap();
        chosen.sort_by_key(|(member, _)| *member.as_uuid());

        let mut expected = vec![
            (fx.ann, NotificationChannel::Disabled),
            (fx.sam, NotificationChannel::InAppAndEmail),
        ];
        expected.sort_by_key(|(member, _)| *member.as_uuid());
        assert_eq!(chosen, expected);
    }

    /// Another organization's id finds neither Ann's preferences nor any
    /// chosen channels belonging to Acme.
    #[tokio::test]
    async fn choices_are_read_only_within_their_organization() {
        let fx = fixture().await;
        fx.store
            .save(&choosing(fx.acme, fx.ann, NotificationChannel::Disabled))
            .await
            .unwrap();
        let other = saved_organization(&fx.db.databases).await;

        let found = fx.store.find(&other, &fx.ann).await.unwrap();
        let chosen = fx
            .store
            .chosen_channels(&other, NotificationCategory::Crypto)
            .await
            .unwrap();

        assert!(found.is_none());
        assert!(chosen.is_empty());
    }

    /// An unknown category in Ann's stored preferences makes the read
    /// fail as corrupt storage.
    #[tokio::test]
    async fn a_choice_of_an_unknown_category_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&choosing(fx.acme, fx.ann, NotificationChannel::Disabled))
            .await
            .unwrap();
        fx.db
            .tamper(
                "ALTER TABLE org_notification_preferences \
                 DROP CONSTRAINT org_notification_preferences_category_known; \
                 UPDATE org_notification_preferences SET category = 'weather' \
                 WHERE category = 'crypto'",
            )
            .await;

        let read = fx.store.find(&fx.acme, &fx.ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
