//! The names the audit trail records for the platform's and organizations'
//! own records: members, operators and their notifications. All of them
//! live in the platform database, outside any tenant's row-level security,
//! and each read is held to the organization, member or operator that owns
//! the record, so one owner's record is never named in another's entry.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::shared::ControlPlaneLabelResolver;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EventLabel, NotificationId, OperatorId, OrgUserId, OrganizationId};
use uuid::Uuid;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;
use crate::postgres::shared::labels::only;
use crate::postgres::shared::labels::record::{NamedRecord, PersonRecord};

/// The Postgres names of the platform's and organizations' records, for
/// the audit trail.
pub struct PgControlPlaneLabelResolver {
    databases: Arc<Databases>,
}

impl PgControlPlaneLabelResolver {
    /// A resolver reading names from `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// The names of the members of `organization` that `ids` names.
    async fn members(
        &self,
        organization: &OrganizationId,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, EventLabel)>, DomainError> {
        let found = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                PersonRecord,
                "queries/org_users/labels.sql",
                organization.as_uuid(),
                ids
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        Ok(found.into_iter().map(PersonRecord::into_label).collect())
    }
}

#[async_trait]
impl ControlPlaneLabelResolver for PgControlPlaneLabelResolver {
    async fn platform_notification(
        &self,
        operator_id: &OperatorId,
        notification_id: &NotificationId,
    ) -> Result<Option<EventLabel>, DomainError> {
        let ids = [*notification_id.as_uuid()];
        let found = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                NamedRecord,
                "queries/platform_notifications/labels.sql",
                operator_id.as_uuid(),
                ids.as_slice()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        Ok(only(found.into_iter().map(NamedRecord::into_label)))
    }

    async fn org_notification(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        notification_id: &NotificationId,
    ) -> Result<Option<EventLabel>, DomainError> {
        let ids = [*notification_id.as_uuid()];
        let found = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                NamedRecord,
                "queries/org_notifications/labels.sql",
                organization_id.as_uuid(),
                org_user_id.as_uuid(),
                ids.as_slice()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        Ok(only(found.into_iter().map(NamedRecord::into_label)))
    }

    async fn org_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<EventLabel>, DomainError> {
        let found = self
            .members(organization_id, &[*org_user_id.as_uuid()])
            .await?;
        Ok(only(found))
    }

    async fn org_users(
        &self,
        organization_id: &OrganizationId,
        org_user_ids: &[OrgUserId],
    ) -> Result<HashMap<OrgUserId, EventLabel>, DomainError> {
        let ids: Vec<Uuid> = org_user_ids.iter().map(|id| *id.as_uuid()).collect();
        let found = self.members(organization_id, &ids).await?;
        Ok(found
            .into_iter()
            .map(|(id, label)| (OrgUserId::from_uuid(id), label))
            .collect())
    }

    async fn operator(&self, operator_id: &OperatorId) -> Result<Option<EventLabel>, DomainError> {
        let ids = [*operator_id.as_uuid()];
        let found = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(NamedRecord, "queries/operators/labels.sql", ids.as_slice())
                .fetch_all(connection)
                .await
        })
        .await?;
        Ok(only(found.into_iter().map(NamedRecord::into_label)))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::notifications::{OrgNotificationStore, PlatformNotificationStore};
    use ianua_app::ports::operator::OperatorStore;
    use ianua_app::ports::organization::OrgUserStore;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::postgres::notifications::{PgOrgNotificationStore, PgPlatformNotificationStore};
    use crate::postgres::operator::PgOperatorStore;
    use crate::postgres::organization::PgOrgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::audit::saved_organization;
    use crate::test_support::rows::notifications::{notice, user_registered};
    use crate::test_support::rows::operator::active_operator;
    use crate::test_support::rows::organization::org_user_row;

    struct Fixture {
        db: TestDb,
        organization: OrganizationId,
        control: PgControlPlaneLabelResolver,
    }

    /// A fresh database holding one organization, and the resolver on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let organization = saved_organization(&db.databases).await;
        Fixture {
            control: PgControlPlaneLabelResolver::new(Arc::clone(&db.databases)),
            organization,
            db,
        }
    }

    impl Fixture {
        /// A member of the organization at `email`, saved through the
        /// member store.
        async fn member(&self, email: &str) -> OrgUserId {
            let member = OrgUser::reconstitute(org_user_row(self.organization, email)).unwrap();
            PgOrgUserStore::new(Arc::clone(&self.db.databases), DomainLimits::default())
                .save(&member)
                .await
                .unwrap();
            *member.id()
        }
    }

    /// A member is named by their name and address, alone and among
    /// others; a gone one is left out.
    #[tokio::test]
    async fn members_are_named_by_name_and_address() {
        let fx = fixture().await;
        let ann = fx.member("ann@acme.example").await;
        let ann_label = EventLabel::of("ann@acme.example (ann@acme.example)");

        let alone = fx.control.org_user(&fx.organization, &ann).await.unwrap();
        let among = fx
            .control
            .org_users(&fx.organization, &[ann, OrgUserId::new()])
            .await
            .unwrap();

        assert_eq!(alone, Some(ann_label.clone()));
        assert_eq!(among, HashMap::from([(ann, ann_label)]));
    }

    /// Single and batch label lookups under another organization both
    /// omit Ann, who belongs to Acme.
    #[tokio::test]
    async fn a_member_of_another_organization_is_not_named() {
        let fx = fixture().await;
        let ann = fx.member("ann@acme.example").await;
        let elsewhere = saved_organization(&fx.db.databases).await;

        let alone = fx.control.org_user(&elsewhere, &ann).await.unwrap();
        let among = fx.control.org_users(&elsewhere, &[ann]).await.unwrap();

        assert_eq!(alone, None);
        assert!(among.is_empty());
    }

    /// An operator is named by their sign-in address; a gone one answers
    /// `None`.
    #[tokio::test]
    async fn an_operator_is_named_by_their_address() {
        let fx = fixture().await;
        let ada = active_operator("ada@ianua.example");
        PgOperatorStore::new(Arc::clone(&fx.db.databases))
            .save(&ada)
            .await
            .unwrap();

        assert_eq!(
            fx.control.operator(ada.id()).await.unwrap(),
            Some(EventLabel::of("ada@ianua.example"))
        );
        assert_eq!(fx.control.operator(&OperatorId::new()).await.unwrap(), None);
    }

    /// Ada's notification resolves to its title for Ada and to no label
    /// when requested for Bea.
    #[tokio::test]
    async fn an_operators_notification_is_named_for_them_alone() {
        let fx = fixture().await;
        let operators = PgOperatorStore::new(Arc::clone(&fx.db.databases));
        let ada = active_operator("ada@ianua.example");
        let bea = active_operator("bea@ianua.example");
        operators.save(&ada).await.unwrap();
        operators.save(&bea).await.unwrap();
        let registered = notice(user_registered(), 0);
        PgPlatformNotificationStore::new(Arc::clone(&fx.db.databases))
            .save(ada.id(), &registered)
            .await
            .unwrap();

        let theirs = fx
            .control
            .platform_notification(ada.id(), &registered.id())
            .await
            .unwrap();
        let others = fx
            .control
            .platform_notification(bea.id(), &registered.id())
            .await
            .unwrap();

        assert_eq!(theirs, Some(EventLabel::of(registered.title().as_str())));
        assert_eq!(others, None);
    }

    /// Ann's notification resolves to its title for Ann and to no label
    /// when requested for Bob in the same organization.
    #[tokio::test]
    async fn a_members_notification_is_named_for_them_alone() {
        let fx = fixture().await;
        let ann = fx.member("ann@acme.example").await;
        let bob = fx.member("bob@acme.example").await;
        let registered = notice(user_registered(), 0);
        PgOrgNotificationStore::new(Arc::clone(&fx.db.databases))
            .save(&fx.organization, &ann, &registered)
            .await
            .unwrap();

        let theirs = fx
            .control
            .org_notification(&fx.organization, &ann, &registered.id())
            .await
            .unwrap();
        let others = fx
            .control
            .org_notification(&fx.organization, &bob, &registered.id())
            .await
            .unwrap();

        assert_eq!(theirs, Some(EventLabel::of(registered.title().as_str())));
        assert_eq!(others, None);
    }
}
