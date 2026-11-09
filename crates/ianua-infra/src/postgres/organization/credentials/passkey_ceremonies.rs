//! Passkey ceremonies in flight on the management plane, in the platform
//! database.
//!
//! A ceremony is found by its id alone: the login plane carries no
//! organization, and the id is single-use, unguessable and short-lived.
//! Settling it is one update that only finds a ceremony nobody settled, so
//! of two answers to one challenge only one goes through.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgPasskeyCeremonyStore;
use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremony;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::CeremonyId;

use self::record::{CeremonyColumns, CeremonyRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of members' passkey ceremonies.
pub struct PgOrgPasskeyCeremonyStore {
    databases: Arc<Databases>,
}

impl PgOrgPasskeyCeremonyStore {
    /// A store keeping ceremonies in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgPasskeyCeremonyStore for PgOrgPasskeyCeremonyStore {
    async fn save(&self, ceremony: &OrgPasskeyCeremony) -> Result<(), DomainError> {
        let columns = CeremonyColumns::of(ceremony);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_passkey_ceremonies/open.sql",
                columns.id,
                columns.org_user_id,
                columns.purpose,
                columns.state,
                columns.created_at,
                columns.expires_at,
                columns.consumed_at,
            )
            .execute(connection)
            .await?;
            Ok(())
        })
        .await
    }

    async fn find_by_id(&self, id: &CeremonyId) -> Result<Option<OrgPasskeyCeremony>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                CeremonyRecord,
                "queries/org_passkey_ceremonies/by_id.sql",
                id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(CeremonyRecord::into_ceremony).transpose()
    }

    async fn mark_consumed(&self, ceremony: &OrgPasskeyCeremony) -> Result<(), DomainError> {
        let Some(consumed_at) = ceremony.consumed_at() else {
            return Err(DomainError::invalid(message!(
                "infra-a-challenge-is-settled-only-once",
                "a challenge is settled only once it has been used"
            )));
        };
        let settled = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_passkey_ceremonies/settle.sql",
                ceremony.id().as_uuid(),
                consumed_at
            )
            .execute(connection)
            .await
        })
        .await?;
        if settled.rows_affected() == 0 {
            return Err(DomainError::invalid(message!(
                "infra-this-challenge-is-unknown-or-has",
                "this challenge is unknown or has already been used"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
        CeremonyPurpose, CeremonySubject,
    };
    use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremonyRow;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{OrgUserId, Usage};

    use super::*;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{
        org_passkey_ceremony_row, org_user_row, organization_row,
    };

    /// A fresh database holding Acme and one member, and the store on it.
    async fn fixture() -> (TestDb, PgOrgPasskeyCeremonyStore, OrgUserId) {
        let db = TestDb::fresh().await;
        let acme = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme)
            .await
            .unwrap();
        let ann = OrgUser::reconstitute(org_user_row(*acme.id(), "ann@acme.example")).unwrap();
        PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&ann)
            .await
            .unwrap();
        let store = PgOrgPasskeyCeremonyStore::new(Arc::clone(&db.databases));
        (db, store, *ann.id())
    }

    fn ceremony(row: OrgPasskeyCeremonyRow) -> OrgPasskeyCeremony {
        OrgPasskeyCeremony::reconstitute(row).unwrap()
    }

    /// `opened`, as it stands once its answer came back at `at_second`.
    fn settled(
        opened: &OrgPasskeyCeremony,
        member: OrgUserId,
        at_second: i64,
    ) -> OrgPasskeyCeremony {
        ceremony(OrgPasskeyCeremonyRow {
            id: *opened.id(),
            usage: Usage::Used { at: at(at_second) },
            ..org_passkey_ceremony_row(member)
        })
    }

    /// A ceremony opened for Ann is found by its id with its member,
    /// purpose and state.
    #[tokio::test]
    async fn an_opened_ceremony_is_found_by_its_id() {
        let (_db, store, ann) = fixture().await;
        let opened = ceremony(org_passkey_ceremony_row(ann));

        store.save(&opened).await.unwrap();

        let found = store.find_by_id(opened.id()).await.unwrap().unwrap();
        assert_eq!(found.org_user_id(), Some(&ann));
        assert_eq!(found.purpose(), CeremonyPurpose::Authentication);
        assert_eq!(found.state_for_storage(), opened.state_for_storage());
        assert_eq!(found.expires_at(), opened.expires_at());
        assert!(found.consumed_at().is_none());
    }

    /// A discoverable sign-in opens for nobody, and reads back that way.
    #[tokio::test]
    async fn a_discoverable_ceremony_names_nobody() {
        let (_db, store, ann) = fixture().await;
        let opened = ceremony(OrgPasskeyCeremonyRow {
            subject: CeremonySubject::Unclaimed,
            purpose: CeremonyPurpose::DiscoverableAuthentication,
            ..org_passkey_ceremony_row(ann)
        });

        store.save(&opened).await.unwrap();

        let found = store.find_by_id(opened.id()).await.unwrap().unwrap();
        assert!(found.org_user_id().is_none());
    }

    /// An id nobody opened finds nothing.
    #[tokio::test]
    async fn an_unknown_ceremony_is_not_found() {
        let (_db, store, _) = fixture().await;

        assert!(
            store
                .find_by_id(&CeremonyId::new())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Settling a ceremony keeps when it was settled.
    #[tokio::test]
    async fn a_settled_ceremony_reads_back_settled() {
        let (_db, store, ann) = fixture().await;
        let opened = ceremony(org_passkey_ceremony_row(ann));
        store.save(&opened).await.unwrap();

        store
            .mark_consumed(&settled(&opened, ann, 10))
            .await
            .unwrap();

        let found = store.find_by_id(opened.id()).await.unwrap().unwrap();
        assert_eq!(found.consumed_at(), Some(at(10)));
    }

    /// Consuming an already consumed ceremony returns a validation error.
    #[tokio::test]
    async fn a_ceremony_is_settled_once() {
        let (_db, store, ann) = fixture().await;
        let opened = ceremony(org_passkey_ceremony_row(ann));
        store.save(&opened).await.unwrap();
        store
            .mark_consumed(&settled(&opened, ann, 10))
            .await
            .unwrap();

        let second = store.mark_consumed(&settled(&opened, ann, 20)).await;

        assert!(matches!(second, Err(DomainError::Validation(_))));
    }

    /// Saving the original ceremony after consumption preserves its stored
    /// consumption time.
    #[tokio::test]
    async fn saving_again_never_reopens_a_settled_ceremony() {
        let (_db, store, ann) = fixture().await;
        let opened = ceremony(org_passkey_ceremony_row(ann));
        store.save(&opened).await.unwrap();
        store
            .mark_consumed(&settled(&opened, ann, 10))
            .await
            .unwrap();

        store.save(&opened).await.unwrap();

        let found = store.find_by_id(opened.id()).await.unwrap().unwrap();
        assert_eq!(found.consumed_at(), Some(at(10)));
    }

    /// Consuming a ceremony that was never saved returns a validation error.
    #[tokio::test]
    async fn settling_an_unknown_ceremony_is_refused() {
        let (_db, store, ann) = fixture().await;
        let never_kept = ceremony(org_passkey_ceremony_row(ann));

        let answer = store.mark_consumed(&settled(&never_kept, ann, 10)).await;

        assert!(matches!(answer, Err(DomainError::Validation(_))));
    }

    /// Consuming an unanswered ceremony returns a validation error and
    /// leaves its stored consumption time unset.
    #[tokio::test]
    async fn settling_an_unanswered_ceremony_is_refused() {
        let (_db, store, ann) = fixture().await;
        let opened = ceremony(org_passkey_ceremony_row(ann));
        store.save(&opened).await.unwrap();

        let answer = store.mark_consumed(&opened).await;

        assert!(matches!(answer, Err(DomainError::Validation(_))));
        let found = store.find_by_id(opened.id()).await.unwrap().unwrap();
        assert!(found.consumed_at().is_none());
    }

    /// Reading a ceremony whose stored purpose was changed to an unknown
    /// word returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_ceremony_is_refused() {
        let (db, store, ann) = fixture().await;
        let opened = ceremony(org_passkey_ceremony_row(ann));
        store.save(&opened).await.unwrap();
        db.tamper(
            "ALTER TABLE org_passkey_ceremonies DROP CONSTRAINT org_passkey_ceremonies_purpose_known; \
             UPDATE org_passkey_ceremonies SET purpose = 'enrolment'",
        )
        .await;

        let read = store.find_by_id(opened.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
