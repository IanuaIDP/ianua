//! Members' consent records, kept in the platform database. Records are
//! only ever added, so a member's history is read whole, newest first.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgConsentStore;
use ianua_domain::domains::identity::privacy::consent::ConsentType;
use ianua_domain::domains::organization::members::privacy::consent::OrgConsentRecord;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OrgUserId, OrganizationId};

use self::record::{ConsentColumns, ConsentRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of members' consent records.
pub struct PgOrgConsentStore {
    databases: Arc<Databases>,
}

impl PgOrgConsentStore {
    /// A store keeping consent records in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgConsentStore for PgOrgConsentStore {
    async fn find_latest(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        consent_type: ConsentType,
    ) -> Result<Option<OrgConsentRecord>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ConsentRecord,
                "queries/org_consents/latest_of_kind.sql",
                organization_id.as_uuid(),
                org_user_id.as_uuid(),
                consent_type.word()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(ConsentRecord::into_record).transpose()
    }

    async fn list_by_member(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Vec<OrgConsentRecord>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                ConsentRecord,
                "queries/org_consents/of_member.sql",
                organization_id.as_uuid(),
                org_user_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        records
            .into_iter()
            .map(ConsentRecord::into_record)
            .collect()
    }

    async fn save(&self, record: &OrgConsentRecord) -> Result<(), DomainError> {
        let columns = ConsentColumns::of(record);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_consents/add.sql",
                columns.id,
                columns.organization_id,
                columns.org_user_id,
                columns.consent_type,
                columns.granted,
                columns.version,
                columns.ip_address,
                columns.recorded_at,
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
    use ianua_app::ports::organization::{OrgUserStore, OrganizationStore};
    use ianua_domain::domains::identity::privacy::consent::ConsentDecision;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::organization::members::privacy::consent::OrgConsentRecordRow;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{ConsentId, Fact, IpAddress};

    use super::*;
    use crate::postgres::organization::{PgOrgUserStore, PgOrganizationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::organization::{
        OrgConsentSeed, org_consent_row, org_user_row, organization_row,
    };

    struct Fixture {
        db: TestDb,
        store: PgOrgConsentStore,
        members: PgOrgUserStore,
        acme: OrganizationId,
        sam: OrgUserId,
    }

    /// A fresh database holding Acme and its member Sam, and the store on
    /// it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = an_organization(&db, "acme").await;
        let members = PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        let sam = a_member(&members, acme, "sam@acme.example").await;
        let store = PgOrgConsentStore::new(Arc::clone(&db.databases));
        Fixture {
            db,
            store,
            members,
            acme,
            sam,
        }
    }

    /// Saves an organization under `slug` through its store.
    async fn an_organization(db: &TestDb, slug: &str) -> OrganizationId {
        let organization = Organization::reconstitute(organization_row(slug, slug)).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        *organization.id()
    }

    /// Saves a member of `organization` at `email` through the member store.
    async fn a_member(
        members: &PgOrgUserStore,
        organization: OrganizationId,
        email: &str,
    ) -> OrgUserId {
        let member = OrgUser::reconstitute(org_user_row(organization, email)).unwrap();
        members.save(&member).await.unwrap();
        *member.id()
    }

    fn record(row: OrgConsentRecordRow) -> OrgConsentRecord {
        OrgConsentRecord::reconstitute(row).unwrap()
    }

    fn decided(
        fx: &Fixture,
        consent_type: ConsentType,
        decision: ConsentDecision,
        seconds: i64,
    ) -> OrgConsentRecord {
        record(org_consent_row(OrgConsentSeed {
            organization: fx.acme,
            member: fx.sam,
            consent_type,
            decision,
            seconds,
        }))
    }

    fn ids(records: &[OrgConsentRecord]) -> Vec<ConsentId> {
        records.iter().map(|record| *record.id()).collect()
    }

    /// Sam agrees to marketing, then withdraws: his history reads newest
    /// first, every part as it was recorded.
    #[tokio::test]
    async fn a_members_decisions_are_listed_newest_first() {
        let fx = fixture().await;
        let agreed = record(OrgConsentRecordRow {
            ip_address: Fact::Known(IpAddress::new("203.0.113.7").unwrap()),
            ..org_consent_row(OrgConsentSeed {
                organization: fx.acme,
                member: fx.sam,
                consent_type: ConsentType::Marketing,
                decision: ConsentDecision::Granted,
                seconds: 0,
            })
        });
        let withdrawn = decided(&fx, ConsentType::Marketing, ConsentDecision::Withdrawn, 60);
        fx.store.save(&agreed).await.unwrap();
        fx.store.save(&withdrawn).await.unwrap();

        let history = fx.store.list_by_member(&fx.acme, &fx.sam).await.unwrap();

        assert_eq!(ids(&history), [*withdrawn.id(), *agreed.id()]);
        let oldest = &history[1];
        assert_eq!(oldest.consent_type(), ConsentType::Marketing);
        assert_eq!(oldest.decision(), ConsentDecision::Granted);
        assert_eq!(oldest.version(), agreed.version());
        assert_eq!(oldest.ip_address(), agreed.ip_address());
        assert_eq!(oldest.recorded_at(), agreed.recorded_at());
    }

    /// The latest decision on one kind of consent is the newest of that
    /// kind, whatever was decided on others since.
    #[tokio::test]
    async fn the_latest_decision_of_a_kind_is_found() {
        let fx = fixture().await;
        let first = decided(&fx, ConsentType::Marketing, ConsentDecision::Granted, 0);
        let latest = decided(&fx, ConsentType::Marketing, ConsentDecision::Withdrawn, 60);
        let other = decided(&fx, ConsentType::Cookies, ConsentDecision::Granted, 120);
        for made in [&first, &latest, &other] {
            fx.store.save(made).await.unwrap();
        }

        let found = fx
            .store
            .find_latest(&fx.acme, &fx.sam, ConsentType::Marketing)
            .await
            .unwrap();

        assert_eq!(found.map(|record| *record.id()), Some(*latest.id()));
    }

    /// A member who decided nothing has no latest decision and no history,
    /// rather than an error.
    #[tokio::test]
    async fn a_member_without_decisions_has_none() {
        let fx = fixture().await;

        let latest = fx
            .store
            .find_latest(&fx.acme, &fx.sam, ConsentType::TermsOfService)
            .await
            .unwrap();
        let history = fx.store.list_by_member(&fx.acme, &fx.sam).await.unwrap();

        assert!(latest.is_none());
        assert!(history.is_empty());
    }

    /// Sam's saved consent appears in neither Ann's history nor a history
    /// requested for Sam under Globex.
    #[tokio::test]
    async fn another_members_decisions_are_absent() {
        let fx = fixture().await;
        let ann = a_member(&fx.members, fx.acme, "ann@acme.example").await;
        let globex = an_organization(&fx.db, "globex").await;
        fx.store
            .save(&decided(
                &fx,
                ConsentType::Marketing,
                ConsentDecision::Granted,
                0,
            ))
            .await
            .unwrap();

        let anns = fx.store.list_by_member(&fx.acme, &ann).await.unwrap();
        let elsewhere = fx.store.list_by_member(&globex, &fx.sam).await.unwrap();

        assert!(anns.is_empty());
        assert!(elsewhere.is_empty());
    }

    /// Saving the same consent twice leaves its ID listed only once in the
    /// member's history.
    #[tokio::test]
    async fn a_record_saved_again_stays_as_it_was() {
        let fx = fixture().await;
        let made = decided(&fx, ConsentType::Cookies, ConsentDecision::Granted, 0);

        fx.store.save(&made).await.unwrap();
        fx.store.save(&made).await.unwrap();

        let history = fx.store.list_by_member(&fx.acme, &fx.sam).await.unwrap();
        assert_eq!(ids(&history), [*made.id()]);
    }

    /// A member's consent records are their personal data: they go with
    /// the member when the member is deleted.
    #[tokio::test]
    async fn a_members_decisions_go_with_them() {
        let fx = fixture().await;
        fx.store
            .save(&decided(
                &fx,
                ConsentType::Marketing,
                ConsentDecision::Granted,
                0,
            ))
            .await
            .unwrap();

        fx.members.delete(&fx.sam).await.unwrap();

        let history = fx.store.list_by_member(&fx.acme, &fx.sam).await.unwrap();
        assert!(history.is_empty());
    }

    /// Listing consent history after a stored version is made empty
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_record_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&decided(
                &fx,
                ConsentType::Marketing,
                ConsentDecision::Granted,
                0,
            ))
            .await
            .unwrap();
        fx.db.tamper("UPDATE org_consents SET version = ''").await;

        let read = fx.store.list_by_member(&fx.acme, &fx.sam).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
