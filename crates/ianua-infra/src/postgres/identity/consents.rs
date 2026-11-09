//! Consent decisions, kept as made: each one row of `consent_records`,
//! under row-level security. A withdrawal is a new row, so the full
//! history stays.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::identity::ConsentStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::privacy::consent::{ConsentRecord, ConsentType};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UserId;

use self::record::{ConsentColumns, DecisionRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of consent decisions.
pub struct PgConsentStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgConsentStore {}

impl PgConsentStore {
    /// A store keeping consent decisions in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl ConsentStore for PgConsentStore {
    async fn find_latest(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        consent_type: ConsentType,
    ) -> Result<Option<ConsentRecord<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DecisionRecord,
                    "queries/consent_records/latest.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    consent_type.word()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(DecisionRecord::into_consent).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        record: &ConsentRecord<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = ConsentColumns::of(record);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/consent_records/add.sql",
                    columns.id,
                    tenant_id.as_uuid(),
                    columns.user_id,
                    columns.consent_type,
                    columns.granted,
                    columns.version,
                    columns.ip_address,
                    columns.recorded_at,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn history(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<ConsentRecord<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    DecisionRecord,
                    "queries/consent_records/history.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(DecisionRecord::into_consent)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::privacy::consent::{ConsentDecision, ConsentRecordRow};
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{ConsentId, Fact, IpAddress, TenantId};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::identity::{consent_row, user_row};

    /// A fresh database holding Ann in one tenant, and the store on it.
    async fn fixture() -> (TestDb, PgConsentStore, ScopedTenant, UserId) {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let ann: User<ResolvedTenant> = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&tenant, &ann)
            .await
            .unwrap();
        let store = PgConsentStore::new(Arc::clone(&db.databases));
        (db, store, tenant, *ann.id())
    }

    fn decision(row: ConsentRecordRow) -> ConsentRecord<ResolvedTenant> {
        ConsentRecord::reconstitute(row).unwrap()
    }

    fn ids(found: &[ConsentRecord<ResolvedTenant>]) -> Vec<ConsentId> {
        found.iter().map(|record| *record.id()).collect()
    }

    /// Ann agrees to marketing, then withdraws: the latest decision is the
    /// withdrawal, and her history keeps both, newest first, beside her
    /// other consents.
    #[tokio::test]
    async fn the_latest_decision_and_the_history_are_kept() {
        let (_db, store, tenant, ann) = fixture().await;
        let agreed = decision(ConsentRecordRow {
            ip_address: Fact::Known(IpAddress::new("192.0.2.7").unwrap()),
            ..consent_row(ann, ConsentType::Marketing, 0)
        });
        let withdrawn = decision(ConsentRecordRow {
            granted: ConsentDecision::Withdrawn,
            ..consent_row(ann, ConsentType::Marketing, 20)
        });
        let terms = decision(consent_row(ann, ConsentType::TermsOfService, 10));
        for record in [&agreed, &withdrawn, &terms] {
            store.save(&tenant, record).await.unwrap();
        }

        let latest = store
            .find_latest(&tenant, &ann, ConsentType::Marketing)
            .await
            .unwrap()
            .unwrap();
        let history = store.history(&tenant, &ann).await.unwrap();

        assert_eq!(latest.id(), withdrawn.id());
        assert!(!latest.granted());
        assert_eq!(ids(&history), [*withdrawn.id(), *terms.id(), *agreed.id()]);
        assert_eq!(
            history[2]
                .ip_address()
                .known()
                .map(|address| address.as_str()),
            Some("192.0.2.7")
        );
    }

    /// No decision of a kind finds nothing, and another tenant sees none of
    /// Ann's decisions.
    #[tokio::test]
    async fn no_decision_and_another_tenants_decisions_are_not_found() {
        let (_db, store, tenant, ann) = fixture().await;
        store
            .save(
                &tenant,
                &decision(consent_row(ann, ConsentType::Cookies, 0)),
            )
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let none = store
            .find_latest(&tenant, &ann, ConsentType::Marketing)
            .await
            .unwrap();

        assert!(none.is_none());
        assert!(store.history(&other, &ann).await.unwrap().is_empty());
    }

    /// Saving a withdrawal under an existing consent decision's ID leaves
    /// the single original granted decision in history.
    #[tokio::test]
    async fn a_decision_is_never_changed_once_kept() {
        let (_db, store, tenant, ann) = fixture().await;
        let row = consent_row(ann, ConsentType::Cookies, 0);
        let id = row.id;
        store.save(&tenant, &decision(row)).await.unwrap();
        let altered = decision(ConsentRecordRow {
            id,
            granted: ConsentDecision::Withdrawn,
            ..consent_row(ann, ConsentType::Cookies, 0)
        });

        store.save(&tenant, &altered).await.unwrap();

        let history = store.history(&tenant, &ann).await.unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].granted());
    }

    /// An unknown stored consent type makes the user's history fail to
    /// load as corrupt storage.
    #[tokio::test]
    async fn a_decision_of_an_unknown_kind_is_refused() {
        let (db, store, tenant, ann) = fixture().await;
        store
            .save(
                &tenant,
                &decision(consent_row(ann, ConsentType::Cookies, 0)),
            )
            .await
            .unwrap();
        db.tamper(
            "ALTER TABLE consent_records DROP CONSTRAINT consent_records_type_known;
             UPDATE consent_records SET consent_type = 'telepathy'",
        )
        .await;

        let read = store.history(&tenant, &ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
