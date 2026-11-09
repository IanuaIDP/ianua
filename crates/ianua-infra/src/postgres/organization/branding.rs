//! Organizations' own branding, kept in the platform database, one row per
//! organization.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::organization::OrgBrandingStore;
use ianua_domain::domains::organization::branding::OrgBranding;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::OrganizationId;

use self::record::{BrandingColumns, BrandingRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of organizations' branding.
pub struct PgOrgBrandingStore {
    databases: Arc<Databases>,
}

impl PgOrgBrandingStore {
    /// A store keeping branding in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OrgBrandingStore for PgOrgBrandingStore {
    async fn find(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Option<OrgBranding>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                BrandingRecord,
                "queries/org_branding/of_organization.sql",
                organization_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(BrandingRecord::into_branding).transpose()
    }

    async fn save(&self, branding: &OrgBranding) -> Result<(), DomainError> {
        let columns = BrandingColumns::of(branding);
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/org_branding/save.sql",
                columns.organization_id,
                columns.logo_url,
                columns.primary_color,
                columns.sender_name,
                columns.created_at,
                columns.updated_at,
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
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_domain::domains::organization::branding::OrgBrandingRow;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{HexColor, HttpsUrl, Label, Setting};

    use super::*;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{org_branding_row, organization_row};

    /// A fresh database holding Acme, the store on it, and Acme's id.
    async fn fixture() -> (TestDb, PgOrgBrandingStore, OrganizationId) {
        let db = TestDb::fresh().await;
        let acme = Organization::reconstitute(organization_row("acme", "Acme")).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme)
            .await
            .unwrap();
        let store = PgOrgBrandingStore::new(Arc::clone(&db.databases));
        (db, store, *acme.id())
    }

    fn branding(row: OrgBrandingRow) -> OrgBranding {
        OrgBranding::reconstitute(row).unwrap()
    }

    /// Acme sets its logo, color and sender name: its branding reads back
    /// as saved.
    #[tokio::test]
    async fn a_saved_branding_is_found_for_its_organization() {
        let (_db, store, acme) = fixture().await;
        let saved = branding(OrgBrandingRow {
            logo_url: Setting::Set(HttpsUrl::new("https://cdn.acme.example/logo.png").unwrap()),
            primary_color: Setting::Set(HexColor::new("#FF5733").unwrap()),
            sender_name: Setting::Set(Label::new("sender_name", "Acme Support").unwrap()),
            ..org_branding_row(acme)
        });

        store.save(&saved).await.unwrap();

        let found = store.find(&acme).await.unwrap().unwrap();
        assert_eq!(found.logo_url(), saved.logo_url());
        assert_eq!(found.primary_color(), saved.primary_color());
        assert_eq!(found.sender_name(), saved.sender_name());
        assert_eq!(found.created_at(), saved.created_at());
    }

    /// An organization nobody branded has none, rather than failing.
    #[tokio::test]
    async fn an_organization_never_branded_has_none() {
        let (_db, store, acme) = fixture().await;

        assert!(store.find(&acme).await.unwrap().is_none());
    }

    /// Acme resets its branding: saving again keeps the parts unset and
    /// when it was first made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_parts() {
        let (_db, store, acme) = fixture().await;
        store
            .save(&branding(OrgBrandingRow {
                primary_color: Setting::Set(HexColor::new("#FFF").unwrap()),
                ..org_branding_row(acme)
            }))
            .await
            .unwrap();

        store
            .save(&branding(OrgBrandingRow {
                updated_at: at(5),
                ..org_branding_row(acme)
            }))
            .await
            .unwrap();

        let found = store.find(&acme).await.unwrap().unwrap();
        assert_eq!(found.primary_color(), None);
        assert_eq!(found.created_at(), at(0));
        assert_eq!(found.updated_at(), at(5));
    }

    /// Reading branding whose stored primary color is not a hex color
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_branding_is_refused() {
        let (db, store, acme) = fixture().await;
        store.save(&branding(org_branding_row(acme))).await.unwrap();
        db.tamper("UPDATE org_branding SET primary_color = 'red'")
            .await;

        let read = store.find(&acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
