//! A tenant's own look: its logo, colors, custom CSS and sender, one row
//! per tenant, under row-level security.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::branding::BrandingStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::branding::config::TenantBranding;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;

use self::record::{BrandingColumns, BrandingRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of tenants' branding.
pub struct PgBrandingStore {
    databases: Arc<Databases>,
}

impl PgBrandingStore {
    /// A store keeping branding in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgBrandingStore {}

#[async_trait]
impl BrandingStore for PgBrandingStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Option<TenantBranding<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    BrandingRecord,
                    "queries/tenant_branding/of_tenant.sql",
                    tenant_id.as_uuid()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(BrandingRecord::into_branding).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        branding: &TenantBranding<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = BrandingColumns::of(branding);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/tenant_branding/save.sql",
                    tenant_id.as_uuid(),
                    columns.logo_url,
                    columns.primary_color,
                    columns.background_color,
                    columns.css_source,
                    columns.css_rendered,
                    columns.email_from_name,
                    columns.email_from_address,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::branding::config::{CustomCss, TenantBrandingRow};
    use ianua_domain::types::{Email, HexColor, RawCss, SanitizedCss, Setting, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::branding::tenant_branding_row;

    /// A fresh database, the store on it, and one tenant.
    async fn fixture() -> (TestDb, PgBrandingStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgBrandingStore::new(Arc::clone(&db.databases));
        (db, store, ScopedTenant::for_background(TenantId::new()))
    }

    fn branding(row: TenantBrandingRow) -> TenantBranding<ResolvedTenant> {
        TenantBranding::reconstitute(row).unwrap()
    }

    /// Acme sets every part of its look: it reads back as saved, and
    /// another tenant has none.
    #[tokio::test]
    async fn a_saved_branding_is_found_for_its_tenant_only() {
        let (_db, store, acme) = fixture().await;
        let saved = branding(tenant_branding_row());

        store.save(&acme, &saved).await.unwrap();

        let found = store.find(&acme).await.unwrap().unwrap();
        assert_eq!(found.logo_url(), saved.logo_url());
        assert_eq!(found.primary_color(), saved.primary_color());
        assert_eq!(found.background_color(), saved.background_color());
        assert_eq!(found.custom_css(), saved.custom_css());
        assert_eq!(found.custom_css_source(), saved.custom_css_source());
        assert_eq!(found.email_from_name(), saved.email_from_name());
        assert_eq!(found.email_from_address(), saved.email_from_address());
        let other = ScopedTenant::for_background(TenantId::new());
        assert!(store.find(&other).await.unwrap().is_none());
    }

    /// Acme goes back to the platform's look: saving again unsets every
    /// part it left out.
    #[tokio::test]
    async fn saving_again_keeps_the_parts_left_unset() {
        let (_db, store, acme) = fixture().await;
        store
            .save(&acme, &branding(tenant_branding_row()))
            .await
            .unwrap();

        store
            .save(&acme, &TenantBranding::default_branding())
            .await
            .unwrap();

        let found = store.find(&acme).await.unwrap().unwrap();
        assert!(!found.has_customization());
        assert!(found.email_from_address().is_none());
    }

    /// Custom CSS keeps both what the tenant wrote and what pages render.
    #[tokio::test]
    async fn custom_css_keeps_its_source_and_its_rules() {
        let (_db, store, acme) = fixture().await;
        let css = CustomCss::new(
            RawCss::new("body { color: red } @import url(x);").unwrap(),
            SanitizedCss::new("body { color: red }").unwrap(),
        );
        let saved = branding(TenantBrandingRow {
            custom_css: Setting::Set(css),
            primary_color: Setting::Set(HexColor::new("#000").unwrap()),
            email_from_address: Setting::Set(Email::new("mail@acme.example").unwrap()),
            ..tenant_branding_row()
        });

        store.save(&acme, &saved).await.unwrap();

        let found = store.find(&acme).await.unwrap().unwrap();
        assert_eq!(found.custom_css_source(), saved.custom_css_source());
        assert_eq!(found.custom_css(), saved.custom_css());
    }

    /// A stored primary color outside the accepted hex format makes the
    /// branding read fail as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_branding_is_refused() {
        let (db, store, acme) = fixture().await;
        store
            .save(&acme, &branding(tenant_branding_row()))
            .await
            .unwrap();
        db.tamper("UPDATE tenant_branding SET primary_color = 'red'")
            .await;

        let read = store.find(&acme).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
