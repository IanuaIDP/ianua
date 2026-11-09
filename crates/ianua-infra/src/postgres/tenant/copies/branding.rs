//! The branding part of a clone: the login page's look and the email
//! templates.
//!
//! The target takes the source's look whole, the platform's own when the
//! source never set one, but for the sender address: the source sends from
//! a domain it proved it holds, which the target does not, so the target
//! sends from the platform's address until it names one of its own. A
//! template goes into the target's slot of the same email and locale,
//! replacing the one there; the target's other templates stay.

use std::sync::Arc;

use ianua_app::listing::SortOrder;
use ianua_app::ports::branding::{BrandingStore as _, EmailTemplateStore as _};
use ianua_domain::domains::branding::config::{CustomCss, TenantBranding, TenantBrandingRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Setting;

use crate::postgres::branding::{PgBrandingStore, PgEmailTemplateStore};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::tenant::copies::{Pair, all_of, whole_part};

/// Copies a tenant's look and its email templates.
pub(crate) struct BrandingCopy {
    branding: PgBrandingStore,
    templates: PgEmailTemplateStore,
}

impl BrandingCopy {
    /// A copy reading and writing the tenants of `databases`.
    pub(crate) fn new(databases: &Arc<Databases>) -> Self {
        Self {
            branding: PgBrandingStore::new(Arc::clone(databases)),
            templates: PgEmailTemplateStore::new(Arc::clone(databases)),
        }
    }

    /// Gives `pair`'s target the source's look and templates.
    pub(crate) async fn copy(&self, pair: &Pair) -> Result<(), DomainError> {
        let look = self
            .branding
            .find(&pair.source)
            .await?
            .unwrap_or_else(TenantBranding::default_branding);
        let page = self
            .templates
            .list_all(&pair.source, &SortOrder::default(), &whole_part())
            .await?;
        let templates = all_of(page, "email templates")?;
        self.branding
            .save(&pair.target, &without_sender(&look)?)
            .await?;
        for template in &templates {
            self.templates.save(&pair.target, template).await?;
        }
        Ok(())
    }
}

/// `look` sending from the platform's address.
fn without_sender(
    look: &TenantBranding<ResolvedTenant>,
) -> Result<TenantBranding<ResolvedTenant>, DomainError> {
    let css = look
        .custom_css_source()
        .zip(look.custom_css())
        .map(|(source, rendered)| CustomCss::new(source.clone(), rendered.clone()));
    TenantBranding::reconstitute(TenantBrandingRow {
        logo_url: Setting::from_stored(look.logo_url().cloned()),
        primary_color: Setting::from_stored(look.primary_color().cloned()),
        background_color: Setting::from_stored(look.background_color().cloned()),
        custom_css: Setting::from_stored(css),
        email_from_name: Setting::from_stored(look.email_from_name().cloned()),
        email_from_address: Setting::Unset,
    })
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::tenant::ClonePartCopier as _;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::branding::email_template::{EmailTemplate, EmailTemplateType};
    use ianua_domain::domains::tenant::clone::ClonePart;
    use ianua_domain::types::{Email, TenantId};

    use super::*;
    use crate::postgres::tenant::copies::tests::{clone_between, copier};
    use crate::test_support::TestDb;
    use crate::test_support::rows::branding::{email_template_row, locale, tenant_branding_row};

    fn template(kind: EmailTemplateType) -> EmailTemplate {
        EmailTemplate::reconstitute(email_template_row(kind, locale("en-US"))).unwrap()
    }

    /// The target takes the source's look and templates.
    #[tokio::test]
    async fn the_look_and_templates_are_copied() {
        let db = TestDb::fresh().await;
        let clone = clone_between(TenantId::new(), TenantId::new());
        let source = ScopedTenant::for_background(*clone.source());
        let target = ScopedTenant::for_background(*clone.target());
        let copy = BrandingCopy::new(&db.databases);
        let look = TenantBranding::reconstitute(tenant_branding_row()).unwrap();
        copy.branding.save(&source, &look).await.unwrap();
        copy.templates
            .save(&source, &template(EmailTemplateType::PasswordReset))
            .await
            .unwrap();

        copier(&db).copy(&clone, ClonePart::Branding).await.unwrap();

        let copied = copy.branding.find(&target).await.unwrap().unwrap();
        assert_eq!(copied.primary_color(), look.primary_color());
        assert_eq!(copied.email_from_name(), look.email_from_name());
        let templates = copy
            .templates
            .list_for_type(&target, EmailTemplateType::PasswordReset)
            .await
            .unwrap();
        assert_eq!(templates.len(), 1);
    }

    /// Copying branding leaves the source's configured sender address out
    /// of the target's branding.
    #[tokio::test]
    async fn the_sender_address_is_left_behind() {
        let db = TestDb::fresh().await;
        let clone = clone_between(TenantId::new(), TenantId::new());
        let source = ScopedTenant::for_background(*clone.source());
        let target = ScopedTenant::for_background(*clone.target());
        let copy = BrandingCopy::new(&db.databases);
        let look = TenantBranding::reconstitute(TenantBrandingRow {
            email_from_address: Setting::Set(Email::new("mail@acme.example").unwrap()),
            ..tenant_branding_row()
        })
        .unwrap();
        copy.branding.save(&source, &look).await.unwrap();

        copier(&db).copy(&clone, ClonePart::Branding).await.unwrap();

        let copied = copy.branding.find(&target).await.unwrap().unwrap();
        assert!(copied.email_from_address().is_none());
    }

    /// A copy made twice leaves one template in each slot.
    #[tokio::test]
    async fn copying_twice_leaves_one_template_per_slot() {
        let db = TestDb::fresh().await;
        let clone = clone_between(TenantId::new(), TenantId::new());
        let source = ScopedTenant::for_background(*clone.source());
        let target = ScopedTenant::for_background(*clone.target());
        let copy = BrandingCopy::new(&db.databases);
        copy.templates
            .save(&source, &template(EmailTemplateType::MagicLink))
            .await
            .unwrap();

        copier(&db).copy(&clone, ClonePart::Branding).await.unwrap();
        copier(&db).copy(&clone, ClonePart::Branding).await.unwrap();

        let templates = copy
            .templates
            .list_for_type(&target, EmailTemplateType::MagicLink)
            .await
            .unwrap();
        assert_eq!(templates.len(), 1);
    }
}
