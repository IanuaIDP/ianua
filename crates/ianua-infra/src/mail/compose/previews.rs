//! Previews: a tenant's mail rendered as it would be sent, filled with
//! samples.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::branding::TemplateRenderer;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::branding::email_template::{EmailTemplate, EmailTemplateType};
use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Preference;

use crate::language::Language;
use crate::mail::audience::MailAudience;
use crate::mail::compose::{Composition, MailComposer, sample_values};

/// Renders a tenant's mail with samples, through the same composer the
/// mail is sent with, so what is previewed is what is sent.
pub struct JinjaTemplateRenderer {
    composer: Arc<MailComposer>,
    audience: Arc<MailAudience>,
}

impl fmt::Debug for JinjaTemplateRenderer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JinjaTemplateRenderer")
            .finish_non_exhaustive()
    }
}

impl JinjaTemplateRenderer {
    /// A renderer composing with `composer`, naming the tenant and its
    /// organization as `audience` reads them.
    #[must_use]
    pub fn new(composer: Arc<MailComposer>, audience: Arc<MailAudience>) -> Self {
        Self { composer, audience }
    }
}

#[async_trait]
impl TemplateRenderer for JinjaTemplateRenderer {
    async fn render_sample(
        &self,
        tenant_id: &ScopedTenant,
        template_type: EmailTemplateType,
        custom: Preference<&EmailTemplate>,
    ) -> Result<RenderedEmail, DomainError> {
        let names = self.audience.names_of(tenant_id).await?.unwrap_or_default();
        let values = sample_values(template_type, &names);
        let written_for = custom
            .value()
            .and_then(|template| template.locale().locale());
        self.composer.compose(&Composition {
            template_type,
            custom,
            language: Language::of_recipient(written_for),
            values: &values,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
    use ianua_domain::domains::branding::control::BrandingControl;
    use ianua_domain::domains::branding::email_template::EmailHtmlBody;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::{HttpsUrl, Label, TenantId};

    use super::*;
    use crate::mail::audience::tests::{acme, audience_over};
    use crate::mail::compose::PlatformLook;
    use crate::test_support::TestDb;
    use crate::test_support::rows::tenant::tenant_row;

    fn renderer(db: &TestDb) -> JinjaTemplateRenderer {
        let composer = MailComposer::new(&PlatformLook {
            logo_url: HttpsUrl::new("https://ianua.test/logo.png").unwrap(),
        })
        .unwrap();
        JinjaTemplateRenderer::new(Arc::new(composer), Arc::new(audience_over(db)))
    }

    /// Acme previews its own welcome mail. Its subject and body come back
    /// with the sample name and a link that leads nowhere.
    #[tokio::test]
    async fn a_tenants_template_is_previewed_with_samples() {
        let db = TestDb::fresh().await;
        let template = EmailTemplate::custom(
            EmailTemplateType::Welcome,
            Preference::Own(Label::new("subject", "Welcome, {{ user_name }}").unwrap()),
            Preference::Own(EmailHtmlBody::new("<p>Start here: {{ action_link }}</p>").unwrap()),
            Preference::Inherited,
            &BrandingControl::new(anyone_holding(&[SystemPermission::Branding(
                BrandingAction::Update,
            )])),
        )
        .unwrap();
        let tenant = ScopedTenant::for_background(TenantId::new());

        let rendered = renderer(&db)
            .render_sample(
                &tenant,
                EmailTemplateType::Welcome,
                Preference::Own(&template),
            )
            .await
            .unwrap();

        assert_eq!(rendered.subject(), "Welcome, Alex Sample");
        assert!(rendered.html().unwrap().contains("example.invalid"));
    }

    /// Acme writes nothing of its own and previews the platform's mail,
    /// which names Acme.
    #[tokio::test]
    async fn an_inherited_template_previews_the_platforms_mail() {
        let db = TestDb::fresh().await;
        let tenant = acme(&db, tenant_row).await;

        let rendered = renderer(&db)
            .render_sample(
                &tenant,
                EmailTemplateType::PasswordReset,
                Preference::Inherited,
            )
            .await
            .unwrap();

        assert_eq!(rendered.subject(), "Reset your password");
        assert!(rendered.text().contains("account in acme on IANUA"));
        assert!(
            rendered
                .text()
                .contains("https://preview.example.invalid/sample-link")
        );
    }
}
