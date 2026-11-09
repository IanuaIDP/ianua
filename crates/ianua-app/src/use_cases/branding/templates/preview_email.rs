//! Preview email template: how one of the tenant's mails reads, saved or
//! still being written, filled with sample values.

use std::sync::Arc;

use ianua_domain::domains::branding::renderer::RenderedEmail;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::branding::{EmailTemplateStore, TemplateRenderer};
use crate::use_case::Query;
use crate::use_cases::branding::templates::preview::{
    PreviewSources, TemplatePreviewRequest, rendered_preview,
};

/// The ports [`PreviewEmailTemplateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PreviewEmailTemplatePorts {
    /// The tenant's custom templates.
    pub template_store: Arc<dyn EmailTemplateStore>,
    /// Renders an email with sample values.
    pub renderer: Arc<dyn TemplateRenderer>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Renders one of the tenant's mails for a preview.
pub struct PreviewEmailTemplateUseCase {
    ports: PreviewEmailTemplatePorts,
}

impl PreviewEmailTemplateUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: PreviewEmailTemplatePorts) -> Self {
        Self { ports }
    }
}

impl Query for PreviewEmailTemplateUseCase {
    type Caller = CallerContext;
    type Input = TemplatePreviewRequest;
    type Output = Result<RenderedEmail, AppError>;

    /// The mail `request` names, rendered for the tenant `ctx` acts in with
    /// sample values and no working link. Nothing is saved or sent.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view branding, or
    ///   may not change it for a version not saved yet.
    /// - `AppError::Domain` when an unsaved version holds template code
    ///   beyond the placeholders the email fills.
    /// - `AppError::Internal` when the template cannot be read or rendered.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: TemplatePreviewRequest,
    ) -> Result<RenderedEmail, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let sources = PreviewSources {
            templates: self.ports.template_store.as_ref(),
            renderer: self.ports.renderer.as_ref(),
        };
        rendered_preview(sources, &ctx.tenant(), &authority, request).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
    use ianua_domain::domains::branding::email_template::{
        EmailTemplateType, EmailTextBody, MAX_SUBJECT_LENGTH,
    };
    use ianua_domain::types::{Label, Preference};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::branding::PLATFORM_SUBJECT;
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::branding::TemplateDraft;

    fn preview(
        authorities: FakeTenantAuthorities,
        draft: TemplateDraft,
    ) -> Result<RenderedEmail, AppError> {
        let uc = PreviewEmailTemplateUseCase::new(PreviewEmailTemplatePorts {
            tenant_authorities: Arc::new(authorities),
            ..PreviewEmailTemplatePorts::fakes()
        });
        let request = TemplatePreviewRequest {
            slot: EmailTemplateType::PasswordReset.into(),
            draft,
        };
        block_on(uc.execute(&test_ctx(), request))
    }

    fn unsaved(body: &str) -> TemplateDraft {
        TemplateDraft::Unsaved {
            subject: Preference::Own(
                Label::with_max_length("email_subject", "Reset it", MAX_SUBJECT_LENGTH).unwrap(),
            ),
            body_html: Preference::Inherited,
            body_text: Preference::Own(EmailTextBody::new(body).unwrap()),
        }
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Branding(BrandingAction::View)])
    }

    /// Acme keeps no reset mail of its own. Ann previews it and sees the
    /// platform's.
    #[test]
    fn a_tenant_without_its_own_mail_previews_the_platforms() {
        let rendered = preview(viewer(), TemplateDraft::Saved).unwrap();

        assert_eq!(rendered.subject(), PLATFORM_SUBJECT);
    }

    /// Fay is writing Acme's reset mail and previews it before saving. She
    /// sees her own subject.
    #[test]
    fn an_unsaved_version_previews_as_written() {
        let rendered = preview(
            FakeTenantAuthorities::holding_everything(),
            unsaved("Go to {{ action_link }}"),
        )
        .unwrap();

        assert_eq!(rendered.subject(), "Reset it");
    }

    /// Previewing an unsaved draft refuses template code that transforms
    /// the action link beyond the supported placeholders.
    #[test]
    fn an_unsaved_version_with_template_code_is_refused() {
        let result = preview(
            FakeTenantAuthorities::holding_everything(),
            unsaved("Go to {{ action_link | replace('https', 'http') }}"),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// The branding view right alone does not permit previewing an unsaved
    /// email draft.
    #[test]
    fn a_viewer_cannot_preview_an_unsaved_version() {
        let result = preview(viewer(), unsaved("Go to {{ action_link }}"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Previewing the saved reset email requires the branding view right.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let result = preview(FakeTenantAuthorities::holding(&[]), TemplateDraft::Saved);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot preview the saved reset email.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = preview(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            TemplateDraft::Saved,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
