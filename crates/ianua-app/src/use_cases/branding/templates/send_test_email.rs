//! Send test email: mail one of the tenant's templates, filled with sample
//! values, to the person asking, through the provider the tenant's mail
//! goes out through now.
//!
//! It goes only to the caller's own address, never to one they type, so a
//! test send cannot mail strangers in the tenant's name.

use std::sync::Arc;

use ianua_domain::domains::branding::renderer::RenderedEmail;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::branding::{
    AddressedMail, BrandingStore, EmailTemplateStore, MailProviderTransport, TemplateRenderer,
    TenantMailProviderStore, mail_credential_place,
};
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::organization::OrgUserStore;
use crate::services::branding::sender::TenantSenders;
use crate::use_case::Query;
use crate::use_cases::branding::lookup::{caller_address, current_mail_provider};
use crate::use_cases::branding::templates::preview::{
    PreviewSources, TemplatePreviewRequest, rendered_preview,
};

/// The ports [`SendTestEmailUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SendTestEmailPorts {
    /// The tenant's custom templates.
    pub template_store: Arc<dyn EmailTemplateStore>,
    /// Renders an email with sample values.
    pub renderer: Arc<dyn TemplateRenderer>,
    /// Where each tenant's mail provider is kept.
    pub provider_store: Arc<dyn TenantMailProviderStore>,
    /// Delivers mail through a named provider, with a timeout.
    pub transport: Arc<dyn MailProviderTransport>,
    /// What a caller holds in their tenant, and who is signed in.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Organization members, for the address of a member asking.
    pub org_users: Arc<dyn OrgUserStore>,
    /// The tenant's sender address and name.
    pub branding: Arc<dyn BrandingStore>,
    /// The domains the sender address must be on.
    pub domains: Arc<dyn RegisteredDomainStore>,
}

/// Mails a preview of one of the tenant's templates to the caller.
pub struct SendTestEmailUseCase {
    ports: SendTestEmailPorts,
    senders: TenantSenders,
}

impl SendTestEmailUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SendTestEmailPorts) -> Self {
        let senders = TenantSenders::new(Arc::clone(&ports.branding), Arc::clone(&ports.domains));
        Self { ports, senders }
    }

    /// Delivers `rendered` to the caller through the provider the tenant's
    /// mail goes out through now, from the address it goes out from.
    ///
    /// # Errors
    ///
    /// - The errors of [`caller_address`].
    /// - `AppError::Upstream` when the provider does not take the mail.
    /// - `AppError::Internal` when the provider or the sender cannot be
    ///   read.
    async fn deliver(&self, ctx: &CallerContext, rendered: &RenderedEmail) -> Result<(), AppError> {
        let to = caller_address(
            self.ports.tenant_authorities.as_ref(),
            self.ports.org_users.as_ref(),
            ctx,
        )
        .await?;
        let named =
            current_mail_provider(self.ports.provider_store.as_ref(), &ctx.tenant()).await?;
        let sent_as = self.senders.of(&ctx.tenant()).await.or_internal()?;
        let mail = AddressedMail {
            to: &to,
            sender: sent_as.sender(),
            sender_name: sent_as.sender_name(),
            rendered,
        };
        let credential = mail_credential_place(Some(ctx.tenant_id()));
        self.ports
            .transport
            .deliver(named.delivers_through(), &credential, &mail)
            .await
            .map_err(AppError::upstream)
    }
}

impl Query for SendTestEmailUseCase {
    type Caller = CallerContext;
    type Input = TemplatePreviewRequest;
    type Output = Result<(), AppError>;

    /// Mails the template `request` names, rendered with sample values and
    /// no working link, to the person `ctx` came as. It changes nothing
    /// anyone holds, so it records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view branding, may
    ///   not change it for a version not saved yet, or came as an operator,
    ///   who has no address to send to.
    /// - `AppError::Domain` when an unsaved version holds template code
    ///   beyond the placeholders the email fills.
    /// - `AppError::Upstream` when the provider does not take the mail.
    /// - `AppError::Internal` when the template cannot be read or rendered.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: TemplatePreviewRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let sources = PreviewSources {
            templates: self.ports.template_store.as_ref(),
            renderer: self.ports.renderer.as_ref(),
        };
        let rendered = rendered_preview(sources, &ctx.tenant(), &authority, request).await?;
        self.deliver(ctx, &rendered).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{BrandingAction, SystemPermission};
    use ianua_domain::domains::branding::email_template::EmailTemplateType;
    use ianua_domain::domains::branding::mail_provider::MailProviderKind;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::branding::FakeMailProviderTransport;
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::branding::TemplateDraft;

    fn send(
        authorities: FakeTenantAuthorities,
        transport: Arc<FakeMailProviderTransport>,
    ) -> Result<(), AppError> {
        let uc = SendTestEmailUseCase::new(SendTestEmailPorts {
            transport,
            tenant_authorities: Arc::new(authorities),
            ..SendTestEmailPorts::fakes()
        });
        let request = TemplatePreviewRequest {
            slot: EmailTemplateType::Invitation.into(),
            draft: TemplateDraft::Saved,
        };
        block_on(uc.execute(&test_ctx(), request))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Branding(BrandingAction::View)])
    }

    /// Ann mails herself Acme's invitation to see it in her own inbox. It
    /// reaches her through the platform's mail, as Acme named no provider.
    #[test]
    fn the_caller_is_mailed_the_preview() {
        let transport = Arc::new(FakeMailProviderTransport::delivering());

        send(viewer(), transport.clone()).unwrap();

        let delivered = transport.delivered();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, MailProviderKind::Platform);
    }

    /// The provider refuses the mail. Ann is told it did not go out.
    #[test]
    fn a_refused_mail_is_reported() {
        let transport = Arc::new(FakeMailProviderTransport::refusing());

        let result = send(viewer(), transport);

        assert!(matches!(result, Err(AppError::Upstream(_))));
    }

    /// Without the branding view right, sending a preview is forbidden
    /// and no mail reaches the transport.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let transport = Arc::new(FakeMailProviderTransport::delivering());

        let result = send(FakeTenantAuthorities::holding(&[]), transport.clone());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(transport.delivered().is_empty());
    }

    /// A signed-out session cannot send a preview, and no mail reaches the
    /// transport.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let transport = Arc::new(FakeMailProviderTransport::delivering());

        let result = send(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            transport.clone(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(transport.delivered().is_empty());
    }
}
