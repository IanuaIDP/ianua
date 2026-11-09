//! The branding use cases the API serves: a tenant's look on its sign-in
//! pages and its logo, its own versions of the platform's emails with their
//! previews and test sends, and the mail provider its mail goes out
//! through.

use std::sync::Arc;

use ianua_app::use_cases::branding::{
    GetMailProviderPorts, GetMailProviderUseCase, GetPorts, GetUseCase, ListEmailTemplatesPorts,
    ListEmailTemplatesUseCase, PreviewEmailTemplatePorts, PreviewEmailTemplateUseCase,
    ResetEmailTemplatePorts, ResetEmailTemplateUseCase, SendTestEmailPorts, SendTestEmailUseCase,
    SwitchMailProviderPorts, SwitchMailProviderUseCase, TestMailProviderPorts,
    TestMailProviderUseCase, UpdateEmailTemplatePorts, UpdateEmailTemplateUseCase, UpdatePorts,
    UpdateUseCase, UploadLogoPorts, UploadLogoUseCase,
};

use crate::deps::Adapters;

/// The branding use cases.
#[derive(Clone)]
pub struct BrandingState {
    pub get: Arc<GetUseCase>,
    pub update: Arc<UpdateUseCase>,
    pub upload_logo: Arc<UploadLogoUseCase>,
    pub list_templates: Arc<ListEmailTemplatesUseCase>,
    pub update_template: Arc<UpdateEmailTemplateUseCase>,
    pub reset_template: Arc<ResetEmailTemplateUseCase>,
    pub preview_template: Arc<PreviewEmailTemplateUseCase>,
    pub send_test_email: Arc<SendTestEmailUseCase>,
    pub mail: MailUseCases,
}

/// The use cases of the provider a tenant's mail goes out through.
#[derive(Clone)]
pub struct MailUseCases {
    pub get: Arc<GetMailProviderUseCase>,
    pub switch: Arc<SwitchMailProviderUseCase>,
    pub test: Arc<TestMailProviderUseCase>,
}

/// Builds the branding use cases over `a`.
pub fn build(a: &Adapters) -> BrandingState {
    BrandingState {
        get: Arc::new(GetUseCase::new(GetPorts {
            branding_store: a.branding_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update: Arc::new(update(a)),
        upload_logo: Arc::new(UploadLogoUseCase::new(UploadLogoPorts {
            branding_store: a.branding_store.clone(),
            logo_store: a.logo_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        list_templates: Arc::new(ListEmailTemplatesUseCase::new(ListEmailTemplatesPorts {
            template_store: a.email_template_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        update_template: Arc::new(UpdateEmailTemplateUseCase::new(UpdateEmailTemplatePorts {
            template_store: a.email_template_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        reset_template: Arc::new(ResetEmailTemplateUseCase::new(ResetEmailTemplatePorts {
            template_store: a.email_template_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        preview_template: Arc::new(preview_template(a)),
        send_test_email: Arc::new(send_test_email(a)),
        mail: mail(a),
    }
}

/// Updates tenant branding with registered-domain and stylesheet validation.
fn update(a: &Adapters) -> UpdateUseCase {
    UpdateUseCase::new(UpdatePorts {
        branding_store: a.branding_store.clone(),
        domains: a.registered_domain_store.clone(),
        css_sanitizer: a.css_sanitizer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Previews a tenant's template through the same renderer used for mail.
fn preview_template(a: &Adapters) -> PreviewEmailTemplateUseCase {
    PreviewEmailTemplateUseCase::new(PreviewEmailTemplatePorts {
        template_store: a.email_template_store.clone(),
        renderer: a.template_renderer.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
    })
}

/// Sends template previews using the tenant's provider and branded sender.
fn send_test_email(a: &Adapters) -> SendTestEmailUseCase {
    SendTestEmailUseCase::new(SendTestEmailPorts {
        template_store: a.email_template_store.clone(),
        renderer: a.template_renderer.clone(),
        provider_store: a.tenant_mail_provider_store.clone(),
        transport: a.mail_provider_transport.clone(),
        tenant_authorities: a.tenant_authorities.clone(),
        org_users: a.org_user_store.clone(),
        branding: a.branding_store.clone(),
        domains: a.registered_domain_store.clone(),
    })
}

/// The use cases that read, switch and test the tenant's mail provider.
fn mail(a: &Adapters) -> MailUseCases {
    MailUseCases {
        get: Arc::new(GetMailProviderUseCase::new(GetMailProviderPorts {
            provider_store: a.tenant_mail_provider_store.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
        })),
        switch: Arc::new(SwitchMailProviderUseCase::new(SwitchMailProviderPorts {
            provider_store: a.tenant_mail_provider_store.clone(),
            encryptor: a.secret_encryptor.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            fresh_proofs: a.fresh_proofs.clone(),
            org_users: a.org_user_store.clone(),
            organizations: a.organization_store.clone(),
        })),
        test: Arc::new(TestMailProviderUseCase::new(TestMailProviderPorts {
            provider_store: a.tenant_mail_provider_store.clone(),
            transport: a.mail_provider_transport.clone(),
            tenant_authorities: a.tenant_authorities.clone(),
            org_users: a.org_user_store.clone(),
            branding: a.branding_store.clone(),
            domains: a.registered_domain_store.clone(),
        })),
    }
}
