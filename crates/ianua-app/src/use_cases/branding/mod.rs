//! Branding use cases: the tenant's look, its own email templates with
//! their previews and test sends, and the mail provider its mail goes out
//! through.

pub(crate) mod get;
mod lookup;
/// The provider the tenant's mail goes out through.
pub(crate) mod mail;
/// The tenant's email templates: edited, previewed, reset, tried.
pub(crate) mod templates;
pub(crate) mod update;
pub(crate) mod upload_logo;

pub use get::{GetPorts, GetUseCase};
pub use mail::{
    GetMailProviderPorts, GetMailProviderUseCase, NamedMailProvider, NamedSmtpServer,
    SwitchMailProviderPorts, SwitchMailProviderRequest, SwitchMailProviderUseCase,
    TestMailProviderPorts, TestMailProviderUseCase,
};
pub use templates::{
    ListEmailTemplatesPorts, ListEmailTemplatesRequest, ListEmailTemplatesUseCase,
    PreviewEmailTemplatePorts, PreviewEmailTemplateUseCase, ResetEmailTemplatePorts,
    ResetEmailTemplateUseCase, SendTestEmailPorts, SendTestEmailUseCase, TemplateDraft,
    TemplatePreviewRequest, UpdateEmailTemplatePorts, UpdateEmailTemplateRequest,
    UpdateEmailTemplateUseCase,
};
pub use update::{UpdatePorts, UpdateRequest, UpdateUseCase};
pub use upload_logo::{UploadLogoPorts, UploadLogoUseCase};
