//! The tenant's email templates: edited, previewed, reset, tried.

pub(crate) mod list_email;
pub(crate) mod preview;
pub(crate) mod preview_email;
pub(crate) mod reset_email;
pub(crate) mod send_test_email;
pub(crate) mod update_email;

pub use list_email::{
    ListEmailTemplatesPorts, ListEmailTemplatesRequest, ListEmailTemplatesUseCase,
};
pub use preview::{TemplateDraft, TemplatePreviewRequest};
pub use preview_email::{PreviewEmailTemplatePorts, PreviewEmailTemplateUseCase};
pub use reset_email::{ResetEmailTemplatePorts, ResetEmailTemplateUseCase};
pub use send_test_email::{SendTestEmailPorts, SendTestEmailUseCase};
pub use update_email::{
    UpdateEmailTemplatePorts, UpdateEmailTemplateRequest, UpdateEmailTemplateUseCase,
};
