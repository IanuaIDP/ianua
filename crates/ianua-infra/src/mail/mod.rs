//! Mail: queued in the change that asked for it, rendered from the
//! platform's templates or the tenant's own, and delivered through the
//! platform's own account or the provider the tenant named.
//!
//! A mail is a `mail.send` job on the job queue, so it is kept exactly
//! when the change that asked for it commits, and a crash loses none. Its
//! payload is sealed, since the values carry live sign-in and reset links.
//! The worker opens it, fills in the names of the tenant and organization
//! it is for, renders it and delivers it through the provider the tenant's
//! mail goes out through now.
//!
//! Every delivery is held to a timeout. Credentials are opened only for
//! the one delivery that needs them and are never logged, nor is what a
//! provider answered.
//!
//! A deployment may run with no mail server. The platform's own mail then
//! fails to send and is recorded as undelivered after its last try, and
//! [`ConfiguredMailSetup`] tells the sign-in so it never waits for a mail.

mod audience;
mod codes;
mod compose;
mod exports;
mod outbox;
mod sending;

pub use audience::MailAudience;
pub use codes::MailedFactorCodeSender;
pub(crate) use codes::minutes_left;
pub use compose::{JinjaTemplateRenderer, MailComposer, PlatformLook};
pub use exports::MailedDataExportNotifier;
pub use outbox::{MAIL_JOB, MailJobHandler, MailJobParts, QueuedMailOutbox};
pub use sending::accounts::{
    ConfiguredMailSetup, MailAccount, PlatformMail, SmtpAccount, SmtpLogin, SmtpTls,
};
pub use sending::apis::{ProviderEndpoints, SesEndpoint};
pub use sending::delivery::MailDelivery;
pub use sending::transport::OutboundMailProviderTransport;
