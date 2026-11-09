//! The mail every worker use case sends: queued on the job queue as a
//! sealed `mail.send` job, and the handler that delivers each one.

use std::num::NonZeroU32;
use std::sync::Arc;

use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::branding::{MailProviderTransport, TenantMailProviderStore};
use ianua_app::ports::scheduling::JobQueue;
use ianua_app::ports::shared::{MailOutbox, Mailer};
use ianua_app::services::branding::mail_route::TenantMailRoute;
use ianua_app::services::branding::mailer::{TenantMailer, TenantMailerPorts};
use ianua_app::use_cases::scheduling::JobHandler;
use ianua_domain::shared::config::DomainLimits;
use ianua_infra::mail::{
    MailJobHandler, MailJobParts, OutboundMailProviderTransport, QueuedMailOutbox,
};
use ianua_infra::postgres::branding::{
    PgBrandingStore, PgEmailTemplateStore, PgTenantMailProviderStore,
};
use ianua_infra::postgres::domain::PgRegisteredDomainStore;
use ianua_infra::postgres::tenant::PgTenantStore;

use crate::config::Config;
use crate::error::{PlatformError, ServerError};
use crate::platform::Platform;

/// The mail every use case sends, and the handler that delivers it.
pub(in crate::worker) struct Mail {
    /// Picks each mail's template and sender, then queues it.
    pub(in crate::worker) mailer: Arc<dyn Mailer>,
    /// Delivers one queued mail a run.
    pub(in crate::worker) handler: Arc<dyn JobHandler>,
}

/// The mail queued on `jobs`, as `config` says it goes out.
///
/// # Errors
///
/// [`ServerError`] when a part of the mail cannot be built.
pub(super) fn mail(
    platform: &Platform,
    config: &Config,
    jobs: &Arc<dyn JobQueue>,
) -> Result<Mail, ServerError> {
    let secrets: Arc<dyn SecretEncryptor> = platform.secrets.encryptor.clone();
    let outbox = outbox(config, jobs, &secrets)?;
    Ok(Mail {
        mailer: mailer(platform, outbox),
        handler: handler(platform, secrets)?,
    })
}

/// The outbox sealing each mail with `secrets` onto `jobs`, each tried as
/// often as `MAIL_DELIVERY_ATTEMPTS` says.
fn outbox(
    config: &Config,
    jobs: &Arc<dyn JobQueue>,
    secrets: &Arc<dyn SecretEncryptor>,
) -> Result<Arc<dyn MailOutbox>, ServerError> {
    let tries = NonZeroU32::new(config.mail.delivery_attempts)
        .ok_or(MailError::NoTries)
        .map_err(PlatformError::of("the mail outbox"))?;
    Ok(Arc::new(QueuedMailOutbox::new(
        Arc::clone(jobs),
        Arc::clone(secrets),
        tries,
    )))
}

/// The mailer choosing each tenant's template and sender before queueing
/// on `outbox`.
fn mailer(platform: &Platform, outbox: Arc<dyn MailOutbox>) -> Arc<dyn Mailer> {
    let databases = &platform.databases;
    Arc::new(TenantMailer::new(TenantMailerPorts {
        templates: Arc::new(PgEmailTemplateStore::new(Arc::clone(databases))),
        branding: Arc::new(PgBrandingStore::new(Arc::clone(databases))),
        domains: Arc::new(PgRegisteredDomainStore::new(Arc::clone(databases))),
        tenants: Arc::new(PgTenantStore::new(
            Arc::clone(databases),
            DomainLimits::default(),
        )),
        outbox,
    }))
}

/// The handler opening, addressing, rendering and delivering each queued
/// mail, through the platform's mail parts the API sends with too.
fn handler(
    platform: &Platform,
    secrets: Arc<dyn SecretEncryptor>,
) -> Result<Arc<dyn JobHandler>, ServerError> {
    let mail = &platform.mail;
    let providers: Arc<dyn TenantMailProviderStore> = Arc::new(PgTenantMailProviderStore::new(
        Arc::clone(&platform.databases),
    ));
    let transport: Arc<dyn MailProviderTransport> = Arc::new(OutboundMailProviderTransport::new(
        Arc::clone(&mail.platform),
        Arc::clone(&mail.delivery),
        Arc::clone(&secrets),
    ));
    let handler = MailJobHandler::new(MailJobParts {
        secrets,
        audience: Arc::clone(&mail.audience),
        composer: Arc::clone(&mail.composer),
        route: Arc::new(TenantMailRoute::new(providers, transport)),
    })
    .map_err(PlatformError::of("the mail handler"))?;
    Ok(Arc::new(handler))
}

/// Why the mail cannot be built.
#[derive(Debug, thiserror::Error)]
enum MailError {
    /// A mail would be given no try at all.
    #[error("MAIL_DELIVERY_ATTEMPTS gives a mail no try")]
    NoTries,
}
