//! The mail outbox: each mail a job on the job queue, queued in the unit of
//! work of the change that asked for it.
//!
//! A change that rolls back takes its mail with it, and one that commits
//! never loses its mail: the job is in the same transaction as the change,
//! in the database the change was written to. The worker's `mail.send`
//! lane delivers it, tries it again on the queue's backoff when the
//! provider fails, and gives it up as dead after its last try, where an
//! operator sees it, recording the mail as undelivered in the platform's
//! trail. A worker that stops during the last try records nothing: the job
//! is still dead, and listed with the dead jobs. Done and dead jobs are removed by the queue's own
//! clean-up, so a sealed mail is not kept for longer than the queue keeps
//! its jobs.
//!
//! A mail is not idempotent: a worker that stops between handing the mail
//! over and settling its job leaves the job to run again once its lease
//! runs out, and the mail is sent twice. Sending twice is chosen over
//! losing a reset link.

mod handler;
mod payload;

use std::fmt;
use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
pub use handler::{MailJobHandler, MailJobParts};
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::scheduling::JobQueue;
use ianua_app::ports::shared::{MailOutbox, OutgoingMail};
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;

/// The job type a queued mail travels under, which the worker's mail lane
/// runs.
pub const MAIL_JOB: &str = "mail.send";

/// The job type of a queued mail.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when [`MAIL_JOB`] is not a job
/// type, which it always is.
fn mail_job() -> Result<JobType, DomainError> {
    JobType::new(MAIL_JOB).map_err(DomainError::infra)
}

/// Queues each mail as a sealed `mail.send` job.
pub struct QueuedMailOutbox {
    queue: Arc<dyn JobQueue>,
    secrets: Arc<dyn SecretEncryptor>,
    tries: NonZeroU32,
}

impl fmt::Debug for QueuedMailOutbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedMailOutbox")
            .field("tries", &self.tries)
            .finish_non_exhaustive()
    }
}

impl QueuedMailOutbox {
    /// An outbox queueing onto `queue`, sealing each mail with `secrets`,
    /// giving each `tries` tries before it is given up as dead.
    #[must_use]
    pub fn new(
        queue: Arc<dyn JobQueue>,
        secrets: Arc<dyn SecretEncryptor>,
        tries: NonZeroU32,
    ) -> Self {
        Self {
            queue,
            secrets,
            tries,
        }
    }
}

#[async_trait]
impl MailOutbox for QueuedMailOutbox {
    async fn queue(&self, mail: &OutgoingMail<'_>) -> Result<(), DomainError> {
        let payload = payload::sealed(mail, self.secrets.as_ref()).await?;
        let job = ScheduledJob::new(mail_job()?, payload, clock::now(), self.tries);
        let job = match mail.tenant {
            Some(tenant) => job.for_tenant(**tenant),
            None => job,
        };
        self.queue.enqueue(&job).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_app::ports::scheduling::JobClaim;
    use ianua_app::tenancy::ScopedTenant;
    use ianua_domain::domains::branding::config::MailSender;
    use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
    use ianua_domain::types::{Email, Preference, TenantId};

    use super::*;
    use crate::crypto::keys::KEY_BYTES;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::postgres::scheduling::PgJobQueue;
    use crate::test_support::TestDb;

    struct Setup {
        queue: Arc<PgJobQueue>,
        secrets: Arc<dyn SecretEncryptor>,
        outbox: QueuedMailOutbox,
    }

    impl Setup {
        fn over(db: &TestDb) -> Self {
            let queue = Arc::new(PgJobQueue::new(Arc::clone(&db.databases)));
            let secrets: Arc<dyn SecretEncryptor> = Arc::new(AesGcmSecretEncryptor::new(
                SealingKey::new("k1", [4; KEY_BYTES]).unwrap(),
                Vec::new(),
            ));
            let outbox = QueuedMailOutbox::new(
                Arc::clone(&queue) as Arc<dyn JobQueue>,
                Arc::clone(&secrets),
                NonZeroU32::new(5).unwrap(),
            );
            Self {
                queue,
                secrets,
                outbox,
            }
        }

        async fn claimed(&self) -> Vec<ScheduledJob> {
            let types = [mail_job().unwrap()];
            self.queue
                .claim(&JobClaim {
                    job_types: &types,
                    limit: NonZeroU32::new(10).unwrap(),
                    per_tenant: NonZeroU32::new(10).unwrap(),
                    lease: time::Duration::MINUTE,
                })
                .await
                .unwrap()
        }
    }

    fn reset_values() -> HashMap<TemplateVariable, String> {
        HashMap::from([(
            TemplateVariable::ActionUrl,
            "https://acme.test/reset?token=live-token".to_owned(),
        )])
    }

    fn mail<'a>(
        to: &'a Email,
        tenant: Option<&'a ScopedTenant>,
        values: &'a HashMap<TemplateVariable, String>,
    ) -> OutgoingMail<'a> {
        OutgoingMail {
            to,
            tenant,
            template_type: EmailTemplateType::PasswordReset,
            template: Preference::Inherited,
            locale: None,
            sender: MailSender::Platform,
            sender_name: None,
            variables: values,
        }
    }

    /// Ann's reset mail is queued as a `mail.send` job of Acme, with the
    /// tries the outbox gives, and the worker opens it to the same mail.
    #[tokio::test]
    async fn a_mail_is_queued_as_a_job_of_its_tenant() {
        let db = TestDb::fresh().await;
        let setup = Setup::over(&db);
        let to = Email::new("ann@acme.test").unwrap();
        let tenant = ScopedTenant::for_background(TenantId::new());
        let values = reset_values();

        setup
            .outbox
            .queue(&mail(&to, Some(&tenant), &values))
            .await
            .unwrap();

        let claimed = setup.claimed().await;
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].tenant_id(), Some(&*tenant));
        assert_eq!(claimed[0].max_attempts().get(), 5);
        let opened = payload::opened(
            claimed[0].payload(),
            claimed[0].tenant_id().copied(),
            setup.secrets.as_ref(),
        )
        .await
        .unwrap();
        assert_eq!(opened.to, to);
        assert_eq!(opened.values, values);
    }

    /// A platform mail is queued without a tenant and keeps the live reset
    /// token out of its stored payload.
    #[tokio::test]
    async fn a_queued_mail_is_kept_sealed() {
        let db = TestDb::fresh().await;
        let setup = Setup::over(&db);
        let to = Email::new("ann@acme.test").unwrap();
        let values = reset_values();

        setup.outbox.queue(&mail(&to, None, &values)).await.unwrap();

        let claimed = setup.claimed().await;
        assert_eq!(claimed.len(), 1);
        assert!(claimed[0].tenant_id().is_none());
        assert!(!claimed[0].payload().contains("live-token"));
    }

    /// Rolling back the unit of work leaves no claimable job for the mail queued
    /// within it.
    #[tokio::test]
    async fn a_mail_of_a_rolled_back_change_is_not_sent() {
        let db = TestDb::fresh().await;
        let setup = Setup::over(&db);
        let to = Email::new("ann@acme.test").unwrap();
        let tenant = ScopedTenant::for_background(TenantId::new());
        let values = reset_values();

        atomically(
            &PgUnitOfWork,
            async {
                setup
                    .outbox
                    .queue(&mail(&to, Some(&tenant), &values))
                    .await
                    .unwrap();
            },
            |()| Settlement::Rollback,
        )
        .await
        .unwrap();

        assert!(setup.claimed().await.is_empty());
    }
}
