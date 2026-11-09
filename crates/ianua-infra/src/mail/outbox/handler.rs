//! The worker's half of the outbox: a `mail.send` job opened, addressed
//! under its tenant's names, rendered, and handed to the provider the
//! tenant's mail goes out through now.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::auditor::RequestAuditor;
use ianua_app::error::AppError;
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::branding::AddressedMail;
use ianua_app::services::branding::mail_route::TenantMailRoute;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_cases::scheduling::{Handled, JobHandler};
use ianua_domain::domains::branding::email_template::EmailTemplateType;
use ianua_domain::domains::notifications::events::{MailSentFor, MailUndelivered, UndeliveredMail};
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{Email, Preference, TenantId, UntrustedText};

use crate::language::Language;
use crate::mail::audience::MailAudience;
use crate::mail::compose::{Composition, MailComposer};
use crate::mail::outbox::mail_job;
use crate::mail::outbox::payload::{QueuedMail, opened};
use crate::mail::sending::delivery::MailFailure;

/// The reason recorded for a mail given up on before any mail service
/// answered, such as one that could not be rendered.
const NOT_HANDED_OVER: &str = "the mail was not handed to a mail service";

/// Delivers queued mail: one `mail.send` job a run.
///
/// The mail of a tenant that is gone is done with, not sent. A mail that
/// cannot be rendered or delivered fails the run, so the queue tries it
/// again on its backoff and gives it up as dead after its last try. A
/// mail failing its last try is recorded as [`MailUndelivered`] first, so
/// a sign-in or reset link nobody received shows up in the trail.
pub struct MailJobHandler {
    job_type: JobType,
    secrets: Arc<dyn SecretEncryptor>,
    audience: Arc<MailAudience>,
    composer: Arc<MailComposer>,
    route: Arc<TenantMailRoute>,
}

impl fmt::Debug for MailJobHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailJobHandler").finish_non_exhaustive()
    }
}

/// What a [`MailJobHandler`] opens, addresses, renders and delivers
/// through.
pub struct MailJobParts {
    /// Opens the sealed mail.
    pub secrets: Arc<dyn SecretEncryptor>,
    /// The names each tenant's mail is addressed under.
    pub audience: Arc<MailAudience>,
    /// Renders the mail.
    pub composer: Arc<MailComposer>,
    /// Picks the provider each tenant's mail goes out through, and hands
    /// the mail to it.
    pub route: Arc<TenantMailRoute>,
}

impl MailJobHandler {
    /// A handler working through `parts`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the job type is not one,
    /// which it always is.
    pub fn new(parts: MailJobParts) -> Result<Self, DomainError> {
        Ok(Self {
            job_type: mail_job()?,
            secrets: parts.secrets,
            audience: parts.audience,
            composer: parts.composer,
            route: parts.route,
        })
    }

    /// Delivers `mail`, or answers that there is nothing to deliver because
    /// its tenant is gone.
    async fn deliver(&self, mut mail: QueuedMail) -> Result<Handled, DomainError> {
        let tenant = mail.tenant.map(ScopedTenant::for_background);
        let given = std::mem::take(&mut mail.values);
        let values = match &tenant {
            None => given,
            Some(tenant) => {
                let Some(names) = self.audience.names_of(tenant).await? else {
                    return Ok(Handled::Done);
                };
                names.fill(given)
            }
        };
        let rendered = self.composer.compose(&Composition {
            template_type: mail.template_type,
            custom: mail
                .template
                .as_ref()
                .map_or(Preference::Inherited, Preference::Own),
            language: Language::of_recipient(mail.locale.as_ref()),
            values: &values,
        })?;
        let addressed = AddressedMail {
            to: &mail.to,
            sender: mail.sender(),
            sender_name: mail.sender_name.as_ref(),
            rendered: &rendered,
        };
        self.route.send(tenant.as_ref(), &addressed).await?;
        Ok(Handled::Done)
    }
}

#[async_trait]
impl JobHandler for MailJobHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    /// Opens the job's mail and delivers it. It changes nothing anyone
    /// holds, so a delivery records nothing; a failed last try records
    /// that the mail was given up on, once, before the run fails.
    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let mail = opened(
            job.payload(),
            job.tenant_id().copied(),
            self.secrets.as_ref(),
        )
        .await
        .map_err(AppError::from_domain)?;
        let last_try = LastTry::of(job, &mail);
        let delivered = self.deliver(mail).await;
        if let (Err(error), Some(last_try)) = (&delivered, last_try) {
            auditor
                .dispatch(&[last_try.given_up(error)])
                .await
                .map_err(AppError::from_domain)?;
        }
        delivered.map_err(AppError::from_domain)
    }
}

/// The mail a run is the last try of, as the record of giving it up names
/// it: which email, for whom, after how many tries, and the tenant it was
/// sent for. Never its values or its body, which hold the link it carries.
struct LastTry {
    template: EmailTemplateType,
    recipient: Email,
    attempts: u32,
    sent_for: Option<TenantId>,
}

impl LastTry {
    /// What `mail` is given up as if this run of `job` fails, or `None`
    /// when the queue still tries it again.
    fn of(job: &ScheduledJob, mail: &QueuedMail) -> Option<Self> {
        if job.can_retry() {
            return None;
        }
        Some(Self {
            template: mail.template_type,
            recipient: mail.to.clone(),
            attempts: job.attempt(),
            sent_for: mail.tenant,
        })
    }

    /// The record that the mail was given up on after `error`, in the
    /// trail of the tenant it was sent for.
    fn given_up(self, error: &DomainError) -> DomainEvent {
        let mail = UndeliveredMail {
            template: self.template,
            recipient: self.recipient,
            attempts: self.attempts,
            reason: UntrustedText::record(&reason_of(error)),
        };
        MailUndelivered::observed(mail, MailSentFor::from(self.sent_for))
    }
}

/// What the mail service last answered, in the words of a [`MailFailure`],
/// which hold no credential, no mail and nothing the service wrote back.
/// Any other failure is a plain phrase, so no store detail is recorded.
fn reason_of(error: &DomainError) -> String {
    std::error::Error::source(error)
        .and_then(|cause| cause.downcast_ref::<MailFailure>())
        .map_or_else(|| NOT_HANDED_OVER.to_owned(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::time::Duration;

    use ianua_app::ports::branding::TenantMailProviderStore;
    use ianua_app::ports::scheduling::{JobClaim, JobQueue};
    use ianua_app::ports::shared::{EventDispatcher, MailOutbox, OutgoingMail};
    use ianua_app::test_support::{FakeEventDispatcher, test_auditor};
    use ianua_domain::domains::branding::config::MailSender;
    use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::shared::security::ssrf::UpstreamNetworks;
    use ianua_domain::types::{Email, HttpsUrl, TenantId};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::crypto::keys::KEY_BYTES;
    use crate::crypto::{AesGcmSecretEncryptor, SealingKey};
    use crate::mail::audience::tests::{acme, audience_over};
    use crate::mail::compose::PlatformLook;
    use crate::mail::outbox::{MAIL_JOB, QueuedMailOutbox};
    use crate::mail::sending::accounts::MailAccount;
    use crate::mail::sending::apis::ProviderEndpoints;
    use crate::mail::sending::apis::stand_in::platform;
    use crate::mail::sending::delivery::MailDelivery;
    use crate::mail::sending::transport::OutboundMailProviderTransport;
    use crate::postgres::branding::PgTenantMailProviderStore;
    use crate::postgres::scheduling::PgJobQueue;
    use crate::test_support::TestDb;
    use crate::test_support::rows::tenant::tenant_row;

    /// The outbox, the queue and the handler over one database, the
    /// platform's mail going out through a stand-in of Postmark.
    struct Setup {
        db: TestDb,
        server: MockServer,
        queue: Arc<PgJobQueue>,
        outbox: QueuedMailOutbox,
        handler: MailJobHandler,
        events: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        async fn new() -> Self {
            Self::with_tries(3).await
        }

        /// The setup with each mail tried at most `tries` times.
        async fn with_tries(tries: u32) -> Self {
            let db = TestDb::fresh().await;
            let server = MockServer::start().await;
            let secrets = mail_secrets();
            let queue = Arc::new(PgJobQueue::new(Arc::clone(&db.databases)));
            let outbox = QueuedMailOutbox::new(
                Arc::clone(&queue) as Arc<dyn JobQueue>,
                Arc::clone(&secrets),
                NonZeroU32::new(tries).unwrap(),
            );
            let transport = mail_transport(&server, &secrets);
            let providers: Arc<dyn TenantMailProviderStore> =
                Arc::new(PgTenantMailProviderStore::new(Arc::clone(&db.databases)));
            let composer = composer();
            let handler = MailJobHandler::new(MailJobParts {
                secrets,
                audience: Arc::new(audience_over(&db)),
                composer: Arc::new(composer),
                route: Arc::new(TenantMailRoute::new(providers, Arc::new(transport))),
            })
            .unwrap();
            Self {
                db,
                server,
                queue,
                outbox,
                handler,
                events: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn undelivered_records(&self) -> usize {
            self.events
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|kind| kind.as_str() == UNDELIVERED)
                .count()
        }

        async fn postmark_answering(&self, status: u16) {
            Mock::given(method("POST"))
                .and(path("/email"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&self.server)
                .await;
        }

        async fn queue_reset(&self, tenant: Option<&ScopedTenant>) {
            let to = Email::new("ann@acme.test").unwrap();
            let values = HashMap::from([
                (TemplateVariable::UserName, "Ann".to_owned()),
                (
                    TemplateVariable::ActionUrl,
                    "https://acme.test/reset?token=live".to_owned(),
                ),
                (TemplateVariable::ExpiresAt, "30 minutes".to_owned()),
            ]);
            let mail = OutgoingMail {
                to: &to,
                tenant,
                template_type: EmailTemplateType::PasswordReset,
                template: Preference::Inherited,
                locale: None,
                sender: MailSender::Platform,
                sender_name: None,
                variables: &values,
            };
            self.outbox.queue(&mail).await.unwrap();
        }

        async fn run_one(&self) -> Result<Handled, AppError> {
            let types = [JobType::new(MAIL_JOB).unwrap()];
            let job = self
                .queue
                .claim(&JobClaim {
                    job_types: &types,
                    limit: NonZeroU32::new(1).unwrap(),
                    per_tenant: NonZeroU32::new(1).unwrap(),
                    lease: time::Duration::MINUTE,
                })
                .await
                .unwrap()
                .remove(0);
            let auditor = test_auditor(Arc::clone(&self.events) as Arc<dyn EventDispatcher>);
            self.handler.handle(&job, &auditor).await
        }
    }

    const UNDELIVERED: &str = "notifications.mail_undelivered";

    /// Seals and opens the fixture's queued payloads under one stable test key.
    fn mail_secrets() -> Arc<dyn SecretEncryptor> {
        Arc::new(AesGcmSecretEncryptor::new(
            SealingKey::new("k1", [6; KEY_BYTES]).unwrap(),
            Vec::new(),
        ))
    }

    /// Delivers through the mock Postmark service with the fixture's sealed credentials.
    fn mail_transport(
        server: &MockServer,
        secrets: &Arc<dyn SecretEncryptor>,
    ) -> OutboundMailProviderTransport {
        let delivery = MailDelivery::new(
            ProviderEndpoints::all_at(&server.uri()).unwrap(),
            UpstreamNetworks::public_only(),
            Duration::from_secs(5),
        )
        .unwrap();
        OutboundMailProviderTransport::new(
            Arc::new(platform(MailAccount::Postmark {
                server_token: Secret::new("platform-token"),
            })),
            Arc::new(delivery),
            Arc::clone(secrets),
        )
    }

    /// Renders queued mail with the platform's test logo.
    fn composer() -> MailComposer {
        MailComposer::new(&PlatformLook {
            logo_url: HttpsUrl::new("https://ianua.test/logo.png").unwrap(),
        })
        .unwrap()
    }

    /// Acme's reset mail for Ann leaves the queue, is addressed under
    /// Acme's name, and is handed to the platform's provider.
    #[tokio::test]
    async fn a_queued_mail_is_rendered_and_delivered() {
        let setup = Setup::new().await;
        let tenant = acme(&setup.db, tenant_row).await;
        Mock::given(method("POST"))
            .and(path("/email"))
            .and(body_partial_json(serde_json::json!({
                "To": "ann@acme.test",
                "Subject": "Reset your password",
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&setup.server)
            .await;
        setup.queue_reset(Some(&tenant)).await;

        let handled = setup.run_one().await.unwrap();

        assert_eq!(handled, Handled::Done);
        let requests = setup.server.received_requests().await.unwrap();
        let body = String::from_utf8(requests[0].body.clone()).unwrap();
        assert!(body.contains("account in acme on IANUA"));
    }

    /// A provider's 503 response makes the mail job fail.
    #[tokio::test]
    async fn a_refused_mail_fails_the_run() {
        let setup = Setup::new().await;
        setup.postmark_answering(503).await;
        setup.queue_reset(None).await;

        let handled = setup.run_one().await;

        assert!(handled.is_err());
    }

    /// A queued mail for an absent tenant completes without contacting the
    /// provider.
    #[tokio::test]
    async fn the_mail_of_a_tenant_that_is_gone_is_not_sent() {
        let setup = Setup::new().await;
        setup.postmark_answering(200).await;
        let gone = ScopedTenant::for_background(TenantId::new());
        setup.queue_reset(Some(&gone)).await;

        let handled = setup.run_one().await.unwrap();

        assert_eq!(handled, Handled::Done);
        assert!(setup.server.received_requests().await.unwrap().is_empty());
    }

    /// A provider failure on the last attempt records one undelivered-mail event
    /// with the recipient, attempt count and status, while excluding the live
    /// reset token.
    #[tokio::test]
    async fn a_mail_failing_its_last_try_is_recorded_undelivered_once() {
        let setup = Setup::with_tries(1).await;
        setup.postmark_answering(503).await;
        setup.queue_reset(None).await;

        let handled = setup.run_one().await;

        assert!(handled.is_err());
        assert_eq!(setup.undelivered_records(), 1);
        let payload = setup.events.payload_of(UNDELIVERED);
        let text = |key: &str| {
            payload
                .value(key)
                .and_then(|value| value.as_str())
                .unwrap()
                .to_owned()
        };
        assert_eq!(text("recipient"), "ann@acme.test");
        assert_eq!(text("attempts"), "1");
        assert!(text("reason").contains("503"));
        assert!(
            payload
                .fields()
                .iter()
                .all(|(_, value)| !value.as_str().unwrap_or_default().contains("token=live"))
        );
    }

    /// A provider failure with attempts remaining fails the job without recording
    /// an undelivered-mail event.
    #[tokio::test]
    async fn an_earlier_failed_try_records_nothing() {
        let setup = Setup::with_tries(3).await;
        setup.postmark_answering(503).await;
        setup.queue_reset(None).await;

        let handled = setup.run_one().await;

        assert!(handled.is_err());
        assert_eq!(setup.undelivered_records(), 0);
    }
}
