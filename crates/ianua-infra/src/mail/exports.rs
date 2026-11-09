//! Telling a person the copy of their data is ready: the tenant's export
//! mail, in their language, saying until when it can be downloaded. The
//! mail holds no link that downloads it.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::identity::DataExportNotifier;
use ianua_app::ports::shared::{MailRecipient, Mailer};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::shared::errors::DomainError;
use time::{OffsetDateTime, UtcOffset};

/// How long handing the mail over may take.
const HAND_OVER_WITHIN: Duration = Duration::from_secs(5);

/// A mail that could not be handed over in time.
#[derive(Debug, thiserror::Error)]
#[error("the export mail could not be handed over in time")]
struct TooSlow;

/// Mails a person that their export is ready.
pub struct MailedDataExportNotifier {
    mailer: Arc<dyn Mailer>,
}

impl fmt::Debug for MailedDataExportNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailedDataExportNotifier")
            .finish_non_exhaustive()
    }
}

impl MailedDataExportNotifier {
    /// A notifier handing its mail to `mailer`.
    #[must_use]
    pub fn new(mailer: Arc<dyn Mailer>) -> Self {
        Self { mailer }
    }
}

#[async_trait]
impl DataExportNotifier for MailedDataExportNotifier {
    async fn ready(
        &self,
        tenant_id: &ScopedTenant,
        to: MailRecipient<'_>,
        available_until: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let values = HashMap::from([(TemplateVariable::ExpiresAt, readable(available_until))]);
        let queued =
            self.mailer
                .send_to_person(to, *tenant_id, EmailTemplateType::ExportReady, &values);
        tokio::time::timeout(HAND_OVER_WITHIN, queued)
            .await
            .map_err(|_| DomainError::infra(TooSlow))?
    }
}

/// `at` as a person reads it, in UTC: `30 October 2026, 14:05 UTC`.
fn readable(at: OffsetDateTime) -> String {
    let utc = at.to_offset(UtcOffset::UTC);
    format!(
        "{} {} {}, {:02}:{:02} UTC",
        utc.day(),
        utc.month(),
        utc.year(),
        utc.hour(),
        utc.minute()
    )
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::FakeMailer;
    use ianua_domain::types::{Email, Locale, Preference, TenantId};

    use super::*;

    /// Ann's export is ready. She is mailed the tenant's export mail in her
    /// language, saying until when she can download it, and no link.
    #[tokio::test]
    async fn the_person_is_told_until_when_to_download() {
        let mailer = Arc::new(FakeMailer::new());
        let notifier = MailedDataExportNotifier::new(mailer.clone());
        let ann = Email::new("ann@acme.test").unwrap();
        let french = Preference::Own(Locale::new("fr-FR").unwrap());
        let until = OffsetDateTime::from_unix_timestamp(1_793_455_500).unwrap();

        notifier
            .ready(
                &ScopedTenant::for_background(TenantId::new()),
                MailRecipient {
                    email: &ann,
                    locale: &french,
                },
                until,
            )
            .await
            .unwrap();

        let sent = mailer.sent.lock().unwrap();
        assert_eq!(sent[0].template, EmailTemplateType::ExportReady);
        assert_eq!(sent[0].locale, french);
        assert_eq!(
            sent[0]
                .variables
                .get(&TemplateVariable::ExpiresAt)
                .map(String::as_str),
            Some(readable(until).as_str())
        );
        assert!(!sent[0].variables.contains_key(&TemplateVariable::ActionUrl));
    }

    /// A moment is written as a date and a time a person reads, in UTC.
    #[test]
    fn a_moment_reads_as_a_date_and_time() {
        let at = OffsetDateTime::from_unix_timestamp(1_440_938_160).unwrap();

        assert_eq!(readable(at), "30 August 2015, 12:36 UTC");
    }
}
