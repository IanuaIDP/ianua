//! Second-factor codes sent by mail: the tenant's sign-in code mail, in the
//! person's language, queued in the sign-in's own unit of work.
//!
//! A code to be texted is refused here: texts go out through
//! [`crate::sms`], and [`RoutedFactorCodeSender`](crate::sms::RoutedFactorCodeSender)
//! hands each code to the sender for its destination. Saying a code was
//! sent when nothing sent it would leave the person waiting for nothing.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{CodeDestination, FactorCodeSender, OutgoingCode};
use ianua_app::ports::shared::{MailRecipient, Mailer};
use ianua_domain::domains::branding::email_template::{EmailTemplateType, TemplateVariable};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

/// How long handing a code over may take.
const HAND_OVER_WITHIN: Duration = Duration::from_secs(5);

/// A code that could not be handed over in time.
#[derive(Debug, thiserror::Error)]
#[error("the sign-in code could not be handed over in time")]
struct TooSlow;

/// A code to be texted, handed to the mail sender.
#[derive(Debug, thiserror::Error)]
#[error("a code to be texted was handed to the mail sender")]
struct NotAnAddress;

/// Mails second-factor codes through the tenant's mail.
pub struct MailedFactorCodeSender {
    mailer: Arc<dyn Mailer>,
}

impl fmt::Debug for MailedFactorCodeSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailedFactorCodeSender")
            .finish_non_exhaustive()
    }
}

impl MailedFactorCodeSender {
    /// A sender handing each code to `mailer`.
    #[must_use]
    pub fn new(mailer: Arc<dyn Mailer>) -> Self {
        Self { mailer }
    }
}

#[async_trait]
impl FactorCodeSender for MailedFactorCodeSender {
    async fn send(
        &self,
        to: CodeDestination<'_>,
        outgoing: OutgoingCode<'_>,
    ) -> Result<(), DomainError> {
        let email = match to {
            CodeDestination::Mail(email) => email,
            CodeDestination::Text(_) => return Err(DomainError::infra(NotAnAddress)),
        };
        let values = HashMap::from([
            (
                TemplateVariable::OneTimeCode,
                outgoing.code.expose().to_owned(),
            ),
            (
                TemplateVariable::ExpiresAt,
                minutes_left(outgoing.expires_at, clock::now()),
            ),
        ]);
        let recipient = MailRecipient {
            email,
            locale: outgoing.locale,
        };
        let queued = self.mailer.send_to_person(
            recipient,
            *outgoing.tenant_id,
            EmailTemplateType::SignInCode,
            &values,
        );
        tokio::time::timeout(HAND_OVER_WITHIN, queued)
            .await
            .map_err(|_| DomainError::infra(TooSlow))?
    }
}

/// How long a code lapsing at `expires_at` still works at `now`, in whole
/// minutes rounded up, at least one. A texted code says it the same way.
pub(crate) fn minutes_left(expires_at: OffsetDateTime, now: OffsetDateTime) -> String {
    let seconds = expires_at
        .unix_timestamp()
        .saturating_sub(now.unix_timestamp())
        .max(1);
    let minutes = seconds.saturating_add(59).checked_div(60).unwrap_or(1);
    match minutes {
        1 => "1 minute".to_owned(),
        many => format!("{many} minutes"),
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::tenancy::ScopedTenant;
    use ianua_app::test_support::FakeMailer;
    use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Email, Locale, Preference, TenantId};

    use super::*;

    fn code_for<'a>(
        tenant: &'a ScopedTenant,
        code: &'a Secret,
        locale: &'a Preference<Locale>,
    ) -> OutgoingCode<'a> {
        OutgoingCode {
            tenant_id: tenant,
            code,
            expires_at: clock::now() + time::Duration::minutes(5),
            locale,
        }
    }

    /// Ann's code is mailed to her as the tenant's sign-in code mail, in her
    /// language, with the code and how long it works.
    #[tokio::test]
    async fn a_code_is_mailed_as_the_sign_in_code_mail() {
        let mailer = Arc::new(FakeMailer::new());
        let sender = MailedFactorCodeSender::new(mailer.clone());
        let ann = Email::new("ann@acme.test").unwrap();
        let tenant = ScopedTenant::for_background(TenantId::new());
        let code = Secret::new("482913");
        let german = Preference::Own(Locale::new("de-DE").unwrap());

        sender
            .send(
                CodeDestination::Mail(&ann),
                code_for(&tenant, &code, &german),
            )
            .await
            .unwrap();

        let sent = mailer.sent.lock().unwrap();
        let mailed = &sent[0];
        assert_eq!(mailed.template, EmailTemplateType::SignInCode);
        assert_eq!(mailed.locale, german);
        assert_code_variables(&mailed.variables);
    }

    /// Checks that the mail retains the exact code and its five-minute lifetime.
    fn assert_code_variables(variables: &HashMap<TemplateVariable, String>) {
        assert_eq!(
            variables
                .get(&TemplateVariable::OneTimeCode)
                .map(String::as_str),
            Some("482913")
        );
        assert_eq!(
            variables
                .get(&TemplateVariable::ExpiresAt)
                .map(String::as_str),
            Some("5 minutes")
        );
    }

    /// Handing a text-message destination to the mail sender returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_code_to_text_is_refused() {
        let sender = MailedFactorCodeSender::new(Arc::new(FakeMailer::new()));
        let number = PhoneNumber::new("+4915112345678").unwrap();
        let tenant = ScopedTenant::for_background(TenantId::new());
        let code = Secret::new("482913");
        let locale = Preference::Inherited;

        let sent = sender
            .send(
                CodeDestination::Text(&number),
                code_for(&tenant, &code, &locale),
            )
            .await;

        assert!(matches!(sent, Err(DomainError::Infrastructure(_))));
    }

    /// A code working for four and a half minutes more is said to work for
    /// five, and one about to lapse for one.
    #[test]
    fn the_time_left_is_rounded_up_to_whole_minutes() {
        let now = clock::now();

        assert_eq!(
            minutes_left(now + time::Duration::seconds(270), now),
            "5 minutes"
        );
        assert_eq!(
            minutes_left(now + time::Duration::seconds(10), now),
            "1 minute"
        );
        assert_eq!(
            minutes_left(now - time::Duration::seconds(10), now),
            "1 minute"
        );
    }
}
