//! The one sender the sign-in holds: each code goes to the mail sender or
//! the text message sender by where it is going.
//!
//! A deployment with no text message provider set up has no text sender,
//! and a code to be texted is refused rather than answered as sent.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::authentication::{
    CodeDestination, FactorCodeSender, OutgoingCode, TextAvailability, TextMessaging,
};
use ianua_domain::shared::errors::DomainError;

/// A code to be texted, with no provider set up to text it.
#[derive(Debug, thiserror::Error)]
#[error("no text message provider is set up, so a code cannot be texted")]
struct NoTextProvider;

/// Hands each code to the sender for its destination.
pub struct RoutedFactorCodeSender {
    mail: Arc<dyn FactorCodeSender>,
    text: Option<Arc<dyn FactorCodeSender>>,
}

impl fmt::Debug for RoutedFactorCodeSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutedFactorCodeSender")
            .field("sms", &self.text.is_some())
            .finish_non_exhaustive()
    }
}

impl RoutedFactorCodeSender {
    /// Mailed codes go to `mail`, texted ones to `text`, or are refused
    /// when no text message provider is set up.
    #[must_use]
    pub fn new(mail: Arc<dyn FactorCodeSender>, text: Option<Arc<dyn FactorCodeSender>>) -> Self {
        Self { mail, text }
    }

    /// Whether this sender can text codes, for the sign-in settings that
    /// must not offer a texted factor it could never deliver.
    #[must_use]
    pub fn text_messaging(&self) -> ConfiguredTextMessaging {
        let availability = match self.text {
            Some(_) => TextAvailability::Available,
            None => TextAvailability::NotSetUp,
        };
        ConfiguredTextMessaging(availability)
    }

    /// Selects mail or text delivery, refusing text when no provider is configured.
    fn sender_for(&self, to: CodeDestination<'_>) -> Result<&dyn FactorCodeSender, DomainError> {
        match to {
            CodeDestination::Mail(_) => Ok(self.mail.as_ref()),
            CodeDestination::Text(_) => self
                .text
                .as_deref()
                .ok_or_else(|| DomainError::infra(NoTextProvider)),
        }
    }
}

/// Whether the deployment's [`RoutedFactorCodeSender`] has a text sender,
/// fixed when it was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfiguredTextMessaging(TextAvailability);

impl TextMessaging for ConfiguredTextMessaging {
    fn availability(&self) -> TextAvailability {
        self.0
    }
}

#[async_trait]
impl FactorCodeSender for RoutedFactorCodeSender {
    async fn send(
        &self,
        to: CodeDestination<'_>,
        outgoing: OutgoingCode<'_>,
    ) -> Result<(), DomainError> {
        self.sender_for(to)?.send(to, outgoing).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::tenancy::ScopedTenant;
    use ianua_app::test_support::authentication::RecordingCodeSender;
    use ianua_domain::domains::identity::account::profile_values::PhoneNumber;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Email, Locale, Preference, TenantId};

    use super::*;

    struct Parties {
        tenant: ScopedTenant,
        code: Secret,
        locale: Preference<Locale>,
    }

    impl Parties {
        fn new() -> Self {
            Self {
                tenant: ScopedTenant::for_background(TenantId::new()),
                code: Secret::new("482913"),
                locale: Preference::Inherited,
            }
        }

        fn outgoing(&self) -> OutgoingCode<'_> {
            OutgoingCode {
                tenant_id: &self.tenant,
                code: &self.code,
                expires_at: clock::now() + time::Duration::minutes(5),
                locale: &self.locale,
            }
        }
    }

    /// Ann's mailed code goes to the mail sender and Bob's texted code to
    /// the text sender, each to its own address.
    #[tokio::test]
    async fn each_code_goes_to_the_sender_for_its_destination() {
        let mail = Arc::new(RecordingCodeSender::default());
        let text = Arc::new(RecordingCodeSender::default());
        let texts: Arc<dyn FactorCodeSender> = text.clone();
        let router = RoutedFactorCodeSender::new(mail.clone(), Some(texts));
        let parties = Parties::new();
        let ann = Email::new("ann@acme.test").unwrap();
        let bob = PhoneNumber::new("+4915112345678").unwrap();

        router
            .send(CodeDestination::Mail(&ann), parties.outgoing())
            .await
            .unwrap();
        router
            .send(CodeDestination::Text(&bob), parties.outgoing())
            .await
            .unwrap();

        assert_eq!(mail.messages()[0].to, "ann@acme.test");
        assert_eq!(text.messages()[0].to, "+4915112345678");
        assert_eq!(mail.messages().len(), 1);
        assert_eq!(text.messages().len(), 1);
    }

    /// Without a text provider, Bob's code fails delivery and no substitute mail is sent.
    #[tokio::test]
    async fn a_code_to_text_with_no_provider_is_refused() {
        let mail = Arc::new(RecordingCodeSender::default());
        let router = RoutedFactorCodeSender::new(mail.clone(), None);
        let parties = Parties::new();
        let bob = PhoneNumber::new("+4915112345678").unwrap();

        let sent = router
            .send(CodeDestination::Text(&bob), parties.outgoing())
            .await;

        assert!(matches!(sent, Err(DomainError::Infrastructure(_))));
        assert!(mail.messages().is_empty());
    }

    /// Text-message availability matches whether the router has a text sender configured.
    #[test]
    fn the_router_says_whether_it_can_text() {
        let mail = Arc::new(RecordingCodeSender::default());
        let without = RoutedFactorCodeSender::new(mail.clone(), None);
        let texts: Arc<dyn FactorCodeSender> = Arc::new(RecordingCodeSender::default());
        let with = RoutedFactorCodeSender::new(mail, Some(texts));

        assert_eq!(
            without.text_messaging().availability(),
            TextAvailability::NotSetUp
        );
        assert_eq!(
            with.text_messaging().availability(),
            TextAvailability::Available
        );
    }
}
