//! Handing one rendered mail to the account it goes out through: an SMTP
//! server or a provider's API, within the delivery's time.

use std::time::Duration;

use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;

use crate::mail::sending::accounts::MailAccount;
use crate::mail::sending::apis::{MailApis, ProviderEndpoints};
use crate::mail::sending::message::{Envelope, message_of};
use crate::mail::sending::smtp::{Reach, SmtpSend, deliver as deliver_by_smtp};

/// Why a mail did not go out. None of it holds a credential, the mail, or
/// what the provider wrote back.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MailFailure {
    /// The provider did not answer in time.
    #[error("{provider} did not answer in time")]
    TimedOut {
        /// Safe service label included in the timeout report.
        provider: &'static str,
    },
    /// The provider answered with something other than success.
    #[error("{provider} refused the mail with status {status}")]
    Refused {
        /// Safe service label identifying who rejected delivery.
        provider: &'static str,
        /// The HTTP status it answered with.
        status: u16,
    },
    /// The provider could not be reached.
    #[error("{provider} could not be reached")]
    Unreachable {
        /// Safe service label identifying the unreachable endpoint.
        provider: &'static str,
        /// What failed, without the address called.
        #[source]
        cause: reqwest::Error,
    },
    /// An SMTP server refused the mail, or the login.
    #[error("the SMTP server refused the mail with reply code {code}")]
    SmtpRefused {
        /// The server's three-digit reply code.
        code: String,
    },
    /// An SMTP server could not be reached, or would not finish the
    /// exchange.
    #[error("the SMTP server could not be reached")]
    SmtpUnreachable,
    /// An SMTP server's name did not resolve.
    #[error("the SMTP server's name does not resolve")]
    Unresolved {
        /// Why.
        #[source]
        cause: std::io::Error,
    },
    /// TLS could not be set up for an SMTP server's name.
    #[error("TLS cannot be set up for the SMTP server")]
    SmtpTls {
        /// Why.
        #[source]
        cause: lettre::transport::smtp::Error,
    },
    /// An SMTP account was handed to the provider APIs.
    #[error("an SMTP server has no web API")]
    NoApi,
    /// The platform's own mail was to go out on a deployment with no mail
    /// server set up.
    #[error("no mail server is set up")]
    NotSetUp,
}

/// Which side chose the account a mail goes out through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Chosen {
    /// The platform, in its configuration.
    ByPlatform,
    /// A tenant, so its SMTP server is reached only at an address the
    /// deployment may reach.
    ByTenant,
}

/// The opened account together with who selected its network destination.
#[derive(Clone, Copy)]
pub(crate) struct DeliveryAccount<'a> {
    /// The provider account used for this send.
    pub(crate) account: &'a MailAccount,
    /// Determines whether SMTP address screening is required.
    pub(crate) chosen: Chosen,
}

/// Delivers rendered mail through SMTP servers and the providers' APIs,
/// each delivery held to one timeout.
#[derive(Debug, Clone)]
pub struct MailDelivery {
    apis: MailApis,
    networks: UpstreamNetworks,
    timeout: Duration,
}

impl MailDelivery {
    /// Delivery through the APIs at `endpoints`, reaching a tenant's SMTP
    /// server only inside `networks`, every delivery held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the HTTP client cannot be
    /// built.
    pub fn new(
        endpoints: ProviderEndpoints,
        networks: UpstreamNetworks,
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            apis: MailApis::new(endpoints, timeout)?,
            networks,
            timeout,
        })
    }

    /// Delivers `rendered` as `envelope` addresses it, through `account`.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when a tenant's SMTP server resolves to
    ///   no address the deployment may reach.
    /// - `DomainError::Infrastructure` when the account cannot be reached in
    ///   time or refuses the mail.
    pub(crate) async fn deliver(
        &self,
        source: DeliveryAccount<'_>,
        envelope: &Envelope<'_>,
        rendered: &RenderedEmail,
    ) -> Result<(), DomainError> {
        let MailAccount::Smtp(smtp) = source.account else {
            return self.apis.send(source.account, envelope, rendered).await;
        };
        let send = SmtpSend {
            account: smtp,
            reach: self.reach(source.chosen),
            hello: envelope.sending_domain(),
            timeout: self.timeout,
        };
        deliver_by_smtp(&send, message_of(envelope, rendered)?).await
    }

    /// Which addresses an SMTP server `chosen` named may be dialled at.
    fn reach(&self, chosen: Chosen) -> Reach<'_> {
        match chosen {
            Chosen::ByPlatform => Reach::AsConfigured,
            Chosen::ByTenant => Reach::Screened(&self.networks),
        }
    }
}
