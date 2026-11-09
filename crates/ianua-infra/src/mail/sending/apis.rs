//! The mail providers' web APIs: SendGrid, Postmark, Mailgun and Amazon
//! SES. Their hosts are the platform's choice, so each is called through
//! the shared client for fixed addresses, never following a redirect and
//! held to the delivery's timeout.
//!
//! A provider that refuses a mail is answered by its status alone: what it
//! wrote back may repeat the mail or the key, so it is never read into an
//! error or a log.

mod mailgun;
mod postmark;
mod sendgrid;
mod ses;

use std::time::Duration;

use ianua_domain::domains::branding::renderer::RenderedEmail;
use ianua_domain::shared::errors::DomainError;
use url::Url;

use crate::http::client::fixed;
use crate::mail::sending::accounts::MailAccount;
use crate::mail::sending::delivery::MailFailure;
use crate::mail::sending::message::Envelope;

/// Where each provider's API answers.
#[derive(Debug, Clone)]
pub struct ProviderEndpoints {
    /// SendGrid's API.
    pub sendgrid: Url,
    /// Postmark's API.
    pub postmark: Url,
    /// Mailgun's API for accounts in the US region.
    pub mailgun_us: Url,
    /// Mailgun's API for accounts in the EU region.
    pub mailgun_eu: Url,
    /// Amazon SES's API.
    pub ses: SesEndpoint,
}

/// Where Amazon SES answers.
#[derive(Debug, Clone)]
pub enum SesEndpoint {
    /// In the account's own region, `email.<region>.amazonaws.com`.
    Regional,
    /// At one address for every region, such as a stand-in in tests.
    At(Url),
}

impl ProviderEndpoints {
    /// The providers' public APIs.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when an address does not read,
    /// which it always does.
    pub fn public() -> Result<Self, DomainError> {
        Ok(Self {
            sendgrid: endpoint("https://api.sendgrid.com/")?,
            postmark: endpoint("https://api.postmarkapp.com/")?,
            mailgun_us: endpoint("https://api.mailgun.net/")?,
            mailgun_eu: endpoint("https://api.eu.mailgun.net/")?,
            ses: SesEndpoint::Regional,
        })
    }

    /// Every provider at `base`, for a stand-in of their APIs.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `base` does not read.
    pub fn all_at(base: &str) -> Result<Self, DomainError> {
        let at = endpoint(base)?;
        Ok(Self {
            sendgrid: at.clone(),
            postmark: at.clone(),
            mailgun_us: at.clone(),
            mailgun_eu: at.clone(),
            ses: SesEndpoint::At(at),
        })
    }
}

/// `address` as a URL.
fn endpoint(address: &str) -> Result<Url, DomainError> {
    Url::parse(address).map_err(DomainError::infra)
}

/// The providers' APIs, reached through one client held to a timeout.
#[derive(Debug, Clone)]
pub(crate) struct MailApis {
    client: reqwest::Client,
    endpoints: ProviderEndpoints,
}

impl MailApis {
    /// The APIs at `endpoints`, each call held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub(crate) fn new(
        endpoints: ProviderEndpoints,
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            client: fixed(timeout)?,
            endpoints,
        })
    }

    /// Sends `rendered` through the API `account` names. An SMTP account
    /// has no API, and is refused here.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the provider cannot be
    /// reached in time or refuses the mail.
    /// The exhaustive dispatch keeps each account variant paired with its provider's wire API.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn send(
        &self,
        account: &MailAccount,
        envelope: &Envelope<'_>,
        rendered: &RenderedEmail,
    ) -> Result<(), DomainError> {
        let mail = Outgoing { envelope, rendered };
        match account {
            MailAccount::Smtp(_) => Err(DomainError::infra(MailFailure::NoApi)),
            MailAccount::SendGrid { api_key } => {
                sendgrid::send(&self.client, &self.endpoints.sendgrid, api_key, &mail).await
            }
            MailAccount::Postmark { server_token } => {
                postmark::send(&self.client, &self.endpoints.postmark, server_token, &mail).await
            }
            MailAccount::Mailgun {
                domain,
                region,
                api_key,
            } => {
                let account = mailgun::Account {
                    domain,
                    region: *region,
                    api_key,
                };
                mailgun::send(&self.client, &self.endpoints, &account, &mail).await
            }
            MailAccount::Ses {
                region,
                access_key_id,
                secret_access_key,
            } => {
                let account = ses::Account {
                    region,
                    access_key_id,
                    secret_access_key,
                };
                ses::send(&self.client, &self.endpoints.ses, &account, &mail).await
            }
        }
    }
}

/// One mail on its way to an API.
#[derive(Debug, Clone, Copy)]
struct Outgoing<'a> {
    envelope: &'a Envelope<'a>,
    rendered: &'a RenderedEmail,
}

/// Whether `provider` took the mail, from how the call came back.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the call did not reach the
/// provider in time, or the provider answered with anything but success.
fn ensure_accepted(
    provider: &'static str,
    sent: Result<reqwest::Response, reqwest::Error>,
) -> Result<(), DomainError> {
    let response = match sent {
        Ok(response) => response,
        Err(error) if error.is_timeout() => {
            return Err(DomainError::infra(MailFailure::TimedOut { provider }));
        }
        Err(error) => {
            return Err(DomainError::infra(MailFailure::Unreachable {
                provider,
                cause: error.without_url(),
            }));
        }
    };
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    Err(DomainError::infra(MailFailure::Refused {
        provider,
        status: status.as_u16(),
    }))
}

#[cfg(test)]
pub(crate) mod stand_in {
    //! A stand-in of the providers' APIs, for the tests of each.

    use ianua_domain::types::{Email, Label};
    use wiremock::MockServer;

    use super::*;
    use crate::mail::sending::accounts::PlatformMail;

    /// The APIs, every one answered by `server`.
    pub(crate) fn apis(server: &MockServer) -> MailApis {
        MailApis::new(
            ProviderEndpoints::all_at(&server.uri()).unwrap(),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    /// The platform's address, `noreply@ianua.test`, under its name.
    pub(crate) fn platform(account: MailAccount) -> PlatformMail {
        PlatformMail {
            account: Some(account),
            from: Email::new("noreply@ianua.test").unwrap(),
            from_name: Some(Label::new("name", "Ianua").unwrap()),
        }
    }

    /// Ann, whom the tests mail.
    pub(crate) fn ann() -> Email {
        Email::new("ann@acme.test").unwrap()
    }

    /// A reset mail with both bodies, its link a live one.
    pub(crate) fn reset_mail() -> RenderedEmail {
        RenderedEmail::multipart(
            "Reset your password",
            "<a href=\"https://acme.test/reset?token=live\">Reset</a>",
            "https://acme.test/reset?token=live",
        )
    }
}
