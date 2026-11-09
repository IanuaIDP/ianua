//! Mailgun's messages API: a form posted to the sending domain, in the
//! region the account lives in, the key as the password of user `api`.

use ianua_domain::domains::branding::mail_provider::MailgunRegion;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::DomainName;
use url::Url;

use crate::mail::sending::apis::{Outgoing, ProviderEndpoints, ensure_accepted};

/// The provider's name in records and errors.
const PROVIDER: &str = "mailgun";

/// The user name Mailgun signs API calls in under.
const API_USER: &str = "api";

/// A Mailgun account, its key open.
pub(super) struct Account<'a> {
    /// The sending domain set up in Mailgun.
    pub(super) domain: &'a DomainName,
    /// The region the account lives in.
    pub(super) region: MailgunRegion,
    /// Authenticates the request as the provider's `api` user.
    pub(super) api_key: &'a Secret,
}

/// The form fields for `mail`.
fn fields_of(mail: &Outgoing<'_>) -> Vec<(&'static str, String)> {
    let rendered = mail.rendered;
    let mut fields = vec![
        ("from", mail.envelope.sender_header()),
        ("to", mail.envelope.to.as_str().to_owned()),
        ("subject", rendered.subject().to_owned()),
        ("text", rendered.text().to_owned()),
    ];
    fields.extend(rendered.html().map(|html| ("html", html.to_owned())));
    fields
}

/// Where the account's messages are posted.
fn messages_of(endpoints: &ProviderEndpoints, account: &Account<'_>) -> Result<Url, DomainError> {
    let base = match account.region {
        MailgunRegion::Us => &endpoints.mailgun_us,
        MailgunRegion::Eu => &endpoints.mailgun_eu,
    };
    let route = ["v3/", account.domain.as_str(), "/messages"].concat();
    base.join(&route).map_err(DomainError::infra)
}

/// Sends `mail` through the Mailgun account `account` names.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when Mailgun cannot be reached in
/// time or does not take the mail.
pub(super) async fn send(
    client: &reqwest::Client,
    endpoints: &ProviderEndpoints,
    account: &Account<'_>,
    mail: &Outgoing<'_>,
) -> Result<(), DomainError> {
    let url = messages_of(endpoints, account)?;
    let sent = client
        .post(url)
        .basic_auth(API_USER, Some(account.api_key.expose()))
        .form(&fields_of(mail))
        .send()
        .await;
    ensure_accepted(PROVIDER, sent)
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_string_contains, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::mail::sending::accounts::MailAccount;
    use crate::mail::sending::apis::stand_in::{ann, apis, platform, reset_mail};
    use crate::mail::sending::message::Envelope;

    fn account(region: MailgunRegion) -> MailAccount {
        MailAccount::Mailgun {
            domain: DomainName::new("mg.acme.test").unwrap(),
            region,
            api_key: Secret::new("key-live"),
        }
    }

    /// The mail is posted as a form to the account's sending domain, signed
    /// in as user `api`.
    #[tokio::test]
    async fn a_mail_is_posted_to_the_sending_domain() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/mg.acme.test/messages"))
            .and(header_exists("authorization"))
            .and(body_string_contains("to=ann%40acme.test"))
            .and(body_string_contains("subject=Reset+your+password"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let account = account(MailgunRegion::Us);
        let platform = platform(account.clone());
        let to = ann();

        let sent = apis(&server)
            .send(&account, &Envelope::platform(&platform, &to), &reset_mail())
            .await;

        assert!(sent.is_ok());
    }

    /// An account in the EU region is posted to Mailgun's EU host, so its
    /// mail never leaves the region it chose.
    #[test]
    fn an_eu_account_is_posted_to_the_eu_host() {
        let endpoints = ProviderEndpoints::public().unwrap();
        let domain = DomainName::new("mg.acme.test").unwrap();
        let key = Secret::new("key-live");
        let eu = Account {
            domain: &domain,
            region: MailgunRegion::Eu,
            api_key: &key,
        };

        let url = messages_of(&endpoints, &eu).unwrap();

        assert_eq!(
            url.as_str(),
            "https://api.eu.mailgun.net/v3/mg.acme.test/messages"
        );
    }
}
