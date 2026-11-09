//! SendGrid's mail send API: one JSON request, the key as a bearer token.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use serde::Serialize;
use url::Url;

use crate::mail::sending::apis::{Outgoing, ensure_accepted};

/// The provider's name in records and errors.
const PROVIDER: &str = "sendgrid";

/// A mail as SendGrid takes it.
#[derive(Serialize)]
struct Mail<'a> {
    personalizations: [Personalization<'a>; 1],
    from: Address<'a>,
    subject: &'a str,
    content: Vec<Content<'a>>,
}

/// The recipients of one copy.
#[derive(Serialize)]
struct Personalization<'a> {
    to: [Address<'a>; 1],
}

/// An address, with the name it shows.
#[derive(Serialize)]
struct Address<'a> {
    email: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

/// One body, plain text first as SendGrid asks.
#[derive(Serialize)]
struct Content<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    value: &'a str,
}

/// The request body for `mail`.
fn body_of<'a>(mail: &Outgoing<'a>) -> Mail<'a> {
    let rendered = mail.rendered;
    let mut content = vec![Content {
        kind: "text/plain",
        value: rendered.text(),
    }];
    content.extend(rendered.html().map(|html| Content {
        kind: "text/html",
        value: html,
    }));
    Mail {
        personalizations: [Personalization {
            to: [Address {
                email: mail.envelope.to.as_str(),
                name: None,
            }],
        }],
        from: Address {
            email: mail.envelope.from.as_str(),
            name: mail.envelope.name,
        },
        subject: rendered.subject(),
        content,
    }
}

/// Sends `mail` through the SendGrid account `api_key` opens.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when SendGrid cannot be reached
/// in time or does not take the mail.
pub(super) async fn send(
    client: &reqwest::Client,
    base: &Url,
    api_key: &Secret,
    mail: &Outgoing<'_>,
) -> Result<(), DomainError> {
    let url = base.join("v3/mail/send").map_err(DomainError::infra)?;
    let sent = client
        .post(url)
        .bearer_auth(api_key.expose())
        .json(&body_of(mail))
        .send()
        .await;
    ensure_accepted(PROVIDER, sent)
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::mail::sending::accounts::MailAccount;
    use crate::mail::sending::apis::stand_in::{ann, apis, platform, reset_mail};
    use crate::mail::sending::message::Envelope;

    fn account() -> MailAccount {
        MailAccount::SendGrid {
            api_key: Secret::new("SG.live-key"),
        }
    }

    /// The mail reaches SendGrid as one request: Ann as the recipient, the
    /// platform's address as the sender, both bodies, the key as a bearer
    /// token.
    #[tokio::test]
    async fn a_mail_is_sent_with_both_bodies_and_the_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v3/mail/send"))
            .and(header("authorization", "Bearer SG.live-key"))
            .and(body_partial_json(serde_json::json!({
                "personalizations": [{"to": [{"email": "ann@acme.test"}]}],
                "from": {"email": "noreply@ianua.test", "name": "Ianua"},
                "subject": "Reset your password",
                "content": [{"type": "text/plain"}, {"type": "text/html"}],
            })))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;
        let platform = platform(account());
        let to = ann();

        let sent = apis(&server)
            .send(
                &account(),
                &Envelope::platform(&platform, &to),
                &reset_mail(),
            )
            .await;

        assert!(sent.is_ok());
    }

    /// A SendGrid refusal that echoes the API key becomes an infrastructure
    /// error showing the status while omitting the echoed key.
    #[tokio::test]
    async fn a_refusal_keeps_only_the_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bad key SG.live-key"))
            .mount(&server)
            .await;
        let platform = platform(account());
        let to = ann();

        let refused = apis(&server)
            .send(
                &account(),
                &Envelope::platform(&platform, &to),
                &reset_mail(),
            )
            .await
            .unwrap_err();

        let shown = format!("{refused} {refused:?}");
        assert!(matches!(refused, DomainError::Infrastructure(_)));
        assert!(shown.contains("401"));
        assert!(!shown.contains("live-key"));
    }
}
