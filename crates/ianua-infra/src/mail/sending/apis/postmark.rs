//! Postmark's email API: one JSON request, the server token in a header of
//! its own, sent on the transactional stream.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use serde::Serialize;
use url::Url;

use crate::mail::sending::apis::{Outgoing, ensure_accepted};

/// The provider's name in records and errors.
const PROVIDER: &str = "postmark";

/// The header Postmark reads the server token from.
const TOKEN_HEADER: &str = "X-Postmark-Server-Token";

/// The stream transactional mail goes out on.
const STREAM: &str = "outbound";

/// A mail as Postmark takes it.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Mail<'a> {
    from: String,
    to: &'a str,
    subject: &'a str,
    text_body: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    html_body: Option<&'a str>,
    message_stream: &'static str,
}

/// The request body for `mail`.
fn body_of<'a>(mail: &Outgoing<'a>) -> Mail<'a> {
    Mail {
        from: mail.envelope.sender_header(),
        to: mail.envelope.to.as_str(),
        subject: mail.rendered.subject(),
        text_body: mail.rendered.text(),
        html_body: mail.rendered.html(),
        message_stream: STREAM,
    }
}

/// Sends `mail` through the Postmark server `server_token` opens.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when Postmark cannot be reached
/// in time or does not take the mail.
pub(super) async fn send(
    client: &reqwest::Client,
    base: &Url,
    server_token: &Secret,
    mail: &Outgoing<'_>,
) -> Result<(), DomainError> {
    let url = base.join("email").map_err(DomainError::infra)?;
    let sent = client
        .post(url)
        .header(TOKEN_HEADER, server_token.expose())
        .header(reqwest::header::ACCEPT, "application/json")
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
        MailAccount::Postmark {
            server_token: Secret::new("pm-token"),
        }
    }

    /// The mail reaches Postmark on the transactional stream, with its
    /// token in Postmark's own header and both bodies.
    #[tokio::test]
    async fn a_mail_is_sent_on_the_transactional_stream() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/email"))
            .and(header(TOKEN_HEADER, "pm-token"))
            .and(body_partial_json(serde_json::json!({
                "From": "\"Ianua\" <noreply@ianua.test>",
                "To": "ann@acme.test",
                "Subject": "Reset your password",
                "MessageStream": "outbound",
            })))
            .respond_with(ResponseTemplate::new(200))
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

    /// Postmark refuses a mail it cannot send, and the delivery fails, so
    /// the job is tried again.
    #[tokio::test]
    async fn a_refused_mail_fails_the_delivery() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(422))
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

        assert!(matches!(sent, Err(DomainError::Infrastructure(_))));
    }
}
