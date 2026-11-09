//! Amazon SES's v2 API: one JSON request to the account's region, signed
//! with AWS Signature Version 4.

use ianua_domain::domains::branding::mail_provider::{AwsAccessKeyId, SesRegion};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use reqwest::header::HeaderMap;
use serde::Serialize;
use url::Url;

use crate::crypto::sigv4::{AccessKey, Payload, Request, Scope, Signing};
use crate::mail::sending::apis::{Outgoing, SesEndpoint, ensure_accepted};

/// The provider's name in records and errors.
const PROVIDER: &str = "ses";

/// The service SES signs requests for.
const SERVICE: &str = "ses";

/// Where a mail is sent, below the API's address.
const SEND_PATH: &str = "/v2/email/outbound-emails";

/// The type every request body has.
const JSON: &str = "application/json";

/// An SES account, its secret open.
pub(super) struct Account<'a> {
    /// The region SES runs in.
    pub(super) region: &'a SesRegion,
    /// The access key's id.
    pub(super) access_key_id: &'a AwsAccessKeyId,
    /// The access key's secret.
    pub(super) secret_access_key: &'a Secret,
}

/// A mail as SES takes it.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Mail<'a> {
    from_email_address: String,
    destination: Destination<'a>,
    content: Content<'a>,
}

/// Who it goes to.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Destination<'a> {
    to_addresses: [&'a str; 1],
}

/// What it says.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Content<'a> {
    simple: Simple<'a>,
}

/// A mail SES builds itself, from a subject and its bodies.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Simple<'a> {
    subject: Text<'a>,
    body: Body<'a>,
}

/// The bodies.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Body<'a> {
    text: Text<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<Text<'a>>,
}

/// One piece of text, in UTF-8.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Text<'a> {
    data: &'a str,
    charset: &'static str,
}

impl<'a> Text<'a> {
    /// `data`, marked as UTF-8.
    fn utf8(data: &'a str) -> Self {
        Self {
            data,
            charset: "UTF-8",
        }
    }
}

/// The request body for `mail`.
fn body_of<'a>(mail: &Outgoing<'a>) -> Mail<'a> {
    let rendered = mail.rendered;
    Mail {
        from_email_address: mail.envelope.sender_header(),
        destination: Destination {
            to_addresses: [mail.envelope.to.as_str()],
        },
        content: Content {
            simple: Simple {
                subject: Text::utf8(rendered.subject()),
                body: Body {
                    text: Text::utf8(rendered.text()),
                    html: rendered.html().map(Text::utf8),
                },
            },
        },
    }
}

/// Where the account's mail is sent.
fn send_url(endpoint: &SesEndpoint, region: &SesRegion) -> Result<Url, DomainError> {
    let base = match endpoint {
        SesEndpoint::Regional => {
            let host = ["https://email.", region.as_str(), ".amazonaws.com/"].concat();
            Url::parse(&host).map_err(DomainError::infra)?
        }
        SesEndpoint::At(url) => url.clone(),
    };
    base.join(SEND_PATH).map_err(DomainError::infra)
}

/// Sends `mail` through the SES account `account` names.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when SES cannot be reached in
/// time or does not take the mail.
pub(super) async fn send(
    client: &reqwest::Client,
    endpoint: &SesEndpoint,
    account: &Account<'_>,
    mail: &Outgoing<'_>,
) -> Result<(), DomainError> {
    let url = send_url(endpoint, account.region)?;
    let body = serde_json::to_vec(&body_of(mail)).map_err(DomainError::infra)?;
    let signed = signed_headers(account, &url, &body)?;
    let sent = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, JSON)
        .headers(signed)
        .body(body)
        .send()
        .await;
    ensure_accepted(PROVIDER, sent)
}

/// Signs the serialized mail under the SES account's key and region.
fn signed_headers(account: &Account<'_>, url: &Url, body: &[u8]) -> Result<HeaderMap, DomainError> {
    let key = AccessKey {
        id: account.access_key_id.as_str(),
        secret: account.secret_access_key.expose(),
        token: None,
    };
    let signing = Signing {
        key: &key,
        scope: Scope {
            region: account.region.as_str(),
            service: SERVICE,
        },
        at: clock::now(),
    };
    signing.headers(&Request {
        method: "POST",
        url,
        headers: &[("content-type", JSON)],
        payload: Payload::Bytes(body),
    })
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::mail::sending::accounts::MailAccount;
    use crate::mail::sending::apis::stand_in::{ann, apis, platform, reset_mail};
    use crate::mail::sending::message::Envelope;

    fn account() -> MailAccount {
        MailAccount::Ses {
            region: SesRegion::new("eu-west-1").unwrap(),
            access_key_id: AwsAccessKeyId::new("AKIAIOSFODNN7EXAMPLE").unwrap(),
            secret_access_key: Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
        }
    }

    /// The mail reaches SES as one signed request: the signature names the
    /// key's id and the region, and the body holds both parts.
    #[tokio::test]
    async fn a_mail_is_sent_as_a_signed_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(SEND_PATH))
            .and(header_exists("authorization"))
            .and(header_exists("x-amz-date"))
            .and(body_partial_json(serde_json::json!({
                "Destination": {"ToAddresses": ["ann@acme.test"]},
                "Content": {"Simple": {"Subject": {"Data": "Reset your password"}}},
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
        let requests = server.received_requests().await.unwrap();
        assert_ses_signature(&requests[0]);
    }

    /// Checks the signing identity and region while excluding the access secret.
    fn assert_ses_signature(request: &wiremock::Request) {
        let signed = request
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(signed.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(signed.contains("/eu-west-1/ses/aws4_request"));
        assert!(!signed.contains("EXAMPLEKEY"));
    }

    /// An account in `eu-west-1` is sent to SES in that region.
    #[test]
    fn an_account_is_sent_to_its_own_region() {
        let region = SesRegion::new("eu-west-1").unwrap();

        let url = send_url(&SesEndpoint::Regional, &region).unwrap();

        assert_eq!(
            url.as_str(),
            "https://email.eu-west-1.amazonaws.com/v2/email/outbound-emails"
        );
    }
}
