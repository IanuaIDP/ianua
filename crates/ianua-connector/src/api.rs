//! The two calls the connector makes to the ianua API: enrolling once with
//! the one-time code, and renewing its certificate for the same key.
//!
//! Each call sends a signing request made from the connector's key and
//! nothing else of it; the key never leaves the machine. Every call has a
//! timeout and follows no redirect. A refusal is final and stops the
//! connector, so a spent code or a revoked connector is never tried in a
//! loop; a busy or unreachable API is tried again later. Neither the code,
//! the key nor the certificate is ever logged.

use std::future::Future;
use std::io::BufReader;
use std::time::Duration;

use ianua_boot::shutdown::Shutdown;
use ianua_domain::shared::security::secret::Secret;
use rcgen::{CertificateParams, KeyPair};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::backoff::Backoff;
use crate::config::ApiConfig;
use crate::state::Issued;

/// Why the API client could not be built.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The HTTP client could not be built.
    #[error("the HTTP client for the API could not be built")]
    Build(#[source] reqwest::Error),
    /// The signing request could not be made from the key.
    #[error("the signing request could not be made from the connector's key")]
    Request,
}

/// How one call ended short of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallError {
    /// The API refused for good, with this status: a code that is not
    /// good, a revoked connector, a key it does not take.
    Refused(u16),
    /// The API was busy or unreachable, or answered something unreadable:
    /// worth trying again later.
    Retry(String),
}

/// How a call tried until it ended came out.
#[derive(Debug)]
pub enum Outcome {
    /// The API answered a certificate.
    Issued(Issued),
    /// The API refused for good, with this status.
    Refused(u16),
    /// The connector is stopping.
    Stopped,
}

/// The API's answer to an enrollment or a renewal.
#[derive(Deserialize)]
struct Answer {
    id: Uuid,
    certificate: String,
    authority: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    renew_after: OffsetDateTime,
}

/// The connector's client of the API.
#[derive(Debug, Clone)]
pub(crate) struct ApiClient {
    http: reqwest::Client,
    connectors: String,
}

impl ApiClient {
    /// A client of the API `api` names, each call held to `timeout`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Build`] when the HTTP client cannot be built.
    pub(crate) fn new(api: &ApiConfig, timeout: Duration) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(ClientError::Build)?;
        let connectors = format!(
            "{}/api/v1/organizations/{}/tenants/{}/connectors",
            api.url.as_str().trim_end_matches('/'),
            api.tenant.organization(),
            api.tenant.tenant()
        );
        Ok(Self { http, connectors })
    }

    /// Enrolls with the one-time `code`, sending `request`.
    ///
    /// # Errors
    ///
    /// [`CallError`] for a refusal or a failure worth trying again.
    pub(crate) async fn enroll(&self, code: &Secret, request: &str) -> Result<Issued, CallError> {
        let url = format!("{}/enroll", self.connectors);
        let body = json!({"code": code.expose(), "csr": request});
        self.called(&url, &body).await
    }

    /// Renews the certificate of connector `id`, sending `request` for the
    /// same key.
    ///
    /// # Errors
    ///
    /// [`CallError`] for a refusal or a failure worth trying again.
    pub(crate) async fn renew(&self, id: Uuid, request: &str) -> Result<Issued, CallError> {
        let url = format!("{}/{id}/renew", self.connectors);
        self.called(&url, &json!({"csr": request})).await
    }

    async fn called(&self, url: &str, body: &serde_json::Value) -> Result<Issued, CallError> {
        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|error| CallError::Retry(retry_reason(&error)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(refusal_or_retry(status));
        }
        let answer: Answer = response
            .json()
            .await
            .map_err(|_| CallError::Retry("the API's answer does not read".to_owned()))?;
        issued_from(answer)
    }
}

/// A signing request for the key `key`, naming nothing else: the authority
/// takes only the key.
///
/// # Errors
///
/// [`ClientError::Request`] when the key does not read or cannot sign.
pub fn signing_request(key: &Secret) -> Result<String, ClientError> {
    let pair = KeyPair::from_pem(key.expose()).map_err(|_| ClientError::Request)?;
    CertificateParams::default()
        .serialize_request(&pair)
        .and_then(|request| request.pem())
        .map_err(|_| ClientError::Request)
}

/// Calls `call` until it answers, the API refuses for good, or `shutdown`
/// stops, waiting `backoff` between tries.
pub(crate) async fn until_answered<F, Fut>(
    backoff: &mut Backoff,
    shutdown: &Shutdown,
    what: &'static str,
    mut call: F,
) -> Outcome
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Issued, CallError>>,
{
    loop {
        let reason = match call().await {
            Ok(issued) => return Outcome::Issued(issued),
            Err(CallError::Refused(status)) => return Outcome::Refused(status),
            Err(CallError::Retry(reason)) => reason,
        };
        let wait = backoff.wait();
        tracing::warn!(call = what, %reason, ?wait, "the API did not answer; trying again");
        tokio::select! {
            () = shutdown.stopping() => return Outcome::Stopped,
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Whether `status` is a refusal for good or a failure worth trying again.
fn refusal_or_retry(status: StatusCode) -> CallError {
    let busy = status.is_server_error()
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::REQUEST_TIMEOUT;
    if busy {
        return CallError::Retry(format!("the API answered {status}"));
    }
    CallError::Refused(status.as_u16())
}

/// Why a call failed before any answer, without the URL or body.
fn retry_reason(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "the API did not answer in time".to_owned();
    }
    if error.is_connect() {
        return "the API could not be reached".to_owned();
    }
    "the call to the API failed".to_owned()
}

/// The certificate `answer` holds, once both certificates in it read.
fn issued_from(answer: Answer) -> Result<Issued, CallError> {
    if !holds_certificate(&answer.certificate) || !holds_certificate(&answer.authority) {
        return Err(CallError::Retry(
            "the API's answer holds no certificate".to_owned(),
        ));
    }
    Ok(Issued {
        id: answer.id,
        certificate_pem: answer.certificate,
        authority_pem: answer.authority,
        expires_at: answer.expires_at,
        renew_after: answer.renew_after,
    })
}

/// Whether `pem` holds at least one certificate that reads.
fn holds_certificate(pem: &str) -> bool {
    let read: Result<Vec<_>, _> =
        rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes())).collect();
    read.is_ok_and(|certificates| !certificates.is_empty())
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::config::TenantPath;

    /// A certificate that reads, made for the test.
    fn certificate_pem() -> String {
        let key = KeyPair::generate().unwrap();
        CertificateParams::new(vec!["test".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem()
    }

    fn answer(id: Uuid) -> serde_json::Value {
        json!({
            "id": id,
            "certificate": certificate_pem(),
            "authority": certificate_pem(),
            "expires_at": "2030-01-02T00:00:00Z",
            "renew_after": "2030-01-01T16:00:00Z",
        })
    }

    fn client(server: &MockServer) -> ApiClient {
        let api = ApiConfig {
            url: url::Url::parse(&server.uri()).unwrap(),
            tenant: "acme/main".parse::<TenantPath>().unwrap(),
            enrollment_code: None,
        };
        ApiClient::new(&api, Duration::from_secs(5)).unwrap()
    }

    fn request() -> String {
        signing_request(&Secret::new(KeyPair::generate().unwrap().serialize_pem())).unwrap()
    }

    /// The connector enrolls with its code and a signing request, and gets
    /// its certificate and the authority's.
    #[tokio::test]
    async fn an_enrollment_answers_the_certificate() {
        let server = MockServer::start().await;
        let id = Uuid::now_v7();
        Mock::given(method("POST"))
            .and(path(
                "/api/v1/organizations/acme/tenants/main/connectors/enroll",
            ))
            .and(body_partial_json(json!({"code": "the code"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(answer(id)))
            .expect(1)
            .mount(&server)
            .await;

        let issued = client(&server)
            .enroll(&Secret::new("the code"), &request())
            .await
            .unwrap();

        assert_eq!(issued.id, id);
        assert!(issued.renew_after < issued.expires_at);
    }

    /// A forbidden enrollment response ends retrying after one request
    /// and preserves the refusal status.
    #[tokio::test]
    async fn a_refused_code_is_never_tried_again() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        let client = client(&server);
        let request = request();
        let code = Secret::new("spent");
        let mut backoff = Backoff::starting_at(Duration::from_millis(1), Duration::from_millis(5));

        let outcome = until_answered(
            &mut backoff,
            &Shutdown::new(Duration::from_secs(1)),
            "enroll",
            || client.enroll(&code, &request),
        )
        .await;

        assert!(matches!(outcome, Outcome::Refused(403)));
    }

    /// The API is restarting and answers 503 once. The renewal is tried
    /// again and gets its answer.
    #[tokio::test]
    async fn a_busy_api_is_tried_again() {
        let server = MockServer::start().await;
        let id = Uuid::now_v7();
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/organizations/acme/tenants/main/connectors/{id}/renew"
            )))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(answer(id)))
            .with_priority(2)
            .mount(&server)
            .await;
        let client = client(&server);
        let request = request();
        let mut backoff = Backoff::starting_at(Duration::from_millis(1), Duration::from_millis(5));

        let outcome = until_answered(
            &mut backoff,
            &Shutdown::new(Duration::from_secs(1)),
            "renew",
            || client.renew(id, &request),
        )
        .await;

        assert!(matches!(outcome, Outcome::Issued(issued) if issued.id == id));
    }

    /// An enrollment response without a valid certificate becomes a
    /// retryable failure rather than an issued credential.
    #[tokio::test]
    async fn an_answer_without_a_certificate_is_not_taken() {
        let server = MockServer::start().await;
        let mut broken = answer(Uuid::now_v7());
        broken["certificate"] = json!("not a certificate");
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(broken))
            .mount(&server)
            .await;

        let result = client(&server)
            .enroll(&Secret::new("the code"), &request())
            .await;

        assert!(matches!(result, Err(CallError::Retry(_))));
    }
}
