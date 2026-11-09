//! How the ACME client reaches the authority: over the platform's fixed
//! client, so every call is held to a time, follows no redirect, and reads
//! a bounded answer, rather than over the library's own unbounded client.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use ianua_domain::shared::errors::DomainError;
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};

use crate::http::client::{body_within, fixed};

/// The longest answer read from an authority: a certificate chain with
/// room to spare.
const LONGEST_ANSWER: usize = 256 * 1024;

/// The ACME client's way out, each call held to the time it was built
/// with.
pub(crate) struct AuthorityHttpClient {
    client: reqwest::Client,
}

impl AuthorityHttpClient {
    /// A client holding each call to the authority to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub(crate) fn new(timeout: Duration) -> Result<Self, DomainError> {
        Ok(Self {
            client: fixed(timeout)?,
        })
    }
}

impl HttpClient for AuthorityHttpClient {
    fn request(
        &self,
        request: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let client = self.client.clone();
        Box::pin(async move { answered(&client, request).await })
    }
}

/// What the authority answered `request` with, its body read whole within
/// the bound.
async fn answered(
    client: &reqwest::Client,
    request: http::Request<BodyWrapper<Bytes>>,
) -> Result<BytesResponse, instant_acme::Error> {
    let (parts, body) = request.into_parts();
    let outgoing =
        reqwest::Request::try_from(http::Request::from_parts(parts, reqwest::Body::wrap(body)))
            .map_err(other)?;
    let response = client.execute(outgoing).await.map_err(other)?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = body_within(response, LONGEST_ANSWER).await.map_err(other)?;
    let (mut parts, ()) = http::Response::new(()).into_parts();
    parts.status = status;
    parts.headers = headers;
    Ok(BytesResponse {
        parts,
        body: Box::new(Bytes::from(body)),
    })
}

/// `error` as the ACME client carries a failure of its transport.
fn other(error: impl std::error::Error + Send + Sync + 'static) -> instant_acme::Error {
    instant_acme::Error::Other(Box::new(error))
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn get(url: &str) -> http::Request<BodyWrapper<Bytes>> {
        http::Request::builder()
            .uri(url)
            .body(BodyWrapper::default())
            .unwrap()
    }

    /// An answer comes back with its status, its headers and its body.
    #[tokio::test]
    async fn an_answer_keeps_its_status_headers_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("replay-nonce", "n1")
                    .set_body_string("{}"),
            )
            .mount(&server)
            .await;
        let client = AuthorityHttpClient::new(Duration::from_secs(5)).unwrap();

        let response = client
            .request(get(&format!("{}/directory", server.uri())))
            .await
            .unwrap();

        assert_eq!(response.parts.status.as_u16(), 200);
        assert_eq!(response.parts.headers["replay-nonce"], "n1");
    }

    /// An authority response one byte beyond the body limit fails the request.
    #[tokio::test]
    async fn an_answer_past_the_bound_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; LONGEST_ANSWER + 1]))
            .mount(&server)
            .await;
        let client = AuthorityHttpClient::new(Duration::from_secs(5)).unwrap();

        let response = client.request(get(&server.uri())).await;

        assert!(response.is_err());
    }

    /// An authority response delayed beyond the configured timeout fails the request.
    #[tokio::test]
    async fn a_hung_authority_is_given_up() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let client = AuthorityHttpClient::new(Duration::from_millis(200)).unwrap();

        let response = client.request(get(&server.uri())).await;

        assert!(response.is_err());
    }
}
