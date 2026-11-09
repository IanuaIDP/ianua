//! How the OpenID Connect library reaches a provider: through the screened
//! client, with every answer read within a size limit, so a provider that
//! sends a discovery document, a key set or a token answer without end
//! cannot fill the process's memory.
//!
//! The library fetches the key set the discovery document names as soon as
//! it has read the document, before anything here sees it. A URL naming an
//! IP address is never resolved, so the screening resolver never sees it
//! either. So every request the library makes is checked here, before it is
//! sent, against the networks the deployment may reach.

use std::future::Future;
use std::pin::Pin;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse};

use crate::http::client::{body_within, ensure_reachable};

/// The most bytes one answer of a provider may hold: far past any real
/// discovery document, key set or token answer.
const MOST_ANSWER: usize = 256 * 1024;

/// A call to a provider that went wrong, without its address or body.
#[derive(Debug, thiserror::Error)]
pub(super) enum ProviderCallError {
    /// The request could not be made into one the client sends.
    #[error("the request to the provider could not be made")]
    Built(#[source] reqwest::Error),
    /// The request names an address the deployment may not reach.
    #[error("the provider named an address this deployment may not reach")]
    Refused(#[source] DomainError),
    /// The provider was not reached, or did not answer in time.
    #[error("the provider was not reached")]
    Unreached(#[source] reqwest::Error),
    /// The answer could not be read, or was longer than it may be.
    #[error("the provider's answer could not be read within its limit")]
    Unread(#[source] DomainError),
    /// The answer could not be handed to the library.
    #[error("the provider's answer could not be passed on")]
    Unpassed(#[source] openidconnect::http::Error),
}

/// The screened client, as the library calls a provider through it.
pub(super) struct Screened {
    http: reqwest::Client,
    networks: UpstreamNetworks,
}

impl Screened {
    /// Calls made through `http`, screened against `networks`, to every
    /// address the library asks for.
    pub(super) fn new(http: reqwest::Client, networks: UpstreamNetworks) -> Self {
        Self { http, networks }
    }

    /// The answer to `request`, read within [`MOST_ANSWER`] bytes.
    async fn answer(&self, request: HttpRequest) -> Result<HttpResponse, ProviderCallError> {
        let sent = reqwest::Request::try_from(request).map_err(ProviderCallError::Built)?;
        ensure_reachable(sent.url(), &self.networks).map_err(ProviderCallError::Refused)?;
        let response = self
            .http
            .execute(sent)
            .await
            .map_err(ProviderCallError::Unreached)?;
        let mut answer = openidconnect::http::Response::builder().status(response.status());
        for (name, value) in response.headers() {
            answer = answer.header(name, value);
        }
        let body = body_within(response, MOST_ANSWER)
            .await
            .map_err(ProviderCallError::Unread)?;
        answer.body(body).map_err(ProviderCallError::Unpassed)
    }
}

impl<'c> AsyncHttpClient<'c> for Screened {
    type Error = ProviderCallError;
    type Future =
        Pin<Box<dyn Future<Output = Result<HttpResponse, ProviderCallError>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(self.answer(request))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::http::calls::tests::loopback;
    use crate::http::client::screened;

    fn transport(networks: UpstreamNetworks) -> Screened {
        Screened::new(
            screened(Duration::from_secs(5), networks.clone()).unwrap(),
            networks,
        )
    }

    fn get(url: &str) -> HttpRequest {
        openidconnect::http::Request::builder()
            .method(openidconnect::http::Method::GET)
            .uri(url)
            .body(Vec::new())
            .unwrap()
    }

    /// A request naming a disallowed loopback IP returns a transport
    /// refusal without reaching the key-set server.
    #[tokio::test]
    async fn a_request_to_an_internal_ip_address_is_never_sent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"keys\":[]}"))
            .mount(&server)
            .await;

        let result = transport(UpstreamNetworks::public_only())
            .call(get(&format!("{}/keys", server.uri())))
            .await;

        assert!(matches!(result, Err(ProviderCallError::Refused(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// An address the deployment lists is reached, and its answer passed
    /// on.
    #[tokio::test]
    async fn a_request_to_a_listed_network_is_answered() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"keys\":[]}"))
            .mount(&server)
            .await;

        let answer = transport(loopback())
            .call(get(&format!("{}/keys", server.uri())))
            .await
            .unwrap();

        assert_eq!(answer.status().as_u16(), 200);
    }
}
