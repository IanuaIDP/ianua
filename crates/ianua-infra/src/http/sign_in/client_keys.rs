//! The keys a `private_key_jwt` client publishes at its `jwks_uri`, read
//! for the check of its assertions at the token endpoint.
//!
//! The address is the tenant's choice, so the call goes through the
//! screened client: an address the deployment may not reach is refused
//! before the call, each name is screened when it resolves, no redirect is
//! followed, the call is held to a timeout and the answer to a size. The
//! set is read only over `https`. Each address's keys are kept for a
//! while, for a bounded number of addresses, so each assertion does not
//! call the client; a set that cannot be read is an error, and nothing is
//! checked against keys that were not read.

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::shared::errors::{DomainError, causes};
use ianua_domain::shared::security::ssrf::UpstreamNetworks;
use ianua_domain::types::HttpsUrl;
use serde_json::Value;

use crate::crypto::PublishedKeys;
use crate::http::client::{body_within, ensure_reachable, screened};
use crate::proofs::{KeyCache, KeyKeeping, MOST_KEY_SET_BYTES, Wanted, key_set_in};

/// The scheme every published key set is read over.
const HTTPS: &str = "https";

/// The key sets clients publish, read over HTTP and kept a while.
pub struct HttpPublishedKeys {
    client: reqwest::Client,
    networks: UpstreamNetworks,
    scheme: &'static str,
    cache: KeyCache<HttpsUrl>,
}

impl HttpPublishedKeys {
    /// Key sets read with each call held to `timeout`, reaching public
    /// addresses and those in `networks`, kept as `keeping` says for at
    /// most `most_sets` addresses.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(
        timeout: Duration,
        networks: UpstreamNetworks,
        keeping: KeyKeeping,
        most_sets: usize,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            client: screened(timeout, networks.clone())?,
            networks,
            scheme: HTTPS,
            cache: KeyCache::new(keeping, most_sets),
        })
    }

    /// The key set published at `url`, read now.
    async fn fetch(&self, url: &HttpsUrl) -> Result<Vec<Value>, DomainError> {
        let mut address = url::Url::parse(url.as_str()).map_err(DomainError::infra)?;
        address
            .set_scheme(self.scheme)
            .map_err(|()| DomainError::infra_msg("a key set is read only over https"))?;
        ensure_reachable(&address, &self.networks)?;
        let response = self
            .client
            .get(address)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(DomainError::infra)?
            .error_for_status()
            .map_err(DomainError::infra)?;
        key_set_in(&body_within(response, MOST_KEY_SET_BYTES).await?)
    }
}

#[async_trait]
impl PublishedKeys for HttpPublishedKeys {
    async fn keys_at(&self, url: &HttpsUrl) -> Result<Vec<Value>, DomainError> {
        self.cache
            .keys(url, Wanted::Kept, || self.fetch(url))
            .await
            .inspect_err(|error| {
                tracing::warn!(
                    jwks_uri = %url.as_str(),
                    error = %causes(error),
                    "a client's published keys could not be read"
                );
            })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::CidrRange;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// The loopback networks the stand-in client listens on.
    fn loopback() -> UpstreamNetworks {
        UpstreamNetworks::new(vec![
            CidrRange::new("127.0.0.0/8").unwrap(),
            CidrRange::new("::1/128").unwrap(),
        ])
    }

    fn keeping() -> KeyKeeping {
        KeyKeeping {
            keep_for: Duration::from_secs(600),
            renew_after: Duration::from_secs(60),
        }
    }

    /// Keys read over plain `http`, which a mock server speaks: an address
    /// `https://localhost:<port>` is read at `http://localhost:<port>`.
    fn over_plain_http() -> HttpPublishedKeys {
        HttpPublishedKeys {
            client: screened(Duration::from_secs(5), loopback()).unwrap(),
            networks: loopback(),
            scheme: "http",
            cache: KeyCache::new(keeping(), 8),
        }
    }

    /// A mock client publishing `body` at `/jwks`, and the `https` address
    /// naming it.
    async fn publishing(body: Value) -> (MockServer, HttpsUrl) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let address = format!("{}/jwks", server.uri())
            .replace("127.0.0.1", "localhost")
            .replacen("http://", "https://", 1);
        (server, HttpsUrl::new(address).unwrap())
    }

    fn one_key() -> Value {
        json!({"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "AQAB", "y": "AQAB"}]})
    }

    /// A client's published keys are read once, then kept.
    #[tokio::test]
    async fn published_keys_are_read_then_kept() {
        let (server, address) = publishing(one_key()).await;
        let keys = over_plain_http();

        let first = keys.keys_at(&address).await.unwrap();
        let again = keys.keys_at(&address).await.unwrap();

        assert_eq!(first.len(), 1);
        assert_eq!(first, again);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// A key-set host resolving to disallowed loopback addresses returns an
    /// error without receiving a request.
    #[tokio::test]
    async fn an_address_inside_the_deployment_is_refused_unasked() {
        let (server, address) = publishing(one_key()).await;
        let keys = HttpPublishedKeys {
            networks: UpstreamNetworks::public_only(),
            client: screened(Duration::from_secs(5), UpstreamNetworks::public_only()).unwrap(),
            ..over_plain_http()
        };

        let read = keys.keys_at(&address).await;

        assert!(read.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A published key set containing no keys returns an infrastructure error.
    #[tokio::test]
    async fn an_answer_that_is_no_key_set_is_an_error() {
        let (_server, address) = publishing(json!({"keys": []})).await;
        let keys = over_plain_http();

        let read = keys.keys_at(&address).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
